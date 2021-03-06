package apiserver

import (
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	kclientsetinternal "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"

	appsapiv1 "github.com/openshift/api/apps/v1"
	appsclientinternal "github.com/openshift/origin/pkg/apps/generated/internalclientset"
	deployconfigetcd "github.com/openshift/origin/pkg/apps/registry/deployconfig/etcd"
	deploylogregistry "github.com/openshift/origin/pkg/apps/registry/deploylog"
	deployconfiginstantiate "github.com/openshift/origin/pkg/apps/registry/instantiate"
	deployrollback "github.com/openshift/origin/pkg/apps/registry/rollback"
	imageclientinternal "github.com/openshift/origin/pkg/image/generated/internalclientset"
)

type ExtraConfig struct {
	KubeAPIServerClientConfig *restclient.Config

	// TODO these should all become local eventually
	Scheme *runtime.Scheme
	Codecs serializer.CodecFactory

	makeV1Storage sync.Once
	v1Storage     map[string]rest.Storage
	v1StorageErr  error
}

type AppsServerConfig struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

type AppsServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	ExtraConfig   *ExtraConfig
}

type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (c *AppsServerConfig) Complete() completedConfig {
	cfg := completedConfig{
		c.GenericConfig.Complete(),
		&c.ExtraConfig,
	}

	return cfg
}

// New returns a new instance of AppsServer from the given config.
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*AppsServer, error) {
	genericServer, err := c.GenericConfig.New("apps.openshift.io-apiserver", delegationTarget)
	if err != nil {
		return nil, err
	}

	s := &AppsServer{
		GenericAPIServer: genericServer,
	}

	v1Storage, err := c.V1RESTStorage()
	if err != nil {
		return nil, err
	}

	parameterCodec := runtime.NewParameterCodec(c.ExtraConfig.Scheme)
	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(appsapiv1.GroupName, c.ExtraConfig.Scheme, parameterCodec, c.ExtraConfig.Codecs)
	apiGroupInfo.VersionedResourcesStorageMap[appsapiv1.SchemeGroupVersion.Version] = v1Storage

	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	return s, nil
}

func (c *completedConfig) V1RESTStorage() (map[string]rest.Storage, error) {
	c.ExtraConfig.makeV1Storage.Do(func() {
		c.ExtraConfig.v1Storage, c.ExtraConfig.v1StorageErr = c.newV1RESTStorage()
	})

	return c.ExtraConfig.v1Storage, c.ExtraConfig.v1StorageErr
}

func (c *completedConfig) newV1RESTStorage() (map[string]rest.Storage, error) {
	openshiftInternalAppsClient, err := appsclientinternal.NewForConfig(c.GenericConfig.LoopbackClientConfig)
	if err != nil {
		return nil, err
	}
	// This client is using the core api server client config, since the apps server doesn't host images
	openshiftInternalImageClient, err := imageclientinternal.NewForConfig(c.ExtraConfig.KubeAPIServerClientConfig)
	if err != nil {
		return nil, err
	}
	kubeInternalClient, err := kclientsetinternal.NewForConfig(c.ExtraConfig.KubeAPIServerClientConfig)
	if err != nil {
		return nil, err
	}
	kubeClient, err := kubernetes.NewForConfig(c.ExtraConfig.KubeAPIServerClientConfig)
	if err != nil {
		return nil, err
	}

	deployConfigStorage, deployConfigStatusStorage, deployConfigScaleStorage, err := deployconfigetcd.NewREST(c.GenericConfig.RESTOptionsGetter)
	if err != nil {
		return nil, err
	}
	dcInstantiateStorage := deployconfiginstantiate.NewREST(
		*deployConfigStorage.Store,
		openshiftInternalImageClient,
		kubeInternalClient,
		c.GenericConfig.AdmissionControl,
	)
	deployConfigRollbackStorage := deployrollback.NewREST(openshiftInternalAppsClient, kubeInternalClient)

	v1Storage := map[string]rest.Storage{}
	v1Storage["deploymentConfigs"] = deployConfigStorage
	v1Storage["deploymentConfigs/scale"] = deployConfigScaleStorage
	v1Storage["deploymentConfigs/status"] = deployConfigStatusStorage
	v1Storage["deploymentConfigs/rollback"] = deployConfigRollbackStorage
	v1Storage["deploymentConfigs/log"] = deploylogregistry.NewREST(openshiftInternalAppsClient.Apps(), kubeInternalClient.Core(), kubeClient.CoreV1())
	v1Storage["deploymentConfigs/instantiate"] = dcInstantiateStorage
	return v1Storage, nil
}
