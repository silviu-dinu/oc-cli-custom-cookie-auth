// Code generated by informer-gen. DO NOT EDIT.

package internalversion

import (
	time "time"

	authorization "github.com/openshift/origin/pkg/authorization/apis/authorization"
	internalinterfaces "github.com/openshift/origin/pkg/authorization/generated/informers/internalversion/internalinterfaces"
	internalclientset "github.com/openshift/origin/pkg/authorization/generated/internalclientset"
	internalversion "github.com/openshift/origin/pkg/authorization/generated/listers/authorization/internalversion"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// ClusterRoleBindingInformer provides access to a shared informer and lister for
// ClusterRoleBindings.
type ClusterRoleBindingInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() internalversion.ClusterRoleBindingLister
}

type clusterRoleBindingInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewClusterRoleBindingInformer constructs a new informer for ClusterRoleBinding type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewClusterRoleBindingInformer(client internalclientset.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredClusterRoleBindingInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredClusterRoleBindingInformer constructs a new informer for ClusterRoleBinding type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredClusterRoleBindingInformer(client internalclientset.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.Authorization().ClusterRoleBindings().List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.Authorization().ClusterRoleBindings().Watch(options)
			},
		},
		&authorization.ClusterRoleBinding{},
		resyncPeriod,
		indexers,
	)
}

func (f *clusterRoleBindingInformer) defaultInformer(client internalclientset.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredClusterRoleBindingInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *clusterRoleBindingInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&authorization.ClusterRoleBinding{}, f.defaultInformer)
}

func (f *clusterRoleBindingInformer) Lister() internalversion.ClusterRoleBindingLister {
	return internalversion.NewClusterRoleBindingLister(f.Informer().GetIndexer())
}
