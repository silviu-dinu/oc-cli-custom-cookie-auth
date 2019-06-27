OpenShift Application Platform
==============================

## Description

`oc` command line tool patch to support ADFS/NTLM authentication.

## Requirements

 - Go 1.10 or higher
 - Docker (optional)

## Compiling on MacOS (with netcgo)
```
$ git clone https://github.com/silviu-dinu/oc-cli-custom-cookie-auth ~/golang/src/github.com/openshift/origin
$ cd ~/golang/src/github.com/openshift/origin
$ make WHAT=cmd/oc GOFLAGS=-v
```

*`oc` binary will be saved to `_output/local/bin/darwin/amd64` location.*

## Compiling for linux inside Docker (without netcgo)
```
$ git clone https://github.com/silviu-dinu/oc-cli-custom-cookie-auth
$ cd oc-cli-custom-cookie-auth
$ hack/env make WHAT=cmd/oc GOFLAGS=-v
```

*`oc` binary will be saved to `_output/local/bin/linux/amd64` location.*

## Caveats

When project is cross-compiled (e.g.: from Linux targeting MacOS) the build will use `netgo` instead of `netcgo`. This might cause issues on MacOS systems behind VPN connections.

## Original project

https://github.com/openshift/origin