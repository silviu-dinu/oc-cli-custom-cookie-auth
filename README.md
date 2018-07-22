OpenShift Application Platform
==============================

```
# Install project
$ git clone https://github.com/silviu-dinu/oc-cli-custom-cookie-auth
$ cd oc-cli-custom-cookie-auth
$ glide up -v

# Compile cli to0ls
$ make WHAT=cmd/oc GOFLAGS=-v

# Set cookie as environment variable
$ export COOKIE_SPX_STICKY_CLOUDLET='__spx_sticky_cloudlet=...'
$ ./_output/local/bin/darwin/amd64/oc login https://os.example.com --token=<token>
```
