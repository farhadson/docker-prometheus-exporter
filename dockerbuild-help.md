### build only phase 1

docker build \
  --build-arg GOPROXY=https://proxy.golang.org \  
  --target builder \
  --output type=local,dest=./out

### complete build

docker build \
  --build-arg GOPROXY=proxy.golang.org \  
  -t my-reset-sidecar:latest .