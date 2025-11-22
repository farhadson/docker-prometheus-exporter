### build only phase 1

### when target is builder all the hfs of the OS get exported
docker build \
  --build-arg GOPROXY=https://proxy.golang.org \
  --target builder \
  --output type=local,dest=./out \
  .

### when target is export since in docker file it gets created from scratch only the file gets exported
docker build \
  --build-arg GOPROXY=https://proxy.golang.org \
  --target export \
  --output type=local,dest=./out \
  .

### complete build

docker build \
  --build-arg GOPROXY=proxy.golang.org \  
  -t my-reset-sidecar:latest .