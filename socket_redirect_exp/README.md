# socket_redirect_exp

## Build

```shell
go generate ./... && go build .
```

## Usage

For example, we have a local TCP service listening on localhost:8000, to accelerate local TCP transmission via `curl`, we can run command:

```shell
sudo ./socket_redirect_exp curl
```
