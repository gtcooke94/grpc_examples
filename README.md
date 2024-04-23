# gRPC Advanced Security Examples
This repo contains example code for different security configurations for grpc.

The servers run a basic hello server with the following setups:
* C++, Unrevoked, SslCredentials, 8887
* C++, Revoked, TlsCredentials, 8886
* Golang, Unrevoked, TlsCredentials, 8885
* Golang, Revoked, TlsCredentials, 8884

The clients in golang and c++ are designed to call these servers with varying configurations of credentials and revocation configurations.

## Generate the credentials used in the examples
Run `./generate.sh` to generate the `creds` directory containing the certificates and CRLs needed for these examples.

## Building and Running C++
```
$ pushd cpp && bazel build :all && popd
# Run the clients
$ ./cpp/bazel-bin/client $(pwd)/creds/
# Run the server
$ ./cpp/bazel-bin/server $(pwd)/creds/
```

## Building and Running Golang
```
# Run the clients from the `go` subdirectory
$ go run client/main.go -credentials_directory $(pwd)/../creds
# Run the server
$ go run server/main.go -credentials_directory $(pwd)/../creds
```

Stop the servers with ctrl-c or by killing the process.