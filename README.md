# gRPC Advanced Security Examples
This repo contains example code for the advancedtls package in grpc-go and the corresponding experimental APIs in C++ grpc. Specifically, this shows how to use the CertificateProvider interface to provide credentials and how to set up clients and servers to use CRLs.

The c++ server and the golang server both run a basic hello server with different setups of the following ports:
* Good Server No CRL - 8887
* Revoked Server No CRL - 8886
* Good Server With CRL - 8885
* Revoked Server With CRL - 8884

The clients in golang and c++ are designed to call each of those servers with the following configurations:
* Good Client No CRL
* Revoked Client No CRL
* Good Client With CRL
* Revoked Client With CRL


Any client should successfully run against any server.

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
# Run the clients
$ go run client/main.go -credentials_directory $(pwd)/creds
# Run the server
$ go run server/main.go -credentials_directory $(pwd)/creds
```

Stop the servers with ctrl-c or by killing the process.