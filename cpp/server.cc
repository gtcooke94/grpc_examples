#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include <grpcpp/grpcpp.h>

#include "hello.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

class HelloServiceImpl final : public HelloService::Service {
  Status Hello(ServerContext *context, const HelloRequest *req,
               HelloResponse *resp) override {
    std::cout << "Received request with name: " << req->name() << std::endl;
    resp->set_response("Hello " + req->name());
    return Status::OK;
  }
};

std::string read_file(std::string file_path) {
  std::ifstream input_stream(file_path);
  std::stringstream buffer;
  buffer << input_stream.rdbuf();
  return buffer.str();
}

void InsecureCredentials() {
  // TODO
}

void SslCredentials(std::string address, std::string credentials_directory) {
  HelloServiceImpl service;
  std::string key = read_file(credentials_directory + "server_key.pem");
  std::string cert = read_file(credentials_directory + "server_cert.pem");
  std::string revoked_cert =
      read_file(credentials_directory + "server_cert_revoked.pem");
  std::string ca_cert = read_file(credentials_directory + "ca_cert.pem");

  grpc::SslServerCredentialsOptions::PemKeyCertPair pair = {key, revoked_cert};
  grpc::SslServerCredentialsOptions sslOpts;
  sslOpts.pem_key_cert_pairs.push_back(pair);
  sslOpts.pem_root_certs = ca_cert;
  sslOpts.force_client_auth = true;

  grpc::SslServerCredentialsOptions sslOpts_revoked;
  sslOpts_revoked.pem_key_cert_pairs.push_back(pair);

  ServerBuilder builder;
  builder.AddListeningPort(address, grpc::SslServerCredentials(sslOpts));
  builder.RegisterService(&service);
  std::unique_ptr<Server> server(builder.BuildAndStart());
  server->Wait();
}

int main(int argc, char **argv) {
  std::string server_addr = "localhost:8887";
  std::string server_addr_revoked = "localhost:8886";
  std::string server_addr_uses_crl = "localhost:8885";
  std::string server_addr_uses_crl_revoked = "localhost:8884";

  if (argc < 2) {
    std::cout << "Enter path to this repo's creds directory as the second "
                 "argument\n$ /path/to/server /path/to/creds/\n";
    return 1;
  }

  std::string credentials_directory = argv[1];

  SslCredentials(server_addr, credentials_directory);

  return 0;
}