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

int main(int argc, char **argv) {
  std::string server_addr = "localhost:8887";
  std::string server_addr_revoked = "localhost:8886";
  std::string server_addr_uses_crl = "localhost:8885";
  std::string server_addr_uses_crl_revoked = "localhost:8884";
  HelloServiceImpl service;

  if (argc < 2) {
    std::cout << "Enter path to this repo's creds directory as the second "
                 "argument\n$ /path/to/server /path/to/creds/\n";
    return 1;
  }

  std::string credentials_directory = argv[1];

  std::string key = read_file(credentials_directory + "server_key.pem");
  std::string cert = read_file(credentials_directory + "server_cert.pem");
  std::string revoked_cert =
      read_file(credentials_directory + "server_cert_revoked.pem");
  std::string ca_cert = read_file(credentials_directory + "ca_cert.pem");

  grpc::SslServerCredentialsOptions::PemKeyCertPair pair = {key, cert};
  grpc::SslServerCredentialsOptions sslOpts;
  sslOpts.pem_key_cert_pairs.push_back(pair);

  grpc::SslServerCredentialsOptions::PemKeyCertPair revoked_pair = {
      key, revoked_cert};
  grpc::SslServerCredentialsOptions sslOpts_revoked;
  sslOpts_revoked.pem_key_cert_pairs.push_back(revoked_pair);

  ServerBuilder builder;
  builder.AddListeningPort(server_addr, grpc::SslServerCredentials(sslOpts));
  builder.RegisterService(&service);
  std::unique_ptr<Server> server(builder.BuildAndStart());

  ServerBuilder builder_revoked;
  builder_revoked.AddListeningPort(server_addr_revoked,
                                   grpc::SslServerCredentials(sslOpts_revoked));
  builder_revoked.RegisterService(&service);
  std::unique_ptr<Server> server_revoked(builder_revoked.BuildAndStart());

  std::vector<grpc::experimental::IdentityKeyCertPair> identity_key_cert_pairs =
      {{key, cert}};
  auto certificate_provider_ptr =
      std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
          ca_cert, identity_key_cert_pairs);
  grpc::experimental::TlsServerCredentialsOptions options(
      certificate_provider_ptr);
  // options.set_certificate_provider(certificate_provider_ptr);
  options.watch_root_certs();
  options.watch_identity_key_cert_pairs();
  options.set_root_cert_name("ca_cert");
  options.set_crl_directory(credentials_directory + "/crl");
  options.set_cert_request_type(GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY);
  auto server_creds = grpc::experimental::TlsServerCredentials(options);
  ServerBuilder builder_uses_crl;
  builder_uses_crl.AddListeningPort(server_addr_uses_crl, server_creds);
  builder_uses_crl.RegisterService(&service);
  std::unique_ptr<Server> server_uses_crl(builder_uses_crl.BuildAndStart());

  std::vector<grpc::experimental::IdentityKeyCertPair>
      identity_key_cert_pairs_revoked = {{key, revoked_cert}};
  auto certificate_provider_ptr_revoked =
      std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
          ca_cert, identity_key_cert_pairs_revoked);
  grpc::experimental::TlsServerCredentialsOptions options_revoked(
      certificate_provider_ptr_revoked);
  // options_revoked.set_certificate_provider(certificate_provider_ptr);
  options_revoked.watch_root_certs();
  options_revoked.watch_identity_key_cert_pairs();
  options_revoked.set_root_cert_name("ca_cert");
  options_revoked.set_crl_directory(credentials_directory + "/crl");
  options_revoked.set_cert_request_type(
      GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY);
  auto server_creds_revoked =
      grpc::experimental::TlsServerCredentials(options_revoked);
  ServerBuilder builder_uses_crl_revoked;
  builder_uses_crl_revoked.AddListeningPort(server_addr_uses_crl_revoked,
                                            server_creds_revoked);
  builder_uses_crl_revoked.RegisterService(&service);
  std::unique_ptr<Server> server_uses_crl_revoked(
      builder_uses_crl_revoked.BuildAndStart());

  std::cout << "Running servers with the following configuration:\n a server "
               "with a good certificate on 8887\n a revoked "
               "certificate on 8886\n a good certificate and a crl active on "
               "8885\n a revoked certificate and a crl active on 8884\n";

  server->Wait();
  return 0;
}