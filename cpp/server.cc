#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include <grpcpp/grpcpp.h>

#include "hello.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

const std::string kGoodServerAddr = "localhost:8887";
const std::string kRevokedServerAddr = "localhost:8886";

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

// Run a server using SslCredentials with a good certificate
void SslCredentials(std::string credentials_directory) {
  // Load necessary files
  std::string key = read_file(credentials_directory + "server_key.pem");
  std::string cert = read_file(credentials_directory + "server_cert.pem");
  std::string ca_cert = read_file(credentials_directory + "ca_cert.pem");

  // Conifugre and create the SslServerCredentials
  grpc::SslServerCredentialsOptions::PemKeyCertPair pair = {key, cert};
  grpc::SslServerCredentialsOptions sslOpts;
  sslOpts.pem_key_cert_pairs.push_back(pair);
  sslOpts.pem_root_certs = ca_cert;
  sslOpts.force_client_auth = true;

  // Create the server with these credentials
  ServerBuilder builder;
  builder.AddListeningPort(kGoodServerAddr,
                           grpc::SslServerCredentials(sslOpts));
  HelloServiceImpl service;
  builder.RegisterService(&service);
  std::unique_ptr<Server> server(builder.BuildAndStart());
  server->Wait();
}

// Run a server using TlsCredentials configured with a revoked certificate
void TlsCredentialsRevoked(std::string credentials_directory,
                           std::string crl_directory) {
  // Load necessary files
  std::string key = read_file(credentials_directory + "server_key.pem");
  std::string revoked_cert =
      read_file(credentials_directory + "server_cert_revoked.pem");
  std::string ca_cert = read_file(credentials_directory + "ca_cert.pem");

  // Create a certificate provider
  std::vector<grpc::experimental::IdentityKeyCertPair> identity_key_cert_pairs =
      {{key, revoked_cert}};
  auto certificate_provider_ptr =
      std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
          ca_cert, identity_key_cert_pairs);

  // Configure and create the credentials
  grpc::experimental::TlsServerCredentialsOptions options(
      certificate_provider_ptr);
  options.watch_root_certs();
  options.watch_identity_key_cert_pairs();
  options.set_root_cert_name("");
  options.set_cert_request_type(GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY);
  auto server_creds = grpc::experimental::TlsServerCredentials(options);

  // Create the server with these credentials
  ServerBuilder builder;
  builder.AddListeningPort(kRevokedServerAddr, server_creds);
  HelloServiceImpl service;
  builder.RegisterService(&service);
  std::unique_ptr<Server> server(builder.BuildAndStart());
  server->Wait();
}

void TlsCredentialsWithCrlDirectory() {
  // TODO
}

void TlsCredentialsWithCrlProvider() {
  // TODO
}

int main(int argc, char **argv) {

  if (argc < 2) {
    std::cout << "Enter path to this repo's creds directory as the second "
                 "argument\n$ /path/to/server /path/to/creds/\n";
    return 1;
  }

  std::string credentials_directory = argv[1];
  std::string crl_directory = credentials_directory + "/crl";

  // Run the servers on threads so they can all run simultaneously
  std::thread good_server(SslCredentials, credentials_directory);
  std::thread bad_server(TlsCredentialsRevoked, credentials_directory,
                         crl_directory);
  std::cout << "Ctrl-C or kill the process to stop\n";
  // Sleep forever until the process is killed
  while (true) {
    sleep(1000);
  }
  return 0;
}