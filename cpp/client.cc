#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include <grpcpp/grpcpp.h>

#include "hello.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::experimental::AltsCredentials;
using grpc::experimental::AltsCredentialsOptions;

class HelloClient {
public:
  HelloClient(std::shared_ptr<Channel> channel)
      : stub_(HelloService::NewStub(channel)) {}

  std::string Hello(const std::string &user) {
    HelloRequest request;
    request.set_name(user);

    HelloResponse reply;
    ClientContext context;
    Status status = stub_->Hello(&context, request, &reply);

    if (status.ok()) {
      return reply.response();
    } else {
      std::cout << "Failure - " << status.error_code() << ": "
                << status.error_message() << std::endl;
      return "";
    }
  }

private:
  std::unique_ptr<HelloService::Stub> stub_;
};

std::string read_file(std::string file_path) {
  std::ifstream input_stream(file_path);
  std::stringstream buffer;
  buffer << input_stream.rdbuf();
  // std::string contents = buffer.str();
  return buffer.str();
}

void InsecureCredentials() {
  // TODO
}

void SslCredentials(std::string address, std::string credentials_directory) {
  // Load necessary files
  std::string ca_cert = read_file(credentials_directory + "ca_cert.pem");
  std::string key = read_file(credentials_directory + "client_key.pem");
  std::string cert = read_file(credentials_directory + "client_cert.pem");
  // Create the SslCredentialsOptions and SslChannelCreds
  grpc::SslCredentialsOptions sslOpts;
  sslOpts.pem_root_certs = ca_cert;
  sslOpts.pem_private_key = key;
  sslOpts.pem_cert_chain = cert;
  auto channel_creds = grpc::SslCredentials(sslOpts);
  // Create the channel with those creds and send a request
  std::shared_ptr<Channel> channel =
      grpc::CreateChannel(address, channel_creds);
  HelloClient client(channel);
  std::string user("world");
  std::string reply = client.Hello(user);
  if (reply != "Hello world") {
    std::cout << "Expected to get \"Hello world\" but got something else.\n";
  } else {
    std::cout << "Greeter received: " << reply << std::endl;
  }
}

void CrlProvider(std::string address, std::string credentials_directory,
                 std::string crl_directory) {
  std::string ca_cert = read_file(credentials_directory + "ca_cert.pem");
  std::string key = read_file(credentials_directory + "client_key.pem");
  std::string cert = read_file(credentials_directory + "client_cert.pem");

  std::vector<grpc::experimental::IdentityKeyCertPair> identity_key_cert_pairs =
      {{key, cert}};
  auto certificate_provider_ptr =
      std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
          ca_cert, identity_key_cert_pairs);

  grpc::experimental::TlsChannelCredentialsOptions options;
  options.set_certificate_provider(certificate_provider_ptr);
  options.watch_root_certs();
  options.watch_identity_key_cert_pairs();
  options.set_root_cert_name("ca_cert");
  grpc_init();
  absl::StatusOr<std::shared_ptr<grpc_core::experimental::CrlProvider>>
      crl_provider =
          grpc_core::experimental::CreateDirectoryReloaderCrlProvider(
              crl_directory, std::chrono::seconds(60), nullptr);
  if (!crl_provider.ok()) {
    std::cout << crl_provider.status() << std::endl;
    return;
  }
  options.set_crl_provider(*crl_provider);
  auto channel_creds = grpc::experimental::TlsCredentials(options);
  std::shared_ptr<Channel> channel =
      grpc::CreateChannel(address, channel_creds);
  HelloClient client(channel);
  std::string user("world");
  std::string reply = client.Hello(user);
  if (reply != "Hello world") {
    std::cout << "Failure expected because of revoked server cert\n";
  } else {
    std::cout << "Request should have failed but didn't\n"
              << reply << std::endl;
  }
  return;
}

int main(int argc, char **argv) {
  std::string server_addr = "localhost:8887";

  if (argc < 2) {
    std::cout << "Enter path to this repo's creds directory as the second "
                 "argument\n$ /path/to/server /path/to/creds/\n";
    return 1;
  }

  std::string credentials_directory = argv[1];
  std::string crl_directory = credentials_directory + "crl";

  std::cout << "start" << std::endl;
  CrlProvider(server_addr, credentials_directory, crl_directory);
  return 0;
}
