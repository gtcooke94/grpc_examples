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

// const serverAddr = "localhost"
// const goodServerPort string = "8885"
// const revokedServerPort string = "8884"
const std::string kGoodServerAddress = "localhost:8887";
const std::string kRevokedServerAddress = "localhost:8886";

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

void SslCredentials(std::string credentials_directory) {
  std::cout << "Client running with SslCredentials against a good server\n";
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
      grpc::CreateChannel(kGoodServerAddress, channel_creds);
  HelloClient client(channel);
  std::string user("world");
  std::string reply = client.Hello(user);
  if (reply != "Hello world") {
    std::cout << "Did not behave as expected to get \"Hello world\" but got "
                 "something else.\n";
  } else {
    std::cout << "Behaved as expectd - Greeter received: " << reply
              << std::endl;
  }
}

void TlsCredentials(std::string credentials_directory) {
  std::cout << "Client running with TlsCredentials against a good server\n";
  // Load necessary files
  std::string ca_cert = read_file(credentials_directory + "ca_cert.pem");
  std::string key = read_file(credentials_directory + "client_key.pem");
  std::string cert = read_file(credentials_directory + "client_cert.pem");

  // Create and populate TlsChannelCredentialsOptions
  grpc::experimental::TlsChannelCredentialsOptions options;
  std::vector<grpc::experimental::IdentityKeyCertPair> identity_key_cert_pairs =
      {{key, cert}};
  auto certificate_provider_ptr =
      std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
          ca_cert, identity_key_cert_pairs);
  options.set_certificate_provider(certificate_provider_ptr);
  options.watch_root_certs();
  options.set_root_cert_name("root_cert");
  options.watch_identity_key_cert_pairs();
  options.set_identity_cert_name("identity_certs");
  auto channel_creds = grpc::experimental::TlsCredentials(options);

  // Create the channel with those creds and send a request
  std::shared_ptr<Channel> channel =
      grpc::CreateChannel(kGoodServerAddress, channel_creds);
  HelloClient client(channel);
  std::string user("world");
  std::string reply = client.Hello(user);
  if (reply != "Hello world") {
    std::cout << "Did not behave as expected to get \"Hello world\" but got "
                 "something else.\n";
  } else {
    std::cout << "Behaved as expected. Greeter received: " << reply
              << std::endl;
  }
}

void TlsCredentialsWithCrlProvider(std::string credentials_directory,
                                   std::string crl_directory) {
  std::cout << "Client running with TlsCredentials and revocation configured "
               "against a revoked server\n";
  // Load necessary files
  std::string ca_cert = read_file(credentials_directory + "ca_cert.pem");
  std::string key = read_file(credentials_directory + "client_key.pem");
  std::string cert = read_file(credentials_directory + "client_cert.pem");

  // Create and populate TlsChannelCredentialsOptions
  grpc::experimental::TlsChannelCredentialsOptions options;
  // Create the certificate provider
  std::vector<grpc::experimental::IdentityKeyCertPair> identity_key_cert_pairs =
      {{key, cert}};
  auto certificate_provider_ptr =
      std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
          ca_cert, identity_key_cert_pairs);
  options.set_certificate_provider(certificate_provider_ptr);
  options.watch_root_certs();
  options.set_root_cert_name("root_cert");
  options.watch_identity_key_cert_pairs();
  options.set_identity_cert_name("identity_certs");
  // Create the CRL provider
  auto crl_provider =
      grpc_core::experimental::CreateDirectoryReloaderCrlProvider(
          crl_directory, std::chrono::seconds(60), nullptr);
  if (!crl_provider.ok()) {
    std::cout << "ERROR: There was a problem creating the crl provider.\n";
  }
  options.set_crl_provider(*crl_provider);
  auto channel_creds = grpc::experimental::TlsCredentials(options);

  // Create the channel with those creds and send a request
  std::shared_ptr<Channel> channel =
      grpc::CreateChannel(kRevokedServerAddress, channel_creds);
  HelloClient client(channel);
  std::string user("world");
  std::string reply = client.Hello(user);
  std::cout << reply;
  if (reply == "Hello world") {
    std::cout << "Did not behave as expected - expected connection failed.\n";
  } else {
    std::cout << "Behaved as expected with failed connection.\n";
  }
}

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cout << "Enter this repo's creds directory as the second "
                 "argument\n/path/to/client <creds_directory>\n";
    return 1;
  }

  std::string credentials_directory = argv[1];
  std::string crl_directory = credentials_directory + "/crl";
  std::cout << "\n\n";
  SslCredentials(credentials_directory);
  std::cout << "\n\n";
  TlsCredentials(credentials_directory);
  std::cout << "\n\n";
  TlsCredentialsWithCrlProvider(credentials_directory, crl_directory);
  std::cout << "\n\n";

  return 0;
}
