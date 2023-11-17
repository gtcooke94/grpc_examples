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

void SslCredentials(std::string address, std::string port,
                    std::string credentials_directory) {
  // Load necessary files
  std::string server_address = address + ":" + port;
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
      grpc::CreateChannel(server_address, channel_creds);
  HelloClient client(channel);
  std::string user("world");
  std::string reply = client.Hello(user);
  if (reply != "Hello world") {
    std::cout << "Expected to get \"Hello world\" but got something else.\n";
  } else {
    std::cout << "Greeter received: " << reply << std::endl;
  }
}

void TlsCredentials() {
  // TODO
}

void TlsCredentialsWithCrlDirectory() {
  // TODO
}

void TlsCredentialsWithCrlProvider() {
  // TODO
}

// Old purpose, clean this up
void run_case(std::string address, std::string port,
              std::string credentials_directory, bool use_revoked_cert,
              bool use_crl, bool should_fail) {

  std::string server_address = address + ":" + port;
  grpc::experimental::TlsChannelCredentialsOptions options;
  std::string ca_cert = read_file(credentials_directory + "ca_cert.pem");
  std::string key = read_file(credentials_directory + "client_key.pem");
  std::string cert = read_file(credentials_directory + "client_cert.pem");
  std::string revoked_cert =
      read_file(credentials_directory + "client_cert_revoked.pem");

  if (use_crl) {
    options.set_crl_directory(credentials_directory + "crl");
  }
  std::string cert_to_use;
  if (use_revoked_cert) {
    cert_to_use = revoked_cert;
  } else {
    cert_to_use = cert;
  }
  // grpc::SslCredentialsOptions::PemKeyCertPair pair = {key, cert_to_use};
  grpc::SslCredentialsOptions sslOpts;
  sslOpts.pem_root_certs = ca_cert;
  sslOpts.pem_private_key = key;
  sslOpts.pem_cert_chain = cert_to_use;

  // sslOpts.pem_key_cert_pairs.push_back(pair);
  auto channel_creds = grpc::SslCredentials(sslOpts);
  // std::vector<grpc::experimental::IdentityKeyCertPair>
  // identity_key_cert_pairs =
  //     {{key, cert_to_use}};
  // auto certificate_provider_ptr =
  //     std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
  //         ca_cert, identity_key_cert_pairs);
  // options.set_certificate_provider(certificate_provider_ptr);
  // options.watch_root_certs();
  // options.set_root_cert_name("root_cert");
  // options.watch_identity_key_cert_pairs();
  // options.set_identity_cert_name("identity_certs");

  // auto channel_creds = grpc::experimental::TlsCredentials(options);

  std::shared_ptr<Channel> channel =
      grpc::CreateChannel(server_address, channel_creds);
  HelloClient client(channel);
  std::string user("world");
  std::string reply = client.Hello(user);
  if (should_fail) {
    if (reply != "") {
      std::cout << "Expected failure but got: " << reply << std::endl;
    } else {
      std::cout << "Handshake failed expectedly\n";
    }

  } else {
    if (reply != "Hello world") {
      std::cout << "Expected to get \"Hello world\" but got something else.\n";

    } else {
      std::cout << "Greeter received: " << reply << std::endl;
    }
  }
}

int main(int argc, char **argv) {
  std::string address = "localhost";

  if (argc < 2) {
    std::cout << "Enter this repo's creds directory as the second "
                 "argument\n/path/to/client <creds_directory>\n";
    return 1;
  }

  std::string credentials_directory = argv[1];

  std::map<std::string, std::string> cases;
  cases["8887"] = "[good server, no CRL]";
  // cases["8886"] = "[revoked server, no CRL]";
  // cases["8885"] = "[good server, with CRL]";
  // cases["8884"] = "[revoked server, with CRL]";
  for (auto const &c : cases) {
    auto port = c.first;
    auto description = c.second;

    std::cout
        << "=============================================================="
           "==================\n";
    std::cout << "Running against localhost:" << port << " " << description
              << std::endl;
    std::cout << "Client running with [good certificate, no CRL] at "
              << description << std::endl;
    bool should_fail = false;
    run_case(address, port, credentials_directory, false, false, should_fail);
    // std::cout <<
    // "-------------------------------------------------------------"
    //              "-------------------\n";
    // std::cout << "Client running with [revoked certificate, no CRL] at "
    //           << description << std::endl;
    // should_fail = port == "8885" || port == "8884";
    // run_case(address, port, credentials_directory, true, false, should_fail);
    // std::cout <<
    // "-------------------------------------------------------------"
    //              "-------------------\n";
    // std::cout << "Client running with [good certificate, CRL] at "
    //           << description << std::endl;
    // should_fail = port == "8886" || port == "8884";
    // run_case(address, port, credentials_directory, false, true, should_fail);
    // std::cout <<
    // "-------------------------------------------------------------"
    //              "-------------------\n";
    // std::cout << "Client running with [revoked certificate, CRL] at "
    //           << description << std::endl;
    // should_fail = port == "8886" || port == "8884" || port == "8885";
    // run_case(address, port, credentials_directory, true, true, should_fail);
  }
  return 0;
}
