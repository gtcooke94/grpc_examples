package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	pb "scratch/helloworld"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/credentials/tls/certprovider"
	"google.golang.org/grpc/credentials/tls/certprovider/pemfile"
	"google.golang.org/grpc/security/advancedtls"
)

type server struct {
	pb.UnimplementedHelloServiceServer
	name string
}

const credRefreshInterval = 1 * time.Minute
const goodServerWithCrlPort int = 8885
const revokedServerWithCrlPort int = 8884
const insecurePort int = 8883

func (s *server) Hello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloResponse, error) {
	fmt.Printf("%v Received: %v\n", s.name, in.GetName())
	return &pb.HelloResponse{Response: "Hello " + in.GetName()}, nil
}

func TlsServers(credentialsDirectory string) {
	go func() {
		createAndRunTlsServer(credentialsDirectory, false, goodServerWithCrlPort)
	}()
	go func() {
		createAndRunTlsServer(credentialsDirectory, true, revokedServerWithCrlPort)
	}()

	fmt.Printf(`Running servers with the following configuration:
    a good certificate and a crl active on  8885
    a revoked certificate and a crl active on 8884
`)
}

func InsecureServer(credentialsDirectory string) {
	go func() {
		createAndRunInsecureServer(insecurePort)
	}()
	fmt.Printf(`Running server with the following configuration:
    insecure credentials on 8883
`)
}

func createAndRunInsecureServer(port int) {
	creds := insecure.NewCredentials()
	s := grpc.NewServer(grpc.Creds(creds))
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Printf("Failed to listen: %v\n", err)
	}
	pb.RegisterHelloServiceServer(s, &server{name: "Insecure Server"})
	if err := s.Serve(lis); err != nil {
		fmt.Printf("Failed to serve: %v\n", err)
		os.Exit(1)
	}
}

func createAndRunTlsServer(credsDirectory string, useRevokedCert bool, port int) {
	identityProvider := makeIdentityProvider(useRevokedCert, credsDirectory)
	defer identityProvider.Close()

	rootProvider := makeRootProvider(credsDirectory)
	defer rootProvider.Close()

	crlProvider := makeCrlProvider(filepath.Join(credsDirectory, "crl"))
	defer crlProvider.Close()

	options := &advancedtls.Options{
		IdentityOptions: advancedtls.IdentityCertificateOptions{
			IdentityProvider: identityProvider,
		},
		RootOptions: advancedtls.RootCertificateOptions{
			RootProvider: rootProvider,
		},
		RequireClientCert: true,
		VerificationType:  advancedtls.CertVerification,
	}

	options.RevocationOptions = &advancedtls.RevocationOptions{
		CRLProvider: crlProvider,
	}

	serverTLSCreds, err := advancedtls.NewServerCreds(options)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		os.Exit(1)
	}

	s := grpc.NewServer(grpc.Creds(serverTLSCreds))
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Printf("Failed to listen: %v\n", err)
	}
	name := "Good TLS Server"
	if useRevokedCert {
		name = "Revoked TLS Server"
	}
	pb.RegisterHelloServiceServer(s, &server{name: name})
	if err := s.Serve(lis); err != nil {
		fmt.Printf("Failed to serve: %v\n", err)
		os.Exit(1)
	}

}

func makeRootProvider(credsDirectory string) certprovider.Provider {
	rootOptions := pemfile.Options{
		RootFile:        filepath.Join(credsDirectory, "/ca_cert.pem"),
		RefreshDuration: credRefreshInterval,
	}

	rootProvider, err := pemfile.NewProvider(rootOptions)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		os.Exit(1)
	}
	return rootProvider
}

func makeIdentityProvider(useRevokedCert bool, credsDirectory string) certprovider.Provider {
	certFilePath := ""
	if useRevokedCert {
		certFilePath = filepath.Join(credsDirectory, "server_cert_revoked.pem")
	} else {
		certFilePath = filepath.Join(credsDirectory, "server_cert.pem")
	}
	identityOptions := pemfile.Options{
		CertFile:        certFilePath,
		KeyFile:         filepath.Join(credsDirectory, "server_key.pem"),
		RefreshDuration: credRefreshInterval,
	}
	identityProvider, err := pemfile.NewProvider(identityOptions)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		os.Exit(1)
	}
	return identityProvider
}

func makeCrlProvider(crlDirectory string) *advancedtls.FileWatcherCRLProvider {
	options := advancedtls.FileWatcherOptions{
		CRLDirectory: crlDirectory,
	}
	provider, err := advancedtls.NewFileWatcherCRLProvider(options)
	if err != nil {
		fmt.Printf("Error making CRL Provider: %v\nExiting...", err)
		os.Exit(1)
	}
	return provider
}

func main() {
	credentialsDirectory := flag.String("credentials_directory", "", "Path to the creds directory of this repo")
	flag.Parse()
	if *credentialsDirectory == "" {
		fmt.Println("Must set credentials_directory argument")
		os.Exit(1)
	}
	TlsServers(*credentialsDirectory)
	InsecureServer(*credentialsDirectory)
	fmt.Printf("Ctrl-C or kill the process to stop\n")
	for {
		time.Sleep(1 * time.Second)
	}
}
