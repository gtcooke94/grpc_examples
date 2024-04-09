package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pb "scratch/helloworld"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/tls/certprovider"
	"google.golang.org/grpc/credentials/tls/certprovider/pemfile"
	"google.golang.org/grpc/security/advancedtls"
)

const credRefreshInterval = 1 * time.Minute
const serverAddr = "localhost"

// -- TLS --

func makeRootProvider(credsDirectory string) certprovider.Provider {
	rootOptions := pemfile.Options{
		RootFile:        filepath.Join(credsDirectory, "ca_cert.pem"),
		RefreshDuration: credRefreshInterval,
	}
	rootProvider, err := pemfile.NewProvider(rootOptions)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		os.Exit(1)
	}
	return rootProvider
}

func makeIdentityProvider(revoked bool, credsDirectory string) certprovider.Provider {
	var cert_file string
	if revoked {
		cert_file = filepath.Join(credsDirectory, "client_cert_revoked.pem")
	} else {
		cert_file = filepath.Join(credsDirectory, "client_cert.pem")
	}
	identityOptions := pemfile.Options{
		CertFile:        cert_file,
		KeyFile:         filepath.Join(credsDirectory, "client_key.pem"),
		RefreshDuration: credRefreshInterval,
	}
	identityProvider, err := pemfile.NewProvider(identityOptions)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		os.Exit(1)
	}
	return identityProvider
}

func runClientWithProviders(rootProvider certprovider.Provider, identityProvider certprovider.Provider, crlProvider advancedtls.CRLProvider, port string, shouldFail bool) {
	// Configure the Identity and Root certs in the Client
	options := &advancedtls.ClientOptions{
		IdentityOptions: advancedtls.IdentityCertificateOptions{
			IdentityProvider: identityProvider,
		},
		RootOptions: advancedtls.RootCertificateOptions{
			RootProvider: rootProvider,
		},
		VType: advancedtls.CertVerification,
	}

	// Configure revocation and CRLs
	options.RevocationConfig = &advancedtls.RevocationConfig{
		CRLProvider: crlProvider,
	}

	clientTLSCreds, err := advancedtls.NewClientCreds(options)

	if err != nil {
		fmt.Printf("Error %v\n", err)
		os.Exit(1)
	}
	fullServerAddr := serverAddr + ":" + port
	conn, err := grpc.Dial(fullServerAddr, grpc.WithTransportCredentials(clientTLSCreds))
	if err != nil {
		fmt.Printf("Error during grpc.Dial %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := pb.NewHelloServiceClient(conn)
	req := &pb.HelloRequest{
		Name: "World",
	}
	context, _ := context.WithTimeout(context.Background(), 24*time.Hour)
	resp, err := client.Hello(context, req)
	if shouldFail {
		if err == nil {
			fmt.Println("Should have failed but didn't")
		} else {
			fmt.Println("Handshake failed expectedly")
		}
	} else {
		if err != nil {
			fmt.Printf("Error during client.Hello %v\n", err)
		} else {
			fmt.Printf("Response: %v\n", resp.Response)
			if resp.Response != "Hello World" {
				fmt.Println("Didn't get correct response")
			}
		}

	}
}

// port 8885 runs a server with an  unrevoked certificate
func TlsWithCrlsToGoodServer(credsDirectory string) {
	rootProvider := makeRootProvider(credsDirectory)
	defer rootProvider.Close()
	identityProvider := makeIdentityProvider(false, credsDirectory)
	defer identityProvider.Close()
	crlProvider := makeCrlProvider(credsDirectory)
	defer crlProvider.Close()

	fmt.Println("Client running against good server.")
	runClientWithProviders(rootProvider, identityProvider, crlProvider, "8885", false)
}

// port 8884 runs a server with a revoked certificate
func TlsWithCrlsToRevokedServer(credsDirectory string) {
	rootProvider := makeRootProvider(credsDirectory)
	defer rootProvider.Close()
	identityProvider := makeIdentityProvider(false, credsDirectory)
	crlProvider := makeCrlProvider(credsDirectory)
	defer crlProvider.Close()

	fmt.Println("Client running against revoked server.")
	runClientWithProviders(rootProvider, identityProvider, crlProvider, "8884", true)
	identityProvider.Close()
}

func TlsWithCrls(credsDirectory string) {
	TlsWithCrlsToGoodServer(credsDirectory)
	TlsWithCrlsToRevokedServer(credsDirectory)
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

// -- SSL --

// -- Insecure --

func main() {
	credsDirectory := flag.String("credentials_directory", "", "Path to the creds directory of this repo")
	flag.Parse()

	if *credsDirectory == "" {
		fmt.Println("Must set credentials_directory argument to this repo's creds directory")
		os.Exit(1)
	}
	TlsWithCrls(*credsDirectory)
}
