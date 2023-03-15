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

func runClientWithProviders(rootProvider certprovider.Provider, identityProvider certprovider.Provider, useCrl bool, credsDirectory string, port string, shouldFail bool) {
	options := &advancedtls.ClientOptions{
		IdentityOptions: advancedtls.IdentityCertificateOptions{
			IdentityProvider: identityProvider,
		},
		RootOptions: advancedtls.RootCertificateOptions{
			RootProvider: rootProvider,
		},
		VType: advancedtls.CertVerification,
	}
	if useCrl {
		options.RevocationConfig = &advancedtls.RevocationConfig{
			RootDir: filepath.Join(credsDirectory, "crl"),
		}
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

func main() {
	credsDirectory := flag.String("credentials_directory", "", "Path to the creds directory of this repo")
	flag.Parse()

	if *credsDirectory == "" {
		fmt.Println("Must set credentials_directory argument to this repo's creds directory")
		os.Exit(1)

	}

	rootProvider := makeRootProvider(*credsDirectory)
	defer rootProvider.Close()
	cases := make(map[string]string)
	cases["8887"] = "[good server, no CRL]"
	cases["8886"] = "[revoked server, no CRL]"
	cases["8885"] = "[good server, with CRL]"
	cases["8884"] = "[revoked server, with CRL]"

	shouldFail := false
	for port, description := range cases {
		fmt.Println("================================================================================")
		fmt.Println("Running against localhost:" + port + " " + description)
		fmt.Println("Client Running with [good certificate, no CRL] at " + description)
		identityProvider := makeIdentityProvider(false, *credsDirectory)
		// Should always pass
		shouldFail = false
		runClientWithProviders(rootProvider, identityProvider, false, *credsDirectory, port, shouldFail)
		identityProvider.Close()
		fmt.Println("--------------------------------------------------------------------------------")

		fmt.Println("Client Running with [revoked certificate, no CRL] at " + description)
		identityProvider = makeIdentityProvider(true, *credsDirectory)
		// Fail if Server is using CRL
		shouldFail = port == "8885" || port == "8884"
		runClientWithProviders(rootProvider, identityProvider, false, *credsDirectory, port, shouldFail)
		identityProvider.Close()
		fmt.Println("--------------------------------------------------------------------------------")

		fmt.Println("Client Running with [good certificate, CRL] at " + description)
		identityProvider = makeIdentityProvider(false, *credsDirectory)
		// Fail if the server cert is revoked
		shouldFail = port == "8886" || port == "8884"
		runClientWithProviders(rootProvider, identityProvider, true, *credsDirectory, port, shouldFail)
		identityProvider.Close()
		fmt.Println("--------------------------------------------------------------------------------")

		fmt.Println("Client Running with [revoked certificate, CRL] at " + description)
		identityProvider = makeIdentityProvider(true, *credsDirectory)
		// Fail if server cert is revoked or the server is using a CRL
		shouldFail = port == "8886" || port == "8884" || port == "8885"
		runClientWithProviders(rootProvider, identityProvider, true, *credsDirectory, port, shouldFail)
		identityProvider.Close()
	}
}
