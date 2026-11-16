package sandboxes

import (
	"context"
	"net"
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type secretMetadataVersionServer struct {
	localv1.UnimplementedSandboxServiceServer
	apiVersion string
}

func (s secretMetadataVersionServer) GetVersion(context.Context, *localv1.GetVersionRequest) (*localv1.GetVersionResponse, error) {
	return &localv1.GetVersionResponse{Version: "test", ApiVersion: s.apiVersion}, nil
}

type secretMetadataSecretServer struct {
	localv1.UnimplementedSecretServiceServer
}

func (secretMetadataSecretServer) List(context.Context, *localv1.SecretServiceListRequest) (*localv1.SecretServiceListResponse, error) {
	return &localv1.SecretServiceListResponse{Secrets: []*localv1.SecretSummary{{
		Service: "github", Scope: "global", CreatedAtUnix: 1700000000, UpdatedAtUnix: 1700000100,
		SourceKind: "value", SecretType: "api_key", Origin: "local",
	}}}, nil
}

type secretMetadataRegistryServer struct {
	localv1.UnimplementedRegistryCredentialServiceServer
}

func (secretMetadataRegistryServer) List(context.Context, *localv1.RegistryCredentialServiceListRequest) (*localv1.RegistryCredentialServiceListResponse, error) {
	return &localv1.RegistryCredentialServiceListResponse{Credentials: []*localv1.RegistryCredentialSummary{{
		Registry: "ghcr.io", Username: "alice", Scope: "host-only",
		CreatedAtUnix: 1700000200, UpdatedAtUnix: 1700000300, Origin: "local",
	}}}, nil
}

func newSecretMetadataClient(t *testing.T, apiVersion string) Client {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	localv1.RegisterSandboxServiceServer(server, secretMetadataVersionServer{apiVersion: apiVersion})
	localv1.RegisterSecretServiceServer(server, secretMetadataSecretServer{})
	localv1.RegisterRegistryCredentialServiceServer(server, secretMetadataRegistryServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	client, err := New(Config{Address: "bufnet", Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
		return listener.DialContext(ctx)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestSecretListMetadataRequiresContractVersion(t *testing.T) {
	for _, tt := range []struct {
		name       string
		apiVersion string
		want       bool
	}{
		{name: "current", apiVersion: secretMetadataMinimumAPIVersion, want: true},
		{name: "newer", apiVersion: "0.0.28", want: true},
		{name: "older", apiVersion: "0.0.26", want: false},
		{name: "invalid", apiVersion: "not-a-version", want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := newSecretMetadataClient(t, tt.apiVersion)
			secrets, err := Secrets(client).List(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(secrets) != 1 {
				t.Fatalf("secrets=%+v", secrets)
			}
			if got := !secrets[0].CreatedAt.IsZero(); got != tt.want {
				t.Fatalf("service metadata present=%t want=%t (%+v)", got, tt.want, secrets[0])
			}
			if got := secrets[0].SourceKind == SecretSourceKindValue; got != tt.want {
				t.Fatalf("service source kind present=%t want=%t (%+v)", got, tt.want, secrets[0])
			}

			lister, ok := RegistryCredentialList(client)
			if !ok {
				t.Fatal("client does not expose registry credential listing")
			}
			credentials, err := lister.ListRegistryCredentials(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(credentials) != 1 {
				t.Fatalf("credentials=%+v", credentials)
			}
			if got := !credentials[0].CreatedAt.IsZero(); got != tt.want {
				t.Fatalf("registry metadata present=%t want=%t (%+v)", got, tt.want, credentials[0])
			}
		})
	}
}
