package sandboxes

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type customSecretFakeServer struct {
	localv1.UnimplementedSecretServiceServer
	calls    int
	last     *localv1.SecretServiceSetCustomRequest
	response *localv1.SecretServiceSetCustomResponse
	err      error
}

func (s *customSecretFakeServer) SetCustom(_ context.Context, req *localv1.SecretServiceSetCustomRequest) (*localv1.SecretServiceSetCustomResponse, error) {
	s.calls++
	s.last = req
	if s.err != nil {
		return nil, s.err
	}
	return s.response, nil
}

func storedCustomSecretResponse() *localv1.SecretServiceSetCustomResponse {
	return &localv1.SecretServiceSetCustomResponse{
		Secret: &localv1.SecretSummary{
			Service: "github", Scope: "sandbox", SandboxName: "sb-1",
			CreatedAtUnix: 1700000000, UpdatedAtUnix: 1700000100,
			SourceKind: "value", SecretType: "api_key", Origin: "local",
			EnvName: "GITHUB_TOKEN", Hosts: []string{"api.github.com", "*.github.com"},
			PlaceholderMasked: "****abcd",
		},
		Placeholder: "sbx-placeholder-abcd",
	}
}

func newCustomSecretClient(t *testing.T, apiVersion string) (Client, *customSecretFakeServer) {
	t.Helper()
	fake := &customSecretFakeServer{response: storedCustomSecretResponse()}
	client := newBufconnClient(t, apiVersion, func(server *grpc.Server) {
		localv1.RegisterSecretServiceServer(server, fake)
	})
	return client, fake
}

func TestSetCustomSecretInlineValueRoundTrip(t *testing.T) {
	client, fake := newCustomSecretClient(t, customSecretsMinimumAPIVersion)
	result, err := CustomSecrets(client).SetCustomSecret(context.Background(), CustomSecretRequest{
		Service: "github", Scope: SecretScopeSandbox, SandboxName: "sb-1",
		Value: []byte("ghp_test_value"), Env: "GITHUB_TOKEN",
		Placeholder: "sbx-placeholder-{rand}", Hosts: []string{"api.github.com", "*.github.com"},
	})
	if err != nil {
		t.Fatalf("SetCustomSecret: %v", err)
	}
	if fake.last.GetService() != "github" || fake.last.GetScope() != "sandbox" || fake.last.GetSandboxName() != "sb-1" {
		t.Fatalf("key fields = %+v", fake.last)
	}
	if string(fake.last.GetValue()) != "ghp_test_value" || fake.last.GetSource() != nil {
		t.Fatalf("inline value not forwarded: %+v", fake.last)
	}
	if fake.last.GetEnv() != "GITHUB_TOKEN" || fake.last.GetPlaceholder() != "sbx-placeholder-{rand}" ||
		!reflect.DeepEqual(fake.last.GetHosts(), []string{"api.github.com", "*.github.com"}) {
		t.Fatalf("placement fields = %+v", fake.last)
	}
	if result.ApprovalRequired || result.ApprovalID != "" {
		t.Fatalf("unexpected approval challenge: %+v", result)
	}
	if result.Placeholder != "sbx-placeholder-abcd" {
		t.Fatalf("placeholder = %q", result.Placeholder)
	}
	want := ServiceSecret{
		Service: "github", Scope: SecretScopeSandbox, SandboxName: "sb-1",
		CreatedAt: time.Unix(1700000000, 0).UTC(), UpdatedAt: time.Unix(1700000100, 0).UTC(),
		SourceKind: SecretSourceKindValue, SecretType: SecretValueTypeAPIKey, Origin: SecretOriginLocal,
		EnvName: "GITHUB_TOKEN", Hosts: []string{"api.github.com", "*.github.com"},
		PlaceholderMasked: "****abcd",
	}
	if !reflect.DeepEqual(result.Secret, want) {
		t.Fatalf("secret = %#v, want %#v", result.Secret, want)
	}
}

func TestSetCustomSecretReferenceSourceReturnsApprovalChallenge(t *testing.T) {
	client, fake := newCustomSecretClient(t, customSecretsMinimumAPIVersion)
	fake.response = &localv1.SecretServiceSetCustomResponse{ApprovalRequired: true, ApprovalId: "apr_secret_1"}

	result, err := CustomSecrets(client).SetCustomSecret(context.Background(), CustomSecretRequest{
		Service: "anthropic", Scope: SecretScopeGlobal, Env: "ANTHROPIC_API_KEY",
		Source: &SecretSource{
			Reference: "op://vault/item/field", Refresh: "55m", NoVerify: true,
			ShowError: true, OPAccount: "work", AWSProfile: "dev",
		},
	})
	if err != nil {
		t.Fatalf("SetCustomSecret: %v", err)
	}
	src := fake.last.GetSource()
	if src == nil || src.GetReference() != "op://vault/item/field" || src.GetRefresh() != "55m" ||
		!src.GetNoVerify() || !src.GetShowError() || src.GetOpAccount() != "work" || src.GetAwsProfile() != "dev" {
		t.Fatalf("source = %+v", src)
	}
	if len(fake.last.GetValue()) != 0 {
		t.Fatal("source request must not carry an inline value")
	}
	if !result.ApprovalRequired || result.ApprovalID != "apr_secret_1" {
		t.Fatalf("challenge = %+v", result)
	}
	if result.Placeholder != "" || !reflect.DeepEqual(result.Secret, ServiceSecret{}) {
		t.Fatalf("pending result must be empty: %+v", result)
	}
}

func TestSetCustomSecretRejectsAmbiguousInputBeforeRPC(t *testing.T) {
	const inlineValue = "sk-inline-test-value"
	tests := []struct {
		name string
		req  CustomSecretRequest
	}{
		{name: "neither value nor source", req: CustomSecretRequest{Service: "svc"}},
		{name: "empty value", req: CustomSecretRequest{Service: "svc", Value: []byte{}}},
		{name: "value and source", req: CustomSecretRequest{Service: "svc", Value: []byte(inlineValue), Source: &SecretSource{Command: "printf x"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, fake := newCustomSecretClient(t, customSecretsMinimumAPIVersion)
			_, err := CustomSecrets(client).SetCustomSecret(context.Background(), tt.req)
			assertAPIErrorCode(t, err, errorCodeInvalidArgument)
			if err != nil && strings.Contains(err.Error(), inlineValue) {
				t.Fatalf("error leaks inline value: %v", err)
			}
			if fake.calls != 0 {
				t.Fatalf("server calls = %d, want 0", fake.calls)
			}
		})
	}
}

func TestSetCustomSecretRequiresContractVersion(t *testing.T) {
	client, fake := newCustomSecretClient(t, "0.0.35")
	_, err := CustomSecrets(client).SetCustomSecret(context.Background(), CustomSecretRequest{Service: "svc", Value: []byte("v")})
	if !isUnsupported(t, err) {
		t.Fatalf("err = %v, want unsupported", err)
	}
	if fake.calls != 0 {
		t.Fatalf("server calls = %d, want 0 on pre-0.0.36 daemon", fake.calls)
	}
}

func TestSetCustomSecretFailsClosedWithoutApprovalProvider(t *testing.T) {
	client, fake := newCustomSecretClient(t, customSecretsMinimumAPIVersion)
	fake.err = status.Error(codes.FailedPrecondition, "no trusted approval provider")

	_, err := CustomSecrets(client).SetCustomSecret(context.Background(), CustomSecretRequest{
		Service: "svc", Source: &SecretSource{Command: "printf token"},
	})
	if !errors.Is(err, ErrApprovalProviderUnavailable) {
		t.Fatalf("command source err = %v, want ErrApprovalProviderUnavailable", err)
	}

	// An inline value does not need host approval, so FAILED_PRECONDITION is
	// not reported as a missing approval provider.
	_, err = CustomSecrets(client).SetCustomSecret(context.Background(), CustomSecretRequest{
		Service: "svc", Value: []byte("v"),
	})
	assertAPIErrorCode(t, err, "conflict")
	if errors.Is(err, ErrApprovalProviderUnavailable) {
		t.Fatal("inline value matched ErrApprovalProviderUnavailable")
	}
}

func TestSetCustomSecretUnsupportedWithoutProvider(t *testing.T) {
	_, err := CustomSecrets(legacySecretsClient{}).SetCustomSecret(context.Background(), CustomSecretRequest{Service: "svc", Value: []byte("v")})
	if !isUnsupported(t, err) {
		t.Fatalf("err = %v, want unsupported", err)
	}
}

// Compile-time parity: the client's optional capability satisfies the same
// interface as the in-memory fixture used by dependents.
var _ CustomSecretService = secretClient{}
var _ CustomSecretServiceProvider = (*client)(nil)
var _ ApprovalServiceProvider = (*client)(nil)
var _ Client = (*client)(nil)
