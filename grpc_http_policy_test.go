package sandboxes

import (
	"context"
	"errors"
	"net"
	"testing"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type httpPolicyServer struct {
	localv1.UnimplementedSandboxServiceServer
	apiVersion  string
	lastCheck   *localv1.CheckPolicyRequest
	mutateCalls int
}

func (s *httpPolicyServer) GetVersion(context.Context, *localv1.GetVersionRequest) (*localv1.GetVersionResponse, error) {
	return &localv1.GetVersionResponse{Version: "test", ApiVersion: s.apiVersion}, nil
}

func (s *httpPolicyServer) UpdatePolicy(context.Context, *localv1.UpdatePolicyRequest) (*localv1.UpdatePolicyResponse, error) {
	s.mutateCalls++
	return &localv1.UpdatePolicyResponse{Sandbox: &localv1.Sandbox{Id: "sb1", Name: "n"}}, nil
}

func (s *httpPolicyServer) MutatePolicy(context.Context, *localv1.MutatePolicyRequest) (*localv1.MutatePolicyResponse, error) {
	s.mutateCalls++
	return &localv1.MutatePolicyResponse{Sandbox: &localv1.Sandbox{Id: "sb1", Name: "n"}}, nil
}

func (s *httpPolicyServer) MutateGlobalPolicy(context.Context, *localv1.MutateGlobalPolicyRequest) (*localv1.MutateGlobalPolicyResponse, error) {
	s.mutateCalls++
	return &localv1.MutateGlobalPolicyResponse{}, nil
}

func (s *httpPolicyServer) CheckPolicy(_ context.Context, req *localv1.CheckPolicyRequest) (*localv1.CheckPolicyResponse, error) {
	s.lastCheck = req
	return &localv1.CheckPolicyResponse{Allowed: true, RuleId: "rul_1", Reason: "allow rule"}, nil
}

func newHTTPPolicyClient(t *testing.T, apiVersion string) (Client, *httpPolicyServer) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	fake := &httpPolicyServer{apiVersion: apiVersion}
	localv1.RegisterSandboxServiceServer(server, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	client, err := New(Config{Address: "bufnet", Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
		return listener.DialContext(ctx)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, fake
}

func httpConditionedRule() NetworkRule {
	return NetworkRule{Protocol: "tcp", Domain: "api.example.com", Methods: []string{"GET"}, Path: "/v1/**"}
}

func isUnsupported(t *testing.T, err error) bool {
	t.Helper()
	var apiErr *Error
	if errors.As(err, &apiErr) {
		return apiErr.Code == errorCodeUnsupported
	}
	return false
}

func TestHTTPPolicyConditionsRequireContractVersion(t *testing.T) {
	conditioned := httpConditionedRule()
	plain := NetworkRule{Protocol: "tcp", Domain: "api.example.com"}

	for _, tt := range []struct {
		name       string
		apiVersion string
		wantOK     bool
	}{
		{name: "current", apiVersion: httpPolicyConditionsMinimumAPIVersion, wantOK: true},
		{name: "newer", apiVersion: "0.0.32", wantOK: true},
		{name: "older", apiVersion: "0.0.30", wantOK: false},
	} {
		t.Run(tt.name+"/update", func(t *testing.T) {
			client, fake := newHTTPPolicyClient(t, tt.apiVersion)
			_, err := Policies(client).UpdatePolicy(context.Background(), "sb1", []NetworkRule{conditioned}, nil)
			if tt.wantOK != (err == nil) {
				t.Fatalf("err=%v wantOK=%v", err, tt.wantOK)
			}
			if !tt.wantOK && !isUnsupported(t, err) {
				t.Fatalf("expected unsupported error, got %v", err)
			}
			if fake.mutateCalls != boolToInt(tt.wantOK) {
				t.Fatalf("server calls=%d want %d", fake.mutateCalls, boolToInt(tt.wantOK))
			}
		})
		t.Run(tt.name+"/mutate", func(t *testing.T) {
			client, _ := newHTTPPolicyClient(t, tt.apiVersion)
			_, err := Policies(client).MutatePolicy(context.Background(), "sb1", "allow", conditioned)
			if tt.wantOK != (err == nil) {
				t.Fatalf("err=%v", err)
			}
		})
		t.Run(tt.name+"/mutate-global", func(t *testing.T) {
			client, _ := newHTTPPolicyClient(t, tt.apiVersion)
			_, _, err := Policies(client).MutateGlobalPolicy(context.Background(), "deny", conditioned)
			if tt.wantOK != (err == nil) {
				t.Fatalf("err=%v", err)
			}
		})
	}

	// Unconditioned rules never consult the version and must work against
	// every daemon.
	client, fake := newHTTPPolicyClient(t, "0.0.24")
	if _, err := Policies(client).UpdatePolicy(context.Background(), "sb1", []NetworkRule{plain}, nil); err != nil {
		t.Fatalf("plain rules gated unnecessarily: %v", err)
	}
	if fake.mutateCalls != 1 {
		t.Fatalf("server calls=%d", fake.mutateCalls)
	}
}

func TestCheckURLRequiresContractVersion(t *testing.T) {
	client, fake := newHTTPPolicyClient(t, "0.0.31")
	_, err := Policies(client).Check(context.Background(), "sb1", "tcp", "", "", 0, "https://api.example.com/v1", "GET")
	if err == nil || !isUnsupported(t, err) {
		t.Fatalf("url check on 0.0.31 must be unsupported: %v", err)
	}
	if fake.lastCheck != nil {
		t.Fatal("server must not be reached when the gate refuses")
	}
	client, fake = newHTTPPolicyClient(t, httpPolicyConditionsMinimumAPIVersion)
	if _, err := Policies(client).Check(context.Background(), "sb1", "tcp", "192.0.2.1", "", 443, "", ""); err != nil {
		t.Fatalf("L4-only check must not consult the version: %v", err)
	}
	if fake.lastCheck.GetUrl() != "" || fake.lastCheck.GetMethod() != "" {
		t.Fatalf("empty url/method must stay empty: %+v", fake.lastCheck)
	}
	client, fake = newHTTPPolicyClient(t, policyCheckURLMinimumAPIVersion)
	decision, err := Policies(client).Check(context.Background(), "sb1", "tcp", "", "", 0, "https://api.example.com/v1", "get")
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("decision=%+v", decision)
	}
	if fake.lastCheck.GetUrl() != "https://api.example.com/v1" || fake.lastCheck.GetMethod() != "get" {
		t.Fatalf("url/method not forwarded: %+v", fake.lastCheck)
	}
}

func TestCreateConditionsRequireContractVersion(t *testing.T) {
	client, _ := newHTTPPolicyClient(t, "0.0.30")
	err := requireCreateFeatureVersions(context.Background(), Version(client), &CreateRequest{
		Allow: []NetworkRule{httpConditionedRule()},
	})
	if err == nil || !isUnsupported(t, err) {
		t.Fatalf("conditioned create on 0.0.30 must be unsupported: %v", err)
	}
	if err := requireCreateFeatureVersions(context.Background(), Version(client), &CreateRequest{
		Allow: []NetworkRule{{Protocol: "tcp", Domain: "api.example.com"}},
	}); err != nil {
		t.Fatalf("unconditioned create must skip the gate: %v", err)
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
