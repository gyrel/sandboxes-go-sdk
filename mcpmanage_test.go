package sandboxes

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type managementTestServer struct {
	mcpTestServer
	load    *localv1.MCPLoadServerRequest
	unload  *localv1.MCPUnloadServerRequest
	inspect *localv1.InspectMCPServerRequest
	status  *localv1.GetMCPAuthStatusRequest
	remove  *localv1.RemoveMCPAuthRequest
	start   *localv1.StartMCPAuthRequest
}

func (s *managementTestServer) MCPLoadServer(_ context.Context, r *localv1.MCPLoadServerRequest) (*localv1.MCPLoadServerResponse, error) {
	s.load = r
	return &localv1.MCPLoadServerResponse{}, nil
}
func (s *managementTestServer) MCPUnloadServer(_ context.Context, r *localv1.MCPUnloadServerRequest) (*localv1.MCPUnloadServerResponse, error) {
	s.unload = r
	return &localv1.MCPUnloadServerResponse{}, nil
}
func (s *managementTestServer) InspectMCPServer(_ context.Context, r *localv1.InspectMCPServerRequest) (*localv1.InspectMCPServerResponse, error) {
	s.inspect = r
	return &localv1.InspectMCPServerResponse{Server: &localv1.MCPServerDetail{Name: "n", SandboxId: "s", IdentityDisplayName: "display", IdentityKind: "kind", IdentityIssuerHost: "host", ToolsCount: 3, LastSyncAtUnix: 123, AuthStatus: localv1.MCPAuthStatus_MCP_AUTH_STATUS_READY, GatewayState: localv1.MCPGatewayState_MCP_GATEWAY_STATE_LOADED}}, nil
}
func (s *managementTestServer) GetMCPAuthStatus(_ context.Context, r *localv1.GetMCPAuthStatusRequest) (*localv1.GetMCPAuthStatusResponse, error) {
	s.status = r
	return &localv1.GetMCPAuthStatusResponse{Status: localv1.MCPAuthStatus_MCP_AUTH_STATUS_READY, Entries: []*localv1.MCPServerAuthStatus{{Name: "n", Status: localv1.MCPAuthStatus_MCP_AUTH_STATUS_EXPIRED}}}, nil
}
func (s *managementTestServer) RemoveMCPAuth(_ context.Context, r *localv1.RemoveMCPAuthRequest) (*localv1.RemoveMCPAuthResponse, error) {
	s.remove = r
	return &localv1.RemoveMCPAuthResponse{Removed: true}, nil
}
func (s *managementTestServer) StartMCPAuth(_ context.Context, r *localv1.StartMCPAuthRequest) (*localv1.StartMCPAuthResponse, error) {
	s.start = r
	return &localv1.StartMCPAuthResponse{ApprovalRequired: true, ApprovalId: "id"}, nil
}
func TestMCPManagementEnums(t *testing.T) {
	auth := []MCPAuthStatus{MCPAuthStatusUnspecified, MCPAuthStatusNotConfigured, MCPAuthStatusReady, MCPAuthStatusPendingApproval, MCPAuthStatusExpired, MCPAuthStatusError}
	for i, w := range auth {
		if g := mcpAuthStatusFromProto(localv1.MCPAuthStatus(i)); g != w {
			t.Fatalf("auth %d: %q", i, g)
		}
	}
	states := []MCPGatewayState{MCPGatewayStateUnspecified, MCPGatewayStateUnloaded, MCPGatewayStateLoaded}
	for i, w := range states {
		if g := mcpGatewayStateFromProto(localv1.MCPGatewayState(i)); g != w {
			t.Fatalf("state %d: %q", i, g)
		}
	}
	if mcpAuthStatusFromProto(99) != MCPAuthStatusUnspecified || mcpGatewayStateFromProto(99) != MCPGatewayStateUnspecified {
		t.Fatal("unknown enum")
	}
}
func TestMCPManagementRoundTrip(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	fake := &managementTestServer{mcpTestServer: mcpTestServer{apiVersion: "0.0.38"}}
	localv1.RegisterSandboxServiceServer(server, fake)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	c, err := New(Config{Address: "buf", Dialer: func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := MCPServerManagement(c)
	ctx := context.Background()
	if err = s.Load(ctx, "n", "s"); err != nil {
		t.Fatal(err)
	}
	if fake.load.GetName() != "n" || fake.load.GetSandboxId() != "s" {
		t.Fatal(fake.load)
	}
	if err = s.Unload(ctx, "n", "s"); err != nil {
		t.Fatal(err)
	}
	if fake.unload.GetName() != "n" || fake.unload.GetSandboxId() != "s" {
		t.Fatal(fake.unload)
	}
	d, err := s.Inspect(ctx, "n", "s")
	if err != nil || !reflect.DeepEqual(d, MCPServerDetail{Name: "n", SandboxID: "s", IdentityDisplayName: "display", IdentityKind: "kind", IdentityIssuerHost: "host", ToolsCount: 3, LastSyncAt: time.Unix(123, 0), AuthStatus: MCPAuthStatusReady, GatewayState: MCPGatewayStateLoaded}) {
		t.Fatalf("detail=%+v err=%v", d, err)
	}
	if fake.inspect.GetName() != "n" || fake.inspect.GetSandboxId() != "s" {
		t.Fatal(fake.inspect)
	}
	statuses, err := s.AuthStatus(ctx, "n", false)
	if err != nil || !reflect.DeepEqual(statuses, []MCPServerAuthStatus{{Name: "n", Status: MCPAuthStatusReady}}) {
		t.Fatalf("%v %v", statuses, err)
	}
	statuses, err = s.AuthStatus(ctx, "", true)
	if err != nil || !reflect.DeepEqual(statuses, []MCPServerAuthStatus{{Name: "n", Status: MCPAuthStatusExpired}}) || !fake.status.GetAll() {
		t.Fatalf("%v %v", statuses, err)
	}
	removed, err := s.RemoveAuth(ctx, "n")
	if err != nil || !removed || fake.remove.GetName() != "n" {
		t.Fatal(removed, err)
	}
	challenge, err := s.StartAuth(ctx, MCPAuthStartRequest{Name: "n", SandboxID: "s", Scopes: []string{"a"}, All: true})
	if err != nil || challenge != (MCPAuthChallenge{ApprovalRequired: true, ApprovalID: "id"}) || fake.start.GetName() != "n" || fake.start.GetSandboxId() != "s" || !reflect.DeepEqual(fake.start.GetScopes(), []string{"a"}) || !fake.start.GetAll() {
		t.Fatal(challenge, err)
	}
	_, err = s.StartAuth(ctx, MCPAuthStartRequest{Scopes: []string{"a"}, NoScope: true})
	if err == nil {
		t.Fatal("expected mutual exclusion error")
	}
	fake.apiVersion = "0.0.37"
	if !isUnsupported(t, s.Load(ctx, "n", "s")) {
		t.Fatal("version gate")
	}
}
func TestMCPManagementFallback(t *testing.T) {
	var c Client = legacySecretsClient{}
	s := MCPServerManagement(c)
	ctx := context.Background()
	if !isUnsupported(t, s.Load(ctx, "n", "s")) || !isUnsupported(t, s.Unload(ctx, "n", "s")) {
		t.Fatal("fallback")
	}
	_, err := s.Inspect(ctx, "n", "s")
	if !isUnsupported(t, err) {
		t.Fatal(err)
	}
	_, err = s.AuthStatus(ctx, "n", false)
	if !isUnsupported(t, err) {
		t.Fatal(err)
	}
	_, err = s.RemoveAuth(ctx, "n")
	if !isUnsupported(t, err) {
		t.Fatal(err)
	}
	_, err = s.StartAuth(ctx, MCPAuthStartRequest{})
	if !isUnsupported(t, err) {
		t.Fatal(err)
	}
}
