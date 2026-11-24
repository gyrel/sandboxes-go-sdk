package sandboxes

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type approvalFakeServer struct {
	localv1.UnimplementedApprovalServiceServer
	lastList    *localv1.ApprovalServiceListRequest
	lastInspect *localv1.ApprovalServiceInspectRequest
	lastRespond *localv1.ApprovalServiceRespondRequest
	calls       int
	inspectErr  error
	respondErr  error
}

func (s *approvalFakeServer) List(_ context.Context, req *localv1.ApprovalServiceListRequest) (*localv1.ApprovalServiceListResponse, error) {
	s.calls++
	s.lastList = req
	return &localv1.ApprovalServiceListResponse{Approvals: []*localv1.Approval{fixtureProtoApproval()}}, nil
}

func (s *approvalFakeServer) Inspect(_ context.Context, req *localv1.ApprovalServiceInspectRequest) (*localv1.ApprovalServiceInspectResponse, error) {
	s.calls++
	s.lastInspect = req
	if s.inspectErr != nil {
		return nil, s.inspectErr
	}
	return &localv1.ApprovalServiceInspectResponse{Approval: fixtureProtoApproval()}, nil
}

func (s *approvalFakeServer) Respond(_ context.Context, req *localv1.ApprovalServiceRespondRequest) (*localv1.ApprovalServiceRespondResponse, error) {
	s.calls++
	s.lastRespond = req
	if s.respondErr != nil {
		return nil, s.respondErr
	}
	approval := fixtureProtoApproval()
	approval.State = localv1.ApprovalState_APPROVAL_STATE_APPROVED
	return &localv1.ApprovalServiceRespondResponse{Approval: approval, PersistedRuleId: "rule_exact_1"}, nil
}

func fixtureProtoApproval() *localv1.Approval {
	return &localv1.Approval{
		Id:              "apr_1",
		Kind:            localv1.ApprovalKind_APPROVAL_KIND_MCP_CALL,
		State:           localv1.ApprovalState_APPROVAL_STATE_PENDING,
		SandboxId:       "sb-1",
		ActionSummary:   "call tool items.list",
		DestinationHost: "api.example.com",
		DestinationPath: "/v1/items",
		Headers: []*localv1.ApprovalHeader{
			{Name: "Authorization", ValueClass: localv1.HeaderValueClass_HEADER_VALUE_CLASS_VAULT, VaultReferenceIds: []string{"vault:github"}},
			{Name: "X-Trace", ValueClass: localv1.HeaderValueClass_HEADER_VALUE_CLASS_STATIC},
		},
		EnvNames:          []string{"PATH", "HOME"},
		EnvNamesTruncated: true,
		CwdSummary:        "<workspace>",
		CreatedAtUnix:     1700000000,
	}
}

func fixtureApproval() Approval {
	return Approval{
		ID:              "apr_1",
		Kind:            ApprovalKindMCPCall,
		State:           ApprovalStatePending,
		SandboxID:       "sb-1",
		ActionSummary:   "call tool items.list",
		DestinationHost: "api.example.com",
		DestinationPath: "/v1/items",
		Headers: []ApprovalHeader{
			{Name: "Authorization", ValueClass: HeaderValueClassVault, VaultReferenceIDs: []string{"vault:github"}},
			{Name: "X-Trace", ValueClass: HeaderValueClassStatic},
		},
		EnvNames:          []string{"PATH", "HOME"},
		EnvNamesTruncated: true,
		CwdSummary:        "<workspace>",
		CreatedAt:         time.Unix(1700000000, 0).UTC(),
	}
}

// newBufconnClient serves the given services over an in-process listener.
// The SandboxService version stub reports apiVersion for capability gates.
func newBufconnClient(t *testing.T, apiVersion string, register func(*grpc.Server)) Client {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	localv1.RegisterSandboxServiceServer(server, &secretMetadataVersionServer{apiVersion: apiVersion})
	register(server)
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

func newApprovalClient(t *testing.T, apiVersion string) (Client, *approvalFakeServer) {
	t.Helper()
	fake := &approvalFakeServer{}
	client := newBufconnClient(t, apiVersion, func(server *grpc.Server) {
		localv1.RegisterApprovalServiceServer(server, fake)
	})
	return client, fake
}

func TestApprovalEnumMappingsFromProto(t *testing.T) {
	kinds := []struct {
		in   localv1.ApprovalKind
		want ApprovalKind
	}{
		{localv1.ApprovalKind_APPROVAL_KIND_UNSPECIFIED, ""},
		{localv1.ApprovalKind_APPROVAL_KIND_HOST_COMMAND, ApprovalKindHostCommand},
		{localv1.ApprovalKind_APPROVAL_KIND_MCP_REGISTRATION, ApprovalKindMCPRegistration},
		{localv1.ApprovalKind_APPROVAL_KIND_MCP_CALL, ApprovalKindMCPCall},
		{localv1.ApprovalKind_APPROVAL_KIND_OTHER, ApprovalKindOther},
		{localv1.ApprovalKind(99), ApprovalKindOther},
	}
	for _, tt := range kinds {
		if got := approvalKindFromProto(tt.in); got != tt.want {
			t.Errorf("kind %v = %q, want %q", tt.in, got, tt.want)
		}
	}
	states := []struct {
		in   localv1.ApprovalState
		want ApprovalState
	}{
		{localv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED, ""},
		{localv1.ApprovalState_APPROVAL_STATE_PENDING, ApprovalStatePending},
		{localv1.ApprovalState_APPROVAL_STATE_APPROVED, ApprovalStateApproved},
		{localv1.ApprovalState_APPROVAL_STATE_DENIED, ApprovalStateDenied},
	}
	for _, tt := range states {
		if got := approvalStateFromProto(tt.in); got != tt.want {
			t.Errorf("state %v = %q, want %q", tt.in, got, tt.want)
		}
	}
	classes := []struct {
		in   localv1.HeaderValueClass
		want HeaderValueClass
	}{
		{localv1.HeaderValueClass_HEADER_VALUE_CLASS_UNSPECIFIED, ""},
		{localv1.HeaderValueClass_HEADER_VALUE_CLASS_STATIC, HeaderValueClassStatic},
		{localv1.HeaderValueClass_HEADER_VALUE_CLASS_VAULT, HeaderValueClassVault},
	}
	for _, tt := range classes {
		if got := headerValueClassFromProto(tt.in); got != tt.want {
			t.Errorf("value class %v = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestApprovalRequestEnumsToProto(t *testing.T) {
	decisions := []struct {
		in      ApprovalDecision
		want    localv1.ApprovalDecision
		wantErr bool
	}{
		{ApprovalDecisionApprove, localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE, false},
		{ApprovalDecisionDeny, localv1.ApprovalDecision_APPROVAL_DECISION_DENY, false},
		{"", localv1.ApprovalDecision_APPROVAL_DECISION_UNSPECIFIED, true},
		{"allow", localv1.ApprovalDecision_APPROVAL_DECISION_UNSPECIFIED, true},
	}
	for _, tt := range decisions {
		got, err := approvalDecisionToProto(tt.in)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("decision %q = %v err=%v, want %v wantErr=%t", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
	scopes := []struct {
		in      ApprovalPersistScope
		want    localv1.ApprovalPersistScope
		wantErr bool
	}{
		{"", localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_UNSPECIFIED, false},
		{ApprovalPersistScopeOnce, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE, false},
		{ApprovalPersistScopeExact, localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_EXACT, false},
		{"forever", localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_UNSPECIFIED, true},
	}
	for _, tt := range scopes {
		got, err := approvalPersistToProto(tt.in)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("persist %q = %v err=%v, want %v wantErr=%t", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestApprovalsRoundTripMapsWireFields(t *testing.T) {
	client, fake := newApprovalClient(t, approvalsMinimumAPIVersion)
	ctx := context.Background()

	list, err := Approvals(client).ListApprovals(ctx, "sb-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if fake.lastList.GetSandboxId() != "sb-1" {
		t.Fatalf("list sandbox filter = %q", fake.lastList.GetSandboxId())
	}
	if len(list) != 1 || !reflect.DeepEqual(list[0], fixtureApproval()) {
		t.Fatalf("list = %#v", list)
	}

	inspected, err := Approvals(client).InspectApproval(ctx, "apr_1", "sb-1")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if fake.lastInspect.GetApprovalId() != "apr_1" || fake.lastInspect.GetSandboxId() != "sb-1" {
		t.Fatalf("inspect request = %+v", fake.lastInspect)
	}
	if !reflect.DeepEqual(inspected, fixtureApproval()) {
		t.Fatalf("inspect = %#v", inspected)
	}

	approval, ruleID, err := Approvals(client).RespondApproval(ctx, "apr_1", ApprovalDecisionApprove, ApprovalPersistScopeExact)
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	if fake.lastRespond.GetDecision() != localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE ||
		fake.lastRespond.GetPersistScope() != localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_EXACT {
		t.Fatalf("respond request = %+v", fake.lastRespond)
	}
	if ruleID != "rule_exact_1" || approval.State != ApprovalStateApproved {
		t.Fatalf("respond approval=%+v rule=%q", approval, ruleID)
	}
}

func TestApprovalRespondRejectsInvalidInputBeforeRPC(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		decision ApprovalDecision
		persist  ApprovalPersistScope
	}{
		{name: "missing id", decision: ApprovalDecisionDeny},
		{name: "unspecified decision", id: "apr_1"},
		{name: "unknown decision", id: "apr_1", decision: "allow"},
		{name: "unknown persist", id: "apr_1", decision: ApprovalDecisionDeny, persist: "forever"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, fake := newApprovalClient(t, approvalsMinimumAPIVersion)
			_, _, err := Approvals(client).RespondApproval(context.Background(), tt.id, tt.decision, tt.persist)
			assertAPIErrorCode(t, err, errorCodeInvalidArgument)
			if fake.calls != 0 {
				t.Fatalf("server calls = %d, want 0", fake.calls)
			}
		})
	}
	client, fake := newApprovalClient(t, approvalsMinimumAPIVersion)
	if _, err := Approvals(client).InspectApproval(context.Background(), "", "sb-1"); err == nil {
		t.Fatal("empty approval ID accepted")
	}
	if fake.calls != 0 {
		t.Fatalf("server calls = %d, want 0", fake.calls)
	}
}

func TestApprovalErrorMappingUsesSentinels(t *testing.T) {
	client, fake := newApprovalClient(t, approvalsMinimumAPIVersion)
	ctx := context.Background()

	fake.respondErr = status.Error(codes.FailedPrecondition, "no trusted approval provider")
	_, _, err := Approvals(client).RespondApproval(ctx, "apr_1", ApprovalDecisionApprove, ApprovalPersistScopeOnce)
	if !errors.Is(err, ErrApprovalProviderUnavailable) {
		t.Fatalf("respond err = %v, want ErrApprovalProviderUnavailable", err)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != errorCodeApprovalProviderUnavailable || typed.Message != "no trusted approval provider" {
		t.Fatalf("typed error = %#v", err)
	}

	fake.inspectErr = status.Error(codes.NotFound, "approval not found")
	_, err = Approvals(client).InspectApproval(ctx, "apr_missing", "sb-1")
	assertAPIErrorCode(t, err, "not_found")
	if errors.Is(err, ErrApprovalProviderUnavailable) {
		t.Fatal("NOT_FOUND matched ErrApprovalProviderUnavailable")
	}

	fake.respondErr = status.Error(codes.PermissionDenied, "denied")
	_, _, err = Approvals(client).RespondApproval(ctx, "apr_1", ApprovalDecisionDeny, "")
	assertAPIErrorCode(t, err, "permission_denied")
	if errors.Is(err, ErrApprovalProviderUnavailable) {
		t.Fatal("PERMISSION_DENIED matched ErrApprovalProviderUnavailable")
	}
}

func TestApprovalsRequireContractVersion(t *testing.T) {
	client, fake := newApprovalClient(t, "0.0.35")
	ctx := context.Background()
	if _, err := Approvals(client).ListApprovals(ctx, "sb-1"); !isUnsupported(t, err) {
		t.Fatalf("list err = %v, want unsupported", err)
	}
	if _, err := Approvals(client).InspectApproval(ctx, "apr_1", ""); !isUnsupported(t, err) {
		t.Fatalf("inspect err = %v, want unsupported", err)
	}
	if _, _, err := Approvals(client).RespondApproval(ctx, "apr_1", ApprovalDecisionDeny, ""); !isUnsupported(t, err) {
		t.Fatalf("respond err = %v, want unsupported", err)
	}
	if fake.calls != 0 {
		t.Fatalf("server calls = %d, want 0 on pre-0.0.36 daemon", fake.calls)
	}
}

func TestApprovalsUnsupportedWithoutProvider(t *testing.T) {
	legacy := legacySecretsClient{}
	if _, err := Approvals(legacy).ListApprovals(context.Background(), ""); !isUnsupported(t, err) {
		t.Fatalf("list err = %v, want unsupported", err)
	}
	if _, err := Approvals(legacy).InspectApproval(context.Background(), "apr_1", ""); !isUnsupported(t, err) {
		t.Fatalf("inspect err = %v, want unsupported", err)
	}
	if _, _, err := Approvals(legacy).RespondApproval(context.Background(), "apr_1", ApprovalDecisionDeny, ""); !isUnsupported(t, err) {
		t.Fatalf("respond err = %v, want unsupported", err)
	}
}

// fixtureClient is a deterministic in-memory Client for dependents that want
// approval behavior without gRPC. It serves one pending approval.
type fixtureClient struct{ legacySecretsClient }

func (fixtureClient) ApprovalService() ApprovalService { return fixtureApprovalService{} }

type fixtureApprovalService struct{}

var _ ApprovalService = fixtureApprovalService{}
var _ ApprovalServiceProvider = fixtureClient{}

func (fixtureApprovalService) ListApprovals(_ context.Context, sandboxID string) ([]Approval, error) {
	if sandboxID != "" && sandboxID != "sb-1" {
		return []Approval{}, nil
	}
	return []Approval{fixtureApproval()}, nil
}

func (fixtureApprovalService) InspectApproval(_ context.Context, approvalID, sandboxID string) (Approval, error) {
	if approvalID != "apr_1" || (sandboxID != "" && sandboxID != "sb-1") {
		return Approval{}, &Error{Code: "not_found", Message: "approval not found"}
	}
	return fixtureApproval(), nil
}

func (fixtureApprovalService) RespondApproval(_ context.Context, approvalID string, decision ApprovalDecision, persist ApprovalPersistScope) (Approval, string, error) {
	if approvalID != "apr_1" {
		return Approval{}, "", &Error{Code: "not_found", Message: "approval not found"}
	}
	if persist == ApprovalPersistScopeExact {
		return Approval{}, "", ErrApprovalProviderUnavailable
	}
	approval := fixtureApproval()
	approval.State = ApprovalStateDenied
	if decision == ApprovalDecisionApprove {
		approval.State = ApprovalStateApproved
	}
	return approval, "", nil
}

func TestFixtureApprovalServiceMatchesClientContract(t *testing.T) {
	var fixture Client = fixtureClient{}
	service := Approvals(fixture)
	ctx := context.Background()

	list, err := service.ListApprovals(ctx, "sb-1")
	if err != nil || len(list) != 1 || !reflect.DeepEqual(list[0], fixtureApproval()) {
		t.Fatalf("list = %#v err=%v", list, err)
	}
	if other, _ := service.ListApprovals(ctx, "sb-2"); len(other) != 0 {
		t.Fatalf("sandbox filter returned %d approvals", len(other))
	}
	if _, err := service.InspectApproval(ctx, "apr_1", "sb-2"); err == nil {
		t.Fatal("cross-sandbox inspect succeeded")
	}
	approval, ruleID, err := service.RespondApproval(ctx, "apr_1", ApprovalDecisionApprove, ApprovalPersistScopeOnce)
	if err != nil || approval.State != ApprovalStateApproved || ruleID != "" {
		t.Fatalf("respond = %+v rule=%q err=%v", approval, ruleID, err)
	}
	if _, _, err := service.RespondApproval(ctx, "apr_1", ApprovalDecisionApprove, ApprovalPersistScopeExact); !errors.Is(err, ErrApprovalProviderUnavailable) {
		t.Fatalf("exact persist err = %v, want ErrApprovalProviderUnavailable", err)
	}
}

func assertAPIErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("err = %#v, want code %q", err, code)
	}
}
