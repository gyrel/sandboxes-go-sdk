package sandboxes

import (
	"context"
	"reflect"
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type kitPolicyFakeServer struct {
	localv1.UnimplementedKitPolicyServiceServer
	calls      int
	lastCheck  *localv1.CheckKitRequest
	lastConfig *localv1.GetKitPolicyConfigRequest
	checkResp  *localv1.CheckKitResponse
	configResp *localv1.GetKitPolicyConfigResponse
	checkErr   error
	configErr  error
}

func (s *kitPolicyFakeServer) CheckKit(_ context.Context, req *localv1.CheckKitRequest) (*localv1.CheckKitResponse, error) {
	s.calls++
	s.lastCheck = req
	if s.checkErr != nil {
		return nil, s.checkErr
	}
	if s.checkResp != nil {
		return s.checkResp, nil
	}
	return fixtureProtoKitCheck(), nil
}

func (s *kitPolicyFakeServer) GetKitPolicyConfig(_ context.Context, req *localv1.GetKitPolicyConfigRequest) (*localv1.GetKitPolicyConfigResponse, error) {
	s.calls++
	s.lastConfig = req
	if s.configErr != nil {
		return nil, s.configErr
	}
	if s.configResp != nil {
		return s.configResp, nil
	}
	return fixtureProtoKitPolicyConfig(), nil
}

func fixtureProtoKitCheck() *localv1.CheckKitResponse {
	return &localv1.CheckKitResponse{
		Allowed:         true,
		Reason:          localv1.CheckKitReason_CHECK_KIT_REASON_OK,
		Message:         "kit allowed",
		CheckedSettings: []string{"kit.allowedSources", "kit.allowLocalKits"},
	}
}

func fixtureKitCheck() KitCheck {
	return KitCheck{
		Allowed:         true,
		Reason:          KitCheckReasonOK,
		Message:         "kit allowed",
		CheckedSettings: []string{"kit.allowedSources", "kit.allowLocalKits"},
	}
}

func fixtureProtoKitPolicyConfig() *localv1.GetKitPolicyConfigResponse {
	return &localv1.GetKitPolicyConfigResponse{
		AllowedSources:   []localv1.KitSourceKind{localv1.KitSourceKind_KIT_SOURCE_KIND_OCI, localv1.KitSourceKind_KIT_SOURCE_KIND_GIT},
		AllowLocalKits:   true,
		RequireSignature: false,
		Managed:          true,
	}
}

func fixtureKitPolicyConfig() KitPolicyConfig {
	return KitPolicyConfig{
		AllowedSources:   []KitSourceKind{KitSourceKindOci, KitSourceKindGit},
		AllowLocalKits:   true,
		RequireSignature: false,
		Managed:          true,
	}
}

func newKitPolicyClient(t *testing.T, apiVersion string) (Client, *kitPolicyFakeServer) {
	t.Helper()
	fake := &kitPolicyFakeServer{}
	client := newBufconnClient(t, apiVersion, func(server *grpc.Server) {
		localv1.RegisterKitPolicyServiceServer(server, fake)
	})
	return client, fake
}

func TestKitPolicyEnumMappingsFromProto(t *testing.T) {
	kinds := []struct {
		in   localv1.KitSourceKind
		want KitSourceKind
	}{
		{localv1.KitSourceKind_KIT_SOURCE_KIND_UNSPECIFIED, ""},
		{localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY, KitSourceKindDirectory},
		{localv1.KitSourceKind_KIT_SOURCE_KIND_ZIP, KitSourceKindZip},
		{localv1.KitSourceKind_KIT_SOURCE_KIND_GIT, KitSourceKindGit},
		{localv1.KitSourceKind_KIT_SOURCE_KIND_OCI, KitSourceKindOci},
		{localv1.KitSourceKind(99), ""},
	}
	for _, tt := range kinds {
		if got := kitSourceKindFromProto(tt.in); got != tt.want {
			t.Errorf("source kind %v = %q, want %q", tt.in, got, tt.want)
		}
	}
	reasons := []struct {
		in   localv1.CheckKitReason
		want KitCheckReason
	}{
		{localv1.CheckKitReason_CHECK_KIT_REASON_UNSPECIFIED, ""},
		{localv1.CheckKitReason_CHECK_KIT_REASON_OK, KitCheckReasonOK},
		{localv1.CheckKitReason_CHECK_KIT_REASON_SOURCE_NOT_ALLOWED, KitCheckReasonSourceNotAllowed},
		{localv1.CheckKitReason_CHECK_KIT_REASON_LOCAL_DISABLED, KitCheckReasonLocalDisabled},
		{localv1.CheckKitReason_CHECK_KIT_REASON_SIGNATURE_REQUIRED, KitCheckReasonSignatureRequired},
		{localv1.CheckKitReason_CHECK_KIT_REASON_POLICY_UNAVAILABLE, KitCheckReasonPolicyUnavailable},
		{localv1.CheckKitReason_CHECK_KIT_REASON_INVALID_REFERENCE, KitCheckReasonInvalidReference},
		{localv1.CheckKitReason(99), ""},
	}
	for _, tt := range reasons {
		if got := kitCheckReasonFromProto(tt.in); got != tt.want {
			t.Errorf("reason %v = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestKitPolicyEnumMappingsToProto(t *testing.T) {
	kinds := []struct {
		in      KitSourceKind
		want    localv1.KitSourceKind
		wantErr bool
	}{
		{"", localv1.KitSourceKind_KIT_SOURCE_KIND_UNSPECIFIED, false},
		{KitSourceKindDirectory, localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY, false},
		{KitSourceKindZip, localv1.KitSourceKind_KIT_SOURCE_KIND_ZIP, false},
		{KitSourceKindGit, localv1.KitSourceKind_KIT_SOURCE_KIND_GIT, false},
		{KitSourceKindOci, localv1.KitSourceKind_KIT_SOURCE_KIND_OCI, false},
		{"bogus", localv1.KitSourceKind_KIT_SOURCE_KIND_UNSPECIFIED, true},
	}
	for _, tt := range kinds {
		got, err := kitSourceKindToProto(tt.in)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("source kind %q = %v err=%v, want %v wantErr=%t", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestKitPolicyRoundTripMapsWireFields(t *testing.T) {
	client, fake := newKitPolicyClient(t, kitPolicyMinimumAPIVersion)
	ctx := context.Background()

	req := KitCheckRequest{
		SourceKind:       KitSourceKindDirectory,
		SourceRef:        "/kits/example",
		SandboxID:        "sb-1",
		SignaturePresent: true,
	}
	got, err := KitPolicy(client).CheckKit(ctx, req)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if fake.lastCheck.GetSourceKind() != localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY ||
		fake.lastCheck.GetSourceRef() != "/kits/example" ||
		fake.lastCheck.GetSandboxId() != "sb-1" ||
		!fake.lastCheck.GetSignaturePresent() {
		t.Fatalf("check request = %+v", fake.lastCheck)
	}
	if !reflect.DeepEqual(got, fixtureKitCheck()) {
		t.Fatalf("check = %#v", got)
	}

	cfg, err := KitPolicy(client).GetKitPolicyConfig(ctx)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if fake.lastConfig == nil {
		t.Fatal("config request not recorded")
	}
	if !reflect.DeepEqual(cfg, fixtureKitPolicyConfig()) {
		t.Fatalf("config = %#v", cfg)
	}
}

func TestKitPolicyCheckRejectsEmptySourceRefBeforeRPC(t *testing.T) {
	client, fake := newKitPolicyClient(t, kitPolicyMinimumAPIVersion)
	_, err := KitPolicy(client).CheckKit(context.Background(), KitCheckRequest{SourceKind: KitSourceKindDirectory})
	assertAPIErrorCode(t, err, errorCodeInvalidArgument)
	if fake.calls != 0 {
		t.Fatalf("server calls = %d, want 0", fake.calls)
	}
}

func TestKitPolicyRequiresContractVersion(t *testing.T) {
	client, fake := newKitPolicyClient(t, "0.0.36")
	ctx := context.Background()
	if _, err := KitPolicy(client).CheckKit(ctx, KitCheckRequest{SourceKind: KitSourceKindDirectory, SourceRef: "/kits/x"}); !isUnsupported(t, err) {
		t.Fatalf("check err = %v, want unsupported", err)
	}
	if _, err := KitPolicy(client).GetKitPolicyConfig(ctx); !isUnsupported(t, err) {
		t.Fatalf("config err = %v, want unsupported", err)
	}
	if fake.calls != 0 {
		t.Fatalf("server calls = %d, want 0 on pre-0.0.37 daemon", fake.calls)
	}
}

func TestKitPolicyUnsupportedWithoutProvider(t *testing.T) {
	legacy := legacySecretsClient{}
	if _, err := KitPolicy(legacy).CheckKit(context.Background(), KitCheckRequest{SourceRef: "/kits/x"}); !isUnsupported(t, err) {
		t.Fatalf("check err = %v, want unsupported", err)
	}
	if _, err := KitPolicy(legacy).GetKitPolicyConfig(context.Background()); !isUnsupported(t, err) {
		t.Fatalf("config err = %v, want unsupported", err)
	}
}

func TestKitPolicyErrorMapping(t *testing.T) {
	client, fake := newKitPolicyClient(t, kitPolicyMinimumAPIVersion)
	ctx := context.Background()

	fake.checkErr = status.Error(codes.InvalidArgument, "bad reference")
	_, err := KitPolicy(client).CheckKit(ctx, KitCheckRequest{SourceKind: KitSourceKindDirectory, SourceRef: "/kits/x"})
	assertAPIErrorCode(t, err, errorCodeInvalidArgument)

	fake.configErr = status.Error(codes.NotFound, "not found")
	_, err = KitPolicy(client).GetKitPolicyConfig(ctx)
	assertAPIErrorCode(t, err, "not_found")
}
