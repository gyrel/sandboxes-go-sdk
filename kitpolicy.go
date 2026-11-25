package sandboxes

import (
	"context"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
)

// KitSourceKind identifies the kind of a kit source reference. Unknown values
// are rejected by daemons with INVALID_ARGUMENT (fail closed).
type KitSourceKind string

const (
	KitSourceKindUnspecified KitSourceKind = ""
	KitSourceKindDirectory   KitSourceKind = "directory"
	KitSourceKindDir         KitSourceKind = KitSourceKindDirectory
	KitSourceKindZip         KitSourceKind = "zip"
	KitSourceKindGit         KitSourceKind = "git"
	KitSourceKindOci         KitSourceKind = "oci"
)

// KitCheckReason is the stable outcome of a kit policy check.
type KitCheckReason string

const (
	KitCheckReasonUnspecified       KitCheckReason = ""
	KitCheckReasonOK                KitCheckReason = "ok"
	KitCheckReasonSourceNotAllowed  KitCheckReason = "source_not_allowed"
	KitCheckReasonLocalDisabled     KitCheckReason = "local_disabled"
	KitCheckReasonSignatureRequired KitCheckReason = "signature_required"
	KitCheckReasonPolicyUnavailable KitCheckReason = "policy_unavailable"
	KitCheckReasonInvalidReference  KitCheckReason = "invalid_reference"
)

// KitCheckRequest asks the daemon whether a kit source may be installed or
// used. SourceRef is a URL/path identifier ONLY.
type KitCheckRequest struct {
	SourceKind       KitSourceKind
	SourceRef        string
	SandboxID        string
	SignaturePresent bool
}

// KitCheck is the daemon's fail-closed decision.
type KitCheck struct {
	Allowed         bool
	Reason          KitCheckReason
	Message         string
	CheckedSettings []string
}

// KitPolicyConfig is the effective kit policy for display.
type KitPolicyConfig struct {
	AllowedSources   []KitSourceKind
	AllowLocalKits   bool
	RequireSignature bool
	Managed          bool
}

// KitPolicyService exposes the daemon's kit source policy. It is an optional
// capability: use KitPolicy(client) so the root Client interface stays source
// compatible.
type KitPolicyService interface {
	CheckKit(ctx context.Context, req KitCheckRequest) (KitCheck, error)
	GetKitPolicyConfig(ctx context.Context) (KitPolicyConfig, error)
}

// KitPolicyServiceProvider is optionally implemented by root clients that
// expose kit policy without changing the root Client interface.
type KitPolicyServiceProvider interface {
	KitPolicyService() KitPolicyService
}

// KitPolicy returns the optional kit policy service.
func KitPolicy(c Client) KitPolicyService {
	if provider, ok := c.(KitPolicyServiceProvider); ok {
		if service := provider.KitPolicyService(); service != nil {
			return service
		}
	}
	return unsupportedKitPolicyService{}
}

const unsupportedKitPolicyMessage = "kit policy is not supported by this client"

type unsupportedKitPolicyService struct{}

func (unsupportedKitPolicyService) CheckKit(context.Context, KitCheckRequest) (KitCheck, error) {
	return KitCheck{}, &Error{Code: errorCodeUnsupported, Message: unsupportedKitPolicyMessage}
}

func (unsupportedKitPolicyService) GetKitPolicyConfig(context.Context) (KitPolicyConfig, error) {
	return KitPolicyConfig{}, &Error{Code: errorCodeUnsupported, Message: unsupportedKitPolicyMessage}
}

func (c *client) KitPolicyService() KitPolicyService { return kitPolicyClient{c: c} }

type kitPolicyClient struct{ c *client }

var _ KitPolicyService = kitPolicyClient{}

func (k kitPolicyClient) CheckKit(ctx context.Context, req KitCheckRequest) (KitCheck, error) {
	if req.SourceRef == "" {
		return KitCheck{}, &Error{Code: errorCodeInvalidArgument, Message: "source ref is required"}
	}
	protoReq, err := kitCheckRequestToProto(req)
	if err != nil {
		return KitCheck{}, err
	}
	if err := requireAPIVersion(ctx, k.c, kitPolicyMinimumAPIVersion, "kit policy"); err != nil {
		return KitCheck{}, err
	}
	ctx, cancel := k.c.context(ctx)
	defer cancel()
	resp, err := k.c.kitPolicy.CheckKit(ctx, protoReq)
	if err != nil {
		return KitCheck{}, mapError(err)
	}
	return fromProtoKitCheck(resp), nil
}

func (k kitPolicyClient) GetKitPolicyConfig(ctx context.Context) (KitPolicyConfig, error) {
	if err := requireAPIVersion(ctx, k.c, kitPolicyMinimumAPIVersion, "kit policy"); err != nil {
		return KitPolicyConfig{}, err
	}
	ctx, cancel := k.c.context(ctx)
	defer cancel()
	resp, err := k.c.kitPolicy.GetKitPolicyConfig(ctx, &localv1.GetKitPolicyConfigRequest{})
	if err != nil {
		return KitPolicyConfig{}, mapError(err)
	}
	return fromProtoKitPolicyConfig(resp), nil
}

func kitCheckRequestToProto(req KitCheckRequest) (*localv1.CheckKitRequest, error) {
	kind, err := kitSourceKindToProto(req.SourceKind)
	if err != nil {
		return nil, err
	}
	return &localv1.CheckKitRequest{
		SourceKind:       kind,
		SourceRef:        req.SourceRef,
		SandboxId:        req.SandboxID,
		SignaturePresent: req.SignaturePresent,
	}, nil
}

// toProtoKitCheckRequest is an alias used by tests and callers.
func toProtoKitCheckRequest(req KitCheckRequest) (*localv1.CheckKitRequest, error) {
	return kitCheckRequestToProto(req)
}

func fromProtoKitCheck(in *localv1.CheckKitResponse) KitCheck {
	if in == nil {
		return KitCheck{}
	}
	return KitCheck{
		Allowed:         in.GetAllowed(),
		Reason:          kitCheckReasonFromProto(in.GetReason()),
		Message:         in.GetMessage(),
		CheckedSettings: append([]string(nil), in.GetCheckedSettings()...),
	}
}

func fromProtoKitPolicyConfig(in *localv1.GetKitPolicyConfigResponse) KitPolicyConfig {
	if in == nil {
		return KitPolicyConfig{}
	}
	out := KitPolicyConfig{
		AllowLocalKits:   in.GetAllowLocalKits(),
		RequireSignature: in.GetRequireSignature(),
		Managed:          in.GetManaged(),
	}
	for _, kind := range in.GetAllowedSources() {
		out.AllowedSources = append(out.AllowedSources, kitSourceKindFromProto(kind))
	}
	return out
}

func kitSourceKindToProto(kind KitSourceKind) (localv1.KitSourceKind, error) {
	switch kind {
	case "":
		return localv1.KitSourceKind_KIT_SOURCE_KIND_UNSPECIFIED, nil
	case KitSourceKindDirectory:
		return localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY, nil
	case KitSourceKindZip:
		return localv1.KitSourceKind_KIT_SOURCE_KIND_ZIP, nil
	case KitSourceKindGit:
		return localv1.KitSourceKind_KIT_SOURCE_KIND_GIT, nil
	case KitSourceKindOci:
		return localv1.KitSourceKind_KIT_SOURCE_KIND_OCI, nil
	default:
		return localv1.KitSourceKind_KIT_SOURCE_KIND_UNSPECIFIED,
			&Error{Code: errorCodeInvalidArgument, Message: "kit source kind must be directory, zip, git or oci"}
	}
}

func kitSourceKindFromProto(kind localv1.KitSourceKind) KitSourceKind {
	switch kind {
	case localv1.KitSourceKind_KIT_SOURCE_KIND_UNSPECIFIED:
		return ""
	case localv1.KitSourceKind_KIT_SOURCE_KIND_DIRECTORY:
		return KitSourceKindDirectory
	case localv1.KitSourceKind_KIT_SOURCE_KIND_ZIP:
		return KitSourceKindZip
	case localv1.KitSourceKind_KIT_SOURCE_KIND_GIT:
		return KitSourceKindGit
	case localv1.KitSourceKind_KIT_SOURCE_KIND_OCI:
		return KitSourceKindOci
	default:
		return ""
	}
}

func kitCheckReasonFromProto(reason localv1.CheckKitReason) KitCheckReason {
	switch reason {
	case localv1.CheckKitReason_CHECK_KIT_REASON_UNSPECIFIED:
		return ""
	case localv1.CheckKitReason_CHECK_KIT_REASON_OK:
		return KitCheckReasonOK
	case localv1.CheckKitReason_CHECK_KIT_REASON_SOURCE_NOT_ALLOWED:
		return KitCheckReasonSourceNotAllowed
	case localv1.CheckKitReason_CHECK_KIT_REASON_LOCAL_DISABLED:
		return KitCheckReasonLocalDisabled
	case localv1.CheckKitReason_CHECK_KIT_REASON_SIGNATURE_REQUIRED:
		return KitCheckReasonSignatureRequired
	case localv1.CheckKitReason_CHECK_KIT_REASON_POLICY_UNAVAILABLE:
		return KitCheckReasonPolicyUnavailable
	case localv1.CheckKitReason_CHECK_KIT_REASON_INVALID_REFERENCE:
		return KitCheckReasonInvalidReference
	default:
		return ""
	}
}

var _ KitPolicyServiceProvider = (*client)(nil)
var _ Client = (*client)(nil)

var _ = toProtoKitCheckRequest
