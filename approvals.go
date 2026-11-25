package sandboxes

import (
	"context"
	"time"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
)

// ApprovalKind classifies a host-side consent request.
type ApprovalKind string

const (
	ApprovalKindHostCommand     ApprovalKind = "host_command"
	ApprovalKindMCPRegistration ApprovalKind = "mcp_registration"
	ApprovalKindMCPCall         ApprovalKind = "mcp_call"
	ApprovalKindOther           ApprovalKind = "other"
)

// ApprovalState is the lifecycle state of an approval.
type ApprovalState string

const (
	ApprovalStatePending  ApprovalState = "pending"
	ApprovalStateApproved ApprovalState = "approved"
	ApprovalStateDenied   ApprovalState = "denied"
)

// HeaderValueClass tells whether a header value comes from the host vault.
// HeaderValueClassStatic only discloses a non-compliant literal; it is never a
// valid way to supply a value.
type HeaderValueClass string

const (
	HeaderValueClassStatic HeaderValueClass = "static"
	HeaderValueClassVault  HeaderValueClass = "vault"
)

// ApprovalDecision is the host-side decision recorded by RespondApproval.
type ApprovalDecision string

const (
	ApprovalDecisionApprove ApprovalDecision = "approve"
	ApprovalDecisionDeny    ApprovalDecision = "deny"
)

// ApprovalPersistScope selects whether a decision is stored as a rule. An
// empty scope is sent as unspecified, which the daemon treats as once.
type ApprovalPersistScope string

const (
	// ApprovalPersistScopeOnce applies the decision to this approval only.
	ApprovalPersistScopeOnce ApprovalPersistScope = "once"
	// ApprovalPersistScopeExact stores a rule for the approval's exact scope.
	// It requires a trusted OS-backed approval provider on the daemon.
	ApprovalPersistScopeExact ApprovalPersistScope = "exact"
)

// ApprovalHeader names one request header that an approval would send. Header
// values never cross the API; only the name, class and vault reference IDs do.
type ApprovalHeader struct {
	Name              string
	ValueClass        HeaderValueClass
	VaultReferenceIDs []string
}

// Approval is a pending or recently resolved host-side consent request. It
// carries no header, environment or secret values, and command text is never
// disclosed. A pending approval grants nothing by being listed or inspected.
type Approval struct {
	ID              string
	Kind            ApprovalKind
	State           ApprovalState
	SandboxID       string
	ActionSummary   string
	DestinationHost string
	DestinationPath string
	Headers         []ApprovalHeader
	// EnvNames holds bounded environment variable names only, never values.
	// EnvNamesTruncated is set when the daemon dropped additional names.
	EnvNames          []string
	EnvNamesTruncated bool
	CwdSummary        string
	CreatedAt         time.Time
}

// ApprovalService lists, inspects and resolves host-side approvals. It is an
// optional capability: use Approvals(client) so the root Client interface stays
// source compatible. Responding never grants consent by itself; the daemon
// must obtain it through its trusted host approval provider.
type ApprovalService interface {
	// ListApprovals returns pending approvals. A non-empty sandboxID limits the
	// result to that sandbox.
	ListApprovals(ctx context.Context, sandboxID string) ([]Approval, error)
	// InspectApproval returns one approval. A non-empty sandboxID that does not
	// match the approval's sandbox returns a not_found error.
	InspectApproval(ctx context.Context, approvalID, sandboxID string) (Approval, error)
	// RespondApproval records a decision and returns the approval and the
	// persisted rule ID, which is set only when an EXACT rule was stored. A
	// daemon without a trusted approval provider returns
	// ErrApprovalProviderUnavailable for APPROVE and EXACT.
	RespondApproval(ctx context.Context, approvalID string, decision ApprovalDecision, persist ApprovalPersistScope) (Approval, string, error)
}

// ApprovalServiceProvider is optionally implemented by root clients that expose
// approvals without changing the root Client interface.
type ApprovalServiceProvider interface {
	ApprovalService() ApprovalService
}

// Approvals returns the optional approval service.
func Approvals(c Client) ApprovalService {
	if provider, ok := c.(ApprovalServiceProvider); ok {
		if service := provider.ApprovalService(); service != nil {
			return service
		}
	}
	return unsupportedApprovalService{}
}

const unsupportedApprovalsMessage = "approvals are not supported by this client"

type unsupportedApprovalService struct{}

func (unsupportedApprovalService) ListApprovals(context.Context, string) ([]Approval, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: unsupportedApprovalsMessage}
}

func (unsupportedApprovalService) InspectApproval(context.Context, string, string) (Approval, error) {
	return Approval{}, &Error{Code: errorCodeUnsupported, Message: unsupportedApprovalsMessage}
}

func (unsupportedApprovalService) RespondApproval(context.Context, string, ApprovalDecision, ApprovalPersistScope) (Approval, string, error) {
	return Approval{}, "", &Error{Code: errorCodeUnsupported, Message: unsupportedApprovalsMessage}
}

func (c *client) ApprovalService() ApprovalService { return approvalClient{c: c} }

type approvalClient struct{ c *client }

var _ ApprovalService = approvalClient{}

func (a approvalClient) ListApprovals(ctx context.Context, sandboxID string) ([]Approval, error) {
	if err := requireAPIVersion(ctx, a.c, approvalsMinimumAPIVersion, "approvals"); err != nil {
		return nil, err
	}
	ctx, cancel := a.c.context(ctx)
	defer cancel()
	resp, err := a.c.approvals.List(ctx, &localv1.ApprovalServiceListRequest{SandboxId: sandboxID})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]Approval, 0, len(resp.GetApprovals()))
	for _, item := range resp.GetApprovals() {
		out = append(out, fromProtoApproval(item))
	}
	return out, nil
}

func (a approvalClient) InspectApproval(ctx context.Context, approvalID, sandboxID string) (Approval, error) {
	if approvalID == "" {
		return Approval{}, &Error{Code: errorCodeInvalidArgument, Message: "approval ID is required"}
	}
	if err := requireAPIVersion(ctx, a.c, approvalsMinimumAPIVersion, "approvals"); err != nil {
		return Approval{}, err
	}
	ctx, cancel := a.c.context(ctx)
	defer cancel()
	resp, err := a.c.approvals.Inspect(ctx, &localv1.ApprovalServiceInspectRequest{ApprovalId: approvalID, SandboxId: sandboxID})
	if err != nil {
		return Approval{}, mapError(err)
	}
	return fromProtoApproval(resp.GetApproval()), nil
}

func (a approvalClient) RespondApproval(ctx context.Context, approvalID string, decision ApprovalDecision, persist ApprovalPersistScope) (Approval, string, error) {
	if approvalID == "" {
		return Approval{}, "", &Error{Code: errorCodeInvalidArgument, Message: "approval ID is required"}
	}
	protoDecision, err := approvalDecisionToProto(decision)
	if err != nil {
		return Approval{}, "", err
	}
	protoPersist, err := approvalPersistToProto(persist)
	if err != nil {
		return Approval{}, "", err
	}
	if err := requireAPIVersion(ctx, a.c, approvalsMinimumAPIVersion, "approvals"); err != nil {
		return Approval{}, "", err
	}
	ctx, cancel := a.c.context(ctx)
	defer cancel()
	resp, err := a.c.approvals.Respond(ctx, &localv1.ApprovalServiceRespondRequest{
		ApprovalId: approvalID, Decision: protoDecision, PersistScope: protoPersist,
	})
	if err != nil {
		return Approval{}, "", mapApprovalUnavailable(err)
	}
	return fromProtoApproval(resp.GetApproval()), resp.GetPersistedRuleId(), nil
}

func approvalDecisionToProto(decision ApprovalDecision) (localv1.ApprovalDecision, error) {
	switch decision {
	case ApprovalDecisionApprove:
		return localv1.ApprovalDecision_APPROVAL_DECISION_APPROVE, nil
	case ApprovalDecisionDeny:
		return localv1.ApprovalDecision_APPROVAL_DECISION_DENY, nil
	default:
		return localv1.ApprovalDecision_APPROVAL_DECISION_UNSPECIFIED,
			&Error{Code: errorCodeInvalidArgument, Message: "approval decision must be approve or deny"}
	}
}

func approvalPersistToProto(scope ApprovalPersistScope) (localv1.ApprovalPersistScope, error) {
	switch scope {
	case "":
		return localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_UNSPECIFIED, nil
	case ApprovalPersistScopeOnce:
		return localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_ONCE, nil
	case ApprovalPersistScopeExact:
		return localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_EXACT, nil
	default:
		return localv1.ApprovalPersistScope_APPROVAL_PERSIST_SCOPE_UNSPECIFIED,
			&Error{Code: errorCodeInvalidArgument, Message: "approval persist scope must be once or exact"}
	}
}

func fromProtoApproval(in *localv1.Approval) Approval {
	if in == nil {
		return Approval{}
	}
	var headers []ApprovalHeader
	for _, h := range in.GetHeaders() {
		if h == nil {
			continue
		}
		headers = append(headers, ApprovalHeader{
			Name:              h.GetName(),
			ValueClass:        headerValueClassFromProto(h.GetValueClass()),
			VaultReferenceIDs: append([]string(nil), h.GetVaultReferenceIds()...),
		})
	}
	return Approval{
		ID:                in.GetId(),
		Kind:              approvalKindFromProto(in.GetKind()),
		State:             approvalStateFromProto(in.GetState()),
		SandboxID:         in.GetSandboxId(),
		ActionSummary:     in.GetActionSummary(),
		DestinationHost:   in.GetDestinationHost(),
		DestinationPath:   in.GetDestinationPath(),
		Headers:           headers,
		EnvNames:          append([]string(nil), in.GetEnvNames()...),
		EnvNamesTruncated: in.GetEnvNamesTruncated(),
		CwdSummary:        in.GetCwdSummary(),
		CreatedAt:         unixTime(in.GetCreatedAtUnix()),
	}
}

// approvalKindFromProto maps unrecognized future kinds to ApprovalKindOther, as
// the contract requires of daemons. An unspecified kind stays empty.
func approvalKindFromProto(kind localv1.ApprovalKind) ApprovalKind {
	switch kind {
	case localv1.ApprovalKind_APPROVAL_KIND_UNSPECIFIED:
		return ""
	case localv1.ApprovalKind_APPROVAL_KIND_HOST_COMMAND:
		return ApprovalKindHostCommand
	case localv1.ApprovalKind_APPROVAL_KIND_MCP_REGISTRATION:
		return ApprovalKindMCPRegistration
	case localv1.ApprovalKind_APPROVAL_KIND_MCP_CALL:
		return ApprovalKindMCPCall
	default:
		return ApprovalKindOther
	}
}

func approvalStateFromProto(state localv1.ApprovalState) ApprovalState {
	switch state {
	case localv1.ApprovalState_APPROVAL_STATE_PENDING:
		return ApprovalStatePending
	case localv1.ApprovalState_APPROVAL_STATE_APPROVED:
		return ApprovalStateApproved
	case localv1.ApprovalState_APPROVAL_STATE_DENIED:
		return ApprovalStateDenied
	default:
		return ""
	}
}

func headerValueClassFromProto(class localv1.HeaderValueClass) HeaderValueClass {
	switch class {
	case localv1.HeaderValueClass_HEADER_VALUE_CLASS_STATIC:
		return HeaderValueClassStatic
	case localv1.HeaderValueClass_HEADER_VALUE_CLASS_VAULT:
		return HeaderValueClassVault
	default:
		return ""
	}
}
