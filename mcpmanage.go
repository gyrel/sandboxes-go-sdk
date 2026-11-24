package sandboxes

import (
	"context"
	"fmt"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

const mcpManagementMinimumAPIVersion = "0.0.38"

type MCPAuthStatus string

const (
	// MCPAuthStatusUnspecified represents an unspecified or unknown wire value.
	MCPAuthStatusUnspecified     MCPAuthStatus = ""
	MCPAuthStatusNotConfigured   MCPAuthStatus = "not_configured"
	MCPAuthStatusReady           MCPAuthStatus = "ready"
	MCPAuthStatusPendingApproval MCPAuthStatus = "pending_approval"
	MCPAuthStatusExpired         MCPAuthStatus = "expired"
	MCPAuthStatusError           MCPAuthStatus = "error"
)

type MCPGatewayState string

const (
	// MCPGatewayStateUnspecified represents an unspecified or unknown wire value.
	MCPGatewayStateUnspecified MCPGatewayState = ""
	MCPGatewayStateUnloaded    MCPGatewayState = "unloaded"
	MCPGatewayStateLoaded      MCPGatewayState = "loaded"
)

type MCPServerDetail struct {
	Name, SandboxID, IdentityDisplayName, IdentityKind, IdentityIssuerHost string
	ToolsCount                                                             int
	LastSyncAt                                                             time.Time
	AuthStatus                                                             MCPAuthStatus
	GatewayState                                                           MCPGatewayState
}
type MCPServerAuthStatus struct {
	Name   string
	Status MCPAuthStatus
}
type MCPAuthStartRequest struct {
	Name, SandboxID string
	Scopes          []string
	NoScope, All    bool
}
type MCPAuthChallenge struct {
	ApprovalRequired bool
	ApprovalID       string
}

// MCPServerManagementService is the optional MCP management capability.
type MCPServerManagementService interface {
	Load(context.Context, string, string) error
	Unload(context.Context, string, string) error
	Inspect(context.Context, string, string) (MCPServerDetail, error)
	AuthStatus(context.Context, string, bool) ([]MCPServerAuthStatus, error)
	RemoveAuth(context.Context, string) (bool, error)
	StartAuth(context.Context, MCPAuthStartRequest) (MCPAuthChallenge, error)
}
type MCPServerManagementServiceProvider interface {
	MCPServerManagementService() MCPServerManagementService
}

func MCPServerManagement(c Client) MCPServerManagementService {
	if p, ok := c.(MCPServerManagementServiceProvider); ok {
		if s := p.MCPServerManagementService(); s != nil {
			return s
		}
	}
	return unsupportedMCPServerManagement{}
}

type unsupportedMCPServerManagement struct{}

func mcpManagementUnsupported() error {
	return &Error{Code: errorCodeUnsupported, Message: "MCP server management is not supported by this client"}
}
func (unsupportedMCPServerManagement) Load(context.Context, string, string) error {
	return mcpManagementUnsupported()
}
func (unsupportedMCPServerManagement) Unload(context.Context, string, string) error {
	return mcpManagementUnsupported()
}
func (unsupportedMCPServerManagement) Inspect(context.Context, string, string) (MCPServerDetail, error) {
	return MCPServerDetail{}, mcpManagementUnsupported()
}
func (unsupportedMCPServerManagement) AuthStatus(context.Context, string, bool) ([]MCPServerAuthStatus, error) {
	return nil, mcpManagementUnsupported()
}
func (unsupportedMCPServerManagement) RemoveAuth(context.Context, string) (bool, error) {
	return false, mcpManagementUnsupported()
}
func (unsupportedMCPServerManagement) StartAuth(context.Context, MCPAuthStartRequest) (MCPAuthChallenge, error) {
	return MCPAuthChallenge{}, mcpManagementUnsupported()
}
func (c *client) MCPServerManagementService() MCPServerManagementService {
	return mcpManagementClient{c}
}

type mcpManagementClient struct{ c *client }

func (s mcpManagementClient) gate(ctx context.Context) error {
	return requireAPIVersion(ctx, s.c, mcpManagementMinimumAPIVersion, "MCP server management")
}
func (s mcpManagementClient) Load(ctx context.Context, name, sandboxID string) error {
	if err := s.gate(ctx); err != nil {
		return err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	_, err := s.c.sandboxes.MCPLoadServer(ctx, &localv1.MCPLoadServerRequest{Name: name, SandboxId: sandboxID})
	return mapError(err)
}
func (s mcpManagementClient) Unload(ctx context.Context, name, sandboxID string) error {
	if err := s.gate(ctx); err != nil {
		return err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	_, err := s.c.sandboxes.MCPUnloadServer(ctx, &localv1.MCPUnloadServerRequest{Name: name, SandboxId: sandboxID})
	return mapError(err)
}
func (s mcpManagementClient) Inspect(ctx context.Context, name, sandboxID string) (MCPServerDetail, error) {
	if err := s.gate(ctx); err != nil {
		return MCPServerDetail{}, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.InspectMCPServer(ctx, &localv1.InspectMCPServerRequest{Name: name, SandboxId: sandboxID})
	if err != nil {
		return MCPServerDetail{}, mapError(err)
	}
	d := resp.GetServer()
	if d == nil {
		return MCPServerDetail{}, fmt.Errorf("daemon returned no MCP server detail")
	}
	out := MCPServerDetail{Name: d.GetName(), SandboxID: d.GetSandboxId(), IdentityDisplayName: d.GetIdentityDisplayName(), IdentityKind: d.GetIdentityKind(), IdentityIssuerHost: d.GetIdentityIssuerHost(), ToolsCount: int(d.GetToolsCount()), AuthStatus: mcpAuthStatusFromProto(d.GetAuthStatus()), GatewayState: mcpGatewayStateFromProto(d.GetGatewayState())}
	if d.GetLastSyncAtUnix() != 0 {
		out.LastSyncAt = time.Unix(d.GetLastSyncAtUnix(), 0)
	}
	return out, nil
}
func (s mcpManagementClient) AuthStatus(ctx context.Context, name string, all bool) ([]MCPServerAuthStatus, error) {
	if err := s.gate(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.GetMCPAuthStatus(ctx, &localv1.GetMCPAuthStatusRequest{Name: name, All: all})
	if err != nil {
		return nil, mapError(err)
	}
	if !all {
		return []MCPServerAuthStatus{{Name: name, Status: mcpAuthStatusFromProto(resp.GetStatus())}}, nil
	}
	out := make([]MCPServerAuthStatus, 0, len(resp.GetEntries()))
	for _, e := range resp.GetEntries() {
		out = append(out, MCPServerAuthStatus{Name: e.GetName(), Status: mcpAuthStatusFromProto(e.GetStatus())})
	}
	return out, nil
}
func (s mcpManagementClient) RemoveAuth(ctx context.Context, name string) (bool, error) {
	if err := s.gate(ctx); err != nil {
		return false, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.RemoveMCPAuth(ctx, &localv1.RemoveMCPAuthRequest{Name: name})
	if err != nil {
		return false, mapError(err)
	}
	return resp.GetRemoved(), nil
}
func (s mcpManagementClient) StartAuth(ctx context.Context, req MCPAuthStartRequest) (MCPAuthChallenge, error) {
	if req.NoScope && len(req.Scopes) > 0 {
		return MCPAuthChallenge{}, &Error{Code: errorCodeInvalidArgument, Message: "MCP scopes and no scope are mutually exclusive"}
	}
	if err := s.gate(ctx); err != nil {
		return MCPAuthChallenge{}, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.StartMCPAuth(ctx, &localv1.StartMCPAuthRequest{Name: req.Name, SandboxId: req.SandboxID, Scopes: append([]string(nil), req.Scopes...), NoScope: req.NoScope, All: req.All})
	if err != nil {
		return MCPAuthChallenge{}, mapError(err)
	}
	return MCPAuthChallenge{ApprovalRequired: resp.GetApprovalRequired(), ApprovalID: resp.GetApprovalId()}, nil
}
func mcpAuthStatusFromProto(v localv1.MCPAuthStatus) MCPAuthStatus {
	switch v {
	case localv1.MCPAuthStatus_MCP_AUTH_STATUS_NOT_CONFIGURED:
		return MCPAuthStatusNotConfigured
	case localv1.MCPAuthStatus_MCP_AUTH_STATUS_READY:
		return MCPAuthStatusReady
	case localv1.MCPAuthStatus_MCP_AUTH_STATUS_PENDING_APPROVAL:
		return MCPAuthStatusPendingApproval
	case localv1.MCPAuthStatus_MCP_AUTH_STATUS_EXPIRED:
		return MCPAuthStatusExpired
	case localv1.MCPAuthStatus_MCP_AUTH_STATUS_ERROR:
		return MCPAuthStatusError
	default:
		return MCPAuthStatusUnspecified
	}
}
func mcpGatewayStateFromProto(v localv1.MCPGatewayState) MCPGatewayState {
	switch v {
	case localv1.MCPGatewayState_MCP_GATEWAY_STATE_UNLOADED:
		return MCPGatewayStateUnloaded
	case localv1.MCPGatewayState_MCP_GATEWAY_STATE_LOADED:
		return MCPGatewayStateLoaded
	default:
		return MCPGatewayStateUnspecified
	}
}
