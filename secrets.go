package sandboxes

import (
	"context"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

// SecretScope controls where a service secret may be used.
type SecretScope string

const (
	SecretScopeGlobal  SecretScope = "global"
	SecretScopeSandbox SecretScope = "sandbox"
)

// SecretSourceKind describes how a host-side service secret is stored.
// It never identifies the referenced value itself.
type SecretSourceKind string

const (
	// SecretSourceKindValue is a literal secret value held by the host vault.
	SecretSourceKindValue SecretSourceKind = "value"
	// SecretSourceKindReference is a resolved host-side reference such as a
	// 1Password URL or AWS Secrets Manager ARN.
	SecretSourceKindReference SecretSourceKind = "reference"
	// SecretSourceKindCommand is a host-side command resolved on demand.
	SecretSourceKindCommand SecretSourceKind = "command"
)

// SecretOrigin names where a secret summary came from. An empty value from an
// older daemon must be treated as local.
type SecretOrigin string

const (
	SecretOriginLocal SecretOrigin = "local"
)

// SecretValueType is the coarse type of a stored service secret. It never
// identifies or encodes the secret value itself.
type SecretValueType string

const (
	SecretValueTypeAPIKey   SecretValueType = "api_key"
	SecretValueTypeExternal SecretValueType = "external"
)

// ServiceSecret is non-secret metadata. It never contains a secret value,
// reference, command, environment value or other secret material.
type ServiceSecret struct {
	Service     string
	Scope       SecretScope
	SandboxName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	SourceKind  SecretSourceKind
	Refresh     string
	Refreshable bool
	SecretType  SecretValueType
	Origin      SecretOrigin
	// EnvName, Hosts and PlaceholderMasked describe custom-secret placement
	// (contract 0.0.36+). They are empty for service secrets and from older
	// daemons. PlaceholderMasked reveals at most the last four characters of
	// the placeholder; the full placeholder is returned only by SetCustomSecret.
	EnvName           string
	Hosts             []string
	PlaceholderMasked string
}

// SecretService manages host-keychain service secrets.
type SecretService interface {
	Set(ctx context.Context, service string, scope SecretScope, sandboxName string, value []byte) (ServiceSecret, error)
	List(ctx context.Context) ([]ServiceSecret, error)
	Remove(ctx context.Context, service string, scope SecretScope, sandboxName string) (bool, error)
}

// SecretCreator is an optional capability for storing a secret only when no
// secret already exists in that scope. Keeping it separate preserves source
// compatibility for existing SecretService implementations.
type SecretCreator interface {
	Create(ctx context.Context, service string, scope SecretScope, sandboxName string, value []byte) (ServiceSecret, error)
}

// SecretSource describes a host-side dynamic credential source. References or
// shell commands are stored by the daemon and resolved only on the host when
// the proxy needs a credential.
type SecretSource struct {
	Reference  string
	Command    string
	Refresh    string
	NoVerify   bool
	ShowError  bool
	OPAccount  string
	AWSProfile string
}

// DynamicSecretCreator is an optional capability for storing a dynamic source.
type DynamicSecretCreator interface {
	SetSource(ctx context.Context, service string, scope SecretScope, sandboxName string, source SecretSource, overwrite bool) (ServiceSecret, error)
}

// SecretSources returns the optional dynamic-source capability.
func SecretSources(c Client) (DynamicSecretCreator, bool) {
	creator, ok := Secrets(c).(DynamicSecretCreator)
	return creator, ok
}

// CustomSecretRequest creates or updates a custom secret that the sandbox uses
// through a placeholder. Set exactly one of Value or Source.
//
// Redaction: Value is write-only. The SDK forwards it to the daemon and never
// logs, formats or returns it, and resolver output from Source is never
// returned either. Do not place Value in process arguments or logs.
type CustomSecretRequest struct {
	// Service is the service identity. Empty lets the daemon derive it from
	// the first host and return the resolved name in CustomSecretResult.Secret.Service.
	Service     string
	Scope       SecretScope
	SandboxName string
	// Value is an inline secret, stored host-side and never echoed.
	Value []byte
	// Source is a host-side reference or command with optional refresh
	// policy. Its first resolution requires host approval, returned as
	// CustomSecretResult.ApprovalRequired and ApprovalID.
	Source *SecretSource
	// Env is the sandbox environment variable that receives the placeholder.
	Env string
	// Placeholder is an explicit placeholder or a template ending in {rand}.
	// Empty lets the daemon generate one.
	Placeholder string
	// Hosts are exact DNS names, IP literals or wildcard patterns ("*" matches
	// one label, "**" matches any number) where the proxy substitutes the value.
	Hosts []string
}

// CustomSecretResult reports the stored custom-secret summary. Placeholder is
// the full placeholder and appears only in this write result; inventories keep
// only ServiceSecret.PlaceholderMasked. While approval is pending, Secret is
// zero and Placeholder is empty.
type CustomSecretResult struct {
	Secret           ServiceSecret
	ApprovalRequired bool
	ApprovalID       string
	Placeholder      string
}

// CustomSecretService manages custom secrets. It is an optional capability so
// existing SecretService implementations remain source compatible.
type CustomSecretService interface {
	SetCustomSecret(ctx context.Context, req CustomSecretRequest) (CustomSecretResult, error)
}

// CustomSecretServiceProvider is implemented by clients that expose custom secrets.
type CustomSecretServiceProvider interface {
	CustomSecretService() CustomSecretService
}

// CustomSecrets returns the optional custom-secret capability; unsupported
// fallback keeps callers compiling against older transports.
func CustomSecrets(c Client) CustomSecretService {
	if provider, ok := c.(CustomSecretServiceProvider); ok {
		if service := provider.CustomSecretService(); service != nil {
			return service
		}
	}
	return unsupportedCustomSecretService{}
}

type unsupportedCustomSecretService struct{}

func (unsupportedCustomSecretService) SetCustomSecret(context.Context, CustomSecretRequest) (CustomSecretResult, error) {
	return CustomSecretResult{}, &Error{Code: errorCodeUnsupported, Message: "custom secrets are not supported by this client"}
}

// SecretCreation returns the optional create-only service-secret capability.
func SecretCreation(c Client) (SecretCreator, bool) {
	creator, ok := Secrets(c).(SecretCreator)
	return creator, ok
}

// SecretServiceProvider is implemented by clients that expose service secrets.
type SecretServiceProvider interface {
	SecretService() SecretService
}

// Secrets returns the optional service-secret client.
func Secrets(c Client) SecretService {
	if provider, ok := c.(SecretServiceProvider); ok {
		if service := provider.SecretService(); service != nil {
			return service
		}
	}
	return unsupportedSecretService{}
}

const unsupportedSecretsMessage = "service secrets are not supported by this client"

type unsupportedSecretService struct{}

func (unsupportedSecretService) Set(context.Context, string, SecretScope, string, []byte) (ServiceSecret, error) {
	return ServiceSecret{}, &Error{Code: errorCodeUnsupported, Message: unsupportedSecretsMessage}
}

func (unsupportedSecretService) List(context.Context) ([]ServiceSecret, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: unsupportedSecretsMessage}
}

func (unsupportedSecretService) Remove(context.Context, string, SecretScope, string) (bool, error) {
	return false, &Error{Code: errorCodeUnsupported, Message: unsupportedSecretsMessage}
}

func (c *client) SecretService() SecretService { return secretClient{c: c} }

func (c *client) CustomSecretService() CustomSecretService { return secretClient{c: c} }

type secretClient struct{ c *client }

var _ CustomSecretService = secretClient{}

func (s secretClient) Set(ctx context.Context, service string, scope SecretScope, sandboxName string, value []byte) (ServiceSecret, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.secrets.Set(ctx, &localv1.SecretServiceSetRequest{
		Service: service, Scope: string(scope), SandboxName: sandboxName, Value: value,
	})
	if err != nil {
		return ServiceSecret{}, mapError(err)
	}
	return serviceSecretWithMetadata(serviceSecretFromProto(resp.GetSecret()), resp.GetSecret()), nil
}

// Create stores a service secret only when no secret already exists in that scope.
// The daemon performs the existence check and write under the same credential gate.
func (s secretClient) Create(ctx context.Context, service string, scope SecretScope, sandboxName string, value []byte) (ServiceSecret, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.secrets.Create(ctx, &localv1.SecretServiceCreateRequest{
		Service: service, Scope: string(scope), SandboxName: sandboxName, Value: value,
	})
	if err != nil {
		return ServiceSecret{}, mapError(err)
	}
	return serviceSecretWithMetadata(serviceSecretFromProto(resp.GetSecret()), resp.GetSecret()), nil
}

// SetSource stores a dynamic reference; it never sends a resolved value through
// the SDK. overwrite selects the daemon's atomic Set or Create RPC.
func (s secretClient) SetSource(ctx context.Context, service string, scope SecretScope, sandboxName string, source SecretSource, overwrite bool) (ServiceSecret, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	version, err := Version(s.c).Get(ctx)
	if err != nil {
		return ServiceSecret{}, err
	}
	if !apiVersionAtLeast(version.APIVersion, dynamicSecretSourcesMinimumAPIVersion) {
		return ServiceSecret{}, &Error{Code: errorCodeUnsupported, Message: "dynamic secret sources require daemon API v0.0.16 or newer"}
	}
	request := secretSourceToProto(source)
	if overwrite {
		resp, err := s.c.secrets.Set(ctx, &localv1.SecretServiceSetRequest{
			Service: service, Scope: string(scope), SandboxName: sandboxName, Source: request,
		})
		if err != nil {
			return ServiceSecret{}, mapError(err)
		}
		return serviceSecretWithMetadata(serviceSecretFromProto(resp.GetSecret()), resp.GetSecret()), nil
	}
	resp, err := s.c.secrets.Create(ctx, &localv1.SecretServiceCreateRequest{
		Service: service, Scope: string(scope), SandboxName: sandboxName, Source: request,
	})
	if err != nil {
		return ServiceSecret{}, mapError(err)
	}
	return serviceSecretWithMetadata(serviceSecretFromProto(resp.GetSecret()), resp.GetSecret()), nil
}

// SetCustomSecret stores a custom secret. Value and resolver output are never
// logged, echoed in errors or returned; see CustomSecretRequest. A reference or
// command Source on a daemon without a trusted approval provider returns
// ErrApprovalProviderUnavailable instead of storing the source.
func (s secretClient) SetCustomSecret(ctx context.Context, req CustomSecretRequest) (CustomSecretResult, error) {
	if (len(req.Value) == 0) == (req.Source == nil) {
		return CustomSecretResult{}, &Error{Code: errorCodeInvalidArgument, Message: "exactly one of Value or Source is required"}
	}
	if err := requireAPIVersion(ctx, s.c, customSecretsMinimumAPIVersion, "custom secrets"); err != nil {
		return CustomSecretResult{}, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.secrets.SetCustom(ctx, toProtoCustomSecretRequest(req))
	if err != nil {
		if req.Source != nil {
			return CustomSecretResult{}, mapApprovalUnavailable(err)
		}
		return CustomSecretResult{}, mapError(err)
	}
	return CustomSecretResult{
		Secret:           serviceSecretWithMetadata(serviceSecretFromProto(resp.GetSecret()), resp.GetSecret()),
		ApprovalRequired: resp.GetApprovalRequired(),
		ApprovalID:       resp.GetApprovalId(),
		Placeholder:      resp.GetPlaceholder(),
	}, nil
}

func toProtoCustomSecretRequest(req CustomSecretRequest) *localv1.SecretServiceSetCustomRequest {
	out := &localv1.SecretServiceSetCustomRequest{
		Service:     req.Service,
		Scope:       string(req.Scope),
		SandboxName: req.SandboxName,
		Value:       req.Value,
		Env:         req.Env,
		Placeholder: req.Placeholder,
		Hosts:       append([]string(nil), req.Hosts...),
	}
	if req.Source != nil {
		out.Source = secretSourceToProto(*req.Source)
	}
	return out
}

func secretSourceToProto(source SecretSource) *localv1.SecretSource {
	return &localv1.SecretSource{
		Reference:  source.Reference,
		Command:    source.Command,
		Refresh:    source.Refresh,
		NoVerify:   source.NoVerify,
		ShowError:  source.ShowError,
		OpAccount:  source.OPAccount,
		AwsProfile: source.AWSProfile,
	}
}

func (s secretClient) List(ctx context.Context) ([]ServiceSecret, error) {
	metadata := secretMetadataSupported(ctx, s.c)
	resp, err := s.list(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ServiceSecret, 0, len(resp.GetSecrets()))
	for _, item := range resp.GetSecrets() {
		if item != nil {
			secret := serviceSecretFromProto(item)
			if metadata {
				secret = serviceSecretWithMetadata(secret, item)
			}
			out = append(out, secret)
		}
	}
	return out, nil
}

func (s secretClient) list(ctx context.Context) (*localv1.SecretServiceListResponse, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.secrets.List(ctx, &localv1.SecretServiceListRequest{})
	if err != nil {
		return nil, mapError(err)
	}
	return resp, nil
}

func (s secretClient) Remove(ctx context.Context, service string, scope SecretScope, sandboxName string) (bool, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.secrets.Remove(ctx, &localv1.SecretServiceRemoveRequest{
		Service: service, Scope: string(scope), SandboxName: sandboxName,
	})
	if err != nil {
		return false, mapError(err)
	}
	return resp.GetRemoved(), nil
}

func serviceSecretFromProto(item *localv1.SecretSummary) ServiceSecret {
	if item == nil {
		return ServiceSecret{}
	}
	return ServiceSecret{Service: item.GetService(), Scope: SecretScope(item.GetScope()), SandboxName: item.GetSandboxName()}
}

func serviceSecretWithMetadata(secret ServiceSecret, item *localv1.SecretSummary) ServiceSecret {
	secret.CreatedAt = unixTime(item.GetCreatedAtUnix())
	secret.UpdatedAt = unixTime(item.GetUpdatedAtUnix())
	secret.SourceKind = SecretSourceKind(item.GetSourceKind())
	secret.Refresh = item.GetRefresh()
	secret.Refreshable = item.GetRefreshable()
	secret.SecretType = SecretValueType(item.GetSecretType())
	secret.Origin = SecretOrigin(item.GetOrigin())
	secret.EnvName = item.GetEnvName()
	secret.Hosts = append([]string(nil), item.GetHosts()...)
	secret.PlaceholderMasked = item.GetPlaceholderMasked()
	return secret
}
