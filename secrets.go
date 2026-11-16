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

type secretClient struct{ c *client }

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
	request := &localv1.SecretSource{
		Reference:  source.Reference,
		Command:    source.Command,
		Refresh:    source.Refresh,
		NoVerify:   source.NoVerify,
		ShowError:  source.ShowError,
		OpAccount:  source.OPAccount,
		AwsProfile: source.AWSProfile,
	}
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
	return secret
}
