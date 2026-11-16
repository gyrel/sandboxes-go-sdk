package sandboxes

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// sbxSecretItem mirrors commands.secretJSON from sbx v0.50.1. Keep the field
// names, order and omitempty behavior aligned with the reference CLI.
type sbxSecretItem struct {
	Scope       string   `json:"scope"`
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Secret      string   `json:"secret,omitempty"`
	Username    string   `json:"username,omitempty"`
	Kind        string   `json:"kind,omitempty"`
	Source      string   `json:"source,omitempty"`
	Refresh     string   `json:"refresh,omitempty"`
	SecretType  string   `json:"secret_type,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	Header      string   `json:"header,omitempty"`
	Format      string   `json:"format,omitempty"`
	Env         string   `json:"env,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
}

type sbxSecretList struct {
	Secrets          []sbxSecretItem `json:"secrets"`
	CustomSecrets    []any           `json:"custom_secrets"`
	ShadowedServices []string        `json:"shadowed_services"`
	EnvOnlyCount     int             `json:"env_only_count"`
}

const storedSecret = "(stored)"

func sbxTimestamp(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func sbxServiceItem(secret ServiceSecret) sbxSecretItem {
	scope := string(secret.Scope)
	if secret.SandboxName != "" {
		scope = secret.SandboxName
	}
	return sbxSecretItem{
		Scope: scope, Type: "service", Name: secret.Service, Secret: storedSecret,
		Kind: string(secret.SourceKind), Source: string(secret.Origin), Refresh: secret.Refresh,
		SecretType: string(secret.SecretType), CreatedAt: sbxTimestamp(secret.CreatedAt),
	}
}

func sbxRegistryItem(credential RegistryCredentialSummary) sbxSecretItem {
	scope := credential.Scope
	if credential.SandboxName != "" {
		scope = credential.SandboxName
	}
	return sbxSecretItem{
		Scope: scope, Type: "registry", Name: credential.Registry, Username: credential.Username,
		Secret: storedSecret, Source: string(credential.Origin), CreatedAt: sbxTimestamp(credential.CreatedAt),
	}
}

func TestSecretListMatchesSbxJSONShape(t *testing.T) {
	created := func(minute int) time.Time {
		return time.Date(2026, 11, 16, 9, minute, 0, 0, time.UTC)
	}
	secrets := []ServiceSecret{
		{
			Service: "github", Scope: SecretScopeGlobal, CreatedAt: created(0),
			SourceKind: SecretSourceKindValue, SecretType: "api_key", Origin: SecretOriginLocal,
		},
		{
			Service: "anthropic", Scope: SecretScopeSandbox, SandboxName: "dev", CreatedAt: created(5),
			SourceKind: SecretSourceKindReference, Refresh: "55m0s", Refreshable: true,
			SecretType: "external", Origin: SecretOriginLocal,
		},
	}
	registries := []RegistryCredentialSummary{
		{
			Registry: "ghcr.io", Username: "alice", Scope: string(RegistryScopeHostOnly),
			CreatedAt: created(10), Origin: SecretOriginLocal,
		},
	}

	list := sbxSecretList{
		Secrets:          make([]sbxSecretItem, 0, len(secrets)+len(registries)),
		CustomSecrets:    make([]any, 0),
		ShadowedServices: make([]string, 0),
	}
	for _, secret := range secrets {
		list.Secrets = append(list.Secrets, sbxServiceItem(secret))
	}
	for _, credential := range registries {
		list.Secrets = append(list.Secrets, sbxRegistryItem(credential))
	}

	got, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "secret_ls.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Git may check the golden file out with CRLF on Windows runners.
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(want)) {
		t.Fatalf("secret JSON shape mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestSecretSummariesNeverCarrySecretMaterial(t *testing.T) {
	const synthetic = "synthetic-secret-value-do-not-print"
	for _, value := range []any{ServiceSecret{}, RegistryCredentialSummary{}} {
		typ := reflect.TypeOf(value)
		for i := 0; i < typ.NumField(); i++ {
			switch typ.Field(i).Name {
			case "Value", "Secret", "Password", "Token", "Credential":
				t.Fatalf("%s exposes secret-bearing field %s", typ.Name(), typ.Field(i).Name)
			}
		}
	}

	item := sbxServiceItem(ServiceSecret{
		Service: "github", Scope: SecretScopeGlobal, CreatedAt: time.Unix(1, 0).UTC(),
		SourceKind: SecretSourceKindValue, SecretType: "api_key", Origin: SecretOriginLocal,
	})
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), synthetic) {
		t.Fatalf("secret item exposed a secret value: %s", encoded)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"value", "password", "token", "secret_value", "reference", "command"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("secret item contains forbidden field %q: %s", forbidden, encoded)
		}
	}
}
