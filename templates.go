package sandboxes

import (
	"context"
	"strings"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

// Template is one recorded local template image (ADR-0008). Field values
// are display metadata and never carry secret material.
type Template struct {
	Name        string
	Digest      string
	SizeBytes   int64
	CreatedUnix int64
	BaseImage   string
	Flavor      string
	Layers      int
}

// TemplateSaveResult carries the recorded template plus the daemon notice
// (guest-resident secret warning) and the optional export path.
type TemplateSaveResult struct {
	Template   Template
	OutputPath string
	Notice     string
}

// TemplateInspectResult adds the reconstructed boot document (presence-only
// environment names, working directory and user) to the template record.
type TemplateInspectResult struct {
	Template   Template
	EnvNames   []string
	WorkingDir string
	User       string
}

// TemplateService manages local template images (save/load/remove/list/inspect).
// Daemons below contract 0.0.33 do not implement the service; calls map to the
// standard unsupported/invalid-argument error families.
type TemplateService interface {
	Save(ctx context.Context, sandboxID, tag, outputPath string) (TemplateSaveResult, error)
	Load(ctx context.Context, tarPath, name string) (Template, error)
	Remove(ctx context.Context, name string, force bool) (bool, error)
	List(ctx context.Context) ([]Template, error)
	Inspect(ctx context.Context, name string) (TemplateInspectResult, error)
	// Export writes a docker-save archive of a recorded template to
	// tarPath and reports its size. Existing files are refused.
	Export(ctx context.Context, name, tarPath string) (int64, error)
}

// TemplateServiceProvider is implemented by clients that expose templates.
type TemplateServiceProvider interface {
	TemplateService() TemplateService
}

// Templates returns the optional template client; unsupported fallback keeps
// callers compiling against older transports.
func Templates(c Client) TemplateService {
	if provider, ok := c.(TemplateServiceProvider); ok {
		if service := provider.TemplateService(); service != nil {
			return service
		}
	}
	return unsupportedTemplateService{}
}

const unsupportedTemplatesMessage = "template service is not supported by this client"

type unsupportedTemplateService struct{}

func (unsupportedTemplateService) Save(context.Context, string, string, string) (TemplateSaveResult, error) {
	return TemplateSaveResult{}, &Error{Code: errorCodeUnsupported, Message: unsupportedTemplatesMessage}
}

func (unsupportedTemplateService) Load(context.Context, string, string) (Template, error) {
	return Template{}, &Error{Code: errorCodeUnsupported, Message: unsupportedTemplatesMessage}
}

func (unsupportedTemplateService) Remove(context.Context, string, bool) (bool, error) {
	return false, &Error{Code: errorCodeUnsupported, Message: unsupportedTemplatesMessage}
}

func (unsupportedTemplateService) List(context.Context) ([]Template, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: unsupportedTemplatesMessage}
}

func (unsupportedTemplateService) Inspect(context.Context, string) (TemplateInspectResult, error) {
	return TemplateInspectResult{}, &Error{Code: errorCodeUnsupported, Message: unsupportedTemplatesMessage}
}

func (unsupportedTemplateService) Export(context.Context, string, string) (int64, error) {
	return 0, &Error{Code: errorCodeUnsupported, Message: unsupportedTemplatesMessage}
}

func (c *client) TemplateService() TemplateService { return templateClient{c: c} }

type templateClient struct{ c *client }

func (t templateClient) Save(ctx context.Context, sandboxID, tag, outputPath string) (TemplateSaveResult, error) {
	ctx, cancel := t.c.context(ctx)
	defer cancel()
	resp, err := t.c.templates.Save(ctx, &localv1.TemplateServiceSaveRequest{
		SandboxId: sandboxID, Tag: tag, OutputPath: outputPath,
	})
	if err != nil {
		return TemplateSaveResult{}, mapError(err)
	}
	return TemplateSaveResult{
		Template:   fromProtoTemplate(resp.GetTemplate()),
		OutputPath: resp.GetOutputPath(),
		Notice:     resp.GetNotice(),
	}, nil
}

func (t templateClient) Load(ctx context.Context, tarPath, name string) (Template, error) {
	ctx, cancel := t.c.context(ctx)
	defer cancel()
	resp, err := t.c.templates.Load(ctx, &localv1.TemplateServiceLoadRequest{TarPath: tarPath, Name: name})
	if err != nil {
		return Template{}, mapError(err)
	}
	return fromProtoTemplate(resp.GetTemplate()), nil
}

func (t templateClient) Remove(ctx context.Context, name string, force bool) (bool, error) {
	ctx, cancel := t.c.context(ctx)
	defer cancel()
	_, err := t.c.templates.Remove(ctx, &localv1.TemplateServiceRemoveRequest{Name: name, Force: force})
	if err != nil {
		return false, mapError(err)
	}
	return true, nil
}

func (t templateClient) List(ctx context.Context) ([]Template, error) {
	ctx, cancel := t.c.context(ctx)
	defer cancel()
	resp, err := t.c.templates.List(ctx, &localv1.TemplateServiceListRequest{})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]Template, 0, len(resp.GetTemplates()))
	for _, t := range resp.GetTemplates() {
		out = append(out, fromProtoTemplate(t))
	}
	return out, nil
}

func (t templateClient) Inspect(ctx context.Context, name string) (TemplateInspectResult, error) {
	ctx, cancel := t.c.context(ctx)
	defer cancel()
	resp, err := t.c.templates.Inspect(ctx, &localv1.TemplateServiceInspectRequest{Name: name})
	if err != nil {
		return TemplateInspectResult{}, mapError(err)
	}
	envNames := make([]string, 0, len(resp.GetEnvNames()))
	for _, e := range resp.GetEnvNames() {
		envNames = append(envNames, strings.Clone(e))
	}
	return TemplateInspectResult{
		Template:   fromProtoTemplate(resp.GetTemplate()),
		EnvNames:   envNames,
		WorkingDir: resp.GetWorkingDir(),
		User:       resp.GetUser(),
	}, nil
}

func fromProtoTemplate(t *localv1.Template) Template {
	if t == nil {
		return Template{}
	}
	return Template{
		Name: t.GetName(), Digest: t.GetDigest(), SizeBytes: t.GetSizeBytes(),
		CreatedUnix: t.GetCreatedUnix(), BaseImage: t.GetBaseImage(),
		Flavor: t.GetFlavor(), Layers: int(t.GetLayers()),
	}
}

func (t templateClient) Export(ctx context.Context, name, tarPath string) (int64, error) {
	ctx, cancel := t.c.context(ctx)
	defer cancel()
	resp, err := t.c.templates.Export(ctx, &localv1.TemplateServiceExportRequest{Name: name, TarPath: tarPath})
	if err != nil {
		return 0, mapError(err)
	}
	return resp.GetSizeBytes(), nil
}
