package sandboxes

import (
	"context"
	"errors"
	"net"
	"testing"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type templateFakeServer struct {
	localv1.UnimplementedTemplateServiceServer
	lastSave   *localv1.TemplateServiceSaveRequest
	lastLoad   *localv1.TemplateServiceLoadRequest
	lastRemove *localv1.TemplateServiceRemoveRequest
	lastExport *localv1.TemplateServiceExportRequest
}

func (s *templateFakeServer) Save(_ context.Context, req *localv1.TemplateServiceSaveRequest) (*localv1.TemplateServiceSaveResponse, error) {
	s.lastSave = req
	return &localv1.TemplateServiceSaveResponse{
		Template:   &localv1.Template{Name: "docker.io/library/mytpl:v1", Digest: "sha256:abc", SizeBytes: 4096, CreatedUnix: 1700000000, BaseImage: "alpine:3.22", Flavor: "codex", Layers: 18},
		OutputPath: req.GetOutputPath(),
		Notice:     "warning: guest-resident secrets",
	}, nil
}

func (s *templateFakeServer) Load(_ context.Context, req *localv1.TemplateServiceLoadRequest) (*localv1.TemplateServiceLoadResponse, error) {
	s.lastLoad = req
	return &localv1.TemplateServiceLoadResponse{
		Template: &localv1.Template{Name: "docker.io/library/loaded:latest", Layers: 12},
	}, nil
}

func (s *templateFakeServer) Remove(_ context.Context, req *localv1.TemplateServiceRemoveRequest) (*localv1.TemplateServiceRemoveResponse, error) {
	s.lastRemove = req
	return &localv1.TemplateServiceRemoveResponse{}, nil
}

func (s *templateFakeServer) List(context.Context, *localv1.TemplateServiceListRequest) (*localv1.TemplateServiceListResponse, error) {
	return &localv1.TemplateServiceListResponse{Templates: []*localv1.Template{
		{Name: "docker.io/library/a:v1"}, {Name: "docker.io/library/b:v2"},
	}}, nil
}

func (s *templateFakeServer) Inspect(context.Context, *localv1.TemplateServiceInspectRequest) (*localv1.TemplateServiceInspectResponse, error) {
	return &localv1.TemplateServiceInspectResponse{
		Template: &localv1.Template{Name: "docker.io/library/a:v1"},
		EnvNames: []string{"PATH", "CODEX_HOME"}, WorkingDir: "/workspace", User: "agent",
	}, nil
}

func (s *templateFakeServer) Export(_ context.Context, req *localv1.TemplateServiceExportRequest) (*localv1.TemplateServiceExportResponse, error) {
	s.lastExport = req
	return &localv1.TemplateServiceExportResponse{SizeBytes: 777}, nil
}

func newTemplateClient(t *testing.T) (Client, *templateFakeServer) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	fake := &templateFakeServer{}
	localv1.RegisterTemplateServiceServer(server, fake)
	localv1.RegisterSandboxServiceServer(server, &secretMetadataVersionServer{apiVersion: "0.0.33"})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	client, err := New(Config{Address: "bufnet", Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
		return listener.DialContext(ctx)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, fake
}

func TestTemplatesServiceRoundTrip(t *testing.T) {
	client, fake := newTemplateClient(t)
	svc := Templates(client)
	saved, err := svc.Save(context.Background(), "sb-1", "mytpl:v1", "/tmp/out.tar")
	if err != nil {
		t.Fatal(err)
	}
	if fake.lastSave.GetSandboxId() != "sb-1" || fake.lastSave.GetTag() != "mytpl:v1" || fake.lastSave.GetOutputPath() != "/tmp/out.tar" {
		t.Fatalf("save request=%+v", fake.lastSave)
	}
	if saved.Template.Name != "docker.io/library/mytpl:v1" || saved.Template.Layers != 18 || saved.Notice == "" || saved.OutputPath != "/tmp/out.tar" {
		t.Fatalf("saved=%+v", saved)
	}
	loaded, err := svc.Load(context.Background(), "/tmp/x.tar", "loaded")
	if err != nil || loaded.Name != "docker.io/library/loaded:latest" || fake.lastLoad.GetName() != "loaded" {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	ok, err := svc.Remove(context.Background(), "mytpl:v1", true)
	if err != nil || !ok || !fake.lastRemove.GetForce() {
		t.Fatalf("remove=%v err=%v req=%+v", ok, err, fake.lastRemove)
	}
	list, err := svc.List(context.Background())
	if err != nil || len(list) != 2 || list[1].Name != "docker.io/library/b:v2" {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	insp, err := svc.Inspect(context.Background(), "a:v1")
	if err != nil || len(insp.EnvNames) != 2 || insp.WorkingDir != "/workspace" || insp.User != "agent" {
		t.Fatalf("inspect=%+v err=%v", insp, err)
	}
}

func TestTemplatesExportPassthrough(t *testing.T) {
	client, fake := newTemplateClient(t)
	size, err := Templates(client).Export(context.Background(), "docker.io/library/mytpl:v1", "/tmp/out.tar")
	if err != nil {
		t.Fatal(err)
	}
	if size != 777 || fake.lastExport.GetName() != "docker.io/library/mytpl:v1" || fake.lastExport.GetTarPath() != "/tmp/out.tar" {
		t.Fatalf("size=%d req=%+v", size, fake.lastExport)
	}
}

func TestTemplatesUnsupportedFallback(t *testing.T) {
	svc := Templates(bareClient{})
	if _, err := svc.List(context.Background()); err == nil {
		t.Fatal("fallback must refuse")
	} else {
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Code != errorCodeUnsupported {
			t.Fatalf("err=%v", err)
		}
	}
	if _, err := Templates(bareClient{}).Save(context.Background(), "x", "y", ""); err == nil {
		t.Fatal("save fallback must refuse")
	}
	if _, err := Templates(bareClient{}).Export(context.Background(), "x", "/tmp/y"); err == nil {
		t.Fatal("export fallback must refuse")
	}
}

// bareClient implements Client without any optional service providers.
type bareClient struct{}

func (bareClient) Sandboxes() SandboxService                      { return nil }
func (bareClient) Operations() OperationService                   { return nil }
func (bareClient) RegistryCredentials() RegistryCredentialService { return nil }
func (bareClient) Close() error                                   { return nil }
