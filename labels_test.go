package sandboxes

import (
	"context"
	"net"
	"testing"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type labelSandboxServer struct {
	localv1.UnimplementedSandboxServiceServer
	request chan *localv1.CreateRequest
}

func (s labelSandboxServer) Create(_ context.Context, req *localv1.CreateRequest) (*localv1.CreateResponse, error) {
	s.request <- req
	return &localv1.CreateResponse{Operation: &localv1.Operation{Id: "op-labels", SandboxId: "sb-labels"}}, nil
}

func (s labelSandboxServer) Get(_ context.Context, req *localv1.GetRequest) (*localv1.GetResponse, error) {
	var labels map[string]string
	if req.GetId() == "sb-labels" {
		labels = map[string]string{"team": "platform", "env": "dev"}
	}
	return &localv1.GetResponse{Sandbox: &localv1.Sandbox{Id: req.GetId(), Labels: labels}}, nil
}

func (s labelSandboxServer) List(context.Context, *localv1.ListRequest) (*localv1.ListResponse, error) {
	return &localv1.ListResponse{Items: []*localv1.Sandbox{
		{Id: "sb-labels", Labels: map[string]string{"team": "platform"}},
		{Id: "sb-unset"},
	}}, nil
}

func newLabelTestClient(t *testing.T) (Client, chan *localv1.CreateRequest) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	capture := labelSandboxServer{request: make(chan *localv1.CreateRequest, 1)}
	localv1.RegisterSandboxServiceServer(server, capture)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	client, err := New(Config{Address: "bufnet", Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
		return listener.DialContext(ctx)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, capture.request
}

func TestLabelsCreatePassthroughAndReadRoundTrip(t *testing.T) {
	client, requests := newLabelTestClient(t)
	labels := map[string]string{"team": "platform", "env": "dev"}
	if _, err := client.Sandboxes().Create(context.Background(), CreateRequest{
		Name: "dev", Labels: labels,
	}); err != nil {
		t.Fatal(err)
	}
	request := <-requests
	if len(request.GetLabels()) != 2 || request.GetLabels()["team"] != "platform" || request.GetLabels()["env"] != "dev" {
		t.Fatalf("labels were not passed to the daemon: %+v", request.GetLabels())
	}

	sandbox, err := client.Sandboxes().Get(context.Background(), "sb-labels")
	if err != nil {
		t.Fatal(err)
	}
	if len(sandbox.Labels) != 2 || sandbox.Labels["team"] != "platform" || sandbox.Labels["env"] != "dev" {
		t.Fatalf("labels were not read from the daemon: %+v", sandbox.Labels)
	}

	unset, err := client.Sandboxes().Get(context.Background(), "sb-unset")
	if err != nil {
		t.Fatal(err)
	}
	if unset.Labels != nil {
		t.Fatalf("unset labels must stay nil: %+v", unset.Labels)
	}

	page, err := client.Sandboxes().List(context.Background(), ListOptions{PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].Labels["team"] != "platform" || page.Items[1].Labels != nil {
		t.Fatalf("list labels mismatch: %+v", page.Items)
	}
}
