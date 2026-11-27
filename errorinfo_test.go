package sandboxes

import (
	"context"
	"errors"
	"net"
	"testing"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type errorInfoSandboxServer struct {
	localv1.UnimplementedSandboxServiceServer
	err error
}

func (s errorInfoSandboxServer) Create(context.Context, *localv1.CreateRequest) (*localv1.CreateResponse, error) {
	return nil, s.err
}

func (s errorInfoSandboxServer) Stop(context.Context, *localv1.StopRequest) (*localv1.StopResponse, error) {
	return nil, s.err
}

func (s errorInfoSandboxServer) Delete(context.Context, *localv1.DeleteRequest) (*localv1.DeleteResponse, error) {
	return nil, s.err
}

func (s errorInfoSandboxServer) List(context.Context, *localv1.ListRequest) (*localv1.ListResponse, error) {
	return nil, s.err
}

func newErrorInfoTestClient(t *testing.T, err error) Client {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	localv1.RegisterSandboxServiceServer(server, errorInfoSandboxServer{err: err})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	client, dialErr := New(Config{Address: "bufnet", Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
		return listener.DialContext(ctx)
	}})
	if dialErr != nil {
		t.Fatal(dialErr)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func statusWithReason(t *testing.T, code codes.Code, message, reason string) error {
	t.Helper()
	st, err := status.New(code, message).WithDetails(&errdetails.ErrorInfo{
		Reason: reason, Domain: "sandboxes.local", Metadata: map[string]string{"label": "team"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

func TestErrorInfoMachineCodeWiresThroughSandboxOperations(t *testing.T) {
	client := newErrorInfoTestClient(t, statusWithReason(t, codes.InvalidArgument, "label key is invalid", "LABEL_INVALID"))
	for name, call := range map[string]func() error{
		"create": func() error {
			_, err := client.Sandboxes().Create(context.Background(), CreateRequest{Name: "dev"})
			return err
		},
		"stop": func() error {
			_, err := client.Sandboxes().Stop(context.Background(), "sb-1", StopOptions{})
			return err
		},
		"delete": func() error {
			_, err := client.Sandboxes().Delete(context.Background(), "sb-1", DeleteOptions{})
			return err
		},
		"list": func() error {
			_, err := client.Sandboxes().List(context.Background(), ListOptions{PageSize: 10})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			var typed *Error
			if !errors.As(err, &typed) {
				t.Fatalf("expected typed SDK error, got %T: %v", err, err)
			}
			if typed.Code != errorCodeInvalidArgument || typed.MachineCode != "LABEL_INVALID" || typed.Message != "label key is invalid" {
				t.Fatalf("unexpected typed error: %+v", typed)
			}
		})
	}
}

func TestErrorInfoMachineCodeIgnoredWithoutMatchingDetail(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "no details", err: status.Error(codes.InvalidArgument, "bad request")},
		{name: "lowercase reason", err: statusWithReason(t, codes.InvalidArgument, "bad request", "label_invalid")},
		{name: "short reason", err: statusWithReason(t, codes.InvalidArgument, "bad request", "LAB")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newErrorInfoTestClient(t, tt.err)
			_, err := client.Sandboxes().Create(context.Background(), CreateRequest{Name: "dev"})
			var typed *Error
			if !errors.As(err, &typed) {
				t.Fatalf("expected typed SDK error, got %T: %v", err, err)
			}
			if typed.Code != errorCodeInvalidArgument || typed.MachineCode != "" {
				t.Fatalf("unexpected typed error: %+v", typed)
			}
			if typed.Message != "bad request" {
				t.Fatalf("message changed: %q", typed.Message)
			}
		})
	}
}
