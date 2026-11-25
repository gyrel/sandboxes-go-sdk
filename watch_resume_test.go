package sandboxes

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
)

type resumeWatchServer struct {
	localv1.UnimplementedSandboxServiceServer

	mu    sync.Mutex
	after []int64
	calls int
	fails map[int]bool // Watch call numbers that fail before sending
}

func (s *resumeWatchServer) Watch(req *localv1.WatchRequest, stream grpc.ServerStreamingServer[localv1.WatchResponse]) error {
	s.mu.Lock()
	s.calls++
	s.after = append(s.after, req.GetAfterRevision())
	call := s.calls
	fail := s.fails[call]
	s.mu.Unlock()
	if fail {
		return status.Error(codes.Unavailable, "synthetic dial failure")
	}
	if call == 1 {
		if err := stream.Send(&localv1.WatchResponse{Type: "sandbox", Revision: 1}); err != nil {
			return err
		}
		if err := stream.Send(&localv1.WatchResponse{Type: "sandbox", Revision: 2}); err != nil {
			return err
		}
		return status.Error(codes.Unavailable, "synthetic drop")
	}
	if err := stream.Send(&localv1.WatchResponse{Type: "sandbox", Revision: 3}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

func (s *resumeWatchServer) resumePoints() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.after...)
}

func newResumeTestClient(t *testing.T, server *resumeWatchServer) Client {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	localv1.RegisterSandboxServiceServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)
	client, err := New(Config{Address: "bufnet", Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestWatchResilientResumesAfterDrop(t *testing.T) {
	server := &resumeWatchServer{}
	client := newResumeTestClient(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := WatchResilient(ctx, client, WatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	for want := int64(1); want <= 3; want++ {
		event, recvErr := stream.Recv()
		if recvErr != nil {
			t.Fatalf("recv %d: %v", want, recvErr)
		}
		if event.Revision != want {
			t.Fatalf("revision=%d want %d", event.Revision, want)
		}
	}
	// Second dial must resume strictly after the last delivered revision.
	points := server.resumePoints()
	if len(points) < 2 || points[1] != 2 {
		t.Fatalf("resume points=%v, want second call after=2", points)
	}
}

func TestWatchResilientRetriesFailedRedials(t *testing.T) {
	// Call 1 delivers rev1+rev2 then drops; call 2 (the first redial) fails;
	// call 3 resumes and delivers rev3.
	server := &resumeWatchServer{fails: map[int]bool{2: true}}
	client := newResumeTestClient(t, server)
	stream, err := WatchResilient(context.Background(), client, WatchOptions{})
	if err != nil {
		t.Fatalf("first dial must succeed: %v", err)
	}
	defer func() { _ = stream.Close() }()
	for want := int64(1); want <= 3; want++ {
		event, recvErr := stream.Recv()
		if recvErr != nil {
			t.Fatalf("recv %d: %v", want, recvErr)
		}
		if event.Revision != want {
			t.Fatalf("revision=%d want %d", event.Revision, want)
		}
	}
	points := server.resumePoints()
	if len(points) != 3 || points[2] != 2 {
		t.Fatalf("resume after failed redial: %v", points)
	}
}

func TestWatchResilientCloseStopsStream(t *testing.T) {
	server := &resumeWatchServer{}
	client := newResumeTestClient(t, server)
	stream, err := WatchResilient(context.Background(), client, WatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("second Close must be idempotent: %v", err)
	}
	if _, err := stream.Recv(); !errors.Is(err, errWatchClosed) {
		t.Fatalf("recv after close=%v want closed sentinel", err)
	}
}
