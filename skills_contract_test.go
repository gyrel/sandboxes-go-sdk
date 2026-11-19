package sandboxes

import (
	"context"
	"errors"
	"net"
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

func TestSkillsContractMapping(t *testing.T) {
	for _, original := range []*SkillsOptions{{Mode: SkillsOff}, {Mode: SkillsReadOnly, StorePath: "/host/skills"}, {Mode: SkillsReadWrite, StorePath: "/host/skills"}} {
		if err := validateSkillsOptions(original); err != nil {
			t.Fatal(err)
		}
		mapped := fromProtoSkills(toProtoSkills(original))
		if *mapped != *original {
			t.Fatalf("got %+v, want %+v", mapped, original)
		}
	}
	for _, invalid := range []*SkillsOptions{{}, {Mode: SkillsOff, StorePath: "/bad"}, {Mode: SkillsReadOnly}, {Mode: "other", StorePath: "/bad"}} {
		if err := validateSkillsOptions(invalid); err == nil {
			t.Fatalf("accepted invalid options: %+v", invalid)
		}
	}
	if _, err := fromProtoSandbox(&localv1.Sandbox{Skills: &localv1.SkillsOptions{Mode: localv1.SkillsMode(999)}}); err == nil {
		t.Fatal("accepted unknown daemon mode")
	}
}

func TestCreateSkillsRequiresSupportedDaemon(t *testing.T) {
	for _, version := range []string{"0.0.27", skillsMinimumAPIVersion} {
		t.Run(version, func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			server := grpc.NewServer()
			capture := captureCreateServer{request: make(chan *localv1.CreateRequest, 1), apiVersion: version}
			localv1.RegisterSandboxServiceServer(server, capture)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)
			client, err := New(Config{Address: "bufnet", Dialer: func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			_, err = client.Sandboxes().Create(context.Background(), CreateRequest{Skills: &SkillsOptions{Mode: SkillsReadOnly, StorePath: "/host/skills"}})
			if version == "0.0.27" {
				var sdkErr *Error
				if !errors.As(err, &sdkErr) || sdkErr.Code != errorCodeUnsupported {
					t.Fatalf("expected unsupported: %v", err)
				}
				select {
				case <-capture.request:
					t.Fatal("old daemon received unsupported create")
				default:
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			req := <-capture.request
			if req.GetSkills().GetMode() != localv1.SkillsMode_SKILLS_MODE_READONLY || req.GetSkills().GetStorePath() != "/host/skills" {
				t.Fatalf("wrong options: %+v", req.GetSkills())
			}
		})
	}
}
