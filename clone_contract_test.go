package sandboxes

import (
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

func TestCloneProtoMapping(t *testing.T) {
	guestWorkdir := "/workspace/project"
	gotRequest := toProtoClone(&CloneOptions{
		SourceWorkspacePath: "/host/project", GuestWorkdir: &guestWorkdir,
	})
	if gotRequest == nil || gotRequest.GetSourceWorkspacePath() != "/host/project" ||
		gotRequest.GuestWorkdir == nil || gotRequest.GetGuestWorkdir() != guestWorkdir {
		t.Fatalf("encoded clone options = %+v", gotRequest)
	}
	emptyGuestWorkdir := ""
	if got := toProtoClone(&CloneOptions{SourceWorkspacePath: "/host/project", GuestWorkdir: &emptyGuestWorkdir}); got == nil || got.GuestWorkdir == nil || got.GetGuestWorkdir() != "" {
		t.Fatalf("explicit empty guest workdir presence was lost: %+v", got)
	}
	if got := toProtoClone(&CloneOptions{SourceWorkspacePath: "/host/project"}); got.GuestWorkdir != nil {
		t.Fatalf("absent guest workdir encoded as present: %+v", got)
	}
	if toProtoClone(nil) != nil || fromProtoClone(nil) != nil {
		t.Fatal("nil clone messages must remain absent")
	}

	gotInfo := fromProtoClone(&localv1.CloneInfo{
		GuestWorkdir: "/workspace/project", RemoteName: "origin",
		GitEndpoint: &localv1.GitEndpoint{HostIp: "127.0.0.1", Port: 44121, Repository: "project.git"},
	})
	wantInfo := &CloneInfo{
		GuestWorkdir: "/workspace/project", RemoteName: "origin",
		GitEndpoint: &GitEndpoint{HostIP: "127.0.0.1", Port: 44121, Repository: "project.git"},
	}
	if gotInfo.GuestWorkdir != wantInfo.GuestWorkdir || gotInfo.RemoteName != wantInfo.RemoteName ||
		gotInfo.GitEndpoint == nil || *gotInfo.GitEndpoint != *wantInfo.GitEndpoint {
		t.Fatalf("decoded clone info = %+v, want %+v", gotInfo, wantInfo)
	}
	withoutEndpoint := fromProtoClone(&localv1.CloneInfo{GuestWorkdir: "/workspace/project", RemoteName: "origin"})
	if withoutEndpoint.GitEndpoint != nil {
		t.Fatalf("absent API GitEndpoint became present: %+v", withoutEndpoint.GitEndpoint)
	}
}
