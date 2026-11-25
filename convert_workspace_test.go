package sandboxes

import (
	"testing"

	localv1 "github.com/gyrel/sandboxes-api/gen/go/sandboxes/local/v1"
)

func TestWorkspaceGuestPathProtoMapping(t *testing.T) {
	gotProto := toProtoWorkspaces([]Workspace{
		{Path: "/host/repo", ReadOnly: true, GuestPath: "/workspace/source"},
		{Path: "/host/cache", GuestPath: "/var/cache/app"},
		{Path: "/host/legacy"},
	})
	wantProto := []*localv1.Workspace{
		{Path: "/host/repo", ReadOnly: true, GuestPath: "/workspace/source"},
		{Path: "/host/cache", GuestPath: "/var/cache/app"},
		{Path: "/host/legacy"},
	}
	if len(gotProto) != len(wantProto) {
		t.Fatalf("encoded workspaces = %d, want %d", len(gotProto), len(wantProto))
	}
	for i := range wantProto {
		if gotProto[i].GetPath() != wantProto[i].GetPath() ||
			gotProto[i].GetReadOnly() != wantProto[i].GetReadOnly() ||
			gotProto[i].GetGuestPath() != wantProto[i].GetGuestPath() {
			t.Errorf("encoded workspace[%d] = %+v, want %+v", i, gotProto[i], wantProto[i])
		}
	}

	gotSDK := fromProtoWorkspaces(append(gotProto, nil))
	wantSDK := []Workspace{
		{Path: "/host/repo", ReadOnly: true, GuestPath: "/workspace/source"},
		{Path: "/host/cache", GuestPath: "/var/cache/app"},
		{Path: "/host/legacy"},
	}
	if len(gotSDK) != len(wantSDK) {
		t.Fatalf("decoded workspaces = %d, want %d", len(gotSDK), len(wantSDK))
	}
	for i := range wantSDK {
		if gotSDK[i] != wantSDK[i] {
			t.Errorf("decoded workspace[%d] = %+v, want %+v", i, gotSDK[i], wantSDK[i])
		}
	}
}
