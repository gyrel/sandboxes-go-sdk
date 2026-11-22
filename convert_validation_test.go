package sandboxes

import (
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

func TestSandboxConversionRejectsInvalidNetworkFields(t *testing.T) {
	for name, input := range map[string]*localv1.Sandbox{
		"host port":  {Ports: []*localv1.Port{{Host: 65536}}},
		"guest port": {Ports: []*localv1.Port{{Guest: 65536}}},
		"allow rule": {Allow: []*localv1.NetworkRule{{Port: 65536}}},
		"deny rule":  {Deny: []*localv1.NetworkRule{{Port: 65536}}},
		"nil rule":   {Deny: []*localv1.NetworkRule{nil}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fromProtoSandbox(input); err == nil {
				t.Fatal("invalid daemon response accepted")
			}
		})
	}
	valid := &localv1.Sandbox{Ports: []*localv1.Port{{Host: 65535, Guest: 443, HostIp: "::1"}}, Deny: []*localv1.NetworkRule{{Port: 65535}}}
	sb, err := fromProtoSandbox(valid)
	if err != nil {
		t.Fatalf("valid daemon response rejected: %v", err)
	}
	if len(sb.Ports) != 1 || sb.Ports[0].HostIP != "::1" {
		t.Fatalf("ports=%+v", sb.Ports)
	}
	proto := toProtoPorts(sb.Ports)
	if len(proto) != 1 || proto[0].GetHostIp() != "::1" {
		t.Fatalf("proto ports=%+v", proto)
	}
}

func TestOperationProgressMapping(t *testing.T) {
	if op := fromProtoOperation(&localv1.Operation{Id: "op1"}); op.Progress != nil {
		t.Fatalf("absent progress must map to nil: %+v", op.Progress)
	}
	op := fromProtoOperation(&localv1.Operation{
		Id:        "op1",
		SandboxId: "sb1",
		State:     localv1.OperationState_OPERATION_STATE_RUNNING,
		Progress:  &localv1.Progress{Phase: "pulling", Completed: 3, Total: 7},
	})
	if op.Progress == nil || op.Progress.Phase != "pulling" || op.Progress.Completed != 3 || op.Progress.Total != 7 {
		t.Fatalf("progress mapping=%+v", op.Progress)
	}
}

func TestNetworkRuleHTTPConditionsRoundTrip(t *testing.T) {
	rules := []NetworkRule{
		{Protocol: "tcp", Domain: "api.example.com",
			Methods: []string{"GET", "ANY"}, Path: "/v1/**",
			Query: []QueryCondition{{Name: "trace", Value: "*"}}},
		{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443},
	}
	proto := toProtoRules(rules)
	if len(proto) != 2 {
		t.Fatalf("proto rules=%d", len(proto))
	}
	if got := proto[0].GetPath(); got != "/v1/**" || len(proto[0].GetMethods()) != 2 {
		t.Fatalf("toProtoRules lost HTTP conditions: %+v", proto[0])
	}
	if proto[0].GetQuery()[0].GetName() != "trace" || proto[0].GetQuery()[0].GetValue() != "*" {
		t.Fatalf("query condition lost: %+v", proto[0].GetQuery())
	}
	if proto[1].GetPath() != "" || len(proto[1].GetMethods()) != 0 || proto[1].GetQuery() != nil {
		t.Fatalf("unconditioned rule gained HTTP fields: %+v", proto[1])
	}
	back := fromProtoRules(proto)
	if len(back) != 2 || back[0].Path != "/v1/**" || len(back[0].Methods) != 2 ||
		back[0].Query[0] != (QueryCondition{Name: "trace", Value: "*"}) {
		t.Fatalf("round trip mismatch: %+v", back)
	}
	if len(back[1].Methods) != 0 || back[1].Path != "" || len(back[1].Query) != 0 {
		t.Fatalf("unconditioned rule must stay empty: %+v", back[1])
	}
	// Degraded daemons (pre 0.0.31) return rules without HTTP fields: the
	// client must see zero conditions, not fabricate them.
	old := fromProtoRules([]*localv1.NetworkRule{{Protocol: "tcp", Domain: "x.example.com"}})
	if len(old) != 1 || len(old[0].Methods) != 0 || old[0].Path != "" || len(old[0].Query) != 0 {
		t.Fatalf("old daemon degradation mismatch: %+v", old)
	}
}
