package buildinfo

import "testing"

func TestAWG3RuntimeCannotBeEnabledByEnvironment(t *testing.T) {
	previous := AWG3Runtime
	AWG3Runtime = "false"
	t.Cleanup(func() { AWG3Runtime = previous })
	t.Setenv("AWG3_RUNTIME", "true")
	if AWG3RuntimeEnabled() {
		t.Fatal("environment variable enabled AWG3 without compiled runtime support")
	}
}
