package protocol

import (
	"strings"
	"testing"
)

func TestAWG3UsesStableMajorProfileID(t *testing.T) {
	profile, ok := ByID("awg_3")
	if !ok || profile.ID() != "awg_3" || profile.Version() != "3.x" {
		t.Fatalf("unexpected AWG 3 profile identity: profile=%#v ok=%t", profile, ok)
	}
	for _, obsoleteID := range []string{"awg_3_0", "awg_3_1", "awg_3_x"} {
		if _, ok := ByID(obsoleteID); ok {
			t.Fatalf("obsolete profile ID %q is still accepted", obsoleteID)
		}
	}
}

func TestAWG3DefaultsMatchPinnedRuntimeFormat(t *testing.T) {
	params, err := (AWG3{}).GenerateDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if err := (AWG3{}).Validate(params); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"Jmin":                   "10",
		"Jmax":                   "50",
		"S4":                     "12",
		"H1":                     "1",
		"H2":                     "2",
		"H3":                     "3",
		"H4":                     "4",
		"I1":                     defaultAWG3I1,
		"ContentPaddingAddition": "10-100",
		"RekeyAfterTime":         "100-120",
		"RekeyTimeout":           "3-7",
		"RejectAfterTime":        "150-180",
		"KeepaliveTimeout":       "5-15",
		"MaxHandshakeAttempts":   "15-20",
		"PersistentKeepalive":    "25-35",
		"RandomTrailers":         "off",
		"DisableCookies":         "off",
	} {
		if got := params[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	jc, err := awg3Uint16(params, "Jc")
	if err != nil || jc < 4 || jc > 6 {
		t.Fatalf("Jc = %q, want 4..6", params["Jc"])
	}
	for _, key := range []string{"I2", "I3", "I4", "I5"} {
		if params[key] != "" {
			t.Fatalf("%s = %q, want empty", key, params[key])
		}
	}
}

func TestAWG3DefaultsAvoidCollidingPacketSizes(t *testing.T) {
	for range 20 {
		params, err := (AWG3{}).GenerateDefaults()
		if err != nil {
			t.Fatal(err)
		}
		s1, _ := awg3Padding(params, "S1")
		s2, _ := awg3Padding(params, "S2")
		s3, _ := awg3Padding(params, "S3")
		s4, _ := awg3Padding(params, "S4")
		if awg3DefaultPacketSizesConflict(s1, s2, s3, s4) {
			t.Fatalf("generated colliding packet sizes: %#v", params)
		}
	}
}

func TestAWG3SecretsAndRangesAreValidated(t *testing.T) {
	p := AWG3{}
	params, err := p.GenerateDefaults()
	if err != nil {
		t.Fatal(err)
	}
	params["PersistentKeepalive"] = "35-25"
	if err := p.Validate(params); err == nil {
		t.Fatal("expected descending PersistentKeepalive range to be rejected")
	}
	params["PersistentKeepalive"] = "25-35"
	params["Jmin"] = "51"
	params["Jmax"] = "50"
	if err := p.Validate(params); err == nil {
		t.Fatal("expected descending J range to be rejected")
	}
	params["Jmin"] = "10"
	params["ContentPaddingAddition"] = "(off)"
	if err := p.Validate(params); err == nil {
		t.Fatal("expected non-numeric AWG3 range to be rejected")
	}
	secrets, err := p.GenerateSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateSecrets(secrets); err != nil {
		t.Fatal(err)
	}
	secrets.HeaderProtectionKey = "not-a-key"
	if err := p.ValidateSecrets(secrets); err == nil {
		t.Fatal("expected malformed HeaderProtectionKey to be rejected")
	}
}

func TestAWG3RejectsUint16Overflow(t *testing.T) {
	p := AWG3{}
	params, err := p.GenerateDefaults()
	if err != nil {
		t.Fatal(err)
	}
	params["PersistentKeepalive"] = "65536"
	if err := p.Validate(params); err == nil {
		t.Fatal("expected uint16 overflow to be rejected")
	}
}

func TestAWG3I1IsClientCompatibleSignature(t *testing.T) {
	if !strings.HasPrefix(defaultAWG3I1, "<r 2><b 0x8580") {
		t.Fatalf("unexpected AWG3 I1 default: %s", defaultAWG3I1)
	}
	if err := validateSignatureParam("I1", defaultAWG3I1); err != nil {
		t.Fatal(err)
	}
}

func TestAWG3BooleanParametersMatchPinnedToolsSyntax(t *testing.T) {
	profile := AWG3{}
	params, err := profile.GenerateDefaults()
	if err != nil {
		t.Fatal(err)
	}
	params["RandomTrailers"] = "ON"
	params["DisableCookies"] = "on"
	if err := profile.Validate(params); err != nil {
		t.Fatalf("upstream-compatible boolean values rejected: %v", err)
	}

	for _, value := range []string{"true", "1", "disabled", ""} {
		params["RandomTrailers"] = value
		if err := profile.Validate(params); err == nil {
			t.Fatalf("RandomTrailers = %q was accepted", value)
		}
	}
}
