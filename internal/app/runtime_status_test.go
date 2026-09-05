package app

import (
	"errors"
	"testing"
	"time"

	"github.com/astronaut808/awg-forge/internal/config"
)

func TestRecordWarpApplyResultClearsRecoveredError(t *testing.T) {
	previous := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	now := previous.Add(time.Minute)
	state := config.State{Warp: config.Warp{
		LastApplyAt:    previous,
		LastApplyError: "previous failure",
	}}

	recordWarpApplyResult(&state, now, nil)

	if state.Warp.LastApplyError != "" {
		t.Fatalf("LastApplyError = %q, want empty after successful reconciliation", state.Warp.LastApplyError)
	}
	if !state.Warp.LastApplyAt.Equal(now) {
		t.Fatalf("LastApplyAt = %v, want %v", state.Warp.LastApplyAt, now)
	}
	if !state.Warp.UpdatedAt.Equal(now) || !state.UpdatedAt.Equal(now) {
		t.Fatal("successful WARP reconciliation did not update timestamps")
	}
}

func TestRecordWarpApplyResultKeepsPreviousSuccessOnFailure(t *testing.T) {
	previous := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	now := previous.Add(time.Minute)
	state := config.State{Warp: config.Warp{LastApplyAt: previous}}

	recordWarpApplyResult(&state, now, errors.New("apply failed"))

	if state.Warp.LastApplyError != "apply failed" {
		t.Fatalf("LastApplyError = %q, want apply failure", state.Warp.LastApplyError)
	}
	if !state.Warp.LastApplyAt.Equal(previous) {
		t.Fatalf("LastApplyAt = %v, want previous successful apply %v", state.Warp.LastApplyAt, previous)
	}
}

func TestWarpRuntimeRequired(t *testing.T) {
	configured := config.State{Warp: config.Warp{
		PrivateKey:    "private",
		PeerPublicKey: "peer",
		Endpoint:      "warp.example:2408",
		AddressV4:     "172.16.0.2/32",
	}}
	if !warpRuntimeRequired(configured) {
		t.Fatal("configured WARP must be reconciled even without active routes")
	}

	requiredByTunnel := config.State{Tunnels: []config.Tunnel{{
		Enabled:    true,
		EgressMode: config.EgressWarp,
	}}}
	if !warpRuntimeRequired(requiredByTunnel) {
		t.Fatal("enabled WARP tunnel must require reconciliation")
	}
	if warpRuntimeRequired(config.State{}) {
		t.Fatal("empty state must not require WARP reconciliation")
	}
}
