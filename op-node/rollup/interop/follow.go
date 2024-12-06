package interop

import (
	"context"

	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum-optimism/optimism/op-node/rollup/event"
	"github.com/ethereum-optimism/optimism/op-service/sources"
)

// FollowMode makes the op-node follow the canonical chain based on a read-only supervisor endpoint.
type FollowMode struct {
	log log.Logger

	emitter event.Emitter

	cl *sources.SupervisorClient
}

var _ SubSystem = (*FollowMode)(nil)

func (s *FollowMode) AttachEmitter(em event.Emitter) {
	s.emitter = em
}

func (s *FollowMode) OnEvent(ev event.Event) bool {
	// TODO: hook up to existing interop deriver
	return false
}

func (s *FollowMode) Start(ctx context.Context) error {
	s.log.Info("Interop sub-system started in follow-mode")
	return nil
}

func (s *FollowMode) Stop(ctx context.Context) error {
	// TODO toggle closing state

	s.log.Info("Interop sub-system stopped")
	return s.cl.Stop(ctx)
}
