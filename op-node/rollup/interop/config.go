package interop

import (
	"context"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum-optimism/optimism/op-service/client"
	"github.com/ethereum-optimism/optimism/op-service/rpc"
	"github.com/ethereum-optimism/optimism/op-service/sources"
)

type Config struct {
	// SupervisorAddr to follow for cross-chain safety updates.
	// Non-empty if running in follow-mode.
	// Cannot be set if RPCAddr is set.
	SupervisorAddr string

	// RPCAddr address to bind RPC server to, to serve external supervisor nodes.
	// Cannot be set if SupervisorAddr is set.
	RPCAddr string
	// RPCPort port to bind RPC server to, to serve external supervisor nodes.
	// Binds to any available port if set to 0.
	// Only applicable if RPCAddr is set.
	RPCPort int
	// RPCJwtSecretPath path of JWT secret file to apply authentication to the interop server address.
	RPCJwtSecretPath string
}

var _ SupervisorSetup = (*Config)(nil)

func (cfg *Config) Check() error {
	if (cfg.SupervisorAddr == "") != (cfg.RPCAddr == "") {
		return errors.New("must have either a supervisor RPC endpoint to follow, or interop RPC address to serve from")
	}
	return nil
}

func (cfg *Config) Setup(ctx context.Context, logger log.Logger) (SubSystem, error) {
	mngr := &InteropManager{}

	if cfg.RPCAddr != "" {
		logger.Info("Setting up Interop RPC server to serve supervisor sync work")
		// Load JWT secret, if any, generate one otherwise.
		jwtSecret, err := rpc.ObtainJWTSecret(logger, cfg.RPCJwtSecretPath, true)
		if err != nil {
			return nil, err
		}
		mngr.srv = rpc.NewServer(cfg.RPCAddr, cfg.RPCPort, "v0.0.0",
			rpc.WithWebsocketEnabled(), rpc.WithJWTSecret(jwtSecret[:]))
	} else {
		logger.Info("Setting up Interop RPC client to sync from read-only supervisor")
		cl, err := client.NewRPC(ctx, logger, cfg.SupervisorAddr, client.WithLazyDial())
		if err != nil {
			return nil, fmt.Errorf("failed to create supervisor RPC: %w", err)
		}
		mngr.cl = sources.NewSupervisorClient(cl)
	}

	return mngr, nil
}
