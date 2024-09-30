package backend

import (
	"context"
	"errors"
	"fmt"
	"github.com/ethereum-optimism/optimism/op-supervisor/supervisor/backend/db/entrydb"
	"io"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum-optimism/optimism/op-service/client"
	"github.com/ethereum-optimism/optimism/op-service/dial"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/sources"
	"github.com/ethereum-optimism/optimism/op-supervisor/config"
	"github.com/ethereum-optimism/optimism/op-supervisor/supervisor/backend/db"
	"github.com/ethereum-optimism/optimism/op-supervisor/supervisor/backend/db/logs"
	"github.com/ethereum-optimism/optimism/op-supervisor/supervisor/backend/source"
	"github.com/ethereum-optimism/optimism/op-supervisor/supervisor/frontend"
	"github.com/ethereum-optimism/optimism/op-supervisor/supervisor/types"
)

type SupervisorBackend struct {
	started atomic.Bool
	logger  log.Logger
	m       Metrics
	dataDir string

	chainProcessors map[types.ChainID]*source.ChainProcessor
	db              *db.ChainsDB
}

var _ frontend.Backend = (*SupervisorBackend)(nil)

var _ io.Closer = (*SupervisorBackend)(nil)

var errAlreadyStopped = errors.New("already stopped")

func NewSupervisorBackend(ctx context.Context, logger log.Logger, m Metrics, cfg *config.Config) (*SupervisorBackend, error) {
	// attempt to prepare the data directory
	if err := prepDataDir(cfg.Datadir); err != nil {
		return nil, err
	}

	// create the chains db
	db := db.NewChainsDB(map[types.ChainID]db.LogStorage{}, logger)

	// create an empty map of chain monitors
	chainProcessors := make(map[types.ChainID]*source.ChainProcessor, len(cfg.L2RPCs))

	// create the supervisor backend
	super := &SupervisorBackend{
		logger:          logger,
		m:               m,
		dataDir:         cfg.Datadir,
		chainProcessors: chainProcessors,
		db:              db,
	}

	// from the RPC strings, have the supervisor backend create a chain monitor
	// don't start the monitor yet, as we will start all monitors at once when Start is called
	for _, rpc := range cfg.L2RPCs {
		err := super.addFromRPC(ctx, logger, rpc, false)
		if err != nil {
			return nil, fmt.Errorf("failed to add chain monitor for rpc %v: %w", rpc, err)
		}
	}
	return super, nil
}

// addFromRPC adds a chain monitor to the supervisor backend from an rpc endpoint
// it does not expect to be called after the backend has been started
// it will start the monitor if shouldStart is true
func (su *SupervisorBackend) addFromRPC(ctx context.Context, logger log.Logger, rpc string, _ bool) error {
	// create the rpc client, which yields the chain id
	rpcClient, chainID, err := clientForL2(ctx, logger, rpc)
	if err != nil {
		return err
	}
	su.logger.Info("adding from rpc connection", "rpc", rpc, "chainID", chainID)
	// create metrics and a logdb for the chain
	cm := newChainMetrics(chainID, su.m)
	path, err := prepLogDBPath(chainID, su.dataDir)
	if err != nil {
		return fmt.Errorf("failed to create datadir for chain %v: %w", chainID, err)
	}
	logDB, err := logs.NewFromFile(logger, cm, path, true)
	if err != nil {
		return fmt.Errorf("failed to create logdb for chain %v at %v: %w", chainID, path, err)
	}
	if su.chainProcessors[chainID] != nil {
		return fmt.Errorf("chain monitor for chain %v already exists", chainID)
	}
	// create a client like the monitor would have
	cl, err := source.NewL1Client(
		ctx,
		logger,
		cm,
		rpc,
		rpcClient, 2*time.Second,
		false,
		sources.RPCKindStandard)
	if err != nil {
		return err
	}
	logProcessor := source.NewLogProcessor(chainID, su.db)
	chainProcessor := source.NewChainProcessor(logger, cl, chainID, logProcessor, su.db)
	su.chainProcessors[chainID] = chainProcessor
	su.db.AddLogDB(chainID, logDB)
	return nil
}

func clientForL2(ctx context.Context, logger log.Logger, rpc string) (client.RPC, types.ChainID, error) {
	ethClient, err := dial.DialEthClientWithTimeout(ctx, 10*time.Second, logger, rpc)
	if err != nil {
		return nil, types.ChainID{}, fmt.Errorf("failed to connect to rpc %v: %w", rpc, err)
	}
	chainID, err := ethClient.ChainID(ctx)
	if err != nil {
		return nil, types.ChainID{}, fmt.Errorf("failed to load chain id for rpc %v: %w", rpc, err)
	}
	return client.NewBaseRPCClient(ethClient.Client()), types.ChainIDFromBig(chainID), nil
}

func (su *SupervisorBackend) Start(ctx context.Context) error {
	// ensure we only start once
	if !su.started.CompareAndSwap(false, true) {
		return errors.New("already started")
	}
	// initiate "ResumeFromLastSealedBlock" on the chains db,
	// which rewinds the database to the last block that is guaranteed to have been fully recorded
	if err := su.db.ResumeFromLastSealedBlock(); err != nil {
		return fmt.Errorf("failed to resume chains db: %w", err)
	}
	return nil
}

func (su *SupervisorBackend) Stop(ctx context.Context) error {
	if !su.started.CompareAndSwap(true, false) {
		return errAlreadyStopped
	}
	// close all chain processors
	for _, processor := range su.chainProcessors {
		processor.Close()
	}
	// close the database
	return su.db.Close()
}

func (su *SupervisorBackend) Close() error {
	// TODO(protocol-quest#288): close logdb of all chains
	return nil
}

// AddL2RPC adds a new L2 chain to the supervisor backend
// it stops and restarts the backend to add the new chain
func (su *SupervisorBackend) AddL2RPC(ctx context.Context, rpc string) error {
	// start the monitor immediately, as the backend is assumed to already be running
	return su.addFromRPC(ctx, su.logger, rpc, true)
}

func (su *SupervisorBackend) CheckMessage(identifier types.Identifier, payloadHash common.Hash) (types.SafetyLevel, error) {
	chainID := identifier.ChainID
	blockNum := identifier.BlockNumber
	logIdx := identifier.LogIndex
	_, err := su.db.Check(chainID, blockNum, uint32(logIdx), payloadHash)
	if errors.Is(err, entrydb.ErrFuture) {
		return types.LocalUnsafe, nil
	}
	if errors.Is(err, entrydb.ErrConflict) {
		return types.Invalid, nil
	}
	if err != nil {
		return types.Invalid, fmt.Errorf("failed to check log: %w", err)
	}
	safest := su.db.Safest(chainID, blockNum, uint32(logIdx))
	return safest, nil
}

func (su *SupervisorBackend) CheckMessages(
	messages []types.Message,
	minSafety types.SafetyLevel) error {
	for _, msg := range messages {
		safety, err := su.CheckMessage(msg.Identifier, msg.PayloadHash)
		if err != nil {
			return fmt.Errorf("failed to check message: %w", err)
		}
		if !safety.AtLeastAsSafe(minSafety) {
			return fmt.Errorf("message %v (safety level: %v) does not meet the minimum safety %v",
				msg.Identifier,
				safety,
				minSafety)
		}
	}
	return nil
}

// CheckBlock checks if the block is safe according to the safety level
// The block is considered safe if all logs in the block are safe
// this is decided by finding the last log in the block and
func (su *SupervisorBackend) CheckBlock(chainID *hexutil.U256, blockHash common.Hash, blockNumber hexutil.Uint64) (types.SafetyLevel, error) {
	// find the last log index in the block
	id := eth.BlockID{Hash: blockHash, Number: uint64(blockNumber)}
	_, err := su.db.FindSealedBlock(types.ChainID(*chainID), id)
	if errors.Is(err, entrydb.ErrFuture) {
		return types.LocalUnsafe, nil
	}
	if errors.Is(err, entrydb.ErrConflict) {
		return types.Invalid, nil
	}
	if err != nil {
		su.logger.Error("failed to scan block", "err", err)
		return "", err
	}
	safest := su.db.Safest(types.ChainID(*chainID), uint64(blockNumber), 0)
	return safest, nil
}

func (su *SupervisorBackend) UpdateLocalUnsafe(chainID types.ChainID, head eth.BlockRef) {
	// l2 to l1 block ref
	ref := eth.BlockRef{
		ParentHash: head.ParentHash,
		Hash:       head.Hash,
		Number:     head.Number,
		Time:       head.Time,
	}
	ctx := context.Background()
	su.chainProcessors[chainID].OnNewHead(ctx, ref)
	su.db.UpdateLocalUnsafe(chainID, head)
}

func (su *SupervisorBackend) UpdateLocalSafe(chainID types.ChainID, derivedFrom eth.BlockRef, lastDerived eth.BlockRef) {
	su.db.UpdateLocalSafe(chainID, derivedFrom, lastDerived)
}

func (su *SupervisorBackend) UpdateFinalizedL1(chainID types.ChainID, finalized eth.BlockRef) {
	su.db.UpdateFinalizedL1(finalized)
}

func (su *SupervisorBackend) UnsafeView(ctx context.Context, chainID types.ChainID, unsafe types.ReferenceView) (types.ReferenceView, error) {
	u, xu, err := su.db.UnsafeView(chainID, unsafe)
	if err != nil {
		return types.ReferenceView{}, fmt.Errorf("failed to get unsafe view: %w", err)
	}
	return types.ReferenceView{
		Local: eth.BlockID{
			Hash:   u.LastSealedBlockHash,
			Number: u.LastSealedBlockNum,
		},
		Cross: eth.BlockID{
			Hash:   xu.LastSealedBlockHash,
			Number: xu.LastSealedBlockNum,
		},
	}, nil
}

func (su *SupervisorBackend) SafeView(ctx context.Context, chainID types.ChainID, safe types.ReferenceView) (types.ReferenceView, error) {
	s, xs, err := su.db.SafeView(chainID, safe)
	if err != nil {
		return types.ReferenceView{}, fmt.Errorf("failed to get safe view: %w", err)
	}
	return types.ReferenceView{
		Local: eth.BlockID{
			Hash:   s.LastSealedBlockHash,
			Number: s.LastSealedBlockNum,
		},
		Cross: eth.BlockID{
			Hash:   xs.LastSealedBlockHash,
			Number: xs.LastSealedBlockNum,
		},
	}, nil
}

func (su *SupervisorBackend) Finalized(ctx context.Context, chainID types.ChainID) (eth.BlockID, error) {
	return eth.BlockID{}, nil
}

func (su *SupervisorBackend) DerivedFrom(
	ctx context.Context,
	chainID types.ChainID,
	blockHash common.Hash,
	blockNumber uint64) (eth.BlockRef, error) {
	// TODO(#12358): attach to backend
	return eth.BlockRef{}, nil
}
