package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum-optimism/optimism/op-chain-ops/script"
	"github.com/ethereum-optimism/optimism/op-deployer/pkg/deployer"
	artifacts2 "github.com/ethereum-optimism/optimism/op-deployer/pkg/deployer/artifacts"
	"github.com/ethereum-optimism/optimism/op-deployer/pkg/deployer/broadcaster"
	"github.com/ethereum-optimism/optimism/op-deployer/pkg/deployer/opcm"
	"github.com/ethereum-optimism/optimism/op-deployer/pkg/deployer/standard"
	"github.com/ethereum-optimism/optimism/op-deployer/pkg/env"
	opcrypto "github.com/ethereum-optimism/optimism/op-service/crypto"
	"github.com/ethereum-optimism/optimism/op-service/ctxinterrupt"
	"github.com/ethereum-optimism/optimism/op-service/ioutil"
	"github.com/ethereum-optimism/optimism/op-service/jsonutil"
	oplog "github.com/ethereum-optimism/optimism/op-service/log"
	"github.com/ethereum-optimism/optimism/op-service/sources/batching"
	"github.com/ethereum-optimism/optimism/packages/contracts-bedrock/snapshots"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
)

type HoloceneConfig struct {
	L1RPCUrl         string
	PrivateKey       string
	Logger           log.Logger
	ArtifactsLocator *artifacts2.Locator

	privateKeyECDSA *ecdsa.PrivateKey

	AbsolutePrestate common.Hash
	SystemConfig     common.Address
}

func (c *HoloceneConfig) Check() error {
	if c.L1RPCUrl == "" {
		return fmt.Errorf("l1RPCUrl must be specified")
	}

	if c.PrivateKey == "" {
		return fmt.Errorf("private key must be specified")
	}

	privECDSA, err := crypto.HexToECDSA(strings.TrimPrefix(c.PrivateKey, "0x"))
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}
	c.privateKeyECDSA = privECDSA

	if c.Logger == nil {
		return fmt.Errorf("logger must be specified")
	}

	if c.ArtifactsLocator == nil {
		return fmt.Errorf("artifacts locator must be specified")
	}

	if c.SystemConfig == (common.Address{}) {
		return fmt.Errorf("system config must be specified")
	}

	if c.AbsolutePrestate == (common.Hash{}) {
		return fmt.Errorf("absolute prestate must be specified")
	}

	return nil
}

type DeployHoloceneOutput struct {
	MipsSingleton           common.Address
	FaultDisputeGame        common.Address
	PermissionedDisputeGame common.Address
}

func HoloceneCLI(cliCtx *cli.Context) error {
	logCfg := oplog.ReadCLIConfig(cliCtx)
	l := oplog.NewLogger(oplog.AppOut(cliCtx), logCfg)
	oplog.SetGlobalLogHandler(l.Handler())

	l1RPCUrl := cliCtx.String(deployer.L1RPCURLFlagName)
	privateKey := cliCtx.String(deployer.PrivateKeyFlagName)
	artifactsURLStr := cliCtx.String(ArtifactsLocatorFlagName)
	artifactsLocator := new(artifacts2.Locator)
	if err := artifactsLocator.UnmarshalText([]byte(artifactsURLStr)); err != nil {
		return fmt.Errorf("failed to parse artifacts URL: %w", err)
	}

	systemConfig := common.HexToAddress(cliCtx.String(SystemConfigFlagName))
	absolutePrestate := common.HexToHash(cliCtx.String(AbsolutePrestateFlagName))

	ctx := ctxinterrupt.WithCancelOnInterrupt(cliCtx.Context)

	return Holocene(ctx, HoloceneConfig{
		L1RPCUrl:         l1RPCUrl,
		PrivateKey:       privateKey,
		Logger:           l,
		ArtifactsLocator: artifactsLocator,
		SystemConfig:     systemConfig,
		AbsolutePrestate: absolutePrestate,
	})
}

func Holocene(ctx context.Context, cfg HoloceneConfig) error {
	if err := cfg.Check(); err != nil {
		return fmt.Errorf("invalid config for MIPS: %w", err)
	}

	lgr := cfg.Logger
	progressor := func(curr, total int64) {
		lgr.Info("artifacts download progress", "current", curr, "total", total)
	}

	artifactsFS, cleanup, err := artifacts2.Download(ctx, cfg.ArtifactsLocator, progressor)
	if err != nil {
		return fmt.Errorf("failed to download artifacts: %w", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			lgr.Warn("failed to clean up artifacts", "err", err)
		}
	}()

	l1Client, err := ethclient.Dial(cfg.L1RPCUrl)
	if err != nil {
		return fmt.Errorf("failed to connect to L1 RPC: %w", err)
	}

	chainID, err := l1Client.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %w", err)
	}

	signer := opcrypto.SignerFnFromBind(opcrypto.PrivateKeySignerFn(cfg.privateKeyECDSA, chainID))
	chainDeployer := crypto.PubkeyToAddress(cfg.privateKeyECDSA.PublicKey)

	bcaster, err := broadcaster.NewKeyedBroadcaster(broadcaster.KeyedBroadcasterOpts{
		Logger:  lgr,
		ChainID: chainID,
		Client:  l1Client,
		Signer:  signer,
		From:    chainDeployer,
	})
	if err != nil {
		return fmt.Errorf("failed to create broadcaster: %w", err)
	}

	nonce, err := l1Client.NonceAt(ctx, chainDeployer, nil)
	if err != nil {
		return fmt.Errorf("failed to get starting nonce: %w", err)
	}

	host, err := env.DefaultScriptHost(
		bcaster,
		lgr,
		chainDeployer,
		artifactsFS,
		nonce,
	)
	if err != nil {
		return fmt.Errorf("failed to create script host: %w", err)
	}

	var release string
	if cfg.ArtifactsLocator.IsTag() {
		release = cfg.ArtifactsLocator.Tag
	} else {
		release = "dev"
	}

	lgr.Info("preparing holocene upgrade", "release", release)

	sysCfgAbi := snapshots.LoadSystemConfigABI()
	result, err := callContract(ctx, l1Client, sysCfgAbi, cfg.SystemConfig, "disputeGameFactory")
	if err != nil {
		return fmt.Errorf("failed to load DisputeGameFactory address: %w", err)
	}

	dgfAddr := result.GetAddress(0)
	lgr.Info("found DisputeGameFactory", "addr", dgfAddr)

	result, err = callContract(ctx, l1Client, snapshots.LoadDisputeGameFactoryABI(), dgfAddr, "gameImpls", uint32(0))
	if err != nil {
		return fmt.Errorf("failed to load current FaultDisputeGame implementation addr: %w", err)
	}
	cannonGameImpl := result.GetAddress(0)
	lgr.Info("found FaultDisputeGame", "addr", cannonGameImpl)

	result, err = callContract(ctx, l1Client, snapshots.LoadDisputeGameFactoryABI(), dgfAddr, "gameImpls", uint32(1))
	if err != nil {
		return fmt.Errorf("failed to load current PermissionedDisputeGame implementation addr: %w", err)
	}
	permissionedGameImpl := result.GetAddress(0)
	lgr.Info("found PermissionedDisputeGame", "addr", permissionedGameImpl)

	dgfABI := snapshots.LoadFaultDisputeGameABI()
	result, err = callContract(ctx, l1Client, dgfABI, permissionedGameImpl, "vm")
	if err != nil {
		return fmt.Errorf("failed to load current MIPS implementation address: %w", err)
	}
	oldMIPS := result.GetAddress(0)
	lgr.Info("found existing MIPS", "addr", oldMIPS)

	result, err = callContract(ctx, l1Client, snapshots.LoadMIPSABI(), oldMIPS, "oracle")
	if err != nil {
		return fmt.Errorf("failed to load PreimageOracle address: %w", err)
	}
	oracleAddr := result.GetAddress(0)
	lgr.Info("found PreimageOracle", "addr", oracleAddr)

	lgr.Info("using absolute prestate", "hash", cfg.AbsolutePrestate)

	deployment := &DeployHoloceneOutput{}

	// First deploy the update MIPS contract
	mipsDeployment, err := opcm.DeployMIPS(
		host,
		opcm.DeployMIPSInput{
			MipsVersion:    1,
			PreimageOracle: oracleAddr,
		},
	)
	if err != nil {
		return fmt.Errorf("error deploying dispute game: %w", err)
	}

	if _, err := bcaster.Broadcast(ctx); err != nil {
		return fmt.Errorf("failed to broadcast: %w", err)
	}

	lgr.Info("deployed new mips", "addr", mipsDeployment.MipsSingleton)
	deployment.MipsSingleton = mipsDeployment.MipsSingleton

	// Populate required code in the local state
	addresses := []common.Address{
		mipsDeployment.MipsSingleton,
		oracleAddr,
	}
	for _, addr := range addresses {
		code, err := l1Client.CodeAt(ctx, addr, nil)
		if err != nil {
			return fmt.Errorf("failed to get code for %v: %w", addr, err)
		}
		host.ImportAccount(addr, types.Account{
			Code: code,
		})
	}

	// Next deploy new FaultDisputeGame if one was already present
	if cannonGameImpl != (common.Address{}) {
		cannonGameDeployment, err := deployDisputeGame(ctx, l1Client, dgfABI, cannonGameImpl, host, mipsDeployment.MipsSingleton, cfg.AbsolutePrestate)
		if err != nil {
			return err
		}
		deployment.FaultDisputeGame = cannonGameDeployment.DisputeGameImpl
	}

	// Deploy PermissionedDisputeGame
	gameDeployment, err := deployDisputeGame(ctx, l1Client, dgfABI, permissionedGameImpl, host, mipsDeployment.MipsSingleton, cfg.AbsolutePrestate)
	if err != nil {
		return err
	}
	deployment.PermissionedDisputeGame = gameDeployment.DisputeGameImpl

	// TODO: Deploy the updated SystemConfig?

	lgr.Info("deployment complete")
	if err := jsonutil.WriteJSON(deployment, ioutil.ToStdOut()); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}

func deployDisputeGame(ctx context.Context, l1Client *ethclient.Client, dgfABI *abi.ABI, gameImpl common.Address, host *script.Host, mips common.Address, absolutePrestate common.Hash) (opcm.DeployDisputeGameOutput, error) {
	caller := &contractCaller{
		l1Client: l1Client,
		abi:      dgfABI,
		addr:     gameImpl,
	}
	delayedWETHProxy, err := caller.getAddress(ctx, "weth")
	if err != nil {
		return opcm.DeployDisputeGameOutput{}, fmt.Errorf("failed to load DelayedWETH proxy for FaultDisputeGame at %v: %w", gameImpl, err)
	}
	anchorStateRegistryProxy, err := caller.getAddress(ctx, "anchorStateRegistry")
	if err != nil {
		return opcm.DeployDisputeGameOutput{}, fmt.Errorf("failed to load AnchorStateRegistry proxy for FaultDisputeGame at %v: %w", gameImpl, err)
	}
	l2ChainID, err := caller.getBigInt(ctx, "l2ChainId")
	if err != nil {
		return opcm.DeployDisputeGameOutput{}, fmt.Errorf("failed to load L2 chain ID for FaultDisputeGame at %v: %w", gameImpl, err)
	}
	gameDeployment, err := opcm.DeployDisputeGame(host, opcm.DeployDisputeGameInput{
		FpVm:                     mips,
		GameKind:                 "FaultDisputeGame",
		GameType:                 0,
		AbsolutePrestate:         absolutePrestate,
		MaxGameDepth:             standard.DisputeMaxGameDepth,
		SplitDepth:               standard.DisputeSplitDepth,
		ClockExtension:           standard.DisputeClockExtension,
		MaxClockDuration:         standard.DisputeMaxClockDuration,
		DelayedWethProxy:         delayedWETHProxy,
		AnchorStateRegistryProxy: anchorStateRegistryProxy,
		L2ChainId:                l2ChainID.Uint64(),
		Proposer:                 common.Address{},
		Challenger:               common.Address{},
	})
	if err != nil {
		return opcm.DeployDisputeGameOutput{}, fmt.Errorf("failed to deploy FaultDisputeGame: %w", err)
	}
	return gameDeployment, nil
}

type contractCaller struct {
	l1Client *ethclient.Client
	abi      *abi.ABI
	addr     common.Address
}

func (c *contractCaller) getAddress(ctx context.Context, method string, args ...interface{}) (common.Address, error) {
	result, err := callContract(ctx, c.l1Client, c.abi, c.addr, method, args...)
	if err != nil {
		return common.Address{}, err
	}
	return result.GetAddress(0), nil
}

func (c *contractCaller) getBigInt(ctx context.Context, method string, args ...interface{}) (*big.Int, error) {
	result, err := callContract(ctx, c.l1Client, c.abi, c.addr, method, args...)
	if err != nil {
		return nil, err
	}
	return result.GetBigInt(0), nil
}

func callContract(ctx context.Context, l1Client *ethclient.Client, contractAbi *abi.ABI, to common.Address, method string, args ...interface{}) (*batching.CallResult, error) {
	call := batching.NewContractCall(contractAbi, to, method, args...)
	calldata, err := call.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack %s call: %w", method, err)
	}
	response, err := l1Client.CallContract(ctx, ethereum.CallMsg{To: &to, Data: calldata}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to call method %v: %w", method, err)
	}
	return call.Unpack(response)
}
