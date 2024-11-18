// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { GnosisSafe as Safe } from "safe-contracts/GnosisSafe.sol";
import { ISemver } from "src/universal/interfaces/ISemver.sol";
import { IDeputyGuardianModule } from "./IDeputyGuardianModule.sol";
import { ISuperchainConfig } from "src/L1/interfaces/ISuperchainConfig.sol";

interface IDeputyPauseModule is ISemver {
    error DeputyPauseModule_InvalidDeputy();
    error DeputyPauseModule_SignatureValidityTooShort();
    error DeputyPauseModule_SignatureValidityTooLong();
    error DeputyPauseModule_InvalidFoundationSafe();
    error DeputyPauseModule_InvalidDeputyGuardianModule();
    error DeputyPauseModule_InvalidSuperchainConfig();
    error DeputyPauseModule_ExecutionFailed(string);
    error DeputyPauseModule_SuperchainNotPaused();
    error DeputyPauseModule_SignatureExpired();
    error DeputyPauseModule_SignatureExpiryTooLong();
    error DeputyPauseModule_Unauthorized();
    error DeputyPauseModule_NonceAlreadyUsed();

    struct PauseMessage {
        uint256 expiry;
        bytes32 nonce;
    }

    struct DeputyAuthMessage {
        address deputy;
    }

    function version() external view returns (string memory);
    function __constructor__(
        Safe _foundationSafe,
        IDeputyGuardianModule _deputyGuardianModule,
        ISuperchainConfig _superchainConfig,
        uint256 _maxSignatureValiditySeconds,
        address _deputy,
        bytes memory _deputySignature
    )
        external;
    function foundationSafe() external view returns (Safe foundationSafe_);
    function deputyGuardianModule() external view returns (IDeputyGuardianModule deputyGuardianModule_);
    function superchainConfig() external view returns (ISuperchainConfig superchainConfig_);
    function deputy() external view returns (address deputy_);
    function maxSignatureValiditySeconds() external view returns (uint256 maxSignatureValiditySeconds_);
    function pauseMessageTypehash() external pure returns (bytes32 pauseMessageTypehash_);
    function deputyAuthMessageTypehash() external pure returns (bytes32 deputyAuthMessageTypehash_);
    function usedNonces(bytes32) external view returns (bool);
    function pause(uint256 _expiry, bytes32 _nonce, bytes memory _signature) external;
}
