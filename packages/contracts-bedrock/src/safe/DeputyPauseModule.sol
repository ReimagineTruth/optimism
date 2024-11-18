// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Safe
import { GnosisSafe as Safe } from "safe-contracts/GnosisSafe.sol";
import { Enum } from "safe-contracts/common/Enum.sol";

// Contracts
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";

// Libraries
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// Interfaces
import { ISemver } from "src/universal/interfaces/ISemver.sol";
import { IDeputyGuardianModule } from "src/safe/interfaces/IDeputyGuardianModule.sol";
import { ISuperchainConfig } from "src/L1/interfaces/ISuperchainConfig.sol";

/// @title DeputyPauseModule
/// @notice Safe Module designed to be installed in the Foundation Safe which allows a specific
///         deputy address to act as the Foundation Safe for the sake of triggering the
///         Superchain-wide pause functionality. Significantly simplifies the process of triggering
///         a Superchain-wide pause without changing the existing security model.
contract DeputyPauseModule is ISemver, EIP712 {
    /// @notice Error message for invalid deputy.
    error DeputyPauseModule_InvalidDeputy();

    /// @notice Error message for signature validity being too short.
    error DeputyPauseModule_SignatureValidityTooShort();

    /// @notice Error message for signature validity being too long.
    error DeputyPauseModule_SignatureValidityTooLong();

    /// @notice Error message for the Foundation Safe not being a Safe.
    error DeputyPauseModule_InvalidFoundationSafe();

    /// @notice Error message for the DeputyGuardianModule not being a DeputyGuardianModule.
    error DeputyPauseModule_InvalidDeputyGuardianModule();

    /// @notice Error message for the SuperchainConfig not being a SuperchainConfig.
    error DeputyPauseModule_InvalidSuperchainConfig();

    /// @notice Error message for unauthorized calls.
    error DeputyPauseModule_Unauthorized();

    /// @notice Error message for expired signatures.
    error DeputyPauseModule_SignatureExpired();

    /// @notice Error message for signature expiry being too long.
    error DeputyPauseModule_SignatureExpiryTooLong();

    /// @notice Error message for nonce reuse.
    error DeputyPauseModule_NonceAlreadyUsed();

    /// @notice Error message for failed transaction execution.
    error DeputyPauseModule_ExecutionFailed(string);

    /// @notice Error message for the SuperchainConfig not being paused.
    error DeputyPauseModule_SuperchainNotPaused();

    /// @notice Struct for the Pause action.
    /// @custom:field expiry Signature expiry timestamp.
    /// @custom:field nonce Signature nonce.
    struct PauseMessage {
        uint256 expiry;
        bytes32 nonce;
    }

    /// @notice Struct for the DeputyAuth action.
    /// @custom:field deputy Address of the deputy account.
    struct DeputyAuthMessage {
        address deputy;
    }

    /// @notice Foundation Safe.
    Safe internal immutable FOUNDATION_SAFE;

    /// @notice DeputyGuardianModule used by the Security Council Safe.
    IDeputyGuardianModule internal immutable DEPUTY_GUARDIAN_MODULE;

    /// @notice SuperchainConfig contract.
    ISuperchainConfig internal immutable SUPERCHAIN_CONFIG;

    /// @notice Address of the deputy account.
    address internal immutable DEPUTY;

    /// @notice Maximum signature validity in seconds.
    uint256 internal immutable MAX_SIGNATURE_VALIDITY_SECONDS;

    /// @notice Typehash for the Pause action.
    bytes32 internal constant PAUSE_MESSAGE_TYPEHASH = keccak256("PauseMessage(uint256 expiry,bytes32 nonce)");

    /// @notice Typehash for the DeputyAuth message.
    bytes32 internal constant DEPUTY_AUTH_MESSAGE_TYPEHASH = keccak256("DeputyAuthMessage(address deputy)");

    /// @notice Used nonces.
    mapping(bytes32 => bool) public usedNonces;

    /// @notice Semantic version.
    /// @custom:semver 1.0.0-beta.1
    string public constant version = "1.0.0-beta.1";

    /// @param _foundationSafe Address of the Foundation Safe.
    /// @param _deputyGuardianModule Address of the DeputyGuardianModule used by the SC Safe.
    /// @param _superchainConfig Address of the SuperchainConfig contract.
    /// @param _maxSignatureValiditySeconds Maximum signature validity in seconds.
    /// @param _deputy Address of the deputy account.
    /// @param _deputySignature Signature from the deputy verifying that the account is an EOA.
    constructor(
        Safe _foundationSafe,
        IDeputyGuardianModule _deputyGuardianModule,
        ISuperchainConfig _superchainConfig,
        uint256 _maxSignatureValiditySeconds,
        address _deputy,
        bytes memory _deputySignature
    )
        EIP712("DeputyPauseModule", "1")
    {
        // Check that the deputy is an EOA.
        // We do not support EIP-1271 signatures here.
        bytes32 digest =
            _hashTypedDataV4(keccak256(abi.encode(DEPUTY_AUTH_MESSAGE_TYPEHASH, DeputyAuthMessage(_deputy))));
        if (ECDSA.recover(digest, _deputySignature) != _deputy) {
            revert DeputyPauseModule_InvalidDeputy();
        }

        // Constant 1 day minimum validity. 1 day is a sane default and guarantees that the
        // signature validity will never be so short that it's effectively useless. We accept that
        // this slightly limits the configurability of this module, but it's not a module that's
        // meant to be deployed on arbitrary Safe contracts, only the Foundation Safe.
        if (_maxSignatureValiditySeconds < 1 days) {
            revert DeputyPauseModule_SignatureValidityTooShort();
        }

        // Constant 1 year maximum validity. 1 year is a sane default and guarantees that the
        // signature validity will never be excessively long. Same reasoning as above
        if (_maxSignatureValiditySeconds > 365 days) {
            revert DeputyPauseModule_SignatureValidityTooLong();
        }

        // Sanity check that the Foundation Safe is actually a Safe.
        // Prevents some accidental misconfigurations.
        try _foundationSafe.VERSION() returns (string memory) {
            // Actual response doesn't matter here.
        } catch {
            revert DeputyPauseModule_InvalidFoundationSafe();
        }

        // Sanity check that the DeputyGuardianModule is actually a DeputyGuardianModule.
        // Prevents some accidental misconfigurations.
        try _deputyGuardianModule.deputyGuardian() returns (address) {
            // Actual response doesn't matter here.
        } catch {
            revert DeputyPauseModule_InvalidDeputyGuardianModule();
        }

        // Sanity check that the SuperchainConfig is actually a SuperchainConfig.
        // Prevents some accidental misconfigurations.
        try _superchainConfig.guardian() returns (address) {
            // Actual response doesn't matter here.
        } catch {
            revert DeputyPauseModule_InvalidSuperchainConfig();
        }

        // Initialize the immutable variables.
        FOUNDATION_SAFE = _foundationSafe;
        DEPUTY_GUARDIAN_MODULE = _deputyGuardianModule;
        SUPERCHAIN_CONFIG = _superchainConfig;
        DEPUTY = _deputy;
        MAX_SIGNATURE_VALIDITY_SECONDS = _maxSignatureValiditySeconds;
    }

    /// @notice Getter function for the Foundation Safe address.
    /// @return foundationSafe_ Foundation Safe address.
    function foundationSafe() public view returns (Safe foundationSafe_) {
        foundationSafe_ = FOUNDATION_SAFE;
    }

    /// @notice Getter function for the DeputyGuardianModule address.
    /// @return deputyGuardianModule_ DeputyGuardianModule address.
    function deputyGuardianModule() public view returns (IDeputyGuardianModule deputyGuardianModule_) {
        deputyGuardianModule_ = DEPUTY_GUARDIAN_MODULE;
    }

    /// @notice Getter function for the SuperchainConfig address.
    /// @return superchainConfig_ SuperchainConfig address.
    function superchainConfig() public view returns (ISuperchainConfig superchainConfig_) {
        superchainConfig_ = SUPERCHAIN_CONFIG;
    }

    /// @notice Getter function for the deputy address.
    /// @return deputy_ Deputy address.
    function deputy() public view returns (address deputy_) {
        deputy_ = DEPUTY;
    }

    /// @notice Getter function for the maximum signature validity in seconds.
    /// @return maxSignatureValiditySeconds_ Maximum signature validity in seconds.
    function maxSignatureValiditySeconds() public view returns (uint256 maxSignatureValiditySeconds_) {
        maxSignatureValiditySeconds_ = MAX_SIGNATURE_VALIDITY_SECONDS;
    }

    /// @notice Getter function for the Pause message typehash.
    /// @return pauseMessageTypehash_ Pause message typehash.
    function pauseMessageTypehash() public pure returns (bytes32 pauseMessageTypehash_) {
        pauseMessageTypehash_ = PAUSE_MESSAGE_TYPEHASH;
    }

    /// @notice Getter function for the DeputyAuth message typehash.
    /// @return deputyAuthMessageTypehash_ DeputyAuth message typehash.
    function deputyAuthMessageTypehash() public pure returns (bytes32 deputyAuthMessageTypehash_) {
        deputyAuthMessageTypehash_ = DEPUTY_AUTH_MESSAGE_TYPEHASH;
    }

    /// @notice Calls the Foundation Safe's `execTransactionFromModuleReturnData()` function with
    ///         the arguments necessary to call `pause()` on the Security Council Safe, which will
    ///         then cause the Security Council Safe to trigger SuperchainConfig pause.
    ///         Front-running this function is completely safe, it'll pause either way.
    /// @param _expiry Signature expiry timestamp.
    /// @param _nonce Signature nonce.
    /// @param _signature ECDSA signature.
    function pause(uint256 _expiry, bytes32 _nonce, bytes memory _signature) external {
        // Check that the signature is not expired.
        if (_expiry <= block.timestamp) {
            revert DeputyPauseModule_SignatureExpired();
        }

        // Check that the signature expiry is not too far in the future.
        if (_expiry - block.timestamp > MAX_SIGNATURE_VALIDITY_SECONDS) {
            revert DeputyPauseModule_SignatureExpiryTooLong();
        }

        // Make sure the nonce hasn't been used yet.
        if (usedNonces[_nonce]) {
            revert DeputyPauseModule_NonceAlreadyUsed();
        }

        // Verify the signature.
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(PAUSE_MESSAGE_TYPEHASH, PauseMessage(_expiry, _nonce))));
        if (ECDSA.recover(digest, _signature) != DEPUTY) {
            revert DeputyPauseModule_Unauthorized();
        }

        // Mark the nonce as used.
        usedNonces[_nonce] = true;

        // Attempt to trigger the call.
        (bool success, bytes memory returnData) = FOUNDATION_SAFE.execTransactionFromModuleReturnData(
            address(DEPUTY_GUARDIAN_MODULE), 0, abi.encodeCall(IDeputyGuardianModule.pause, ()), Enum.Operation.Call
        );

        // If the call fails, revert.
        if (!success) {
            revert DeputyPauseModule_ExecutionFailed(string(returnData));
        }

        // Verify that the SuperchainConfig is now paused.
        if (!SUPERCHAIN_CONFIG.paused()) {
            revert DeputyPauseModule_SuperchainNotPaused();
        }
    }
}
