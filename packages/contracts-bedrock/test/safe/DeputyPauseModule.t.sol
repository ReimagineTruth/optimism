// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Testing
import { CommonTest } from "test/setup/CommonTest.sol";
import { GnosisSafe as Safe } from "safe-contracts/GnosisSafe.sol";
import "test/safe-tools/SafeTestTools.sol";

// Scripts
import { DeployUtils } from "scripts/libraries/DeployUtils.sol";

// Interfaces
import { IDeputyGuardianModule } from "src/safe/interfaces/IDeputyGuardianModule.sol";
import { IDeputyPauseModule } from "src/safe/interfaces/IDeputyPauseModule.sol";
import { ISuperchainConfig } from "src/L1/interfaces/ISuperchainConfig.sol";

/// @title DeputyPauseModule_TestInit
/// @notice Base test setup for the DeputyPauseModule.
contract DeputyPauseModule_TestInit is CommonTest, SafeTestTools {
    using SafeTestLib for SafeInstance;

    event ExecutionFromModuleSuccess(address indexed);

    IDeputyPauseModule deputyPauseModule;
    IDeputyGuardianModule deputyGuardianModule;
    SafeInstance securityCouncilSafeInstance;
    SafeInstance foundationSafeInstance;
    address deputy;
    uint256 deputyKey;
    bytes deputyAuthSignature;
    uint256 maxSignatureValiditySeconds;

    bytes32 constant SOME_VALID_NONCE = keccak256("some valid nonce");
    bytes32 constant PAUSE_MESSAGE_TYPEHASH = keccak256("PauseMessage(uint256 expiry,bytes32 nonce)");
    bytes32 constant DEPUTY_AUTH_MESSAGE_TYPEHASH = keccak256("DeputyAuthMessage(address deputy)");

    /// @notice Sets up the test environment.
    function setUp() public virtual override {
        super.setUp();

        // Set up 20 keys.
        (, uint256[] memory keys) = SafeTestLib.makeAddrsAndKeys("DeputyPauseModule_test_", 20);

        // Split into two sets of 10 keys.
        uint256[] memory keys1 = new uint256[](10);
        uint256[] memory keys2 = new uint256[](10);
        for (uint256 i; i < 10; i++) {
            keys1[i] = keys[i];
            keys2[i] = keys[i + 10];
        }

        // Create a Security Council Safe with 10 owners.
        securityCouncilSafeInstance = _setupSafe(keys1, 10);

        // Create a Foundation Safe with 10 different owners.
        foundationSafeInstance = _setupSafe(keys2, 10);

        // Set the Security Council Safe as the Guardian of the SuperchainConfig.
        vm.store(
            address(superchainConfig),
            superchainConfig.GUARDIAN_SLOT(),
            bytes32(uint256(uint160(address(securityCouncilSafeInstance.safe))))
        );

        // Create a DeputyGuardianModule and set the Foundation Safe as the Deputy Guardian.
        deputyGuardianModule = IDeputyGuardianModule(
            DeployUtils.create1({
                _name: "DeputyGuardianModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyGuardianModule.__constructor__,
                        (securityCouncilSafeInstance.safe, superchainConfig, address(foundationSafeInstance.safe))
                    )
                )
            })
        );

        // Enable the DeputyGuardianModule on the Security Council Safe.
        securityCouncilSafeInstance.enableModule(address(deputyGuardianModule));

        // Create the deputy for the DeputyPauseModule.
        (deputy, deputyKey) = makeAddrAndKey("deputy");

        // Set the maximum signature validity.
        maxSignatureValiditySeconds = 1 days;

        // Create the deputy auth signature.
        deputyAuthSignature = makeAuthSignature(getNextContract(), deputyKey, deputy);

        // Create the DeputyPauseModule.
        deputyPauseModule = IDeputyPauseModule(
            DeployUtils.create1({
                _name: "DeputyPauseModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyPauseModule.__constructor__,
                        (
                            foundationSafeInstance.safe,
                            deputyGuardianModule,
                            superchainConfig,
                            maxSignatureValiditySeconds,
                            deputy,
                            deputyAuthSignature
                        )
                    )
                )
            })
        );

        // Enable the DeputyPauseModule on the Foundation Safe.
        foundationSafeInstance.enableModule(address(deputyPauseModule));
    }

    /// @notice Generates a signature to authenticate as the deputy.
    /// @param _verifyingContract The verifying contract.
    /// @param _privateKey The private key to use to sign the message.
    /// @param _deputy The deputy to authenticate as.
    /// @return Generated signature.
    function makeAuthSignature(
        address _verifyingContract,
        uint256 _privateKey,
        address _deputy
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(DEPUTY_AUTH_MESSAGE_TYPEHASH, _deputy));
        bytes32 digest = hashTypedData(_verifyingContract, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Generates a signature to trigger a pause.
    /// @param _verifyingContract The verifying contract.
    /// @param _expiry Signature expiry timestamp.
    /// @param _nonce Signature nonce.
    /// @param _privateKey The private key to use to sign the message.
    /// @return Generated signature.
    function makePauseSignature(
        address _verifyingContract,
        uint256 _expiry,
        bytes32 _nonce,
        uint256 _privateKey
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(PAUSE_MESSAGE_TYPEHASH, _expiry, _nonce));
        bytes32 digest = hashTypedData(_verifyingContract, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Helper function to compute EIP-712 typed data hash
    /// @param _verifyingContract The verifying contract.
    /// @param _structHash The struct hash.
    /// @return The EIP-712 typed data hash.
    function hashTypedData(address _verifyingContract, bytes32 _structHash) internal view returns (bytes32) {
        bytes32 DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("DeputyPauseModule"),
                keccak256("1"),
                block.chainid,
                _verifyingContract
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _structHash));
    }

    /// @notice Gets the next contract that will be created by this test contract.
    /// @return Address of the next contract to be created.
    function getNextContract() internal view returns (address) {
        return vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
    }
}

/// @title DeputyPauseModule_Constructor_Test
/// @notice Tests that the constructor works.
contract DeputyPauseModule_Constructor_Test is DeputyPauseModule_TestInit {
    /// @notice Tests that the constructor works.
    function testFuzz_constructor_validParameters_succeeds(uint256 _maxSignatureValiditySeconds) external {
        // Make sure that the max signature validity is within the allowed range.
        _maxSignatureValiditySeconds = bound(_maxSignatureValiditySeconds, 1 days, 365 days);

        // Create the signature.
        bytes memory signature = makeAuthSignature(getNextContract(), deputyKey, deputy);

        // Deploy the module.
        deputyPauseModule = IDeputyPauseModule(
            DeployUtils.create1({
                _name: "DeputyPauseModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyPauseModule.__constructor__,
                        (
                            foundationSafeInstance.safe,
                            deputyGuardianModule,
                            superchainConfig,
                            _maxSignatureValiditySeconds,
                            deputy,
                            signature
                        )
                    )
                )
            })
        );
    }
}

/// @title DeputyPauseModule_Constructor_TestFail
/// @notice Tests that the constructor fails when it should.
contract DeputyPauseModule_Constructor_TestFail is DeputyPauseModule_TestInit {
    /// @notice Tests that the constructor reverts when the signature is not the deputy auth message.
    function testFuzz_constructor_signatureNotAuthMessage_reverts(uint256 _expiry) external {
        // Create the signature.
        bytes memory signature = makePauseSignature(getNextContract(), _expiry, bytes32(0), deputyKey);

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_InvalidDeputy.selector));
        IDeputyPauseModule(
            DeployUtils.create1({
                _name: "DeputyPauseModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyPauseModule.__constructor__,
                        (
                            foundationSafeInstance.safe,
                            deputyGuardianModule,
                            superchainConfig,
                            maxSignatureValiditySeconds,
                            deputy,
                            signature
                        )
                    )
                )
            })
        );
    }

    /// @notice Tests that the constructor reverts when the signature is not the deputy auth message.
    function testFuzz_constructor_signatureNotOverDeputy_reverts(address _nextContract) external {
        // Make sure that the next contract is not correct.
        vm.assume(_nextContract != getNextContract());

        // Create the signature.
        bytes memory signature = makeAuthSignature(_nextContract, deputyKey, deputy);

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_InvalidDeputy.selector));
        IDeputyPauseModule(
            DeployUtils.create1({
                _name: "DeputyPauseModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyPauseModule.__constructor__,
                        (
                            foundationSafeInstance.safe,
                            deputyGuardianModule,
                            superchainConfig,
                            maxSignatureValiditySeconds,
                            deputy,
                            signature
                        )
                    )
                )
            })
        );
    }

    /// @notice Tests that the constructor reverts when the signature is not the deputy auth message.
    function testFuzz_constructor_signatureNotForNextContract_reverts(address _deputy) external {
        // Make sure that the deputy is not correct.
        vm.assume(_deputy != deputy);

        // Create the signature.
        bytes memory signature = makeAuthSignature(getNextContract(), deputyKey, _deputy);

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_InvalidDeputy.selector));
        IDeputyPauseModule(
            DeployUtils.create1({
                _name: "DeputyPauseModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyPauseModule.__constructor__,
                        (
                            foundationSafeInstance.safe,
                            deputyGuardianModule,
                            superchainConfig,
                            maxSignatureValiditySeconds,
                            deputy,
                            signature
                        )
                    )
                )
            })
        );
    }

    /// @notice Tests that the constructor reverts when the signature is not from the deputy.
    function testFuzz_constructor_signatureNotFromDeputy_reverts(uint256 _privateKey) external {
        // Make sure that the private key is not the deputy's private key.
        vm.assume(_privateKey != deputyKey);

        // Make sure that the private key is in the range of a valid secp256k1 private key.
        _privateKey = bound(_privateKey, 1, SECP256K1_ORDER - 1);

        // Create the signature.
        bytes memory signature = makeAuthSignature(getNextContract(), _privateKey, deputy);

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_InvalidDeputy.selector));
        IDeputyPauseModule(
            DeployUtils.create1({
                _name: "DeputyPauseModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyPauseModule.__constructor__,
                        (
                            foundationSafeInstance.safe,
                            deputyGuardianModule,
                            superchainConfig,
                            maxSignatureValiditySeconds,
                            deputy,
                            signature
                        )
                    )
                )
            })
        );
    }

    /// @notice Tests that the constructor reverts when the signature validity is too short.
    function testFuzz_constructor_signatureValidityTooShort_reverts(uint256 _maxSignatureValiditySeconds) external {
        // Make sure that the max signature validity is too short.
        _maxSignatureValiditySeconds = bound(_maxSignatureValiditySeconds, 0, 1 days - 1);

        // Create the signature.
        bytes memory signature = makeAuthSignature(getNextContract(), deputyKey, deputy);

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_SignatureValidityTooShort.selector));
        IDeputyPauseModule(
            DeployUtils.create1({
                _name: "DeputyPauseModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyPauseModule.__constructor__,
                        (
                            foundationSafeInstance.safe,
                            deputyGuardianModule,
                            superchainConfig,
                            _maxSignatureValiditySeconds,
                            deputy,
                            signature
                        )
                    )
                )
            })
        );
    }

    /// @notice Tests that the constructor reverts when the signature validity is too long.
    function testFuzz_constructor_signatureValidityTooLong_reverts(uint256 _maxSignatureValiditySeconds) external {
        // Make sure that the max signature validity is too long.
        _maxSignatureValiditySeconds = bound(_maxSignatureValiditySeconds, 365 days + 1, type(uint256).max);

        // Create the signature.
        bytes memory signature = makeAuthSignature(getNextContract(), deputyKey, deputy);

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_SignatureValidityTooLong.selector));
        IDeputyPauseModule(
            DeployUtils.create1({
                _name: "DeputyPauseModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyPauseModule.__constructor__,
                        (
                            foundationSafeInstance.safe,
                            deputyGuardianModule,
                            superchainConfig,
                            _maxSignatureValiditySeconds,
                            deputy,
                            signature
                        )
                    )
                )
            })
        );
    }

    /// @notice Tests that the constructor reverts when the foundation safe is not valid.
    function test_constructor_invalidFoundationSafe_reverts() external {
        // Create the signature.
        bytes memory signature = makeAuthSignature(getNextContract(), deputyKey, deputy);

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_InvalidFoundationSafe.selector));
        IDeputyPauseModule(
            DeployUtils.create1({
                _name: "DeputyPauseModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyPauseModule.__constructor__,
                        (
                            Safe(payable(address(deputyGuardianModule))),
                            deputyGuardianModule,
                            superchainConfig,
                            maxSignatureValiditySeconds,
                            deputy,
                            signature
                        )
                    )
                )
            })
        );
    }

    /// @notice Tests that the constructor reverts when the deputy guardian module is not valid.
    function test_constructor_invalidDeputyGuardianModule_reverts() external {
        // Create the signature.
        bytes memory signature = makeAuthSignature(getNextContract(), deputyKey, deputy);

        // Expect a revert.
        vm.expectRevert(
            abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_InvalidDeputyGuardianModule.selector)
        );
        IDeputyPauseModule(
            DeployUtils.create1({
                _name: "DeputyPauseModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyPauseModule.__constructor__,
                        (
                            foundationSafeInstance.safe,
                            IDeputyGuardianModule(address(foundationSafeInstance.safe)),
                            superchainConfig,
                            maxSignatureValiditySeconds,
                            deputy,
                            signature
                        )
                    )
                )
            })
        );
    }

    /// @notice Tests that the constructor reverts when the superchain config is not valid.
    function test_constructor_invalidSuperchainConfig_reverts() external {
        // Create the signature.
        bytes memory signature = makeAuthSignature(getNextContract(), deputyKey, deputy);

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_InvalidSuperchainConfig.selector));
        IDeputyPauseModule(
            DeployUtils.create1({
                _name: "DeputyPauseModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyPauseModule.__constructor__,
                        (
                            foundationSafeInstance.safe,
                            deputyGuardianModule,
                            ISuperchainConfig(address(deputyGuardianModule)),
                            maxSignatureValiditySeconds,
                            deputy,
                            signature
                        )
                    )
                )
            })
        );
    }
}

/// @title DeputyPauseModule_Getters_Test
/// @notice Tests that the getters work.
contract DeputyPauseModule_Getters_Test is DeputyPauseModule_TestInit {
    /// @notice Tests that the getters work.
    function test_getters_works() external view {
        assertEq(address(deputyPauseModule.foundationSafe()), address(foundationSafeInstance.safe));
        assertEq(address(deputyPauseModule.deputyGuardianModule()), address(deputyGuardianModule));
        assertEq(deputyPauseModule.maxSignatureValiditySeconds(), maxSignatureValiditySeconds);
        assertEq(deputyPauseModule.deputy(), deputy);
    }
}

/// @title DeputyPauseModule_Pause_Test
/// @notice Tests that the pause() function works.
contract DeputyPauseModule_Pause_Test is DeputyPauseModule_TestInit {
    /// @notice Tests that pause() successfully pauses when called by the deputy.
    /// @param _expiry Signature expiry timestamp.
    /// @param _nonce Signature nonce.
    function testFuzz_pause_validParameters_succeeds(uint256 _expiry, bytes32 _nonce) external {
        // Make sure that the expiry is valid.
        _expiry = bound(_expiry, block.timestamp + 1, block.timestamp + maxSignatureValiditySeconds);

        vm.expectEmit(address(superchainConfig));
        emit Paused("Deputy Guardian");

        vm.expectEmit(address(securityCouncilSafeInstance.safe));
        emit ExecutionFromModuleSuccess(address(deputyGuardianModule));

        vm.expectEmit(address(deputyGuardianModule));
        emit Paused("Deputy Guardian");

        vm.expectEmit(address(foundationSafeInstance.safe));
        emit ExecutionFromModuleSuccess(address(deputyPauseModule));

        // State assertions before the pause.
        assertEq(deputyPauseModule.usedNonces(_nonce), false);
        assertEq(superchainConfig.paused(), false);

        // Trigger the pause.
        bytes memory signature = makePauseSignature(address(deputyPauseModule), _expiry, _nonce, deputyKey);
        deputyPauseModule.pause(_expiry, _nonce, signature);

        // State assertions after the pause.
        assertEq(deputyPauseModule.usedNonces(_nonce), true);
        assertEq(superchainConfig.paused(), true);
    }

    /// @notice Tests that pause() succeeds when called with the same expiry but a different nonce.
    /// @param _nonce1 First nonce.
    /// @param _nonce2 Second nonce.
    function test_pause_sameExpiryDifferentNonce_succeeds(uint256 _expiry, bytes32 _nonce1, bytes32 _nonce2) external {
        // Make sure that the expiry is valid.
        _expiry = bound(_expiry, block.timestamp + 1, block.timestamp + maxSignatureValiditySeconds);

        // Make sure that the nonces are different.
        vm.assume(_nonce1 != _nonce2);

        // Pause once.
        bytes memory sig1 = makePauseSignature(address(deputyPauseModule), _expiry, _nonce1, deputyKey);
        deputyPauseModule.pause(_expiry, _nonce1, sig1);

        // Unpause.
        vm.prank(address(securityCouncilSafeInstance.safe));
        superchainConfig.unpause();

        // Pause again with the same expiry but a different nonce.
        bytes memory sig2 = makePauseSignature(address(deputyPauseModule), _expiry, _nonce2, deputyKey);
        deputyPauseModule.pause(_expiry, _nonce2, sig2);
    }

    /// @notice Tests that multiple valid pauses work (after unpause) with different expiry times.
    function test_pause_successiveValidPauses_succeeds() external {
        // Set up different expiry times.
        uint256 expiry1 = block.timestamp + 100;
        uint256 expiry2 = block.timestamp + 200;

        // Trigger the first pause.
        bytes32 nonce1 = keccak256("nonce1");
        bytes memory sig1 = makePauseSignature(address(deputyPauseModule), expiry1, nonce1, deputyKey);
        deputyPauseModule.pause(expiry1, nonce1, sig1);

        // Unpause.
        vm.prank(address(securityCouncilSafeInstance.safe));
        superchainConfig.unpause();

        // Second pause.
        bytes32 nonce2 = keccak256("nonce2");
        bytes memory sig2 = makePauseSignature(address(deputyPauseModule), expiry2, nonce2, deputyKey);
        deputyPauseModule.pause(expiry2, nonce2, sig2);
    }

    /// @notice Tests that pause() succeeds when called after the superchain has already been paused.
    function test_pause_alreadyPaused_succeeds() external {
        // Pause once.
        uint256 expiry1 = block.timestamp + 1;
        bytes32 nonce1 = keccak256("nonce1");
        bytes memory signature1 = makePauseSignature(address(deputyPauseModule), expiry1, nonce1, deputyKey);
        deputyPauseModule.pause(expiry1, nonce1, signature1);

        // Pause again.
        uint256 expiry2 = block.timestamp + 2;
        bytes32 nonce2 = keccak256("nonce2");
        bytes memory signature2 = makePauseSignature(address(deputyPauseModule), expiry2, nonce2, deputyKey);
        deputyPauseModule.pause(expiry2, nonce2, signature2);
    }

    /// @notice Tests that pause() succeeds when called at the boundary expiry.
    function test_pause_atBoundaryExpiry_succeeds() external {
        uint256 expiry = block.timestamp + maxSignatureValiditySeconds;
        bytes memory signature = makePauseSignature(address(deputyPauseModule), expiry, SOME_VALID_NONCE, deputyKey);
        deputyPauseModule.pause(expiry, SOME_VALID_NONCE, signature);
    }

    /// @notice Tests that pause() succeeds within 1 million gas.
    function test_pause_withinMillionGas_succeeds() external {
        uint256 expiry = block.timestamp + 100;
        bytes memory signature = makePauseSignature(address(deputyPauseModule), expiry, SOME_VALID_NONCE, deputyKey);

        uint256 gasBefore = gasleft();
        deputyPauseModule.pause(expiry, SOME_VALID_NONCE, signature);
        uint256 gasUsed = gasBefore - gasleft();

        // Ensure gas usage is within expected bounds.
        // 1m is a conservative limit that means we can trigger the pause in most blocks. It would
        // be prohibitively expensive to fill up blocks to prevent the pause from being triggered
        // even at 1m gas for any prolonged duration. Means that we can always trigger the pause
        // within a short period of time.
        assertLt(gasUsed, 1000000);
    }
}

/// @title DeputyPauseModule_Pause_TestFail
/// @notice Tests that the pause() function reverts when it should.
contract DeputyPauseModule_Pause_TestFail is DeputyPauseModule_TestInit {
    /// @notice Tests that pause() reverts when called by an address other than the deputy.
    /// @param _privateKey The private key to use to sign the message.
    function testFuzz_pause_notDeputy_reverts(uint256 _privateKey) external {
        // Make sure that the private key is not the deputy's private key.
        vm.assume(_privateKey != deputyKey);

        // Make sure that the private key is in the range of a valid secp256k1 private key.
        _privateKey = bound(_privateKey, 1, SECP256K1_ORDER - 1);

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_Unauthorized.selector));
        uint256 expiry = block.timestamp + 1;
        bytes memory signature = makePauseSignature(address(deputyPauseModule), expiry, SOME_VALID_NONCE, _privateKey);
        deputyPauseModule.pause(expiry, SOME_VALID_NONCE, signature);
    }

    /// @notice Tests that pause() reverts when the expiry has already been used.
    /// @param _nonce Signature nonce.
    function testFuzz_pause_nonceAlreadyUsed_reverts(bytes32 _nonce) external {
        // Pause once.
        uint256 expiry = block.timestamp + 1;
        bytes memory signature = makePauseSignature(address(deputyPauseModule), expiry, _nonce, deputyKey);
        deputyPauseModule.pause(expiry, _nonce, signature);

        // Unpause.
        vm.prank(address(securityCouncilSafeInstance.safe));
        superchainConfig.unpause();

        // Expect that the expiry is now used.
        assertEq(deputyPauseModule.usedNonces(_nonce), true);

        // Pause again.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_NonceAlreadyUsed.selector));
        deputyPauseModule.pause(expiry, _nonce, signature);
    }

    /// @notice Tests that pause() reverts when the expiry is too long.
    /// @param _expiry Signature expiry timestamp.
    function testFuzz_pause_expiryTooLong_reverts(uint256 _expiry) external {
        // Make sure the expiry will be too long.
        _expiry = bound(_expiry, block.timestamp + maxSignatureValiditySeconds + 1, type(uint256).max);

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_SignatureExpiryTooLong.selector));
        bytes memory signature = makePauseSignature(address(deputyPauseModule), _expiry, SOME_VALID_NONCE, deputyKey);
        deputyPauseModule.pause(_expiry, SOME_VALID_NONCE, signature);
    }

    /// @notice Tests that pause() reverts when the signature has expired.
    /// @param _expiry Signature expiry timestamp.
    function testFuzz_pause_signatureExpired_reverts(uint256 _expiry) external {
        // Make sure the signature will be expired.
        _expiry = bound(_expiry, 0, block.timestamp);

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_SignatureExpired.selector));
        bytes memory signature = makePauseSignature(address(deputyPauseModule), _expiry, SOME_VALID_NONCE, deputyKey);
        deputyPauseModule.pause(_expiry, SOME_VALID_NONCE, signature);
    }

    /// @notice Tests that pause() reverts when the signature is longer than 65 bytes.
    /// @param _length The length of the malformed signature.
    function testFuzz_pause_signatureTooLong_reverts(uint256 _length) external {
        // Make sure signature is longer than 65 bytes.
        _length = bound(_length, 66, 1000);

        // Create the malformed signature.
        bytes memory signature = new bytes(_length);

        // Expect a revert.
        vm.expectRevert("ECDSA: invalid signature length");
        deputyPauseModule.pause(block.timestamp + 100, SOME_VALID_NONCE, signature);
    }

    /// @notice Tests that pause() reverts when the signature is shorter than 65 bytes.
    /// @param _length The length of the malformed signature.
    function testFuzz_pause_signatureTooShort_reverts(uint256 _length) external {
        // Make sure signature is shorter than 65 bytes.
        _length = bound(_length, 0, 64);

        // Create the malformed signature.
        bytes memory signature = new bytes(_length);

        // Expect a revert.
        vm.expectRevert("ECDSA: invalid signature length");
        deputyPauseModule.pause(block.timestamp + 100, SOME_VALID_NONCE, signature);
    }

    /// @notice Tests that pause() reverts when the expiry is exactly the current timestamp.
    function test_pause_expiryIsNow_reverts() external {
        // Expect a revert.
        uint256 expiry = block.timestamp;
        bytes memory signature = makePauseSignature(address(deputyPauseModule), expiry, SOME_VALID_NONCE, deputyKey);
        vm.expectRevert(IDeputyPauseModule.DeputyPauseModule_SignatureExpired.selector);
        deputyPauseModule.pause(expiry, SOME_VALID_NONCE, signature);
    }

    /// @notice Tests that pause() reverts when the expiry is zero.
    function test_pause_expiryIsZero_reverts() external {
        // Expect a revert.
        uint256 expiry = 0;
        bytes memory signature = makePauseSignature(address(deputyPauseModule), expiry, SOME_VALID_NONCE, deputyKey);
        vm.expectRevert(IDeputyPauseModule.DeputyPauseModule_SignatureExpired.selector);
        deputyPauseModule.pause(expiry, SOME_VALID_NONCE, signature);
    }

    /// @notice Tests that pause() reverts when the expiry is exactly the max signature validity seconds + 1.
    function test_pause_overBoundaryExpiry_reverts() external {
        // Test exact boundary conditions
        uint256 expiry = block.timestamp + maxSignatureValiditySeconds + 1;

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_SignatureExpiryTooLong.selector));
        bytes memory signature = makePauseSignature(address(deputyPauseModule), expiry, SOME_VALID_NONCE, deputyKey);
        deputyPauseModule.pause(expiry, SOME_VALID_NONCE, signature);
    }

    /// @notice Tests that the error message is returned when the call to the safe reverts.
    function test_pause_targetReverts_reverts() external {
        // Make sure that the SuperchainConfig pause() reverts.
        vm.mockCallRevert(
            address(superchainConfig),
            abi.encodePacked(superchainConfig.pause.selector),
            "SuperchainConfig: pause() reverted"
        );

        // Note that the error here will be somewhat awkwardly double-encoded because the
        // DeputyGuardianModule will encode the revert message as an ExecutionFailed error and then
        // the DeputyPauseModule will re-encode it as another ExecutionFailed error.
        vm.expectRevert(
            abi.encodeWithSelector(
                IDeputyPauseModule.DeputyPauseModule_ExecutionFailed.selector,
                string(
                    abi.encodeWithSelector(
                        IDeputyGuardianModule.ExecutionFailed.selector, "SuperchainConfig: pause() reverted"
                    )
                )
            )
        );
        uint256 expiry = block.timestamp + 1;
        bytes memory signature = makePauseSignature(address(deputyPauseModule), expiry, SOME_VALID_NONCE, deputyKey);
        deputyPauseModule.pause(expiry, SOME_VALID_NONCE, signature);
    }

    /// @notice Tests that pause() reverts when the superchain is not in a paused state after the
    /// transaction is sent.
    function test_pause_superchainPauseFails_reverts() external {
        // Make sure that the SuperchainConfig paused() returns false.
        vm.mockCall(address(superchainConfig), abi.encodePacked(superchainConfig.paused.selector), abi.encode(false));

        // Expect a revert.
        vm.expectRevert(IDeputyPauseModule.DeputyPauseModule_SuperchainNotPaused.selector);
        deputyPauseModule.pause(
            block.timestamp + 1,
            SOME_VALID_NONCE,
            makePauseSignature(address(deputyPauseModule), block.timestamp + 1, SOME_VALID_NONCE, deputyKey)
        );
    }
}
