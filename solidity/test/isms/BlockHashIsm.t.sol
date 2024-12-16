// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";

import {IBlockHashOracle} from "../../contracts/interfaces/IBlockHashOracle.sol";

import {TestMailbox} from "../../contracts/test/TestMailbox.sol";
import {TestRecipient} from "../../contracts/test/TestRecipient.sol";

import {TypeCasts} from "../../contracts/libs/TypeCasts.sol";
import {BlockHashIsm} from "../../contracts/isms/block-hash/BlockHashIsm.sol";

/// @notice to run tests:
/// forge test --match-path ./test/isms/BlockHashIsm.t.sol
/// forge test --match-path ./test/isms/BlockHashIsm.t.sol --match-test test_verify_success

contract BlockHashIsmTest is Test {
    using TypeCasts for address;

    uint32 localDomain = 12345;
    uint32 remoteDomain = 54321;
    uint32 origin = 1;

    TestMailbox mailbox;
    BlockHashIsm ism;
    TestRecipient recipient;
    MockBlockHashOracle oracle;

    address relayer;

    function setUp() public {
        relayer = msg.sender;
        recipient = new TestRecipient();
        mailbox = new TestMailbox(12345);
        oracle = new MockBlockHashOracle(origin);
        ism = new BlockHashIsm(address(mailbox), relayer, address(oracle));
        recipient.setInterchainSecurityModule(address(ism));
    }

    function test_revertsWhen_invalidInputParams() public {
        vm.expectRevert("BlockHashIsm: invalid relayer");
        new BlockHashIsm(address(mailbox), address(0), address(oracle));
        vm.expectRevert("BlockHashIsm: invalid mailbox");
        new BlockHashIsm(relayer, relayer, address(oracle));
        vm.expectRevert("BlockHashIsm: invalid blockHashOracle");
        new BlockHashIsm(address(mailbox), relayer, address(1));
    }

    function test_verify_success(
        uint256 height,
        bytes32 sender,
        bytes calldata body
    ) public {
        // creating the msg
        bytes memory message = mailbox.buildInboundMessage(
            origin,
            address(recipient).addressToBytes32(),
            sender,
            body
        );

        bytes32 computedHash = keccak256(
            abi.encodePacked(
                height,
                block.chainid,
                address(oracle),
                block.timestamp
            )
        );

        // setting the hash and the id in our oracle
        oracle.setBlockhash(height, computedHash);

        bytes memory metadata = abi.encodePacked(height, computedHash);

        vm.prank(relayer);
        mailbox.process(metadata, message);
        assertTrue(ism.verify(metadata, message));
    }

    function test_RevertIf_isNotTrustedRelayer(
        uint256 height,
        bytes32 sender,
        bytes calldata body
    ) public {
        // creating the msg
        bytes memory message = mailbox.buildInboundMessage(
            origin,
            address(recipient).addressToBytes32(),
            sender,
            body
        );

        bytes32 computedHash = keccak256(
            abi.encodePacked(
                height,
                block.chainid,
                address(oracle),
                block.timestamp
            )
        );
        // setting the hash in our mock oracle
        oracle.setBlockhash(height, computedHash);

        bytes memory metadata = abi.encodePacked(height, computedHash);

        vm.expectRevert("Mailbox: ISM verification failed");
        mailbox.process(metadata, message);
        assertFalse(ism.verify(metadata, message));
    }

    function test_RevertIf_originIsNotCorrect(
        uint256 height,
        bytes32 sender,
        bytes calldata body
    ) public {
        // creating the msg
        bytes memory message = mailbox.buildInboundMessage(
            2,
            address(recipient).addressToBytes32(),
            sender,
            body
        );

        bytes32 computedHash = keccak256(
            abi.encodePacked(
                height,
                block.chainid,
                address(oracle),
                block.timestamp
            )
        );
        // setting the hash in our mock oracle
        oracle.setBlockhash(height, computedHash);

        bytes memory metadata = abi.encodePacked(height, computedHash);

        vm.expectRevert("Mailbox: ISM verification failed");
        mailbox.process(metadata, message);
        assertFalse(ism.verify(metadata, message));
    }

    function test_RevertIf_hashesDontMatch(
        uint256 height,
        bytes32 sender,
        bytes calldata body
    ) public {
        // creating the msg
        bytes memory message = mailbox.buildInboundMessage(
            origin,
            address(recipient).addressToBytes32(),
            sender,
            body
        );

        bytes32 computedHash = keccak256(
            abi.encodePacked(
                height,
                block.chainid,
                address(oracle),
                block.timestamp
            )
        );
        // setting the hash in our mock oracle
        oracle.setBlockhash(height, computedHash);
        // computing the hash to compare to the one on the oracle

        bytes memory metadata = abi.encodePacked(height, computedHash);

        vm.expectRevert("Mailbox: ISM verification failed");
        mailbox.process(metadata, message);
        assertFalse(ism.verify(metadata, message));
    }
}

contract MockBlockHashOracle is IBlockHashOracle {
    uint32 private immutable _origin;
    mapping(uint256 => uint256) private _blockHashes;

    constructor(uint32 origin_) {
        _origin = origin_;
    }

    function origin() external view override returns (uint32) {
        return _origin;
    }

    function getBlockhash(
        uint256 height
    ) external view override returns (uint256 hash) {
        return _blockHashes[height];
    }

    function setBlockhash(uint256 height, bytes32 hash) external {
        _blockHashes[height] = uint256(hash);
    }
}
