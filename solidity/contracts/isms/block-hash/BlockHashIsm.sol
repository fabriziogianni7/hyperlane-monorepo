// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ Internal Imports ============
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {IBlockHashOracle} from "../../interfaces/IBlockHashOracle.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Message} from "../../libs/Message.sol";
import {Mailbox} from "../../Mailbox.sol";

contract BlockHashIsm is IInterchainSecurityModule {
    using Message for bytes;

    uint8 public immutable moduleType = uint8(Types.BLOCK_HASH);
    Mailbox public immutable mailbox;
    IBlockHashOracle public immutable blockHashOracle;
    address public immutable trustedRelayer;

    constructor(
        address _mailbox,
        address _trustedRelayer,
        address _blockHashOracle
    ) {
        require(_trustedRelayer != address(0), "BlockHashIsm: invalid relayer");
        require(Address.isContract(_mailbox), "BlockHashIsm: invalid mailbox");
        require(
            Address.isContract(_blockHashOracle),
            "BlockHashIsm: invalid blockHashOracle"
        );
        mailbox = Mailbox(_mailbox);
        blockHashOracle = IBlockHashOracle(_blockHashOracle);
        trustedRelayer = _trustedRelayer;
    }

    function verify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external view override returns (bool) {
        // is the relayer trusted?
        bool isTrustedRelayer = mailbox.processor(_message.id()) ==
            trustedRelayer;

        // is the origin in the message equals to origin from the oracle?
        bool isOriginCorrect = _message.origin() ==
            IBlockHashOracle(blockHashOracle).origin();

        // is the hash returned by the oracle same of the one included in the metadata?
        (uint256 blockHeight, bytes32 messageHash) = abi.decode(
            _metadata,
            (uint256, bytes32)
        );

        bool isBlockHashCorrect = blockHashOracle.getBlockhash(blockHeight) ==
            uint256(messageHash);

        return isTrustedRelayer && isOriginCorrect && isBlockHashCorrect;
    }
}
