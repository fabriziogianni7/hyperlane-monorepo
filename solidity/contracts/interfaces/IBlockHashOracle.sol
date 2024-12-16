// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

interface IBlockHashOracle {
    // uint32 public immutable origin;
    function origin() external view returns (uint32);

    // function blockhash(uint256 height) external view returns (uint256 hash);
    function getBlockhash(uint256 height) external view returns (uint256 hash);
}