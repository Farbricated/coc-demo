// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

/**
 * @title EvidenceRegistryV2
 * @dev Upgraded contract to store both image and metadata hashes.
 */
contract EvidenceRegistryV2 {

    struct EvidenceRecord {
        bytes32 metadataHash;
        uint256 timestamp;
    }

    // Mapping from the image hash (unique key) to its record
    mapping(bytes32 => EvidenceRecord) private evidenceRecords;

    event EvidenceRegistered(
        bytes32 indexed imageHash,
        bytes32 metadataHash,
        uint256 timestamp
    );

    /**
     * @dev Records a new piece of evidence by storing its image and metadata hashes.
     */
    function registerEvidence(bytes32 _imageHash, bytes32 _metadataHash) public {
        require(evidenceRecords[_imageHash].timestamp == 0, "Image hash already exists.");
        
        evidenceRecords[_imageHash] = EvidenceRecord({
            metadataHash: _metadataHash,
            timestamp: block.timestamp
        });
        
        emit EvidenceRegistered(_imageHash, _metadataHash, block.timestamp);
    }

    /**
     * @dev Verifies evidence. Returns the metadata hash and timestamp if the image hash exists.
     */
    function getEvidenceRecord(bytes32 _imageHash) public view returns (bytes32, uint256) {
        EvidenceRecord memory record = evidenceRecords[_imageHash];
        return (record.metadataHash, record.timestamp);
    }
}
