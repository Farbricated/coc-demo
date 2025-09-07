// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EvidenceRegistry
 * @dev Stores a metadata hash against a unique SHA256 file hash.
 */
contract EvidenceRegistry {

    struct EvidenceRecord {
        string metadataHash;      // The hash of the file's metadata.
        uint256 timestamp;        // The immutable timestamp of registration.
    }

    // Mapping from the file's SHA256 hash (as bytes32) to its record.
    mapping(bytes32 => EvidenceRecord) private evidenceRecords;

    event EvidenceRegistered(
        bytes32 indexed sha256Hash,
        string metadataHash,
        uint256 timestamp
    );

    /**
     * @dev Records a new piece of evidence.
     * The SHA256 hash of the file is the unique key.
     */
    function registerEvidence(bytes32 _sha256Hash, string memory _metadataHash) public {
        require(evidenceRecords[_sha256Hash].timestamp == 0, "Evidence with this SHA256 hash already exists.");
        
        evidenceRecords[_sha256Hash] = EvidenceRecord({
            metadataHash: _metadataHash,
            timestamp: block.timestamp
        });
        
        emit EvidenceRegistered(_sha256Hash, _metadataHash, block.timestamp);
    }

    /**
     * @dev Retrieves the metadata hash and timestamp for a given SHA256 hash.
     */
    function getEvidenceRecord(bytes32 _sha256Hash) public view returns (string memory, uint256) {
        EvidenceRecord memory record = evidenceRecords[_sha256Hash];
        require(record.timestamp != 0, "Evidence not found.");
        return (record.metadataHash, record.timestamp);
    }
}
