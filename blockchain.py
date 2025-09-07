# blockchain.py - Complete Enhanced Version with Advanced Verification and Error Handling

import os
from web3 import Web3
from dotenv import load_dotenv
import json
import hashlib
import traceback
from datetime import datetime

class BlockchainService:
    """Enhanced singleton class for blockchain interactions with comprehensive error handling."""
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(BlockchainService, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return
            
        self._initialized = False
        
        try:
            # Load environment variables
            dotenv_path = os.path.join(os.path.dirname(__file__), 'assets', '.env')
            if not os.path.exists(dotenv_path):
                raise FileNotFoundError(f".env file not found at: {dotenv_path}")
            load_dotenv(dotenv_path)

            # Get environment variables
            self.GANACHE_URL = os.getenv("GANACHE_URL")
            self.CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
            self.SENDER_ADDRESS = os.getenv("SENDER_ADDRESS")
            self.PRIVATE_KEY = os.getenv("PRIVATE_KEY")

            # Validate all variables are present
            required_vars = {
                "GANACHE_URL": self.GANACHE_URL,
                "CONTRACT_ADDRESS": self.CONTRACT_ADDRESS,
                "SENDER_ADDRESS": self.SENDER_ADDRESS,
                "PRIVATE_KEY": self.PRIVATE_KEY
            }
            
            missing = [name for name, value in required_vars.items() if not value]
            if missing:
                raise ValueError(f"Missing environment variables: {', '.join(missing)}")

            # Connect to blockchain
            self.w3 = Web3(Web3.HTTPProvider(self.GANACHE_URL))
            if not self.w3.is_connected():
                raise ConnectionError(f"Cannot connect to Ganache at {self.GANACHE_URL}")

            # Load contract ABI
            abi_path = os.path.join(os.path.dirname(__file__), 'abi.json')
            if not os.path.exists(abi_path):
                print(f"WARNING: ABI file not found at {abi_path}, using fallback ABI")
                self.contract_abi = self._get_fallback_abi()
            else:
                with open(abi_path) as f:
                    self.contract_abi = json.load(f)

            # Validate contract address format
            if not Web3.is_address(self.CONTRACT_ADDRESS):
                raise ValueError(f"Invalid contract address: {self.CONTRACT_ADDRESS}")

            # Create contract instance
            self.contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.CONTRACT_ADDRESS), 
                abi=self.contract_abi
            )
            
            self._initialized = True
            print("SUCCESS: Smart contract instance created.")
            print(f"Connected to: {self.GANACHE_URL}")
            print(f"Contract Address: {self.CONTRACT_ADDRESS}")
            print(f"Chain ID: {self.w3.eth.chain_id}")
            
        except Exception as e:
            print(f"CRITICAL ERROR: Blockchain initialization failed: {e}")
            self._initialized = False
            raise

    def _get_fallback_abi(self):
        """Fallback ABI for EvidenceRegistry contract if abi.json is missing"""
        return [
            {
                "inputs": [
                    {"internalType": "bytes32", "name": "_sha256Hash", "type": "bytes32"},
                    {"internalType": "string", "name": "_metadataHash", "type": "string"}
                ],
                "name": "registerEvidence",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "bytes32", "name": "_sha256Hash", "type": "bytes32"}
                ],
                "name": "getEvidenceRecord",
                "outputs": [
                    {"internalType": "string", "name": "", "type": "string"},
                    {"internalType": "uint256", "name": "", "type": "uint256"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "getEvidenceCount",
                "outputs": [
                    {"internalType": "uint256", "name": "", "type": "uint256"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "uint256", "name": "_index", "type": "uint256"}
                ],
                "name": "getEvidenceByIndex",
                "outputs": [
                    {"internalType": "bytes32", "name": "", "type": "bytes32"},
                    {"internalType": "string", "name": "", "type": "string"},
                    {"internalType": "uint256", "name": "", "type": "uint256"},
                    {"internalType": "address", "name": "", "type": "address"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "anonymous": False,
                "inputs": [
                    {"indexed": True, "internalType": "bytes32", "name": "sha256Hash", "type": "bytes32"},
                    {"indexed": False, "internalType": "string", "name": "metadataHash", "type": "string"},
                    {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
                    {"indexed": False, "internalType": "address", "name": "registeredBy", "type": "address"}
                ],
                "name": "EvidenceRegistered",
                "type": "event"
            }
        ]

    def calculate_sha256(self, file_bytes):
        """Calculate SHA256 hash of file bytes."""
        try:
            if not isinstance(file_bytes, bytes):
                raise ValueError("Input must be bytes")
            return hashlib.sha256(file_bytes).digest()
        except Exception as e:
            print(f"Error calculating SHA256: {e}")
            return None

    def record_evidence_on_chain(self, sha256_hash_bytes, metadata_hash_hex):
        """Record evidence hash on blockchain with enhanced error handling."""
        try:
            if not self._initialized:
                raise RuntimeError("Blockchain service not initialized")
                
            if not isinstance(sha256_hash_bytes, bytes) or len(sha256_hash_bytes) != 32:
                raise ValueError("SHA256 hash must be 32 bytes")

            # Validate account balance
            balance = self.w3.eth.get_balance(self.SENDER_ADDRESS)
            if balance == 0:
                raise ValueError("Sender account has insufficient balance for transaction")

            # Get nonce for sender
            nonce = self.w3.eth.get_transaction_count(self.SENDER_ADDRESS)
            
            # Estimate gas
            try:
                gas_estimate = self.contract.functions.registerEvidence(
                    sha256_hash_bytes,
                    metadata_hash_hex
                ).estimate_gas({'from': self.SENDER_ADDRESS})
                gas_limit = min(gas_estimate + 50000, 3000000)  # Add buffer but cap at 3M
            except Exception as gas_error:
                print(f"Gas estimation failed, using default: {gas_error}")
                gas_limit = 2000000

            # Build transaction
            transaction = self.contract.functions.registerEvidence(
                sha256_hash_bytes,
                metadata_hash_hex
            ).build_transaction({
                'from': self.SENDER_ADDRESS,
                'nonce': nonce,
                'gas': gas_limit,
                'gasPrice': self.w3.eth.gas_price,
                'chainId': self.w3.eth.chain_id
            })

            # Sign transaction
            signed_txn = self.w3.eth.account.sign_transaction(transaction, private_key=self.PRIVATE_KEY)
            
            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
            
            print(f"Transaction sent: {tx_hash.hex()}")
            print("Waiting for transaction receipt...")
            
            # Wait for receipt with timeout
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            if tx_receipt.status == 1:
                print(f"SUCCESS: Evidence recorded on blockchain.")
                print(f"Transaction Hash: {tx_receipt.transactionHash.hex()}")
                print(f"Block Number: {tx_receipt.blockNumber}")
                print(f"Gas Used: {tx_receipt.gasUsed}")
                
                # 🔧 FIX: Convert AttributeDict to dict before assignment
                receipt_dict = dict(tx_receipt)
                receipt_dict['from'] = self.SENDER_ADDRESS
                receipt_dict['timestamp'] = datetime.utcnow()
                
                return receipt_dict
            else:
                print(f"Transaction failed with status: {tx_receipt.status}")
                return None
            
        except Exception as e:
            print(f"BLOCKCHAIN ERROR: {e}")
            traceback.print_exc()
            return None

    def get_evidence_record(self, sha256_hash_hex):
        """Retrieve evidence record from blockchain with enhanced error handling."""
        try:
            if not self._initialized:
                raise RuntimeError("Blockchain service not initialized")
                
            # Convert hex string to bytes
            if isinstance(sha256_hash_hex, str):
                # Remove '0x' prefix if present
                if sha256_hash_hex.startswith('0x'):
                    sha256_hash_hex = sha256_hash_hex[2:]
                sha256_hash_bytes = bytes.fromhex(sha256_hash_hex)
            else:
                sha256_hash_bytes = sha256_hash_hex
            
            if len(sha256_hash_bytes) != 32:
                raise ValueError("SHA256 hash must be 32 bytes")
            
            # 🔧 FIX: Enhanced contract call with better error handling
            try:
                result = self.contract.functions.getEvidenceRecord(sha256_hash_bytes).call()
                
                if isinstance(result, tuple) and len(result) >= 2:
                    metadata_hash, timestamp = result[0], result[1]
                    
                    if timestamp == 0:
                        print(f"No blockchain record found for hash: {sha256_hash_hex}")
                        return None, 0
                    
                    print(f"SUCCESS: Found blockchain record for hash: {sha256_hash_hex}")
                    print(f"Timestamp: {datetime.fromtimestamp(timestamp)}")
                    print(f"Metadata Hash: {metadata_hash}")
                    
                    return metadata_hash, timestamp
                else:
                    print(f"Unexpected result format from contract: {result}")
                    return None, 0
                    
            except Exception as contract_error:
                print(f"Contract call failed: {contract_error}")
                # Return None,0 instead of raising error for graceful handling
                return None, 0
                
        except Exception as e:
            print(f"Error fetching blockchain record: {e}")
            return None, 0

    def get_block_details(self, sha256_hash):
        """Get detailed blockchain information for verification."""
        try:
            if not self._initialized:
                return {}
                
            sha256_hash_hex = sha256_hash
            if sha256_hash_hex.startswith('0x'):
                sha256_hash_hex = sha256_hash_hex[2:]
            sha256_hash_bytes = bytes.fromhex(sha256_hash_hex)
            
            # Get transaction events using event filter
            try:
                event_filter = self.contract.events.EvidenceRegistered.create_filter(
                    fromBlock='earliest',
                    argument_filters={'sha256Hash': sha256_hash_bytes}
                )
                
                events = event_filter.get_all_entries()
                
                if events:
                    event = events[0]
                    tx_hash = event['transactionHash']
                    
                    # Get transaction receipt
                    tx_receipt = self.w3.eth.get_transaction_receipt(tx_hash)
                    block = self.w3.eth.get_block(tx_receipt.blockNumber)
                    
                    return {
                        'block_number': tx_receipt.blockNumber,
                        'gas_used': tx_receipt.gasUsed,
                        'transaction_hash': tx_hash.hex(),
                        'block_timestamp': datetime.fromtimestamp(block.timestamp),
                        'confirmations': self.w3.eth.block_number - tx_receipt.blockNumber + 1,
                        'status': tx_receipt.status,
                        'from_address': tx_receipt['from'],
                        'to_address': tx_receipt.to,
                        'event_data': {
                            'metadataHash': event['args']['metadataHash'],
                            'timestamp': event['args']['timestamp'],
                            'registeredBy': event['args']['registeredBy']
                        }
                    }
                
            except Exception as filter_error:
                print(f"Event filter error: {filter_error}")
            
            return {}
            
        except Exception as e:
            print(f"Error getting block details: {e}")
            return {}

    def verify_blockchain_integrity(self, sha256_hash):
        """Comprehensive blockchain verification with enhanced details."""
        try:
            metadata_hash, timestamp = self.get_evidence_record(sha256_hash)
            
            if timestamp > 0:
                block_details = self.get_block_details(sha256_hash)
                
                verification_result = {
                    'verified': True,
                    'timestamp': timestamp,
                    'datetime': datetime.fromtimestamp(timestamp),
                    'metadata_hash': metadata_hash,
                    'block_details': block_details,
                    'verification_time': datetime.utcnow().isoformat(),
                    'chain_id': self.w3.eth.chain_id,
                    'network': self.GANACHE_URL,
                    'integrity_score': 100,
                    'trust_level': 'HIGH'
                }
                
                print(f"Blockchain verification successful for: {sha256_hash}")
                return verification_result
            else:
                verification_result = {
                    'verified': False,
                    'error': 'No blockchain record found',
                    'verification_time': datetime.utcnow().isoformat(),
                    'chain_id': self.w3.eth.chain_id,
                    'network': self.GANACHE_URL,
                    'integrity_score': 0,
                    'trust_level': 'NONE'
                }
                
                print(f"Blockchain verification failed for: {sha256_hash}")
                return verification_result
                
        except Exception as e:
            print(f"Blockchain verification error: {e}")
            return {
                'verified': False,
                'error': str(e),
                'verification_time': datetime.utcnow().isoformat(),
                'integrity_score': 0,
                'trust_level': 'ERROR'
            }

    def get_evidence_count(self):
        """Get total number of evidence records on blockchain."""
        try:
            if not self._initialized:
                return 0
            
            try:
                count = self.contract.functions.getEvidenceCount().call()
                return count
            except:
                # If function doesn't exist, count events
                event_filter = self.contract.events.EvidenceRegistered.create_filter(
                    fromBlock='earliest'
                )
                events = event_filter.get_all_entries()
                return len(events)
                
        except Exception as e:
            print(f"Error getting evidence count: {e}")
            return 0

    def get_all_evidence_hashes(self):
        """Get all evidence hashes stored on blockchain."""
        try:
            if not self._initialized:
                return []
                
            evidence_list = []
            
            try:
                # Try to get evidence count first
                count = self.get_evidence_count()
                
                # If we have getEvidenceByIndex function
                for i in range(count):
                    try:
                        result = self.contract.functions.getEvidenceByIndex(i).call()
                        if result and len(result) >= 4:
                            sha256_hash, metadata_hash, timestamp, registered_by = result
                            evidence_list.append({
                                'sha256_hash': sha256_hash.hex(),
                                'metadata_hash': metadata_hash,
                                'timestamp': timestamp,
                                'registered_by': registered_by,
                                'datetime': datetime.fromtimestamp(timestamp)
                            })
                    except:
                        break
                        
            except:
                # Fallback: use event logs
                event_filter = self.contract.events.EvidenceRegistered.create_filter(
                    fromBlock='earliest'
                )
                events = event_filter.get_all_entries()
                
                for event in events:
                    evidence_list.append({
                        'sha256_hash': event['args']['sha256Hash'].hex(),
                        'metadata_hash': event['args']['metadataHash'],
                        'timestamp': event['args']['timestamp'],
                        'registered_by': event['args']['registeredBy'],
                        'datetime': datetime.fromtimestamp(event['args']['timestamp'])
                    })
            
            return evidence_list
            
        except Exception as e:
            print(f"Error getting all evidence hashes: {e}")
            return []

    def get_contract_info(self):
        """Get contract information for debugging and status."""
        try:
            if not self._initialized:
                return {"error": "Not initialized"}
            
            # Get evidence count
            evidence_count = self.get_evidence_count()
                
            balance_wei = self.w3.eth.get_balance(self.SENDER_ADDRESS)
            balance_eth = self.w3.from_wei(balance_wei, 'ether')
                
            return {
                "contract_address": self.CONTRACT_ADDRESS,
                "sender_address": self.SENDER_ADDRESS,
                "network_id": self.w3.net.version,
                "latest_block": self.w3.eth.block_number,
                "is_connected": self.w3.is_connected(),
                "chain_id": self.w3.eth.chain_id,
                "evidence_count": evidence_count,
                "account_balance_eth": float(balance_eth),
                "account_balance_wei": balance_wei,
                "gas_price": self.w3.eth.gas_price,
                "ganache_url": self.GANACHE_URL
            }
        except Exception as e:
            return {"error": str(e)}

    def test_connection(self):
        """Test blockchain connection and contract interaction."""
        try:
            if not self._initialized:
                print("ERROR: Blockchain service not initialized")
                return False
                
            # Test Web3 connection
            if not self.w3.is_connected():
                print("ERROR: Web3 not connected to Ganache")
                return False
                
            # Test contract interaction
            latest_block = self.w3.eth.block_number
            print(f"SUCCESS: Connected to blockchain at block {latest_block}")
            
            # Test account balance
            balance = self.w3.eth.get_balance(self.SENDER_ADDRESS)
            balance_eth = self.w3.from_wei(balance, 'ether')
            print(f"Account balance: {balance_eth} ETH")
            
            if balance == 0:
                print("WARNING: Account has no ETH balance")
                return False
            
            # Test contract call
            try:
                # Try to get evidence count
                evidence_count = self.get_evidence_count()
                print(f"Evidence count from contract: {evidence_count}")
            except Exception as contract_error:
                print(f"Contract interaction test: {contract_error}")
                # This might be normal if function doesn't exist
                
            print("✅ Blockchain connection test successful")
            return True
            
        except Exception as e:
            print(f"❌ Connection test failed: {e}")
            return False

    def get_transaction_history(self, limit=10):
        """Get recent transaction history for this contract."""
        try:
            if not self._initialized:
                return []
            
            # Get recent blocks to search for transactions
            latest_block = self.w3.eth.block_number
            start_block = max(0, latest_block - 1000)  # Search last 1000 blocks
            
            transactions = []
            
            # Create event filter for EvidenceRegistered events
            try:
                event_filter = self.contract.events.EvidenceRegistered.create_filter(
                    fromBlock=start_block,
                    toBlock='latest'
                )
                
                events = event_filter.get_all_entries()
                
                for event in events[-limit:]:  # Get most recent events
                    tx_receipt = self.w3.eth.get_transaction_receipt(event['transactionHash'])
                    block = self.w3.eth.get_block(tx_receipt.blockNumber)
                    
                    transactions.append({
                        'tx_hash': event['transactionHash'].hex(),
                        'block_number': event['blockNumber'],
                        'timestamp': datetime.fromtimestamp(block.timestamp),
                        'sha256_hash': event['args']['sha256Hash'].hex(),
                        'metadata_hash': event['args']['metadataHash'],
                        'registered_by': event['args']['registeredBy'],
                        'gas_used': tx_receipt.gasUsed
                    })
                    
            except Exception as e:
                print(f"Error fetching transaction history: {e}")
            
            return transactions
            
        except Exception as e:
            print(f"Error getting transaction history: {e}")
            return []

    def estimate_gas_cost(self, sha256_hash_bytes, metadata_hash_hex):
        """Estimate gas cost for recording evidence."""
        try:
            if not self._initialized:
                return 0
                
            gas_estimate = self.contract.functions.registerEvidence(
                sha256_hash_bytes,
                metadata_hash_hex
            ).estimate_gas({'from': self.SENDER_ADDRESS})
            
            gas_price = self.w3.eth.gas_price
            cost_wei = gas_estimate * gas_price
            cost_eth = self.w3.from_wei(cost_wei, 'ether')
            
            return {
                'gas_estimate': gas_estimate,
                'gas_price_wei': gas_price,
                'cost_wei': cost_wei,
                'cost_eth': float(cost_eth)
            }
            
        except Exception as e:
            print(f"Error estimating gas cost: {e}")
            return 0

    def get_network_status(self):
        """Get comprehensive network status."""
        try:
            if not self._initialized:
                return {"status": "not_initialized"}
            
            latest_block = self.w3.eth.block_number
            block = self.w3.eth.get_block(latest_block)
            
            return {
                "status": "connected",
                "latest_block": latest_block,
                "block_timestamp": datetime.fromtimestamp(block.timestamp),
                "gas_price": self.w3.eth.gas_price,
                "chain_id": self.w3.eth.chain_id,
                "node_version": self.w3.client_version,
                "peer_count": self.w3.net.peer_count,
                "is_syncing": self.w3.eth.syncing,
                "accounts": len(self.w3.eth.accounts),
                "network_hashrate": self.w3.eth.hashrate if hasattr(self.w3.eth, 'hashrate') else 0
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def bulk_verify_evidence(self, sha256_hashes):
        """Verify multiple evidence records in bulk."""
        try:
            if not self._initialized:
                return []
            
            verification_results = []
            
            for sha256_hash in sha256_hashes:
                try:
                    metadata_hash, timestamp = self.get_evidence_record(sha256_hash)
                    verification_results.append({
                        'sha256_hash': sha256_hash,
                        'verified': timestamp > 0,
                        'timestamp': timestamp,
                        'metadata_hash': metadata_hash
                    })
                except Exception as e:
                    verification_results.append({
                        'sha256_hash': sha256_hash,
                        'verified': False,
                        'error': str(e)
                    })
            
            return verification_results
            
        except Exception as e:
            print(f"Error in bulk verification: {e}")
            return []

# Create singleton instance
blockchain_service = BlockchainService()

# Test connection on import
if __name__ == "__main__":
    print("=== TESTING BLOCKCHAIN CONNECTION ===")
    
    if blockchain_service.test_connection():
        print("✅ Blockchain service initialized successfully")
        
        # Get contract info
        info = blockchain_service.get_contract_info()
        print("Contract Info:")
        for key, value in info.items():
            print(f"  {key}: {value}")
        
        # Get network status
        network_status = blockchain_service.get_network_status()
        print("\nNetwork Status:")
        for key, value in network_status.items():
            print(f"  {key}: {value}")
        
        # Get transaction history
        tx_history = blockchain_service.get_transaction_history(5)
        print(f"\nRecent Transactions: {len(tx_history)} found")
        
        # Get all evidence
        all_evidence = blockchain_service.get_all_evidence_hashes()
        print(f"Total Evidence Records: {len(all_evidence)}")
        
    else:
        print("❌ Blockchain service initialization failed")
        print("Make sure Ganache is running and all environment variables are set correctly")
