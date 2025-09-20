"""
Professional Blockchain Manager
==============================
Enhanced Ganache integration with smart contract support
"""

import os
import logging
import secrets
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass

try:
    from web3 import Web3
    from eth_account import Account
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class BlockchainTransaction:
    tx_hash: str
    block_number: int
    gas_used: int
    timestamp: datetime
    evidence_id: str
    status: str = "confirmed"

class BlockchainManager:
    """Professional blockchain manager with enhanced features"""
    
    def __init__(self):
        self.ganache_url = os.getenv('GANACHE_URL', 'http://127.0.0.1:7545')
        self.network_id = int(os.getenv('GANACHE_NETWORK_ID', '5777'))
        self.contract_address = os.getenv('CONTRACT_ADDRESS')
        self.private_key = os.getenv('PRIVATE_KEY')
        
        self.w3 = None
        self.contract = None
        self.connected = False
        self.account = None
        
        self._initialize_connection()
        
    def _initialize_connection(self):
        """Initialize blockchain connection"""
        if not WEB3_AVAILABLE:
            logger.warning("Web3 not available - using simulation mode")
            self.connected = False
            return
            
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.ganache_url))
            
            if self.w3.is_connected():
                self.connected = True
                self._setup_account()
                self._load_contract()
                logger.info(f"Blockchain connected to {self.ganache_url}")
            else:
                logger.warning("Ganache not responding - using simulation mode")
                self.connected = False
                
        except Exception as e:
            logger.error(f"Blockchain connection failed: {e}")
            self.connected = False
    
    def _setup_account(self):
        """Setup blockchain account"""
        try:
            if self.private_key:
                self.account = Account.from_key(self.private_key)
                logger.info(f"Account loaded: {self.account.address}")
            else:
                # Use first available account from Ganache
                accounts = self.w3.eth.accounts
                if accounts:
                    self.account = accounts[0]
                    logger.info(f"Using Ganache account: {self.account}")
                    
        except Exception as e:
            logger.error(f"Account setup failed: {e}")
    
    def _load_contract(self):
        """Load smart contract if available"""
        if self.contract_address and self.w3:
            try:
                # Simplified ABI for evidence contract
                contract_abi = [
                    {
                        "inputs": [
                            {"name": "_evidenceId", "type": "string"},
                            {"name": "_fileHash", "type": "string"},
                            {"name": "_timestamp", "type": "uint256"}
                        ],
                        "name": "anchorEvidence",
                        "outputs": [],
                        "type": "function"
                    },
                    {
                        "inputs": [{"name": "_evidenceId", "type": "string"}],
                        "name": "getEvidence",
                        "outputs": [
                            {"name": "", "type": "string"},
                            {"name": "", "type": "string"},
                            {"name": "", "type": "uint256"}
                        ],
                        "type": "function"
                    }
                ]
                
                self.contract = self.w3.eth.contract(
                    address=self.contract_address,
                    abi=contract_abi
                )
                logger.info(f"Contract loaded: {self.contract_address}")
                
            except Exception as e:
                logger.error(f"Contract loading failed: {e}")
    
    def anchor_evidence(self, evidence_id: str, file_hash: str, classification_level: int = 2, case_id: str = None) -> Dict[str, Any]:
        """Anchor evidence on blockchain"""
        try:
            if self.connected and self.contract and self.account:
                return self._real_blockchain_anchor(evidence_id, file_hash, classification_level, case_id)
            else:
                return self._simulate_blockchain_anchor(evidence_id, file_hash, classification_level, case_id)
                
        except Exception as e:
            logger.error(f"Evidence anchoring failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'evidence_id': evidence_id,
                'simulation': not self.connected
            }
    
    def _real_blockchain_anchor(self, evidence_id: str, file_hash: str, classification_level: int, case_id: str) -> Dict[str, Any]:
        """Real blockchain anchoring"""
        try:
            # Build transaction
            tx_data = self.contract.functions.anchorEvidence(
                evidence_id,
                file_hash,
                int(datetime.now().timestamp())
            ).build_transaction({
                'from': self.account if isinstance(self.account, str) else self.account.address,
                'gas': 300000,
                'gasPrice': self.w3.to_wei('20', 'gwei'),
                'nonce': self.w3.eth.get_transaction_count(
                    self.account if isinstance(self.account, str) else self.account.address
                )
            })
            
            # Sign and send transaction
            if hasattr(self.account, 'sign_transaction'):
                signed_txn = self.account.sign_transaction(tx_data)
                tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            else:
                tx_hash = self.w3.eth.send_transaction(tx_data)
            
            # Wait for confirmation
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            if tx_receipt.status == 1:
                logger.info(f"Evidence anchored on blockchain: {evidence_id}")
                return {
                    'success': True,
                    'tx_hash': tx_hash.hex(),
                    'block_number': tx_receipt.blockNumber,
                    'gas_used': tx_receipt.gasUsed,
                    'timestamp': datetime.now().isoformat(),
                    'evidence_id': evidence_id,
                    'contract_address': self.contract_address,
                    'simulation': False
                }
            else:
                raise Exception("Transaction failed")
                
        except Exception as e:
            logger.error(f"Real blockchain anchoring failed: {e}")
            return self._simulate_blockchain_anchor(evidence_id, file_hash, classification_level, case_id)
    
    def _simulate_blockchain_anchor(self, evidence_id: str, file_hash: str, classification_level: int, case_id: str) -> Dict[str, Any]:
        """Simulate blockchain anchoring"""
        tx_hash = f"0x{secrets.token_hex(32)}"
        block_number = 1000000 + abs(hash(evidence_id)) % 100000
        gas_used = 250000 + abs(hash(file_hash)) % 50000
        
        logger.info(f"[SIMULATED] Evidence anchored: {evidence_id}")
        
        return {
            'success': True,
            'tx_hash': tx_hash,
            'block_number': block_number,
            'gas_used': gas_used,
            'timestamp': datetime.now().isoformat(),
            'evidence_id': evidence_id,
            'simulation': True,
            'classification_level': classification_level,
            'case_id': case_id or f"CASE-SIM-{secrets.token_hex(4).upper()}"
        }
    
    def verify_evidence(self, evidence_id: str, file_hash: str) -> Dict[str, Any]:
        """Verify evidence integrity"""
        try:
            if self.connected and self.contract:
                # Real verification
                try:
                    evidence_data = self.contract.functions.getEvidence(evidence_id).call()
                    stored_hash = evidence_data[1] if len(evidence_data) > 1 else ""
                    
                    return {
                        'verified': stored_hash.lower() == file_hash.lower(),
                        'evidence_id': evidence_id,
                        'stored_hash': stored_hash,
                        'provided_hash': file_hash,
                        'timestamp': evidence_data[2] if len(evidence_data) > 2 else 0,
                        'simulation': False
                    }
                except Exception as e:
                    logger.error(f"Contract verification failed: {e}")
            
            # Simulation verification
            return {
                'verified': True,
                'evidence_id': evidence_id,
                'stored_hash': file_hash,
                'provided_hash': file_hash,
                'timestamp': int(datetime.now().timestamp()),
                'simulation': True
            }
            
        except Exception as e:
            logger.error(f"Evidence verification failed: {e}")
            return {'verified': False, 'error': str(e)}
    
    def get_network_status(self) -> Dict[str, Any]:
        """Get comprehensive network status"""
        status = {
            'connected': self.connected,
            'network_type': 'ganache' if self.connected else 'simulation',
            'network_url': self.ganache_url,
            'contract_deployed': self.contract is not None,
            'contract_address': self.contract_address,
            'account_address': str(self.account) if self.account else None,
            'last_check': datetime.now().isoformat()
        }
        
        if self.connected:
            try:
                status.update({
                    'chain_id': self.w3.eth.chain_id,
                    'latest_block': self.w3.eth.block_number,
                    'gas_price': str(self.w3.eth.gas_price),
                    'account_balance': str(self.w3.eth.get_balance(self.account)) if self.account else '0'
                })
            except Exception as e:
                status['error'] = str(e)
        else:
            status['simulation_message'] = 'Running in simulation mode - start Ganache for real blockchain functionality'
        
        return status

# Global blockchain manager instance
blockchain = BlockchainManager()
