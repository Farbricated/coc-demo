# coc-demo/blockchain.py

from web3 import Web3
from dotenv import load_dotenv
import os

# Correctly locate the .env file within the 'assets' directory
dotenv_path = os.path.join(os.path.dirname(__file__), '..', 'assets', '.env')
load_dotenv(dotenv_path=dotenv_path)

GANACHE_URL = os.getenv("GANACHE_URL")
WALLET_PRIVATE_KEY = os.getenv("WALLET_PRIVATE_KEY")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")

# Ensure your ABI is a clean JSON string
CONTRACT_ABI = """
[
    {
        "inputs": [
            {
                "internalType": "bytes32",
                "name": "_hash",
                "type": "bytes32"
            }
        ],
        "name": "getEvidenceTimestamp",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "bytes32",
                "name": "_hash",
                "type": "bytes32"
            }
        ],
        "name": "registerEvidence",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]
"""

# --- Connection Setup ---
w3, is_connected, contract = None, False, None
if GANACHE_URL:
    try:
        w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
        is_connected = w3.is_connected()
    except Exception as e:
        is_connected = False
        print(f"Failed to connect to blockchain: {e}")
print(f"Blockchain connection status: {is_connected}")

if is_connected and CONTRACT_ADDRESS and 'YOUR_DEPLOYED' not in CONTRACT_ADDRESS:
    try:
        contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=CONTRACT_ABI)
        print("Smart contract loaded successfully.")
    except Exception as e:
        print(f"Could not load smart contract: {e}")
else:
    print("Contract address not set or blockchain not connected.")

def record_hash_on_blockchain(image_hash):
    """
    Sends a transaction to the smart contract to record an evidence hash.
    Includes robust error handling and the final corrected attribute name.
    """
    if not contract or not WALLET_PRIVATE_KEY:
        print("Blockchain Error: Smart contract or wallet private key is not configured.")
        return None
    
    try:
        account = w3.eth.account.from_key(WALLET_PRIVATE_KEY)
        
        tx = contract.functions.registerEvidence(bytes.fromhex(image_hash)).build_transaction({
            'from': account.address,
            'nonce': w3.eth.get_transaction_count(account.address)
        })
        
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=WALLET_PRIVATE_KEY)
        
        # --- THIS IS THE FINAL CORRECTED LINE ---
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        print(f"Transaction sent to blockchain. Waiting for receipt... TX Hash: {tx_hash.hex()}")
        
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if tx_receipt['status'] == 0:
            print("Transaction FAILED! Status is 0. Check the revert reason in Ganache.")
            return None
        
        print(f"Transaction successful! Block: {tx_receipt['blockNumber']}")
        return tx_hash.hex()
        
    except Exception as e:
        print(f"An explicit error occurred during the blockchain transaction: {e}")
        return None

def get_evidence_timestamp(image_hash):
    if not contract: return 0
    try:
        return contract.functions.getEvidenceTimestamp(bytes.fromhex(image_hash)).call()
    except Exception as e:
        print(f"Error calling getEvidenceTimestamp: {e}")
        return 0
