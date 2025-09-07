# deploy.py
import json
from web3 import Web3
from solcx import compile_standard, install_solc
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv(os.path.join('assets', '.env'))
GANACHE_URL = os.getenv("GANACHE_URL")
WALLET_PRIVATE_KEY = os.getenv("WALLET_PRIVATE_KEY")

def deploy_contract():
    # 1. Compile the Solidity Contract
    with open("EvidenceRegistry.sol", "r") as file:
        evidence_registry_file = file.read()

    print("Installing/Verifying Solidity compiler...")
    install_solc("0.8.20")
    
    compiled_sol = compile_standard(
        {"language": "Solidity", "sources": {"EvidenceRegistry.sol": {"content": evidence_registry_file}}},
        solc_version="0.8.20",
    )
    
    # 2. Save the ABI
    abi = compiled_sol["contracts"]["EvidenceRegistry.sol"]["EvidenceRegistry"]["abi"]
    with open("abi.json", "w") as file:
        json.dump(abi, file, indent=4)
    print("ABI created successfully: abi.json")
    
    # 3. Connect to Ganache
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    account = w3.eth.account.from_key(WALLET_PRIVATE_KEY)
    
    # 4. Deploy the Contract
    bytecode = compiled_sol["contracts"]["EvidenceRegistry.sol"]["EvidenceRegistry"]["evm"]["bytecode"]["object"]
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    
    print("Deploying contract...")
    tx_hash = Contract.constructor().transact({"from": account.address})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    print("\n-------------------------------------------------")
    print("  CONTRACT DEPLOYED SUCCESSFULLY!")
    print(f"  Contract Address: {tx_receipt.contractAddress}")
    print("  IMPORTANT: Copy this address and paste it into your")
    print("  assets/.env file for the CONTRACT_ADDRESS variable.")
    print("-------------------------------------------------")

if __name__ == "__main__":
    deploy_contract()
