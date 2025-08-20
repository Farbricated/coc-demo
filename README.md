# 🛡️ Advanced Blockchain Evidence Management System

This project is an innovative, full-stack platform designed to provide a reliable, transparent, and tamper-proof chain of custody for digital evidence. It's built to demonstrate how modern technology can solve a critical problem in forensics: proving that digital evidence has not been altered.

This system is perfect for students, developers, and professionals interested in blockchain applications, digital forensics, and secure web development.

***

## 📖 How It Works: The Chain of Custody Flow

The system ensures evidence integrity through a clear, three-step process:

1.  **INGEST:** An operator uploads a new piece of digital evidence (like an image) and assigns it a **Case ID**.
    *   The system immediately performs a **forensic analysis**, extracting all metadata and assessing it for tampering risks.
    *   It calculates a unique digital fingerprint (an **SHA-256 hash**) of the file.

2.  **RECORD:** This digital fingerprint is then permanently recorded in two separate, secure locations:
    *   **On the Blockchain:** The hash is sent to a custom **Solidity smart contract**, creating an immutable, timestamped, and publicly verifiable record. This is the ultimate source of truth.
    *   **In the Database:** A full record, including the hash, case ID, filename, and all forensic analysis data, is stored in a **MongoDB Atlas** database for fast and easy access.

3.  **VERIFY:** At any point in the future, an investigator, lawyer, or court official can upload their copy of the evidence to the **Verify Integrity** page.
    *   The system calculates a new hash of their file and compares it against the original records from both the database and the blockchain.
    *   It provides an instant, clear "✅ Verified" or "❌ Not Verified" status, proving whether the evidence is still in its original, pristine state.
    

***

## ✨ Key Features

*   **🔍 Advanced Forensic Analysis:** Automatically extracts all EXIF metadata and runs a risk assessment engine to detect signs of tampering.
*   **🔗 Immutable Blockchain Ledger:** Uses a custom Solidity smart contract on an Ethereum-compatible blockchain to create a permanent, unchangeable record of evidence.
*   **🗂️ Centralized Database with Case Management:** All evidence is cataloged with a Case ID and stored securely in MongoDB Atlas.
*   **✅ End-to-End Verification:** A simple, powerful workflow for anyone to independently verify the integrity of evidence against trusted records.
*   **🖥️ Responsive & Professional UI:** A clean, multi-page web application built with Python and Dash, featuring a dynamic dashboard with real-time statistics.

***

*   **🔍 Advanced Forensic Analysis:**
    *   Automatic extraction and display of all available EXIF metadata, including GPS coordinates, timestamps, and camera/device information.
    *   Detection and decoding of steganographic content hidden via Least Significant Bit (LSB) techniques.
    *   Recognition and decoding of QR codes embedded within images.

*   **🔗 Immutable Blockchain Ledger:**
    *   Seamless integration with any Ethereum-compatible blockchain (using Ganache for local development).
    *   A custom Solidity smart contract deployed to the network to store cryptographic hashes, providing an immutable and publicly verifiable proof of evidence integrity.

*   **🗂️ Centralized NoSQL Database Management:**
    *   Scalable and persistent evidence storage using a cloud-based MongoDB Atlas cluster.
    *   Efficient querying and filtering of all evidence records through an interactive web UI.

*   **✅ End-to-End Verification Workflow:**
    *   Users can upload any image to independently re-calculate its hash and verify it against both the blockchain ledger and the stored database record.
    *   The system provides clear, immediate feedback, displaying a "Verified" or "Not Verified" status for both verification methods, completing the chain of custody loop.

*   **🖥️ Responsive & Professional UI:**
    *   A multi-page web application built with Python's Dash and Dash Bootstrap Components.
    *   Features a professional sidebar for easy navigation between the Dashboard, Upload, Verify, and Database pages.
    *   A fully responsive design that provides an optimal user experience on desktops, tablets, and mobile devices.
    *   A dynamic dashboard with real-time system status indicators for MongoDB and blockchain connectivity.

***

## 🛠️ Tech Stack

*   **Frontend & Backend:** Python, Dash, Flask, Dash Bootstrap Components
*   **Database:** MongoDB (via MongoDB Atlas)
*   **Blockchain:** Solidity, Ganache, Web3.py
*   **Forensic & Utility Libraries:** Pillow, piexif, python-dotenv
*   **Forensic & Utility Libraries:** Pillow, piexif, pyzbar, stegano, python-dotenv
  
***

## 🚀 Getting Started

Follow these instructions to get a local copy of the project up and running.

### Prerequisites

This project requires a few free tools. Don't worry, we'll walk you through setting them up!

*   **Python (3.8 or higher):** The core programming language for the application. You can download it from [python.org](https://www.python.org/downloads/).
*   **Git:** A version control system used to copy the project files to your machine. You can get it from [git-scm.com](https://git-scm.com/downloads).
*   **Ganache UI:** A personal blockchain for local development. It's like a blockchain simulator that runs on your computer. Download it from the [Truffle Suite website](https://trufflesuite.com/ganache/).
*   **MongoDB Atlas Account:** A free, cloud-hosted database. Sign up at [mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas) and create a free-tier cluster.

### Installation & Setup

#### **Step 1: Clone the Repository**

First, use Git to download the project files to your computer.

```sh
git clone https://github.com/your-username/coc-demo.git
cd coc-demo
```

#### **Step 2: Create a Virtual Environment**

This creates an isolated space for this project's Python libraries so they don't interfere with other projects.

```sh
# Create the environment
python -m venv venv

# Activate it
# On macOS and Linux:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate
```
*(You'll know it's active when you see `(venv)` at the beginning of your terminal prompt.)*

#### **Step 3: Install Dependencies**

This command reads the `requirements.txt` file and installs all the necessary Python libraries.

```sh
pip install -r requirements.txt
```

#### **Step 4: Deploy the Smart Contract**

Before the app can run, you need to deploy its smart contract to your local Ganache blockchain.

1.  **Start Ganache:** Open the Ganache UI application you installed. Click "Quickstart" to launch a personal Ethereum blockchain.
2.  **Use Remix IDE:** Open your web browser and navigate to the [Remix IDE](https://remix.ethereum.org/).
3.  **Load the Contract:** In Remix, create a new file named `EvidenceRegistry.sol` and paste the contents of this project's `EvidenceRegistry.sol` file into it.
4.  **Compile:** Go to the "Solidity Compiler" tab in Remix (the second icon on the left). Make sure the compiler version is `0.8.0` or compatible, and click "Compile EvidenceRegistry.sol".
5.  **Deploy:**
    *   Go to the "Deploy & Run Transactions" tab (the third icon).
    *   Change the "ENVIRONMENT" dropdown from "Remix VM" to **"Injected Provider - MetaMask"** (or "Injected Web3" if you don't use MetaMask, ensuring it connects to Ganache).
    *   Click the "Deploy" button.
6.  **Get the Contract Address:** After deployment, you will see your deployed contract under the "Deployed Contracts" section in Remix. Copy its address. You'll need it for the next step.

#### **Step 5: Configure Environment Variables**

This is where you'll connect the app to your database and blockchain.

1.  In the project's root directory, create a folder named `assets`.
2.  Inside `assets`, create a file named `.env`.
3.  Open the `.env` file and fill it with your credentials, using the format below.

    ```dotenv
    # .env file inside the 'assets' folder
    
    # Get this from your MongoDB Atlas dashboard
    MONGO_URI="mongodb+srv://:@/..."
    
    # This is usually http://127.0.0.1:7545 for Ganache UI
    GANACHE_URL="http://127.0.0.1:7545"
    
    # In Ganache, copy the private key from one of the accounts
    WALLET_PRIVATE_KEY="your_ganache_wallet_private_key_here"
    
    # The contract address you copied from Remix in the previous step
    CONTRACT_ADDRESS="your_deployed_contract_address_here"
    ```

#### **Step 6: Run the Application**

Now you're ready to start the server!

```sh
python app.py
```

#### **Step 7: Access the UI**

Open your web browser and go to **`http://127.0.0.1:8050`**. You should see the application dashboard.

***

## 📁 Understanding the Components

*   `app.py`: The heart of the application. It defines the user interface (UI) layouts, handles user interactions (callbacks), and orchestrates the overall application flow.
*   `blockchain.py`: Manages all communication with the Ganache blockchain. It handles recording new evidence hashes and retrieving them for verification.
*   `database.py`: Manages all communication with the MongoDB database. It's responsible for saving, finding, and retrieving evidence records.
*   `EvidenceRegistry.sol`: The Solidity code for our smart contract. This defines the rules for how data is stored on the blockchain.
*   `requirements.txt`: A list of all the Python libraries the project needs to run. `pip` uses this file to install everything at once.
*   `assets/.env`: Your local, secret configuration file. It stores your private keys and connection strings so they are kept separate from the main source code.

***

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.
=======
Follow these instructions to get a local copy of the project up and running for development and testing purposes.

### Prerequisites

*   Python 3.8 or higher
*   Git version control
*   Ganache Desktop Application (or Ganache CLI)
*   A free MongoDB Atlas account and a provisioned cluster

### Installation & Setup

1.  **Clone the Repository:**
    ```sh
    git clone https://github.com/Farbricated/coc-demo.git
    cd coc-demo
    ```

2.  **Create and Activate a Virtual Environment:**
    It is highly recommended to use a virtual environment to manage project dependencies.
    ```sh
    # Create the environment
    python -m venv venv

    # Activate it
    # On macOS and Linux:
    source venv/bin/activate
    # On Windows:
    .\venv\Scripts\activate
    ```

3.  **Install Dependencies:**
    Install all required Python libraries from the `requirements.txt` file.
    ```sh
    pip install -r requirements.txt
    ```

4.  **Configure Environment Variables:**
    *   Create your own local environment file by copying the provided template:
        ```sh
        # On macOS and Linux:
        cp .env.example .env
        # On Windows:
        copy .env.example .env
        ```
    *   Open the newly created `.env` file and add your actual credentials for your MongoDB Atlas connection string, your Ganache wallet private key, and the address of your deployed smart contract.
    > **⚠️ Important:** The `.env` file is listed in `.gitignore` and must **never** be committed to your repository to protect your secret keys.

5.  **Run the Application:**
    Once your environment is set up and Ganache is running, start the Dash web server.
    ```sh
    python app.py
    ```

6.  **Access the UI:**
    Open your web browser and navigate to `http://127.0.0.1:8050`.

***

## 📁 Project Structure

```
coc-demo/
├── .gitignore           # Specifies files to be ignored by Git
├── .env.example         # Template for environment variables
├── README.md            # This documentation file
├── app.py               # Main Dash application, UI layouts, and callbacks
├── blockchain.py        # All blockchain interaction logic
├── database.py          # All MongoDB interaction logic
├── requirements.txt     # List of Python dependencies for pip
└── EvidenceRegistry.sol # The Solidity smart contract code
```

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.
