# 🛡️ Advanced Blockchain Evidence Management System

This project is an innovative, full-stack platform designed to provide a reliable, transparent, and tamper-proof chain of custody for digital evidence. Leveraging cutting-edge blockchain technology alongside advanced forensic analysis tools, this system ensures the integrity and traceability of evidentiary images, making it an ideal prototype for law enforcement and legal applications.

***

## ✨ Key Features

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
*   **Forensic & Utility Libraries:** Pillow, piexif, pyzbar, stegano, python-dotenv

***

## 🚀 Getting Started

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

***

## 🌟 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

***

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.
