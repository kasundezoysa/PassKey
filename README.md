# 🛡️ Passkey & WebAuthn Lab

A minimalist Python and JavaScript implementation of passwordless authentication using the **WebAuthn API**. 
This lab demonstrates how to use hardware biometrics (TouchID, FaceID) and mobile devices as secure authenticators.

## 🚀 Features

* **Passwordless Registration:** Create credentials using a Mac's Secure Enclave or a mobile phone.
* **Cross-Platform Support:** Register on a PC/Mac and authenticate using a smartphone via QR code (Hybrid Transport).
* **Resident Keys (Discoverable Credentials):** Uses `ResidentKeyRequirement.PREFERRED` to enable a seamless "Passkey" experience.
* **Replay Protection:** Implements `sign_count` tracking to prevent credential cloning.
* **Modern UI:** A clean, Apple-inspired interface with responsive input fields.

## 🛠️ Tech Stack

* **Backend:** Python 3.10+ with `Flask` and `py_webauthn` library.
* **Frontend:** Vanilla JavaScript (WebAuthn Navigator API).
* **Storage:** In-memory dictionary for rapid lab testing.

## 📋 Prerequisites

1. **HTTPS or Localhost:** WebAuthn requires a secure context. Running on `http://localhost:8080` is supported.
2. **Hardware:** A device with a biometric sensor (TouchID/FaceID) or a mobile phone with Bluetooth enabled.
3. **Python Libraries:**
```pip install flask flask-cors webauthn


## 🔧 Installation & Setup

1. **Clone the repository:**
> git clone https://github.com/your-username/passkey-lab.git
> cd passkey-lab

2. **Run the server:**
> python app.py

3. **Access the Lab:**
Open your browser and navigate to `http://localhost:8080`.

## 📖 How it Works

### 1. Registration

The server generates a unique **Challenge** and user ID. 
The browser prompts the user to "create a passkey." 
The Public Key is sent back and stored in the server's `db` dictionary.

### 2. Login

The server sends the stored `credential_id`. 
The user provides a biometric scan. 
The server verifies the cryptographic signature against the stored **Public Key**.

## ⚠️ Important Note on `sign_count`

If you are using **Synced Passkeys** (iCloud Keychain/Google Password Manager), 
the `sign_count` may stay at `0`. This is expected behavior for credentials that exist on multiple devices. 
Security is maintained through the unique, one-time-use **Challenge**.
