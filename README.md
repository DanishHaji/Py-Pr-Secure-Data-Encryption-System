# 🔒 Secure Data Vault

A multi-user encryption system built with Streamlit that provides secure data storage with military-grade AES-256 encryption.

## ✨ Features
- **User Authentication**: Login/register system with hashed passwords
- **Secure Encryption**: PBKDF2 key derivation with 100,000 iterations
- **Data Management**:
  - Store encrypted data with unique passphrases
  - Retrieve data with proper credentials
  - Delete entries with admin verification
- **Security**:
  - 3-attempt lockout system (30-second timeout)
  - Separate encryption keys per user/data
  - No plaintext storage of sensitive data

## 🚀 Quick Start
1. Install requirements:
```bash
pip install streamlit cryptography
```
2. Run the app:
```bash
streamlit run app.py
```
3. Register a user or login with:
**Default admin password: admin123**

## 🛠️ Technical Stack
- **Frontend:** Streamlit
- **Encryption:** cryptography (Fernet with AES-256)
- **Storage:** JSON files (secure_vault.json, users.json)

## ⚠️ Important Notes
- Change the default MASTER_PASSWORD in production
- For real-world use, store salts/keys more securely
- Data persists via JSON files (in-memory during session)