import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import time
from pathlib import Path

# Security Configuration
MASTER_PASSWORD = "admin123"
SALT = b'\x12\xf4\x8b\xa9\x7f\xc3\x91\x16\xe8\xd3\xf2\x45\x98\xa2\xe1\x5b'
FAILED_ATTEMPT_LOCKOUT = 30  # seconds
DATA_FILE = "secure_vault.json"
USERS_FILE = "users.json"  # Store user credentials

# Session state
def init_session():
    if 'stored_data' not in st.session_state:
        st.session_state.stored_data = load_data(DATA_FILE)
    if 'failed_attempts' not in st.session_state:
        st.session_state.failed_attempts = 0
    if 'lockout_time' not in st.session_state:
        st.session_state.lockout_time = 0
    if 'delete_verified' not in st.session_state:
        st.session_state.delete_verified = False
    if 'is_authenticated' not in st.session_state:
        st.session_state.is_authenticated = False
    if 'current_user' not in st.session_state:
        st.session_state.current_user = None

# Load/save data
def load_data(filename):
    if Path(filename).exists():
        with open(filename, 'r') as f:
            return json.load(f)
    return {}

def save_data(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4, sort_keys=True)

# Encryption helpers
def derive_key(passkey: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

def encrypt_data(text: str, passkey: str) -> str:
    fernet = Fernet(derive_key(passkey))
    return fernet.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text: str, passkey: str) -> str:
    try:
        fernet = Fernet(derive_key(passkey))
        return fernet.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Lockout checker
def check_lockout() -> bool:
    if st.session_state.lockout_time > time.time():
        remaining = int(st.session_state.lockout_time - time.time())
        st.warning(f"🚫 Account locked. Time remaining: {remaining} seconds.")
        time.sleep(1)
        st.rerun()
        return True
    return False

# Pages
def home_page():
    st.subheader("🏠 Welcome to the Secure Data Vault")
    st.write("Securely store and retrieve sensitive data using military-grade encryption.")
    user_data = st.session_state.stored_data.get(st.session_state.current_user, {})
    if user_data:
        st.info(f"🔐 Currently storing {len(user_data)} encrypted items")
    else:
        st.warning("No data stored yet. Use 'Store Data' to begin.")

def store_data_page():
    st.subheader("📥 Store New Data")
    user_data = st.text_area("Data to Encrypt:", height=150, key="data_input")
    passkey = st.text_input("Encryption Passphrase:", type="password", key="encrypt_pass")
    if st.button("🔒 Encrypt & Save"):
        if user_data and passkey:
            passkey_hash = hashlib.sha3_256(passkey.encode()).hexdigest()
            user_stored_data = st.session_state.stored_data.get(st.session_state.current_user, {})
            if any(entry["passkey_hash"] == passkey_hash for entry in user_stored_data.values()):
                st.error("❌ This passphrase has already been used. Please use a unique passphrase.")
                return
            encrypted = encrypt_data(user_data, passkey)
            entry_id = f"entry_{len(user_stored_data)+1}"
            user_stored_data[entry_id] = {
                "encrypted_text": encrypted,
                "passkey_hash": passkey_hash
            }
            st.session_state.stored_data[st.session_state.current_user] = user_stored_data
            save_data(DATA_FILE, st.session_state.stored_data)
            st.success("✅ Data securely stored!")
            with st.expander("🔍 View Encrypted Data"):
                st.code(encrypted)
        else:
            st.error("❌ Both fields are required!")

def retrieve_data_page():
    st.subheader("📤 Retrieve Stored Data")
    if check_lockout():
        return
    user_data = st.session_state.stored_data.get(st.session_state.current_user, {})
    if user_data:
        entry_ids = list(user_data.keys())
        selected_id = st.selectbox("Select stored data:", entry_ids)
        entry = user_data[selected_id]
        encrypted_text = entry["encrypted_text"]
        st.text_area("Encrypted Data:", value=encrypted_text, height=100, disabled=True)
    else:
        st.warning("No data stored yet")
        return
    passkey = st.text_input("Decryption Passphrase:", type="password", key="decrypt_pass")
    if st.button("🔓 Decrypt"):
        if not passkey:
            st.error("❌ Passphrase required!")
            return
        input_hash = hashlib.sha3_256(passkey.encode()).hexdigest()
        if entry["passkey_hash"] == input_hash:
            decrypted = decrypt_data(encrypted_text, passkey)
            if decrypted:
                st.session_state.failed_attempts = 0
                st.success("✅ Decryption Successful!")
                with st.expander("👀 View Decrypted Data"):
                    st.text_area("Decrypted Data:", value=decrypted, height=150, key="decrypted_output")
            else:
                st.error("❌ Decryption failed - invalid ciphertext")
        else:
            st.session_state.failed_attempts += 1
            attempts_left = 3 - st.session_state.failed_attempts
            if attempts_left > 0:
                st.error(f"❌ Invalid passkey. Attempts left: {attempts_left}")
            else:
                st.session_state.lockout_time = time.time() + FAILED_ATTEMPT_LOCKOUT
                st.session_state.failed_attempts = 0
                remaining = int(st.session_state.lockout_time - time.time())
                st.error(f"🔒 Too many failed attempts. Account locked for {remaining} seconds.")

def delete_data_page():
    st.subheader("🗑️ Delete Stored Entry")
    if check_lockout():
        return
    user_data = st.session_state.stored_data.get(st.session_state.current_user, {})
    if not user_data:
        st.warning("No data stored to delete.")
        return
    entry_ids = list(user_data.keys())
    selected_id = st.selectbox("Select entry to delete:", entry_ids)
    st.text_area("Encrypted Data (read-only)", user_data[selected_id]["encrypted_text"], height=100, disabled=True)
    master_pass = st.text_input("Enter Master Password to delete", type="password")
    if not st.session_state.delete_verified:
        if st.button("🔍 Verify Master Password"):
            if master_pass == MASTER_PASSWORD:
                st.session_state.delete_verified = True
                st.success("✅ Verified! Click below to confirm deletion.")
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                if attempts_left > 0:
                    st.error(f"❌ Invalid master password. Attempts left: {attempts_left}")
                else:
                    st.session_state.lockout_time = time.time() + FAILED_ATTEMPT_LOCKOUT
                    st.session_state.failed_attempts = 0
                    remaining = int(st.session_state.lockout_time - time.time())
                    st.error(f"🔒 Too many failed attempts. Account locked for {remaining} seconds.")
    else:
        if st.button("❌ Confirm Delete", key="confirm_delete"):
            del user_data[selected_id]
            st.session_state.stored_data[st.session_state.current_user] = user_data
            save_data(DATA_FILE, st.session_state.stored_data)
            st.success("✅ Entry deleted successfully!")
            st.session_state.delete_verified = False
            st.rerun()

# Login and Register Pages
def register_user(username, password):
    users_data = load_data(USERS_FILE)
    if username in users_data:
        st.error("❌ User already exists.")
    else:
        password_hash = hashlib.sha3_256(password.encode()).hexdigest()
        users_data[username] = {"password_hash": password_hash}
        save_data(USERS_FILE, users_data)
        st.success("✅ User registered successfully!")

def login_user(username, password):
    users_data = load_data(USERS_FILE)
    if username not in users_data:
        st.error("❌ User does not exist.")
        return False
    password_hash = hashlib.sha3_256(password.encode()).hexdigest()
    if users_data[username]["password_hash"] == password_hash:
        st.session_state.is_authenticated = True
        st.session_state.current_user = username
        st.success("✅ Login successful!")
        return True
    else:
        st.error("❌ Incorrect password.")
        return False

def login_register_page():
    st.subheader("🔐 Login or Register")
    choice = st.radio("Choose Option", ["Login", "Register"])
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if choice == "Login":
        if st.button("Login"):
            if login_user(username, password):
                st.session_state.is_authenticated = True
                st.rerun()
                
    elif choice == "Register":
        if st.button("Register"):
            register_user(username, password)

# Main App
def main():
    st.title("🔒 Secure Data Vault")
    st.sidebar.header("Navigation")
    init_session()

    if not st.session_state.is_authenticated:
        login_register_page()
        return

    menu_options = {
        "Home": home_page,
        "Store Data": store_data_page,
        "Retrieve Data": retrieve_data_page,
        "Delete Data": delete_data_page,
        "Logout": lambda: logout()
    }

    choice = st.sidebar.radio("Menu", list(menu_options.keys()))
    menu_options[choice]()

def logout():
    st.session_state.is_authenticated = False
    st.session_state.current_user = None
    st.rerun()

if __name__ == "__main__":
    main()
