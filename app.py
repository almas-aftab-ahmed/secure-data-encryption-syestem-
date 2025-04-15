import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (In production, store this securely)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data store
stored_data = {}
failed_attempts = 0

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)
    
    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None

# Streamlit UI
st.title("🔐 Secure Data Encryption App")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Home":
    st.subheader("Welcome to the Secure Data App")
    st.write("Use this to encrypt and decrypt sensitive info using passkeys.")

elif choice == "Store Data":
    st.subheader("Encrypt and Store")
    user_data = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Enter passkey:", type="password")
    
    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data, passkey)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language="text")
        else:
            st.error("Please enter both fields.")

elif choice == "Retrieve Data":
    st.subheader("Decrypt Stored Data")
    encrypted_text = st.text_area("Enter encrypted text:")
    passkey = st.text_input("Enter passkey:", type="password")
    
    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted = decrypt_data(encrypted_text, passkey)
            if decrypted:
                st.success(f"Decrypted Data: {decrypted}")
            else:
                st.error(f"Wrong passkey! {3 - failed_attempts} attempts left.")
                if failed_attempts >= 3:
                    st.warning("Too many failed attempts. Redirecting to Login.")
                    st.experimental_rerun()
        else:
            st.error("Please fill in all fields.")

elif choice == "Login":
    st.subheader("Login to Reset Attempts")
    master = st.text_input("Enter master password:", type="password")
    
    if st.button("Login"):
        if master == "admin123":
            failed_attempts = 0
            st.success("Login successful. Redirecting...")
            st.experimental_rerun()
        else:
            st.error("Incorrect password.")