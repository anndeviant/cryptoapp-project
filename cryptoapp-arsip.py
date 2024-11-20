import streamlit as st
import sqlite3
from datetime import datetime
import hashlib
import time
import pandas as pd
import numpy as np
from PIL import Image
import cloudinary
import cloudinary.uploader
import secrets
from io import BytesIO
import requests
from cryptography.fernet import Fernet
# import pyperclip

# Load environment variables
PIN = "Annas#123"

# Add Cloudinary configuration
cloudinary.config(
    cloud_name="ddeff44yv",
    api_key="149435764148321",
    api_secret="IndKSdSVIxDnCU20WOHDiPf_H0c",
)

# Database connection~
conn = sqlite3.connect("data_instansi_kesehatan.db")
c = conn.cursor()
c.execute(
    """CREATE TABLE IF NOT EXISTS admin
             (username TEXT PRIMARY KEY, password TEXT, created_at TIMESTAMP)"""
)
c.execute(
    """CREATE TABLE IF NOT EXISTS pin_instansi
             (pin TEXT PRIMARY KEY, created_at TIMESTAMP)"""
)
c.execute(
    """CREATE TABLE IF NOT EXISTS encrypted_data 
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_name TEXT,
            encrypted_text TEXT, 
            caesar_key INTEGER,
            rc4_key TEXT,
            created_at TIMESTAMP)"""
)

c.execute(
    """
    CREATE TABLE IF NOT EXISTS encrypted_stegano (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_name TEXT,
        encryption_key TEXT,
        created_at TIMESTAMP,
        image_url TEXT
    )
"""
)

c.execute(
    """
    CREATE TABLE IF NOT EXISTS encrypted_docs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_name TEXT,
        encryption_key TEXT, 
        file_url TEXT,
        file_name TEXT,
        created_at TIMESTAMP
    )
"""
)
conn.commit()

# Insert the key PIN if not exists
c.execute("SELECT * FROM pin_instansi WHERE pin=?", (PIN,))
if c.fetchone() is None:
    c.execute(
        "INSERT INTO pin_instansi (pin, created_at) VALUES (?, ?)",
        (PIN, datetime.now()),
    )
    conn.commit()


# Helper functions
def hash_username(username):
    return username


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def authenticate(username, password):
    c.execute(
        "SELECT * FROM admin WHERE username=? AND password=?", (username, password)
    )
    return c.fetchone() is not None


def register_user(username, password, pin):
    c.execute("SELECT * FROM pin_instansi WHERE pin=?", (pin,))
    if c.fetchone() is None:
        return False, "Invalid PIN Instansi!"
    c.execute("SELECT * FROM admin WHERE username=?", (username,))
    if c.fetchone() is not None:
        return False, "Username sudah terdaftar!"
    c.execute(
        "INSERT INTO admin (username, password, created_at) VALUES (?, ?, ?)",
        (username, password, datetime.now()),
    )
    conn.commit()
    return True, "Admin berhasil didaftarkan!"


def delete_user(username):
    c.execute("DELETE FROM admin WHERE username=?", (username,))
    conn.commit()


# Caesar cipher encryption
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord("A") if char.isupper() else ord("a")
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result


# RC4 encryption
def rc4_encrypt(text, key):
    S = list(range(256))
    j = 0
    # Key-scheduling algorithm
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-random generation algorithm
    i = j = 0
    result = []
    for char in text.encode():
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(char ^ k)

    return bytes(result).hex()


# RC4 decryption
def rc4_decrypt(encrypted_hex, key):
    encrypted = bytes.fromhex(encrypted_hex)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result = []
    for byte in encrypted:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    return bytes(result).decode()


# Caesar cipher decryption
def caesar_decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord("A") if char.isupper() else ord("a")
            result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            result += char
    return result


# LSB Encoding Steganography
def to_binary(data):
    """Convert data to binary string"""
    if isinstance(data, str):
        return "".join(format(ord(i), "08b") for i in data)
    return "".join(format(i, "08b") for i in data)


def encode_lsb(image, secret_data, key):
    """
    Encode secret data into image using LSB steganography
    """
    # Convert image to numpy array
    img_array = np.array(image)

    # Ensure image is RGB
    if len(img_array.shape) < 3:
        raise ValueError("Image must be RGB")

    # Get image dimensions
    height, width = img_array.shape[:2]

    # Prepare secret message with key and terminator
    secret = f"{key}:{secret_data}:END"
    binary_secret = to_binary(secret)

    # Calculate required pixels
    required_pixels = len(binary_secret)
    available_pixels = height * width * 3  # 3 channels RGB

    if required_pixels > available_pixels:
        raise ValueError(
            f"Image too small. Needs {required_pixels} pixels but has {available_pixels}"
        )

    # Create copy of image
    encoded_image = img_array.copy()

    data_index = 0
    # Iterate through pixels
    for row in range(height):
        for col in range(width):
            # Modify each RGB channel
            for color_channel in range(3):
                if data_index < len(binary_secret):
                    # Get pixel value and binary secret bit
                    pixel_value = encoded_image[row, col, color_channel]
                    secret_bit = int(binary_secret[data_index])

                    # Clear LSB and set it to secret bit
                    encoded_image[row, col, color_channel] = (
                        pixel_value & 254
                    ) | secret_bit

                    data_index += 1
                else:
                    break
            if data_index >= len(binary_secret):
                break
        if data_index >= len(binary_secret):
            break

    # Convert back to PIL Image
    return Image.fromarray(encoded_image)


# LSB Decoding Steganography
def decode_lsb(encoded_image):
    """
    Decode message hidden in image using LSB steganography
    Returns (key, message) tuple
    """
    # Convert to numpy array
    img_array = np.array(encoded_image)

    # Validate image format
    if len(img_array.shape) < 3:
        raise ValueError("Image must be RGB format")

    # Extract binary data from LSBs
    binary_data = ""
    decoded_text = ""

    for row in range(img_array.shape[0]):
        for col in range(img_array.shape[1]):
            for channel in range(3):  # RGB channels
                # Extract LSB
                binary_data += str(img_array[row, col, channel] & 1)

                # Convert every 8 bits to character
                if len(binary_data) >= 8:
                    current_byte = binary_data[:8]
                    binary_data = binary_data[8:]
                    decoded_text += chr(int(current_byte, 2))

                    # Check for terminator
                    if ":END" in decoded_text:
                        try:
                            # Split at first occurrence of ':'
                            message = decoded_text[: decoded_text.index(":END")]
                            key, content = message.split(":", 1)
                            return key, content
                        except ValueError:
                            continue

                    # Safety check
                    if len(decoded_text) > 1000:  # Reduced from 10000
                        raise ValueError("No valid message found")

    raise ValueError("No hidden message found")


# FILE Encryption
def generate_key():
    return Fernet.generate_key()


def encrypt_file(file_bytes, key):
    f = Fernet(key)
    return f.encrypt(file_bytes)


def decrypt_file(encrypted_bytes, key):
    f = Fernet(key)
    return f.decrypt(encrypted_bytes)


# Pages
def login_page():
    st.markdown("## Pengarsipan Data Dokumen Kesehatan")
    st.markdown("### :closed_lock_with_key: Login as Admin!")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        col1, col2 = st.columns([1, 1])
        with col1:
            submitted = col1.container().form_submit_button(
                "Login", use_container_width=True
            )
        with col2:
            if col2.container().form_submit_button(
                "Go to Register", use_container_width=True
            ):
                st.session_state.page = "register"
                st.rerun()
        if submitted:
            if not username or not password:
                st.warning("Please enter both username and password")
            else:
                hashed_username = hash_username(username)
                hashed_password = hash_password(password)
                if authenticate(hashed_username, hashed_password):
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.rerun()
                else:
                    st.error("Invalid username or password")


def register_page():
    st.markdown("## Pengarsipan Data Dokumen Kesehatan")
    st.markdown("### :pencil2: Register as Admin!")
    with st.form("register_form"):
        new_username = st.text_input("Username")
        new_password = st.text_input("Password", type="password")
        pin = st.text_input("PIN Instansi", type="password")
        col1, col2 = st.columns([1, 1])
        with col1:
            submitted = col1.container().form_submit_button(
                "Register", use_container_width=True
            )
        with col2:
            if col2.container().form_submit_button(
                "Go to Login", use_container_width=True
            ):
                st.session_state.page = "login"
                st.rerun()
        if submitted:
            if not new_username or not new_password or not pin:
                st.warning("Please enter username, password, and PIN")
            else:
                hashed_password = hash_password(new_password)
                success, message = register_user(new_username, hashed_password, pin)
                if success:
                    st.success(message)
                    time.sleep(1)
                    st.session_state.page = "login"
                    st.rerun()
                else:
                    st.error(message)


def admin_page():
    st.markdown("# 📑 Arsip Management Dashboard")

    st.sidebar.markdown("### Data Management")
    history_option = st.sidebar.selectbox(
        "Pilih Arsip Data:",
        ["Arsip Admin", "Arsip Pesan", "Arsip Gambar", "Arsip Dokumen"],
    )

    if history_option == "Arsip Admin":
        st.markdown("### Arsip Data Admin")

        # Admin table
        st.markdown(
            "<div style='text-align: justify; margin-bottom: 10px;'>"
            "Arsip data admin merupakan kumpulan catatan mengenai akun admin yang terdaftar dalam sistem pengarsipan yang bertugas mengelola akses ke sistem dan memantau aktivitas administratif dalam platform."
            "</div>",
            unsafe_allow_html=True,
        )
        c.execute("SELECT * FROM admin")
        admin = c.fetchall()
        df = pd.DataFrame(admin, columns=["Username", "Password", "Created At"])
        df.index = df.index + 1
        st.table(df)

        # Delete user section with PIN validation
        st.markdown("### Delete Inactive Admin")
        delete_username = st.text_input("Username to delete")
        pin = st.text_input("Enter PIN Instansi", type="password")
        if st.button("Delete Admin", type="primary"):
            if not delete_username or not pin:
                st.warning("Please enter both username and PIN!")
            else:
                c.execute("SELECT * FROM pin_instansi WHERE pin=?", (pin,))
                if c.fetchone() is None:
                    st.error("Invalid PIN Instansi!")
                else:
                    delete_user(delete_username)
                    st.success(f"User {delete_username} deleted successfully")
                    st.rerun()

    elif history_option == "Arsip Pesan":
        st.markdown("### Arsip Data Pesan")

        # Admin table
        st.markdown(
            "<div style='text-align: justify; margin-bottom: 10px;'>"
            "Arsip data pesan adalah kumpulan pesan terenkripsi yang berisi informasi kesehatan yang telah dienkripsi menggunakan kombinasi metode Caesar Cipher dan RC4 untuk menjaga kerahasiaan data."
            "</div>",
            unsafe_allow_html=True,
        )
        c.execute("SELECT * FROM encrypted_data")
        encrypted = c.fetchall()
        df = pd.DataFrame(
            encrypted,
            columns=[
                "ID",
                "Pemilik",
                "Encrypted Text",
                "Caesar Key",
                "RC4 Key",
                "Created At",
            ],
        )
        df.index = df.index + 1
        st.table(df)
        # Delete data pasien section with PIN validation
        st.markdown("### Delete Data Pesan")
        delete_id = st.number_input("ID to delete", min_value=1)
        pin = st.text_input("Enter PIN Instansi for deletion", type="password")
        if st.button("Delete Data", type="primary"):
            if not delete_id or not pin:
                st.warning("Please enter both ID and PIN!")
            else:
                c.execute("SELECT * FROM pin_instansi WHERE pin=?", (pin,))
                if c.fetchone() is None:
                    st.error("Invalid PIN Instansi!")
                else:
                    c.execute("DELETE FROM encrypted_data WHERE id=?", (delete_id,))
                    conn.commit()
                    st.success(f"Data with ID {delete_id} deleted successfully")
                    time.sleep(1)
                    st.rerun()

    elif history_option == "Arsip Gambar":
        st.markdown("### Arsip Pesan Bergambar")
        st.markdown(
            "<div style='text-align: justify; margin-bottom: 10px;'>"
            "Arsip pesan bergambar adalah kumpulan gambar yang berisi pesan rahasia yang disisipkan menggunakan teknik steganografi."
            "</div>",
            unsafe_allow_html=True,
        )
        # Get all encrypted images
        c.execute(
            """
            SELECT id, patient_name, encryption_key, image_url, created_at 
            FROM encrypted_stegano 
            ORDER BY id ASC
        """
        )
        encrypted_images = c.fetchall()

        if not encrypted_images:
            st.warning("No encrypted images found")
        else:
            # Display data table
            df = pd.DataFrame(
                encrypted_images,
                columns=["ID", "Pemilik", "Key", "Image URL", "Created At"],
            )
            df.index = df.index + 1
            st.table(df)

            # Delete section
            st.markdown("### Delete Pesan Bergambar")
            delete_id = st.number_input("ID to delete", min_value=1)
            pin = st.text_input("Enter PIN Instansi for deletion", type="password")

            if st.button("Delete Data", type="primary"):
                if not delete_id or not pin:
                    st.warning("Please enter both ID and PIN!")
                else:
                    # Validate PIN
                    c.execute("SELECT * FROM pin_instansi WHERE pin=?", (pin,))
                    if c.fetchone() is None:
                        st.error("Invalid PIN Instansi!")
                    else:
                        try:
                            # Get Cloudinary URL before deleting from database
                            c.execute(
                                "SELECT image_url FROM encrypted_stegano WHERE id=?",
                                (delete_id,),
                            )
                            result = c.fetchone()

                            if result:
                                image_url = result[0]

                                # Extract public_id from Cloudinary URL
                                public_id = image_url.split("/")[-1].split(".")[0]

                                # Delete from Cloudinary
                                cloudinary.uploader.destroy(f"kriptografi/{public_id}")

                                # Delete from database
                                c.execute(
                                    "DELETE FROM encrypted_stegano WHERE id=?",
                                    (delete_id,),
                                )
                                conn.commit()

                                st.success(
                                    f"Data with ID {delete_id} deleted successfully"
                                )
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error("Data not found!")

                        except Exception as e:
                            st.error(f"Error deleting data: {str(e)}")
                            conn.rollback()

    elif history_option == "Arsip Dokumen":
        st.markdown("### Arsip Dokumen Kesehatan")
        st.markdown(
            "<div style='text-align: justify; margin-bottom: 10px;'>"
            "Arsip dokumen kesehatan adalah kumpulan dokumen medis terenkripsi yang berisi data dan catatan penting terkait kondisi kesehatan pasien atau data instansi yang dijaga kerahasiaannya menggunakan teknik enkripsi yang aman."
            "</div>",
            unsafe_allow_html=True,
        )
        # Get all encrypted documents
        c.execute(
            """
            SELECT id, patient_name, encryption_key, file_url, file_name, created_at 
            FROM encrypted_docs 
            ORDER BY id ASC
        """
        )
        encrypted_docs = c.fetchall()

        if not encrypted_docs:
            st.warning("No encrypted documents found")
        else:
            # Display data table
            df = pd.DataFrame(
                encrypted_docs,
                columns=[
                    "ID",
                    "Pemilik",
                    "Key",
                    "File URL",
                    "File Name",
                    "Created At",
                ],
            )
            df.index = df.index + 1
            st.table(df)

            # Delete section
            st.markdown("### Delete Document Kesehatan")
            delete_id = st.number_input("ID to delete", min_value=1)
            pin = st.text_input("Enter PIN Instansi for deletion", type="password")

            if st.button("Delete Data", type="primary"):
                if not delete_id or not pin:
                    st.warning("Please enter both ID and PIN!")
                else:
                    # Validate PIN
                    c.execute("SELECT * FROM pin_instansi WHERE pin=?", (pin,))
                    if c.fetchone() is None:
                        st.error("Invalid PIN Instansi!")
                    else:
                        try:
                            # Get Cloudinary URL before deleting from database
                            c.execute(
                                "SELECT file_url FROM encrypted_docs WHERE id=?",
                                (delete_id,),
                            )
                            result = c.fetchone()

                            if result:
                                file_url = result[0]

                                # Extract public_id from Cloudinary URL including the .enc extension
                                file_name = file_url.split("/")[-1]
                                public_id = f"kriptografi/{file_name}"

                                # Delete from Cloudinary with resource_type=raw for non-image files
                                cloudinary.uploader.destroy(
                                    public_id, resource_type="raw"
                                )

                                # Delete from database
                                c.execute(
                                    "DELETE FROM encrypted_docs WHERE id=?",
                                    (delete_id,),
                                )
                                conn.commit()

                                st.success(
                                    f"Document with ID {delete_id} deleted successfully"
                                )
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error("Document not found!")

                        except Exception as e:
                            st.error(f"Error deleting document: {str(e)}")
                            conn.rollback()


def crypto_page():
    st.markdown("# 🏥 Pengarsipan Data Kesehatan")
    action = st.sidebar.selectbox(
        "Select Action", ["Arsipkan (Encrypt)", "Ambil Arsip (Decrypt)"]
    )

    if action == "Arsipkan (Encrypt)":
        encrypt_option = st.sidebar.selectbox(
            "Select Data Type to Encrypt",
            ["Data Kesehatan", "Pesan Bergambar", "Dokumen Kesehatan"],
        )
        if encrypt_option == "Data Kesehatan":
            st.markdown("### Arsipkan Data Kesehatan")
            st.markdown(
                """
                <div style='text-align: justify; margin-bottom: 10px;'>
                Arsip data kesehatan adalah kumpulan informasi penting yang berkaitan dengan kesehatan, yaitu:
                <ul>
                    <li>Data Obat: Informasi mengenai obat-obatan.</li>
                    <li>Data Pasien: Informasi pribadi pasien dengan keluhannya.</li>
                </ul>
                </div>
                """,
                unsafe_allow_html=True,
            )
            # Input fields
            nama = st.text_input("Nama Pemilik")
            keterangan = st.text_input("Keterangan")

            # Encryption keys
            caesar_key = st.number_input(
                "Caesar Cipher Key (0-25)", min_value=0, max_value=25, value=3
            )
            rc4_key = st.text_input("RC4 Key", type="password")

            if st.button("Arsipkan! (Encrypt)", use_container_width=True):
                if not nama or not keterangan or not rc4_key:
                    st.error("Please fill all required fields")
                else:
                    # Apply double encryption
                    caesar_encrypted = caesar_encrypt(keterangan, caesar_key)
                    final_encrypted = rc4_encrypt(caesar_encrypted, rc4_key)

                    st.success("Encryption successful!")
                    # st.write("Caesar Cipher Result:", caesar_encrypted)
                    # st.write("Final Encrypted Result:", final_encrypted)

                    # Display encrypted result in a table
                    encrypted_df = pd.DataFrame(
                        {"Hasil Enkripsi": [final_encrypted]}, index=[1]
                    )
                    st.table(encrypted_df)
                    # Store in database
                    c.execute(
                        "INSERT INTO encrypted_data (patient_name, encrypted_text, caesar_key, rc4_key, created_at) VALUES (?, ?, ?, ?, ?)",
                        (nama, final_encrypted, caesar_key, rc4_key, datetime.now()),
                    )
                    conn.commit()
        # Ini Gambar
        elif encrypt_option == "Pesan Bergambar":
            st.markdown("### Arsipkan Pesan Bergambar")
            st.markdown(
                "<div style='text-align: justify; margin-bottom: 10px;'>"
                "Arsip pesan bergambar adalah gambar digital yang menyimpan pesan tersembunyi melalui teknik steganografi. Metode ini memungkinkan penyembunyian informasi rahasia ke dalam gambar tanpa mengubah tampilan visual secara signifikan."
                "</div>",
                unsafe_allow_html=True,
            )
            patient_name = st.text_input("Nama Pemilik")
            secret_message = st.text_input("Pesan")

            # Key generation/input
            key_placeholder = st.empty()
            key = st.text_input(
                "Kunci Enkripsi",
                value=st.session_state.get("random_key", ""),
                type="password",
            )
            # Generate random encryption key button
            if st.button("Generate Random Key"):
                random_key = secrets.token_hex(8)  # 16 characters
                st.session_state["random_key"] = random_key
                st.rerun()
            image = st.file_uploader("Upload Image", type=["png"])  # Restrict to PNG

            if st.button("Arsipkan! (Encrypt)", use_container_width=True):
                if all([image, secret_message, key, patient_name]):
                    try:
                        # Open and verify image
                        img = Image.open(image)
                        if img.mode != "RGB":
                            img = img.convert("RGB")

                        # Encode message
                        encoded_image = encode_lsb(img, secret_message, key)

                        # Save as PNG to avoid compression
                        img_byte_arr = BytesIO()
                        encoded_image.save(img_byte_arr, format="PNG")
                        img_byte_arr.seek(0)

                        # Upload to Cloudinary
                        try:
                            upload_result = cloudinary.uploader.upload(
                                img_byte_arr,
                                folder="kriptografi/",
                                resource_type="image",
                            )

                            # Save to database
                            c.execute(
                                """INSERT INTO encrypted_stegano 
                                (patient_name, encryption_key, created_at, image_url)
                                VALUES (?, ?, ?, ?)""",
                                (
                                    patient_name,
                                    key,
                                    datetime.now(),
                                    upload_result["secure_url"],
                                ),
                            )
                            conn.commit()

                            st.success("Image encrypted and uploaded successfully!")
                            st.image(
                                encoded_image,
                                use_column_width=True,
                            )
                            st.markdown(
                                "<div style='text-align: center;'>Gambar Hasil Steganografi</div>",
                                unsafe_allow_html=True,
                            )
                        except Exception as e:
                            st.error(f"Upload failed: {str(e)}")

                    except Exception as e:
                        st.error(f"Encryption error: {str(e)}")
                else:
                    st.warning("Please fill all required fields")

        elif encrypt_option == "Dokumen Kesehatan":
            st.markdown("### Arsipkan Dokumen Kesehatan")
            st.markdown(
                "<div style='text-align: justify; margin-bottom: 10px;'>"
                "Arsip dokumen kesehatan adalah sistem penyimpanan digital untuk dokumen medis yang terenkripsi. Sistem menyimpan dengan aman berbagai dokumen kesehatan seperti rekam medis, hasil laboratorium, dan resep dokter dengan menggunakan enkripsi untuk melindungi privasi dan kerahasiaan data."
                "</div>",
                unsafe_allow_html=True,
            )
            patient_name = st.text_input("Nama Pemilik")
            uploaded_file = st.file_uploader(
                "Upload Document",
                type=["pdf", "doc", "docx", "txt", "csv", "xlsx", "pptx"],
            )

            # Key generation/input layout
            key_placeholder = st.empty()
            key = st.text_input(
                "Encryption Key",
                value=st.session_state.get("doc_key", ""),
                type="password",
                disabled=False,
            )

            # Create two columns for buttons
            col1, col2 = st.columns([1, 1])

            # Container for success messages
            msg_container = st.empty()

            with col1:
                # Generate key button
                if col1.button("Generate Random Key", use_container_width=True):
                    new_key = generate_key()
                    st.session_state["doc_key"] = new_key.decode()
                    st.rerun()
            # with col2:
            #     if "doc_key" in st.session_state:
            #         # Create custom HTML/JS button for clipboard
            #         js = f"""
            #         <script>
            #         async function copyToClipboard() {{
            #             try {{
            #                 await navigator.clipboard.writeText('{st.session_state["doc_key"]}');
            #                 document.getElementById('copy-status').innerHTML = '✅ Copied!';
            #                 setTimeout(() => document.getElementById('copy-status').innerHTML = '', 2000);
            #             }} catch (err) {{
            #                 document.getElementById('copy-status').innerHTML = '❌ Failed to copy';
            #                 console.error('Failed to copy:', err);
            #             }}
            #         }}
            #         </script>
            #         <div style="text-align: center;">
            #             <button 
            #                 onclick="copyToClipboard()"
            #                 style="width: 100%; padding: 0.5rem; 
            #                 cursor: pointer; background-color: #ffffff; 
            #                 border: 1px solid #cccccc; border-radius: 4px;">
            #                 Copy Key to Clipboard
            #             </button>
            #             <div id="copy-status" style="margin-top: 5px; color: #4CAF50;"></div>
            #         </div>
            #         """
            #         st.components.v1.html(js, height=80)

            if st.button("Arsipkan! (Encrypt)", use_container_width=True):
                if patient_name and uploaded_file and key:
                    try:
                        # Get file extension and name from original filename
                        file_name = uploaded_file.name
                        # Add .enc extension
                        enc_file_name = file_name + ".enc"

                        # Read and encrypt file
                        file_bytes = uploaded_file.read()
                        encrypted_bytes = encrypt_file(file_bytes, key.encode())

                        # Create BytesIO object with encrypted content
                        encrypted_io = BytesIO(encrypted_bytes)
                        encrypted_io.seek(0)

                        # Upload to Cloudinary with .enc filename
                        result = cloudinary.uploader.upload(
                            encrypted_io,
                            resource_type="raw",
                            folder="kriptografi/",
                            filename=enc_file_name,
                            use_filename=True,
                        )

                        # Save to database with original filename
                        c.execute(
                            """
                            INSERT INTO encrypted_docs 
                            (patient_name, encryption_key, file_url, file_name, created_at)
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                patient_name,
                                key,
                                result["secure_url"],
                                uploaded_file.name,  # Store original filename
                                datetime.now(),
                            ),
                        )
                        conn.commit()

                        st.success("Document encrypted and uploaded successfully!")

                    except Exception as e:
                        st.error(f"Error: {str(e)}")
                else:
                    st.warning(
                        "Please provide patient name, encryption key and upload a document"
                    )

    elif action == "Ambil Arsip (Decrypt)":
        decrypt_option = st.sidebar.selectbox(
            "Select Data Type to Decrypt",
            ["Data Kesehatan", "Pesan Bergambar", "Dokumen Kesehatan"],
        )
        if decrypt_option == "Data Kesehatan":
            st.markdown("### Baca Data Kesehatan")
            st.markdown(
                "<div style='text-align: justify; margin-bottom: 10px;'>"
                "Baca Data Kesehatan adalah proses mengakses dan mendekripsi dokumen medis yang telah diarsipkan. "
                "Sistem ini memungkinkan admin untuk membuka kembali dokumen kesehatan terenkripsi menggunakan kunci yang sesuai."
                "</div>",
                unsafe_allow_html=True,
            )
            c.execute("SELECT * FROM encrypted_data")
            encrypted = c.fetchall()
            df = pd.DataFrame(
                encrypted,
                columns=[
                    "ID",
                    "Pemilik",
                    "Encrypted Text",
                    "Caesar Key",
                    "RC4 Key",
                    "Created At",
                ],
            )
            df.index = df.index + 1
            st.table(df)

            # Decryption inputs
            st.markdown("### Proses Dekripsi")
            encrypted_text = st.text_input("Masukkan Ciphertext")
            caesar_key = st.number_input(
                "Masukkan Caesar Key", min_value=0, max_value=25
            )
            rc4_key = st.text_input("Masukkan RC4 Key", type="password")

            if st.button("Baca Data! (Decrypt)", use_container_width=True):
                if not encrypted_text or not rc4_key:
                    st.error("Please fill all required fields")
                else:
                    try:
                        # Apply decryption in reverse order
                        rc4_decrypted = rc4_decrypt(encrypted_text, rc4_key)
                        final_decrypted = caesar_decrypt(rc4_decrypted, caesar_key)
                        st.success("Decryption successful!")
                        st.markdown("### Hasil Pesan:")
                        decrypted_df = pd.DataFrame(
                            {"Keterangan": [final_decrypted]}, index=[1]
                        )
                        st.table(decrypted_df)
                    except Exception as e:
                        st.error(f"Decryption failed! Masukkan Kunci yang benar!")

        elif decrypt_option == "Pesan Bergambar":
            st.markdown("### Baca Pesan Bergambar")
            st.markdown(
                "<div style='text-align: justify; margin-bottom: 10px;'>"
                "Baca Pesan Bergambar adalah proses mengekstrak dan mendekripsi pesan tersembunyi dari gambar yang telah disisipkan menggunakan steganografi. "
                "Sistem ini memungkinkan pengguna untuk membaca kembali pesan rahasia dalam gambar menggunakan kunci yang sesuai, "
                "tanpa merusak kualitas visual dari gambar asli."
                "</div>",
                unsafe_allow_html=True,
            )
            c.execute(
                "SELECT patient_name, encryption_key, image_url, created_at FROM encrypted_stegano"
            )
            encrypted = c.fetchall()
            df = pd.DataFrame(
                encrypted,
                columns=[
                    "Pemilik",
                    "Secret Key",
                    "Image URL",
                    "Created At",
                ],
            )
            df.index = df.index + 1
            st.table(df)

            c.execute(
                """
                SELECT patient_name, image_url, created_at 
                FROM encrypted_stegano 
                ORDER BY created_at DESC
            """
            )
            encrypted_images = c.fetchall()

            if not encrypted_images:
                st.warning("No encrypted images found in database")
            else:
                st.markdown("### Proses Dekripsi")
                patient_names = [img[0] for img in encrypted_images]
                selected_patient = st.selectbox("Select Patient", patient_names)

                c.execute(
                    """
                    SELECT image_url, encryption_key 
                    FROM encrypted_stegano 
                    WHERE patient_name = ? 
                    ORDER BY created_at DESC 
                    LIMIT 1
                """,
                    (selected_patient,),
                )
                result = c.fetchone()

                if result:
                    image_url = result[0]
                    stored_key = result[1]

                    decryption_key = st.text_input(
                        "Enter Decryption Key", type="password"
                    )

                    if st.button("Baca Pesan! (Decrypt)", use_container_width=True):
                        if not decryption_key:
                            st.error("Please enter decryption key")
                        else:
                            try:
                                response = requests.get(image_url)
                                if response.status_code != 200:
                                    st.error("Failed to download image from Cloudinary")
                                    return

                                try:
                                    img = Image.open(BytesIO(response.content))
                                except:
                                    st.error("Failed to open downloaded image")
                                    return

                                if decryption_key == stored_key:
                                    try:
                                        decoded_key, decoded_message = decode_lsb(img)
                                        st.success("Decryption successful!")
                                        st.markdown("### Original Image:")
                                        st.image(
                                            img,
                                            caption="Original Image",
                                            use_column_width=True,
                                        )
                                        # st.write("Decoded Message:", decoded_message)
                                        st.markdown("### Pesan Tersembunyi:")
                                        decoded_df = pd.DataFrame(
                                            {"Pesan Tersembunyi": [decoded_message]},
                                            index=[1],
                                        )
                                        st.table(decoded_df)
                                    except ValueError as ve:
                                        st.error(f"LSB Decoding failed: {str(ve)}")
                                else:
                                    st.error("Invalid decryption key")

                            except requests.RequestException as e:
                                st.error(f"Network error: {str(e)}")
                            except Exception as e:
                                st.error(
                                    f"Unexpected error during decryption: {str(e)}"
                                )
                else:
                    st.error("Could not find image data for selected patient")

        elif decrypt_option == "Dokumen Kesehatan":
            st.markdown("### Baca Dokumen Kesehatan")
            st.markdown(
                "<div style='text-align: justify; margin-bottom: 10px;'>"
                "Baca Dokumen Kesehatan adalah proses mengakses dan mendekripsi dokumen medis yang telah tersimpan dalam sistem. "
                "Fitur ini memungkinkan pengguna untuk membuka dan membaca kembali dokumen kesehatan terenkripsi menggunakan kunci yang sesuai, "
                "sambil tetap menjaga keamanan dan kerahasiaan data medis pasien."
                "</div>",
                unsafe_allow_html=True,
            )
            # Display encrypted documents table
            c.execute(
                """
                SELECT id, patient_name, file_name, encryption_key, file_url, created_at 
                FROM encrypted_docs 
                ORDER BY id ASC
            """
            )
            docs = c.fetchall()

            if not docs:
                st.warning("No encrypted documents found")
            else:
                # Show documents table
                df = pd.DataFrame(
                    docs,
                    columns=[
                        "ID",
                        "Pemilik",
                        "Nama File",
                        "Key",
                        "File URL",
                        "Created At",
                    ],
                )
                df.index = df.index + 1
                st.table(df)

                # Decryption interface
                # Get all document IDs
                c.execute(
                    """
                    SELECT id 
                    FROM encrypted_docs 
                    ORDER BY id ASC
                """
                )
                doc_ids = c.fetchall()

                if doc_ids:
                    st.markdown("### Proses Dekripsi")
                    id_list = [str(doc[0]) for doc in doc_ids]
                    selected_id = st.selectbox("Select Document ID", id_list)

                    # Get document details for selected ID
                    c.execute(
                        """
                        SELECT file_url, encryption_key, file_name 
                        FROM encrypted_docs 
                        WHERE id = ? 
                    """,
                        (selected_id,),
                    )
                    result = c.fetchone()

                    if result:
                        file_url, stored_key, original_filename = result
                        decryption_key = st.text_input(
                            "Enter Decryption Key", type="password"
                        )

                        if st.button(
                            "Ambil Dokumen! (Decrypt)", use_container_width=True
                        ):
                            if not decryption_key:
                                st.error("Please enter decryption key")
                            else:
                                try:
                                    if decryption_key == stored_key:
                                        # Download encrypted file with proper headers
                                        headers = {
                                            "User-Agent": "Mozilla/5.0",
                                            "Accept": "*/*",
                                        }
                                        response = requests.get(
                                            file_url,
                                            headers=headers,
                                            allow_redirects=True,
                                        )

                                        if response.status_code == 200:
                                            # Decrypt content
                                            encrypted_content = response.content
                                            try:
                                                decrypted_content = decrypt_file(
                                                    encrypted_content,
                                                    decryption_key.encode(),
                                                )

                                                # Create download button
                                                st.success(
                                                    "File decrypted successfully!"
                                                )
                                                st.download_button(
                                                    label="Download File",
                                                    data=decrypted_content,
                                                    file_name=original_filename,
                                                    mime="application/octet-stream",
                                                    use_container_width=True,
                                                )

                                            except Exception as e:
                                                st.error(f"Decryption failed: {str(e)}")
                                        else:
                                            st.error(
                                                f"Failed to download file. Status code: {response.status_code}"
                                            )
                                            st.write("URL attempted:", file_url)
                                    else:
                                        st.error("Invalid decryption key")
                                except Exception as e:
                                    st.error(f"Error during decryption: {str(e)}")
                    else:
                        st.error("Could not find document data for selected ID")


# Main Navigation
def main():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "page" not in st.session_state:
        st.session_state.page = "login"

    if st.session_state.logged_in:
        st.sidebar.image(
            "security.png",
            width=110,  
        )
        st.sidebar.title("Navigation")
        menu = ["Document Store", "Manage Arsip"]
        choice = st.sidebar.selectbox("Select Menu", menu)

        if choice == "Manage Arsip":
            admin_page()
        elif choice == "Document Store":
            crypto_page()

        # Add Log Out button at the bottom of the sidebar
        if st.sidebar.button("Log Out", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.page = "login"
            st.sidebar.write(
                "<div style='text-align: center;'>You have been logged out. Returning to login page.</div>",
                unsafe_allow_html=True,
            )
            st.rerun()
    else:
        if st.session_state.page == "login":
            login_page()
        elif st.session_state.page == "register":
            register_page()


if __name__ == "__main__":
    main()
