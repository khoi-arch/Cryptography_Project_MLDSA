from dilithium_py.ml_dsa import ML_DSA_44
import base64
import json
import hashlib
import os
from docx import Document
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, TextStringObject
from datetime import datetime

# PEM file format constants
PRIVATEKEY_HEADER = b"-----BEGIN PRIVATE KEY-----\n"
PRIVATEKEY_FOOTER = b"-----END PRIVATE KEY-----\n"
PUBLICKEY_HEADER = b"-----BEGIN PUBLIC KEY-----\n"
PUBLICKEY_FOOTER = b"-----END PUBLIC KEY-----\n"

SIGNATURE_PLACEHOLDER = '__SIGNATURE_PLACEHOLDER__'

def read_file_content(file_path):
    """Read content from file."""
    try:
        document = Document(file_path)
        full_text = []
        for para in document.paragraphs:
            full_text.append(para.text)
        return "\n".join(full_text)
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def save_keys(public_key_bytes, secret_key_bytes, public_key_file="public.pem", private_key_file="private.pem"):
    """Save public and secret keys to .pem files."""
    try:
        # Save PublicKey
        with open(public_key_file, 'wb') as f_pub:
            f_pub.write(PUBLICKEY_HEADER)
            f_pub.write(base64.b64encode(public_key_bytes))
            f_pub.write(b'\n')
            f_pub.write(PUBLICKEY_FOOTER)

        # Save PrivateKey
        with open(private_key_file, 'wb') as f_priv:
            f_priv.write(PRIVATEKEY_HEADER)
            f_priv.write(base64.b64encode(secret_key_bytes))
            f_priv.write(b'\n')
            f_priv.write(PRIVATEKEY_FOOTER)
        return True
    except Exception as e:
        print(f"Error saving keys to .PEM file: {e}")
        return False

def load_private_key(password, signer_name):
    """Load and decrypt private key for signing."""
    try:
        print(f"Loading private key for {signer_name}")  # Debug log
        
        # Create full path to private key file
        private_key_path = os.path.join('keys', f"{signer_name}.private.pem")
        
        print(f"Private key path: {private_key_path}")  # Debug log
        
        # Check if private key file exists
        if not os.path.exists(private_key_path):
            print(f"Private key file not found: {private_key_path}")  # Debug log
            return None
        
        # Load private key data
        print("Loading private key data...")  # Debug log
        with open(private_key_path, 'r') as f:
            private_key_data = json.load(f)
            salt = base64.b64decode(private_key_data['salt'])
            iv = base64.b64decode(private_key_data['iv'])
            encrypted_key = base64.b64decode(private_key_data['encrypted_key'])
        print("Private key data loaded")  # Debug log
        
        # Derive AES key from password
        print("Deriving AES key...")  # Debug log
        key = PBKDF2(password.encode(), salt, dkLen=32, count=10000)
        
        # Create AES cipher
        print("Creating AES cipher...")  # Debug log
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt the private key
        print("Decrypting private key...")  # Debug log
        decrypted_key = cipher.decrypt(encrypted_key)
        
        # Remove padding
        private_key = decrypted_key.rstrip(b'\0')
        print(f"Private key decrypted. Length: {len(private_key)} bytes")  # Debug log
        
        return private_key
        
    except Exception as e:
        print(f"Error in load_private_key: {str(e)}")  # Debug log
        import traceback
        print(traceback.format_exc())  # Print full traceback
        return None

def load_public_key(signer_name):
    """Load public key for verification."""
    try:
        print(f"Loading public key for {signer_name}")  # Debug log
        
        # Create full path to public key file
        public_key_path = os.path.join('keys', f"{signer_name}.public.pem")
        
        print(f"Public key path: {public_key_path}")  # Debug log
        
        # Check if public key file exists
        if not os.path.exists(public_key_path):
            print(f"Public key file not found: {public_key_path}")  # Debug log
            return None
        
        # Load public key
        print("Loading public key...")  # Debug log
        with open(public_key_path, 'r') as f:
            public_key_data = json.load(f)
            public_key = base64.b64decode(public_key_data['public_key'])
        print(f"Public key loaded. Length: {len(public_key)} bytes")  # Debug log
        
        return public_key
        
    except Exception as e:
        print(f"Error in load_public_key: {str(e)}")  # Debug log
        import traceback
        print(traceback.format_exc())  # Print full traceback
        return None

def generate_keys(password, signer_name):
    """Generate new ML-DSA-44 key pair and save with encryption."""
    try:
        print(f"Starting key generation for {signer_name}")  # Debug log
        
        # Generate new key pair
        print("Generating ML-DSA-44 key pair...")  # Debug log
        pk, sk = ML_DSA_44.keygen()
        print(f"Key pair generated. Public key length: {len(pk)}, Secret key length: {len(sk)}")  # Debug log
        
        # Generate random salt and IV
        print("Generating salt and IV...")  # Debug log
        salt = get_random_bytes(16)
        iv = get_random_bytes(16)
        
        # Derive AES key from password using PBKDF2
        print("Deriving AES key...")  # Debug log
        key = PBKDF2(password.encode(), salt, dkLen=32, count=10000)
        
        # Create AES cipher
        print("Creating AES cipher...")  # Debug log
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad the secret key to be multiple of 16 bytes
        print("Padding secret key...")  # Debug log
        padded_sk = sk + b'\0' * (16 - len(sk) % 16)
        
        # Encrypt the secret key
        print("Encrypting secret key...")  # Debug log
        encrypted_sk = cipher.encrypt(padded_sk)
        
        # Create directory if it doesn't exist
        print("Creating keys directory...")  # Debug log
        os.makedirs('keys', exist_ok=True)
        
        # Save public key
        print("Saving public key...")  # Debug log
        public_key_data = {
            'public_key': base64.b64encode(pk).decode('utf-8')
        }
        public_key_path = os.path.join('keys', f"{signer_name}.public.pem")
        with open(public_key_path, 'w') as f:
            json.dump(public_key_data, f)
        print(f"Public key saved to {public_key_path}")  # Debug log
        
        # Save encrypted private key with salt and IV
        print("Saving private key...")
        private_key_data = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'encrypted_key': base64.b64encode(encrypted_sk).decode('utf-8')
        }
        private_key_path = os.path.join('keys', f"{signer_name}.private.pem")
        with open(private_key_path, 'w') as f:
            json.dump(private_key_data, f)
        print(f"Private key saved to {private_key_path}")  # Debug log
        
        return pk, sk
        
    except Exception as e:
        print(f"Error in generate_keys: {str(e)}")
        import traceback
        print(traceback.format_exc())  # Print full traceback
        return None, None

def sign_document(secret_key, document_path, signer_name):
    """Sign a document using ML-DSA-44."""
    try:
        # Read document content
        content = read_file_content(document_path)
        if not content:
            return None
            
        # Hash the content
        content_hash = hashlib.sha256(content.encode()).digest()
        
        # Sign the hash
        signature = ML_DSA_44.sign(secret_key, content_hash)
        
        # Create signature data
        signature_data = {
            'signature': base64.b64encode(signature).decode('utf-8'),
            'timestamp': datetime.now().isoformat(),
            'signer_name': signer_name
        }
        
        return signature_data
        
    except Exception as e:
        print(f"Error in sign_document: {str(e)}")
        return None

def verify_signature(public_key, document_path, signature_data):
    """Verify a document signature using ML-DSA-44."""
    try:
        # Read document content
        content = read_file_content(document_path)
        if not content:
            return None
            
        # Hash the content
        content_hash = hashlib.sha256(content.encode()).digest()
        
        # Decode signature
        signature = base64.b64decode(signature_data['signature'])
        
        # Verify signature
        is_valid = ML_DSA_44.verify(public_key, content_hash, signature)
        
        return {
            'is_valid': is_valid,
            'timestamp': signature_data['timestamp'],
            'signer_name': signature_data['signer_name']
        }
        
    except Exception as e:
        print(f"Error in verify_signature: {str(e)}")
        return None

def sign_pdf_and_embed_signature(pdf_path, private_key, output_path):
    """Ký file PDF và nhúng signature vào metadata trường /Subject với placeholder."""
    try:
        # Bước 1: Ghi file PDF với placeholder
        reader = PdfReader(pdf_path)
        writer = PdfWriter()
        writer.append_pages_from_reader(reader)
        metadata = reader.metadata or {}
        metadata = {NameObject(str(k)): str(v) for k, v in metadata.items()}
        metadata[NameObject('/Subject')] = SIGNATURE_PLACEHOLDER
        writer.add_metadata(metadata)
        import io
        buf = io.BytesIO()
        writer.write(buf)
        pdf_bytes_with_placeholder = buf.getvalue()

        # Debug: In metadata gốc
        print('Original PDF metadata:', metadata)

        # Lưu file PDF với placeholder để debug
        debug_dir = os.path.join(os.path.dirname(pdf_path), 'debug')
        print(f"Creating debug directory at: {debug_dir}")
        os.makedirs(debug_dir, exist_ok=True)
        placeholder_path = os.path.join(debug_dir, 'pdf_with_placeholder_backend.pdf')
        print(f"Saving placeholder PDF to: {placeholder_path}")
        with open(placeholder_path, 'wb') as f:
            f.write(pdf_bytes_with_placeholder)
        print(f"Successfully saved placeholder PDF, size: {len(pdf_bytes_with_placeholder)} bytes")

        # Bước 2: Sinh signature trên bytes này
        signature = ML_DSA_44.sign(private_key, pdf_bytes_with_placeholder)
        signature_b64 = base64.b64encode(signature).decode('utf-8')

        # Debug: In signature
        print('Generated signature:', signature_b64)
        print('Signature length:', len(signature))

        # Bước 3: Ghi lại file PDF với signature thực sự
        writer2 = PdfWriter()
        reader2 = PdfReader(io.BytesIO(pdf_bytes_with_placeholder))
        writer2.append_pages_from_reader(reader2)
        metadata2 = reader2.metadata or {}
        metadata2 = {NameObject(str(k)): str(v) for k, v in metadata2.items()}
        metadata2[NameObject('/Subject')] = signature_b64
        writer2.add_metadata(metadata2)
        with open(output_path, 'wb') as f:
            writer2.write(f)

        # Debug: In metadata sau khi ký
        print('Metadata after signing:', metadata2)

        # Tạo thông tin debug
        debug_info = {
            'original_pdf_size': os.path.getsize(pdf_path),
            'placeholder_pdf_size': len(pdf_bytes_with_placeholder),
            'signed_pdf_size': os.path.getsize(output_path),
            'signature_length': len(signature),
            'private_key_length': len(private_key),
            'metadata': {
                'title': metadata.get('/Title', ''),
                'author': metadata.get('/Author', ''),
                'subject': metadata.get('/Subject', ''),
                'creator': metadata.get('/Creator', ''),
                'producer': metadata.get('/Producer', ''),
                'creation_date': metadata.get('/CreationDate', ''),
                'modification_date': metadata.get('/ModDate', '')
            },
            'timestamp': datetime.now().isoformat()
        }

        # Lưu thông tin debug
        debug_info_path = os.path.join(debug_dir, 'debug_info.json')
        print(f"Saving debug info to: {debug_info_path}")
        with open(debug_info_path, 'w') as f:
            json.dump(debug_info, f, indent=2)
        print(f"Successfully saved debug info: {debug_info}")

        return output_path, signature_b64

    except Exception as e:
        print(f"Error in sign_pdf_and_embed_signature: {e}")
        return None, None

def verify_pdf_with_embedded_signature(pdf_path, public_key):
    """Xác thực file PDF đã nhúng signature ở trường /Subject với placeholder."""
    try:
        # Đọc signature từ metadata
        reader = PdfReader(pdf_path)
        metadata = reader.metadata or {}
        print('Metadata khi xác thực:', metadata)
        signature_b64 = metadata.get('/Subject')
        if not signature_b64:
            print("Không tìm thấy signature trong metadata PDF (/Subject).")
            return False
        signature = base64.b64decode(signature_b64)

        # Debug: In signature
        print('Signature from PDF:', signature_b64)
        print('Signature length:', len(signature))

        # Thay /Subject về lại placeholder (dùng TextStringObject)
        metadata[NameObject('/Subject')] = TextStringObject(SIGNATURE_PLACEHOLDER)
        writer = PdfWriter()
        writer.append_pages_from_reader(reader)
        writer.add_metadata(metadata)
        import io
        buf = io.BytesIO()
        writer.write(buf)
        pdf_bytes_with_placeholder = buf.getvalue()

        # Debug: In bytes
        print('Original PDF size:', os.path.getsize(pdf_path))
        print('PDF with placeholder size:', len(pdf_bytes_with_placeholder))

        # Lưu file PDF với placeholder để debug
        debug_dir = os.path.join(os.path.dirname(pdf_path), 'debug')
        print(f"Creating debug directory at: {debug_dir}")
        os.makedirs(debug_dir, exist_ok=True)
        placeholder_path = os.path.join(debug_dir, 'pdf_with_placeholder_backend_verify.pdf')
        print(f"Saving placeholder PDF to: {placeholder_path}")
        with open(placeholder_path, 'wb') as f:
            f.write(pdf_bytes_with_placeholder)
        print(f"Successfully saved placeholder PDF, size: {len(pdf_bytes_with_placeholder)} bytes")

        # Debug: In key bytes
        print('Public key length:', len(public_key))

        # Xác thực
        is_valid = ML_DSA_44.verify(public_key, pdf_bytes_with_placeholder, signature)
        print(f'Kết quả xác thực: {is_valid}')

        # Tạo thông tin debug
        debug_info = {
            'original_pdf_size': os.path.getsize(pdf_path),
            'placeholder_pdf_size': len(pdf_bytes_with_placeholder),
            'signature_length': len(signature),
            'public_key_length': len(public_key),
            'metadata': {
                'title': metadata.get('/Title', ''),
                'author': metadata.get('/Author', ''),
                'subject': metadata.get('/Subject', ''),
                'creator': metadata.get('/Creator', ''),
                'producer': metadata.get('/Producer', ''),
                'creation_date': metadata.get('/CreationDate', ''),
                'modification_date': metadata.get('/ModDate', '')
            },
            'timestamp': datetime.now().isoformat()
        }

        # Lưu thông tin debug
        debug_info_path = os.path.join(debug_dir, 'debug_info_verify.json')
        print(f"Saving debug info to: {debug_info_path}")
        with open(debug_info_path, 'w') as f:
            json.dump(debug_info, f, indent=2)
        print(f"Successfully saved debug info: {debug_info}")

        return is_valid

    except Exception as e:
        print(f"Error in verify_pdf_with_embedded_signature: {e}")
        return False 