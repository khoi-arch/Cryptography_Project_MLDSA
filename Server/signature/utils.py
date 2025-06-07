from dilithium_py.ml_dsa import ML_DSA_44
import base64
import json
import hashlib
import os
from docx import Document

# PEM file format constants
PRIVATEKEY_HEADER = b"-----BEGIN PRIVATE KEY-----\n"
PRIVATEKEY_FOOTER = b"-----END PRIVATE KEY-----\n"
PUBLICKEY_HEADER = b"-----BEGIN PUBLIC KEY-----\n"
PUBLICKEY_FOOTER = b"-----END PUBLIC KEY-----\n"

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

def load_keys(public_key_file="public.pem", private_key_file="private.pem"):
    """Load public and secret keys from .pem files."""
    public_key_bytes = None
    secret_key_bytes = None

    try:
        # Load PublicKey
        if os.path.exists(public_key_file):
            with open(public_key_file, 'rb') as f_pub:
                content = f_pub.read().strip()
                if content.startswith(PUBLICKEY_HEADER) and content.endswith(PUBLICKEY_FOOTER):
                    encoded_key = content[len(PUBLICKEY_HEADER):-len(PUBLICKEY_FOOTER)].strip()
                    public_key_bytes = base64.b64decode(encoded_key)

        # Load PrivateKey
        if os.path.exists(private_key_file):
            with open(private_key_file, 'rb') as f_priv:
                content = f_priv.read().strip()
                if content.startswith(PRIVATEKEY_HEADER) and content.endswith(PRIVATEKEY_FOOTER):
                    encoded_key = content[len(PRIVATEKEY_HEADER):-len(PRIVATEKEY_FOOTER)].strip()
                    secret_key_bytes = base64.b64decode(encoded_key)

    except Exception as e:
        print(f"Error loading keys from PEM file: {e}")

    return public_key_bytes, secret_key_bytes

def generate_keys():
    """Generate new ML-DSA key pair."""
    return ML_DSA_44.keygen()

def sign_document(secret_key_bytes, document_path, signer_name):
    """Sign a document and return signature data."""
    try:
        with open(document_path, 'rb') as f:
            document_content_bytes = f.read()
        
        document_hash = hashlib.sha256(document_content_bytes).digest()
        
        signature_metadata = {
            "signer_name": signer_name,
            "document_hash": base64.b64encode(document_hash).decode('utf-8'),
            "timestamp": os.path.getmtime(document_path)
        }
        
        metadata_bytes = json.dumps(signature_metadata, sort_keys=True).encode('utf-8')
        signature = ML_DSA_44.sign(secret_key_bytes, metadata_bytes)
        
        return {
            "ml_dsa_signature": base64.b64encode(signature).decode('utf-8'),
            "signed_metadata": base64.b64encode(metadata_bytes).decode('utf-8')
        }
    except Exception as e:
        print(f"Error signing document: {e}")
        return None

def verify_signature(public_key_bytes, document_path, signature_data):
    """Verify document signature."""
    try:
        with open(document_path, 'rb') as f:
            document_content = f.read()
        current_document_hash = hashlib.sha256(document_content).digest()
        
        actual_signature = base64.b64decode(signature_data["ml_dsa_signature"])
        metadata_bytes = base64.b64decode(signature_data["signed_metadata"])
        
        signature_metadata = json.loads(metadata_bytes.decode('utf-8'))
        signed_document_hash = base64.b64decode(signature_metadata["document_hash"])
        
        is_signature_valid = ML_DSA_44.verify(public_key_bytes, metadata_bytes, actual_signature)
        
        return {
            "is_signature_valid": is_signature_valid,
            "is_document_unchanged": current_document_hash == signed_document_hash,
            "signer_name": signature_metadata.get("signer_name"),
            "timestamp": signature_metadata.get("timestamp")
        }
    except Exception as e:
        print(f"Error verifying signature: {e}")
        return None 