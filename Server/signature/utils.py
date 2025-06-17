from dilithium_py.ml_dsa import ML_DSA_44
from django.conf import settings 
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
from datetime import datetime, timedelta
import uuid

# PEM file format constants
PRIVATEKEY_HEADER = b"-----BEGIN PRIVATE KEY-----\n"
PRIVATEKEY_FOOTER = b"-----END PRIVATE KEY-----\n"
PUBLICKEY_HEADER = b"-----BEGIN PUBLIC KEY-----\n"
PUBLICKEY_FOOTER = b"-----END PUBLIC KEY-----\n"

SIGNATURE_PLACEHOLDER = '__SIGNATURE_PLACEHOLDER__'

def verify_proof_of_possession(public_key, payload, signature):
    """Verify that the user owns the private key"""
    try:
        # Convert payload to string and encode
        payload_str = json.dumps(payload, sort_keys=True).encode()
        
        # Ensure signature is in correct format
        if isinstance(signature, str):
            signature = base64.b64decode(signature)
            
        
        # Verify signature using ML-DSA-44
        try:
            result = ML_DSA_44.verify(public_key, payload_str, signature)
            print(f"Verify result: {result}")
            return result
        except Exception as verify_error:
            print(f"Verify error: {str(verify_error)}")
            return False
            
    except Exception as e:
        print(f"Error in verify_proof_of_possession: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def create_certificate(username, public_key, role):
    """Create a certificate for the user"""
    try:
        # Create certificate payload
        payload = {
            'version': '1.0',
            'serial_number': str(uuid.uuid4()),
            'subject': username,
            'public_key': base64.b64encode(public_key).decode('utf-8'),
            'issuer': 'CA',
            'validity': {
                'not_before': datetime.utcnow().isoformat(),
                'not_after': (datetime.utcnow() + timedelta(days=365)).isoformat()
            },
            'role': role
        }
        
        # Check and create CA keys if not exist
        if not os.path.exists('keys/ca_private_key.pem'):
            create_ca_keys()
            
        # Read CA's private key
        with open('keys/ca_private_key.pem', 'r') as f:
            ca_key_data = json.load(f)  # Parse JSON data
            ca_private_key = base64.b64decode(ca_key_data['private_key'])
            
        # Sign the payload
        signature = ML_DSA_44.sign(ca_private_key, json.dumps(payload, sort_keys=True).encode())
        
        # Create certificate
        certificate = {
            'payload': payload,
            'signature': base64.b64encode(signature).decode('utf-8')
        }
        
        # Save certificate
        os.makedirs('certificates', exist_ok=True)
        with open(f'certificates/{username}_cert.json', 'w') as f:
            json.dump(certificate, f, indent=2)
            
        return certificate
        
    except Exception as e:
        print(f"Error creating certificate: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        raise

def create_ca_keys():
    """Tạo và lưu private key cho CA"""
    try:
        # Tạo cặp khóa cho CA
        pk, sk = ML_DSA_44.keygen()
        
        # Tạo thư mục keys nếu chưa tồn tại
        keys_dir = os.path.join(settings.BASE_DIR, 'keys')
        os.makedirs(keys_dir, exist_ok=True)
        
        # Lưu private key của CA
        ca_private_key_path = os.path.join(keys_dir, 'ca_private_key.pem')
        with open(ca_private_key_path, 'w') as f:
            json.dump({
                'private_key': base64.b64encode(sk).decode('utf-8')
            }, f)
        
        # Lưu public key của CA
        ca_public_key_path = os.path.join(keys_dir, 'ca_public_key.pem')
        with open(ca_public_key_path, 'w') as f:
            json.dump({
                'public_key': base64.b64encode(pk).decode('utf-8')
            }, f)
            
        print("CA keys created successfully")
        return True
    except Exception as e:
        print(f"Error creating CA keys: {str(e)}")
        return False







 