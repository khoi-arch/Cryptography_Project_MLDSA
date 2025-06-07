from dilithium_py.ml_dsa import ML_DSA_44
import base64
import json
import hashlib
import os
from docx import Document
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

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
    """Generate new ML-DSA key pair and save with encryption."""
    try:
        print(f"Starting key generation for {signer_name}")  # Debug log
        
        # Generate new key pair
        print("Generating ML-DSA key pair...")  # Debug log
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
        print("Saving private key...")  # Debug log
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
    """Sign a document using ML-DSA."""
    try:
        print(f"Starting document signing for {signer_name}")  # Debug log
        print(f"Document path: {document_path}")  # Debug log
        
        # Check if document exists
        if not os.path.exists(document_path):
            print(f"Document not found: {document_path}")  # Debug log
            return None
            
        # Read document
        print("Reading document...")  # Debug log
        with open(document_path, 'rb') as f:
            document_data = f.read()
        print(f"Document size: {len(document_data)} bytes")  # Debug log
        
        # Generate signature
        print("Generating signature...")  # Debug log
        signature = ML_DSA_44.sign(secret_key, document_data)
        print(f"Signature generated. Length: {len(signature)} bytes")  # Debug log
        
        # Convert signature to base64
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        # Save signature to database
        print("Saving signature to database...")  # Debug log
        from .models import Signature
        try:
            # Check if signature already exists
            existing_signature = Signature.objects.filter(
                signer_name=signer_name,
                document_path=document_path
            ).first()
            
            if existing_signature:
                # Update existing signature
                existing_signature.signature_data = signature_b64
                existing_signature.save()
                print("Updated existing signature")  # Debug log
            else:
                # Create new signature
                Signature.objects.create(
                    signer_name=signer_name,
                    document_path=document_path,
                    signature_data=signature_b64
                )
                print("Created new signature")  # Debug log
                
        except Exception as db_error:
            print(f"Database error: {str(db_error)}")  # Debug log
            import traceback
            print(traceback.format_exc())  # Print full traceback
            return None
            
        print("Signature saved successfully")  # Debug log
        return signature_b64
        
    except Exception as e:
        print(f"Error in sign_document: {str(e)}")  # Debug log
        import traceback
        print(traceback.format_exc())  # Print full traceback
        return None

def verify_signature(public_key, document_path, signature_data):
    """Verify a document signature using ML-DSA."""
    try:
        print(f"Starting signature verification for document: {document_path}")  # Debug log
        
        # Check if document exists
        if not os.path.exists(document_path):
            print(f"Document not found: {document_path}")  # Debug log
            return None
            
        # Read document
        print("Reading document...")  # Debug log
        with open(document_path, 'rb') as f:
            document_data = f.read()
        print(f"Document size: {len(document_data)} bytes")  # Debug log
        
        # Decode signature
        print("Decoding signature...")  # Debug log
        signature = base64.b64decode(signature_data)
        print(f"Signature length: {len(signature)} bytes")  # Debug log
        
        # Verify signature
        print("Verifying signature...")  # Debug log
        is_valid = ML_DSA_44.verify(public_key, document_data, signature)
        print(f"Signature verification result: {is_valid}")  # Debug log
        
        return {
            'is_signature_valid': is_valid,
            'is_document_unchanged': is_valid
        }
        
    except Exception as e:
        print(f"Error in verify_signature: {str(e)}")  # Debug log
        import traceback
        print(traceback.format_exc())  # Print full traceback
        return None 