# ML-DSA Signature System

A Django-based web application for digital document signing using ML-DSA (Machine Learning Digital Signature Algorithm).

## Features

- Generate ML-DSA key pairs
- Sign documents (DOCX, PDF, JPG)
- Verify document signatures
- Store signature metadata
- Web-based user interface

## Requirements

- Python 3.8+
- Django 4.2+
- python-docx
- dilithium-py
- python-magic

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ml-dsa-server
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run migrations:
```bash
python manage.py makemigrations
python manage.py migrate
```

5. Start the development server:
```bash
python manage.py runserver
```

The application will be available at http://localhost:8000

## Usage

1. **Generate Key Pair**
   - Enter the signer's name
   - Click "Generate Keys"
   - The system will create public and private key files

2. **Sign Document**
   - Enter the signer's name
   - Provide the path to the document you want to sign
   - Click "Sign Document"
   - The system will create a signature file

3. **Verify Signature**
   - Enter the signer's name
   - Provide the path to the signed document
   - Click "Verify Signature"
   - The system will verify the signature and show the results

## Security Notes

- Keep private keys secure and never share them
- The system stores keys in PEM format
- Signatures include document hash and timestamp
- All operations are performed server-side

## API Endpoints

- `POST /generate-keys/`: Generate new key pair
- `POST /sign-document/`: Sign a document
- `POST /verify-signature/`: Verify document signature

## License

This project is licensed under the MIT License - see the LICENSE file for details. 