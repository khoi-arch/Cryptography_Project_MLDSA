from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import os
import json
from .models import Signature, KeyPair
from .utils import (
    generate_keys, save_keys,
    sign_document, verify_signature,
    load_private_key, load_public_key
)

def index(request):
    return render(request, 'signature/index.html')

@csrf_exempt
def generate_key_pair(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            signer_name = data.get('signer_name')
            password = data.get('password')
            
            if not all([signer_name, password]):
                return JsonResponse({'error': 'Signer name and password are required'}, status=400)
            
            print(f"Generating keys for {signer_name}")  # Debug log
            
            # Generate new key pair
            public_key_bytes, secret_key_bytes = generate_keys(password, signer_name)
            
            if public_key_bytes and secret_key_bytes:
                print(f"Keys generated successfully for {signer_name}")  # Debug log
                return JsonResponse({
                    'message': 'Key pair generated successfully',
                    'public_key_file': f"{signer_name}.public.pem",
                    'private_key_file': f"{signer_name}.private.pem"
                })
            else:
                print(f"Failed to generate keys for {signer_name}")  # Debug log
                return JsonResponse({'error': 'Failed to generate keys'}, status=500)
                
        except Exception as e:
            print(f"Error in generate_key_pair: {str(e)}")  # Debug log
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def sign_document_view(request):
    if request.method == 'POST':
        try:
            print("Received sign document request")  # Debug log
            data = json.loads(request.body)
            print(f"Request data: {data}")  # Debug log
            
            signer_name = data.get('signer_name')
            password = data.get('password')
            document_path = data.get('document_path')
            
            if not all([signer_name, password, document_path]):
                print("Missing required fields")  # Debug log
                return JsonResponse({'error': 'Signer name, password and document path are required'}, status=400)
            
            print(f"Loading private key for {signer_name}")  # Debug log
            
            # Load private key
            secret_key_bytes = load_private_key(password, signer_name)
            
            if not secret_key_bytes:
                print("Failed to load private key")  # Debug log
                return JsonResponse({
                    'error': 'Failed to load private key. Please make sure you have generated keys first and the signer name is correct.'
                }, status=500)
            
            print("Private key loaded successfully")  # Debug log
            
            # Sign document
            signature_data = sign_document(secret_key_bytes, document_path, signer_name)
            
            if signature_data:
                print("Document signed successfully")  # Debug log
                return JsonResponse({
                    'message': 'Document signed successfully',
                    'signature_data': signature_data
                })
            else:
                print("Failed to sign document")  # Debug log
                return JsonResponse({
                    'error': 'Failed to sign document. Please check if the document exists and you have the correct permissions.'
                }, status=500)
                
        except Exception as e:
            print(f"Error in sign_document_view: {str(e)}")  # Debug log
            import traceback
            print(traceback.format_exc())  # Print full traceback
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def verify_signature_view(request):
    if request.method == 'POST':
        try:
            print("Received verify signature request")  # Debug log
            data = json.loads(request.body)
            print(f"Request data: {data}")  # Debug log
            
            signer_name = data.get('signer_name')
            document_path = data.get('document_path')
            
            if not all([signer_name, document_path]):
                print("Missing required fields")  # Debug log
                return JsonResponse({'error': 'Signer name and document path are required'}, status=400)
            
            print(f"Loading public key for {signer_name}")  # Debug log
            
            # Load public key
            public_key_bytes = load_public_key(signer_name)
            
            if not public_key_bytes:
                print("Failed to load public key")  # Debug log
                return JsonResponse({
                    'error': 'Failed to load public key. Please make sure you have generated keys first and the signer name is correct.'
                }, status=500)
            
            print("Public key loaded successfully")  # Debug log
            
            # Get signature from database
            try:
                from .models import Signature
                signature = Signature.objects.get(
                    signer_name=signer_name,
                    document_path=document_path
                )
                signature_data = signature.signature_data
            except Signature.DoesNotExist:
                print("Signature not found in database")  # Debug log
                return JsonResponse({
                    'error': 'No signature found for this document and signer.'
                }, status=404)
            
            # Verify signature
            verification_result = verify_signature(
                public_key_bytes,
                document_path,
                signature_data
            )
            
            if verification_result:
                print("Signature verification completed")  # Debug log
                return JsonResponse({
                    'message': 'Signature verification completed',
                    'result': verification_result
                })
            else:
                print("Failed to verify signature")  # Debug log
                return JsonResponse({
                    'error': 'Failed to verify signature. Please check if the document exists and you have the correct permissions.'
                }, status=500)
                
        except Exception as e:
            print(f"Error in verify_signature_view: {str(e)}")  # Debug log
            import traceback
            print(traceback.format_exc())  # Print full traceback
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)
