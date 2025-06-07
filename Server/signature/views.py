from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import os
import json
from .models import Signature, KeyPair
from .utils import (
    generate_keys, save_keys, load_keys,
    sign_document, verify_signature
)

def index(request):
    return render(request, 'signature/index.html')

@csrf_exempt
def generate_key_pair(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            signer_name = data.get('signer_name')
            
            if not signer_name:
                return JsonResponse({'error': 'Signer name is required'}, status=400)
            
            # Generate new key pair
            public_key_bytes, secret_key_bytes = generate_keys()
            
            # Save keys to files
            public_key_file = f"{signer_name}.public.pem"
            private_key_file = f"{signer_name}.private.pem"
            
            if save_keys(public_key_bytes, secret_key_bytes, public_key_file, private_key_file):
                # Save to database
                KeyPair.objects.create(
                    signer_name=signer_name,
                    public_key_file=public_key_file,
                    private_key_file=private_key_file
                )
                return JsonResponse({
                    'message': 'Key pair generated successfully',
                    'public_key_file': public_key_file,
                    'private_key_file': private_key_file
                })
            else:
                return JsonResponse({'error': 'Failed to save keys'}, status=500)
                
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def sign_document_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            signer_name = data.get('signer_name')
            document_path = data.get('document_path')
            
            if not all([signer_name, document_path]):
                return JsonResponse({'error': 'Signer name and document path are required'}, status=400)
            
            # Load keys
            key_pair = KeyPair.objects.get(signer_name=signer_name)
            public_key_bytes, secret_key_bytes = load_keys(
                key_pair.public_key_file,
                key_pair.private_key_file
            )
            
            if not secret_key_bytes:
                return JsonResponse({'error': 'Failed to load keys'}, status=500)
            
            # Sign document
            signature_data = sign_document(secret_key_bytes, document_path, signer_name)
            
            if signature_data:
                # Save signature to database
                Signature.objects.create(
                    signer_name=signer_name,
                    document_path=document_path,
                    signature_data=signature_data
                )
                return JsonResponse({
                    'message': 'Document signed successfully',
                    'signature_data': signature_data
                })
            else:
                return JsonResponse({'error': 'Failed to sign document'}, status=500)
                
        except KeyPair.DoesNotExist:
            return JsonResponse({'error': 'Key pair not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def verify_signature_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            signer_name = data.get('signer_name')
            document_path = data.get('document_path')
            
            if not all([signer_name, document_path]):
                return JsonResponse({'error': 'Signer name and document path are required'}, status=400)
            
            # Get signature from database
            signature = Signature.objects.get(
                signer_name=signer_name,
                document_path=document_path
            )
            
            # Load public key
            key_pair = KeyPair.objects.get(signer_name=signer_name)
            public_key_bytes, _ = load_keys(key_pair.public_key_file)
            
            if not public_key_bytes:
                return JsonResponse({'error': 'Failed to load public key'}, status=500)
            
            # Verify signature
            verification_result = verify_signature(
                public_key_bytes,
                document_path,
                signature.signature_data
            )
            
            if verification_result:
                return JsonResponse({
                    'message': 'Signature verification completed',
                    'result': verification_result
                })
            else:
                return JsonResponse({'error': 'Failed to verify signature'}, status=500)
                
        except (Signature.DoesNotExist, KeyPair.DoesNotExist):
            return JsonResponse({'error': 'Signature or key pair not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)
