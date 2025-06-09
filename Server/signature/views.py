from django.shortcuts import render, redirect
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import os
import json
from .models import Signature, KeyPair
from .utils import (
    generate_keys, save_keys,
    sign_document, verify_signature,
    load_private_key, load_public_key,
    sign_pdf_and_embed_signature, verify_pdf_with_embedded_signature
)
import tempfile
from datetime import datetime
from dilithium_py.ml_dsa import ML_DSA_44

# Tạo thư mục lưu hóa đơn nếu chưa tồn tại
INVOICES_DIR = os.path.join(settings.BASE_DIR, 'invoices')
os.makedirs(INVOICES_DIR, exist_ok=True)

# Tạo thư mục lưu order nếu chưa có
ORDERS_DIR = os.path.join(settings.BASE_DIR, 'orders')
os.makedirs(ORDERS_DIR, exist_ok=True)

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
                    'result': verification_result,
                    'timestamp': signature.created_at,
                    'signer': signature.signer_name
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

@csrf_exempt
def sign_pdf(request):
    if request.method == 'POST':
        try:
            pdf_file = request.FILES.get('pdf')
            signer_name = request.POST.get('signer_name')
            password = request.POST.get('password')
            if not pdf_file or not signer_name or not password:
                return JsonResponse({'error': 'Thiếu thông tin đầu vào.'}, status=400)
            # Lưu file tạm
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_in:
                tmp_in.write(pdf_file.read())
                tmp_in_path = tmp_in.name
            # Load private key
            private_key = load_private_key(password, signer_name)
            if not private_key:
                os.remove(tmp_in_path)
                return JsonResponse({'error': 'Không load được private key.'}, status=400)
            # Ký và nhúng signature
            tmp_out_path = tmp_in_path + '.signed.pdf'
            signed_pdf_path, _ = sign_pdf_and_embed_signature(tmp_in_path, private_key, tmp_out_path)
            if not signed_pdf_path:
                os.remove(tmp_in_path)
                return JsonResponse({'error': 'Ký PDF thất bại.'}, status=500)
            # Trả file PDF đã ký
            f = open(signed_pdf_path, 'rb')
            response = FileResponse(f, as_attachment=True, filename='signed_' + pdf_file.name)
            os.remove(tmp_in_path)
            return response
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def verify_pdf(request):
    if request.method == 'POST':
        try:
            pdf_file = request.FILES.get('pdf')
            public_key_b64 = request.POST.get('public_key')
            if not pdf_file or not public_key_b64:
                return JsonResponse({'error': 'Thiếu thông tin đầu vào.'}, status=400)
            import base64
            public_key = base64.b64decode(public_key_b64.replace('\n', '').replace(' ', ''))
            # Lưu file tạm
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_in:
                tmp_in.write(pdf_file.read())
                tmp_in_path = tmp_in.name
            # Xác thực
            is_valid = verify_pdf_with_embedded_signature(tmp_in_path, public_key)
            os.remove(tmp_in_path)
            return JsonResponse({'is_valid': is_valid})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def check_user(request):
    """Kiểm tra user tồn tại"""
    if request.method == 'GET':
        username = request.GET.get('username')
        if not username:
            return JsonResponse({'error': 'Username is required'}, status=400)
            
        # Kiểm tra public key file tồn tại
        public_key_path = os.path.join('keys', f"{username}.public.pem")
        if os.path.exists(public_key_path):
            return JsonResponse({'message': 'User exists'})
        else:
            return JsonResponse({'error': 'User not found'}, status=404)
            
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def upload_invoice(request):
    """Upload hóa đơn đã ký lên server"""
    if request.method == 'POST':
        try:
            # Lấy thông tin từ request
            signer_name = request.POST.get('signer_name')
            signature = request.POST.get('signature')
            timestamp = request.POST.get('timestamp')
            pdf_file = request.FILES.get('pdf')

            if not all([signer_name, signature, timestamp, pdf_file]):
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            # Tạo tên file duy nhất
            filename = f"invoice_{signer_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            file_path = os.path.join(INVOICES_DIR, filename)

            # Lưu file PDF
            with open(file_path, 'wb+') as destination:
                for chunk in pdf_file.chunks():
                    destination.write(chunk)

            # Lưu thông tin hóa đơn vào database
            invoice_data = {
                'id': len(os.listdir(INVOICES_DIR)),  # ID đơn giản
                'signer_name': signer_name,
                'file_path': file_path,
                'signature': signature,
                'timestamp': timestamp
            }

            # Lưu metadata vào file JSON
            metadata_path = os.path.join(INVOICES_DIR, 'invoices.json')
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    invoices = json.load(f)
            else:
                invoices = []

            invoices.append(invoice_data)

            with open(metadata_path, 'w') as f:
                json.dump(invoices, f, indent=2)

            return JsonResponse({
                'message': 'Invoice uploaded successfully',
                'invoice_id': invoice_data['id']
            })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def list_invoices(request):
    """Lấy danh sách hóa đơn"""
    if request.method == 'GET':
        try:
            metadata_path = os.path.join(INVOICES_DIR, 'invoices.json')
            if not os.path.exists(metadata_path):
                return JsonResponse([], safe=False)

            with open(metadata_path, 'r') as f:
                invoices = json.load(f)

            # Chỉ trả về thông tin cần thiết
            invoice_list = [{
                'id': inv['id'],
                'signer_name': inv['signer_name'],
                'timestamp': inv['timestamp']
            } for inv in invoices]

            return JsonResponse(invoice_list, safe=False)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def download_invoice(request, invoice_id):
    """Tải hóa đơn"""
    if request.method == 'GET':
        try:
            metadata_path = os.path.join(INVOICES_DIR, 'invoices.json')
            if not os.path.exists(metadata_path):
                return JsonResponse({'error': 'No invoices found'}, status=404)

            with open(metadata_path, 'r') as f:
                invoices = json.load(f)

            # Tìm hóa đơn theo ID
            invoice = next((inv for inv in invoices if inv['id'] == int(invoice_id)), None)
            if not invoice:
                return JsonResponse({'error': 'Invoice not found'}, status=404)

            # Trả về file PDF
            return FileResponse(
                open(invoice['file_path'], 'rb'),
                as_attachment=True,
                filename=f"invoice_{invoice['signer_name']}.pdf"
            )

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def get_public_key(request):
    """Trả về public key của user"""
    if request.method == 'GET':
        signer_name = request.GET.get('signer_name')
        if not signer_name:
            return JsonResponse({'error': 'Missing signer_name'}, status=400)
        public_key_path = os.path.join('keys', f"{signer_name}.public.pem")
        if not os.path.exists(public_key_path):
            return JsonResponse({'error': 'Public key not found'}, status=404)
        with open(public_key_path, 'r') as f:
            data = json.load(f)
        return JsonResponse({'public_key': data['public_key']})
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def upload_order(request):
    """Bên mua upload file order PDF đã ký"""
    if request.method == 'POST':
        try:
            buyer_name = request.POST.get('buyer_name')
            signature = request.POST.get('signature')
            timestamp = request.POST.get('timestamp')
            pdf_file = request.FILES.get('pdf')

            if not all([buyer_name, signature, timestamp, pdf_file]):
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            filename = f"order_{buyer_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            file_path = os.path.join(ORDERS_DIR, filename)

            with open(file_path, 'wb+') as destination:
                for chunk in pdf_file.chunks():
                    destination.write(chunk)

            order_data = {
                'id': len(os.listdir(ORDERS_DIR)),
                'buyer_name': buyer_name,
                'file_path': file_path,
                'signature': signature,
                'timestamp': timestamp
            }

            metadata_path = os.path.join(ORDERS_DIR, 'orders.json')
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    orders = json.load(f)
            else:
                orders = []

            orders.append(order_data)
            with open(metadata_path, 'w') as f:
                json.dump(orders, f, indent=2)

            return JsonResponse({'message': 'Order uploaded successfully', 'order_id': order_data['id']})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def list_orders(request):
    """Lấy danh sách order PDF"""
    if request.method == 'GET':
        try:
            metadata_path = os.path.join(ORDERS_DIR, 'orders.json')
            if not os.path.exists(metadata_path):
                return JsonResponse([], safe=False)
            with open(metadata_path, 'r') as f:
                orders = json.load(f)
            order_list = [{
                'id': order['id'],
                'buyer_name': order['buyer_name'],
                'timestamp': order['timestamp']
            } for order in orders]
            return JsonResponse(order_list, safe=False)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def download_order(request, order_id):
    """Tải order PDF"""
    if request.method == 'GET':
        try:
            metadata_path = os.path.join(ORDERS_DIR, 'orders.json')
            if not os.path.exists(metadata_path):
                return JsonResponse({'error': 'No orders found'}, status=404)
            with open(metadata_path, 'r') as f:
                orders = json.load(f)
            order = next((o for o in orders if o['id'] == int(order_id)), None)
            if not order:
                return JsonResponse({'error': 'Order not found'}, status=404)
            return FileResponse(
                open(order['file_path'], 'rb'),
                as_attachment=True,
                filename=f"order_{order['buyer_name']}.pdf"
            )
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Method not allowed'}, status=405)
