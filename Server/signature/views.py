from django.shortcuts import render, redirect
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import os
import json
from .models import Signature, KeyPair
from .utils import (
    verify_proof_of_possession, create_certificate
)
import tempfile
from datetime import datetime
from dilithium_py.ml_dsa import ML_DSA_44
import traceback
import base64
from rest_framework.decorators import api_view
from rest_framework.response import Response
import hashlib

# Tạo thư mục lưu hóa đơn nếu chưa tồn tại
INVOICES_DIR = os.path.join(settings.BASE_DIR, 'invoices')
os.makedirs(INVOICES_DIR, exist_ok=True)

# Tạo thư mục lưu order nếu chưa có
ORDERS_DIR = os.path.join(settings.BASE_DIR, 'orders')
os.makedirs(ORDERS_DIR, exist_ok=True)

def index(request):
    return render(request, 'signature/index.html')


@csrf_exempt
def check_user(request):
    """Kiểm tra user tồn tại và trả về vai trò"""
    if request.method == 'GET':
        username = request.GET.get('username')
        if not username:
            return JsonResponse({'error': 'Username is required'}, status=400)
            
        # Kiểm tra certificate file tồn tại và đọc vai trò
        certificate_path = os.path.join('certificates', f"{username}_cert.json")
        if os.path.exists(certificate_path):
            try:
                with open(certificate_path, 'r') as f:
                    certificate = json.load(f)
                    role = certificate['payload']['role']  # Lấy vai trò từ certificate
                return JsonResponse({'message': 'User exists', 'role': role})  # Trả về vai trò
            except Exception as e:
                # Ghi log lỗi nếu không đọc được file hoặc thiếu trường role
                print(f"Error reading certificate file for user {username}: {str(e)}")
                return JsonResponse({'error': f'Could not read user data for {username}'}, status=500)
        else:
            return JsonResponse({'message': 'User not found'})
            
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
                print(f"Error: orders.json not found at {metadata_path}") # Debug log
                return JsonResponse({'error': 'No orders found'}, status=404)
            
            with open(metadata_path, 'r') as f:
                orders = json.load(f)
            
            order = next((o for o in orders if o['id'] == int(order_id)), None)
            if not order:
                print(f"Error: Order with ID {order_id} not found in {metadata_path}") # Debug log
                return JsonResponse({'error': 'Order not found'}, status=404)
            
            file_path = order['file_path']
            print(f"Attempting to open file: {file_path}") # Debug log
            
            if not os.path.exists(file_path):
                print(f"Error: File does not exist at {file_path}") # Debug log
                return JsonResponse({'error': f'File not found on server: {file_path}'}, status=404)
            
            # Check permissions (optional, but good for debugging)
            if not os.access(file_path, os.R_OK):
                print(f"Error: No read permissions for file: {file_path}") # Debug log
                return JsonResponse({'error': f'No read permissions for file: {file_path}'}, status=403) # Forbidden
            
            return FileResponse(
                open(file_path, 'rb'),
                as_attachment=True,
                filename=f"order_{order['buyer_name']}.pdf"
            )
        except Exception as e:
            print(f"Exception in download_order: {str(e)}") # Debug log
            print(traceback.format_exc()) # In toàn bộ traceback
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@api_view(['POST'])
def register(request):
    try:
        data = request.data
        
        if not all(key in data for key in ['public_key', 'payload', 'signature']):
            return Response({
                'error': 'Missing required fields',
                'received_fields': list(data.keys())
            }, status=400)
            
        try:
            public_key = base64.b64decode(data['public_key'])
            payload = data['payload']
            signature = base64.b64decode(data['signature'])
        except Exception as e:
            return Response({
                'error': f'Invalid data format: {str(e)}'
            }, status=400)
        
        # Verify proof of possession
        if not verify_proof_of_possession(public_key, payload, signature):
            return Response({
                'error': 'Invalid proof of possession'
            }, status=400)
            
        try:
            # Create certificate
            certificate = create_certificate(payload['username'], public_key, payload['role'])
            
            # Read CA public key and create its hash
            with open('keys/ca_public_key.pem', 'r') as f:
                ca_key_data = json.load(f)  # Parse JSON data
                ca_public_key = ca_key_data['public_key']
                ca_public_key_bytes = base64.b64decode(ca_public_key)
                # Sử dụng hashlib.sha256 thay vì ML_DSA_44.hash
                ca_public_key_hash = hashlib.sha256(ca_public_key_bytes).digest()
                
            return Response({
                'message': 'Registration successful',
                'certificate': certificate,
                'ca_public_key': ca_public_key,
                'ca_public_key_hash': base64.b64encode(ca_public_key_hash).decode('utf-8')
            })
        except Exception as e:
            print(f"Error in certificate creation: {str(e)}")
            return Response({
                'error': f'Certificate creation failed: {str(e)}'
            }, status=400)
            
    except Exception as e:
        print(f"Error in register: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return Response({
            'error': str(e)
        }, status=400)

@csrf_exempt
def get_certificate(request):
    """Lấy certificate của user"""
    if request.method == 'GET':
        username = request.GET.get('username')
        if not username:
            return JsonResponse({'error': 'Missing username'}, status=400)
            
        certificate_path = os.path.join(settings.BASE_DIR, 'certificates', f"{username}_cert.json")
        if not os.path.exists(certificate_path):
            return JsonResponse({'error': 'Certificate not found'}, status=404)
            
        with open(certificate_path, 'r') as f:
            certificate = json.load(f)
            
        return JsonResponse({'certificate': certificate})
        
    return JsonResponse({'error': 'Method not allowed'}, status=405)
