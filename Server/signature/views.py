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

# Tạo thư mục lưu sản phẩm nếu chưa có
PRODUCTS_DIR = os.path.join(settings.BASE_DIR, 'products')
os.makedirs(PRODUCTS_DIR, exist_ok=True)

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
            uploaded_file = request.FILES.get('pdf') # Tên field vẫn là 'pdf' từ client

            if not all([signer_name, signature, timestamp, uploaded_file]):
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            # Tạo tên file duy nhất với đuôi .pdf
            filename = f"invoice_{signer_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            file_path = os.path.join(INVOICES_DIR, filename)

            # Lưu file PDF
            with open(file_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)

            # Lưu thông tin hóa đơn vào database
            invoice_data = {
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
            
            # Tạo ID mới, đảm bảo duy nhất
            new_id = (max([inv['id'] for inv in invoices]) + 1) if invoices else 1
            invoice_data['id'] = new_id

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
                filename=f"invoice_{invoice['signer_name']}.pdf",
                content_type='application/pdf'
            )

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)



@csrf_exempt
def upload_order(request):
    """Bên mua upload file order TXT đã ký"""
    if request.method == 'POST':
        try:
            buyer_name = request.POST.get('buyer_name')
            signature = request.POST.get('signature')
            timestamp = request.POST.get('timestamp')
            uploaded_file = request.FILES.get('txt')  # Đổi từ 'pdf' sang 'txt'

            if not all([buyer_name, signature, timestamp, uploaded_file]):
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            # Tạo tên file duy nhất với đuôi .txt
            filename = f"order_{buyer_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            file_path = os.path.join(ORDERS_DIR, filename)

            with open(file_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)

            order_data = {
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

            # Tạo ID mới, đảm bảo duy nhất
            new_id = (max([o['id'] for o in orders]) + 1) if orders else 1
            order_data['id'] = new_id

            orders.append(order_data)
            with open(metadata_path, 'w') as f:
                json.dump(orders, f, indent=2)

            return JsonResponse({'message': 'Order uploaded successfully', 'order_id': order_data['id']})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def list_orders(request):
    """Lấy danh sách order DOCX"""
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
    """Tải order DOCX"""
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
            
            # Trả về file DOCX
            return FileResponse(
                open(order['file_path'], 'rb'),
                as_attachment=True,
                filename=f"order_{order['buyer_name']}.txt",
                content_type='text/plain'
            )
        except Exception as e:
            print(f"Error downloading order: {str(e)}") # Debug log
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@api_view(['POST'])
def register(request):
    """Đăng ký người dùng mới và tạo certificate"""
    try:
        data = request.data
        public_key_b64 = data.get('public_key')
        payload = data.get('payload')
        signature_b64 = data.get('signature')
        
        if not all([public_key_b64, payload, signature_b64]):
            return Response({'error': 'Missing required data'}, status=400)
            
        public_key = base64.b64decode(public_key_b64)
        signature = base64.b64decode(signature_b64)
        
        # Verify proof of possession
        if not verify_proof_of_possession(public_key, payload, signature):
            return Response({'error': 'Invalid proof of possession'}, status=400)
            
        # Create certificate
        username = payload.get('username')
        role = payload.get('role')
        certificate = create_certificate(username, public_key, role)
            
        # Lấy public key và hash của CA để trả về cho client
        with open('keys/ca_public_key.pem', 'r') as f:
            ca_public_key_data = json.load(f)
            ca_public_key_b64 = ca_public_key_data['public_key']
            
        ca_public_key_bytes = base64.b64decode(ca_public_key_b64)
        ca_public_key_hash_b64 = base64.b64encode(hashlib.sha256(ca_public_key_bytes).digest()).decode('utf-8')
                
        return Response({
            'message': 'User registered successfully',
            'certificate': certificate,
            'ca_public_key': ca_public_key_b64,
            'ca_public_key_hash': ca_public_key_hash_b64
        })
            
    except Exception as e:
        traceback.print_exc()
        return Response({'error': str(e)}, status=500)

@csrf_exempt
def get_certificate(request):
    """Lấy certificate của người dùng"""
    if request.method == 'GET':
        username = request.GET.get('username')
        if not username:
            return JsonResponse({'error': 'Username required'}, status=400)
            
        cert_path = f'certificates/{username}_cert.json'
        if not os.path.exists(cert_path):
            return JsonResponse({'error': 'Certificate not found'}, status=404)
            
        try:
            with open(cert_path, 'r') as f:
                certificate = json.load(f)
            return JsonResponse({'certificate': certificate})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
        
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def add_product(request):
    """Bên bán thêm sản phẩm mới"""
    if request.method == 'POST':
        try:
            seller_name = request.POST.get('seller_name')
            product_name = request.POST.get('product_name')
            price = request.POST.get('price')
            
            if not all([seller_name, product_name, price]):
                return JsonResponse({'error': 'Missing required fields'}, status=400)
            
            try:
                price = float(price)
            except ValueError:
                return JsonResponse({'error': 'Invalid price format'}, status=400)
            
            # Lưu sản phẩm vào file JSON
            products_file = os.path.join(PRODUCTS_DIR, 'products.json')
            if os.path.exists(products_file):
                with open(products_file, 'r') as f:
                    products = json.load(f)
            else:
                products = []
            
            # Tạo ID mới cho sản phẩm
            new_id = (max([p['id'] for p in products]) + 1) if products else 1
            
            product_data = {
                'id': new_id,
                'seller_name': seller_name,
                'product_name': product_name,
                'price': price,
                'created_at': datetime.now().isoformat()
            }
            
            products.append(product_data)
            
            with open(products_file, 'w') as f:
                json.dump(products, f, indent=2)
            
            return JsonResponse({
                'message': 'Product added successfully',
                'product_id': new_id
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def list_products(request):
    """Lấy danh sách sản phẩm"""
    if request.method == 'GET':
        try:
            products_file = os.path.join(PRODUCTS_DIR, 'products.json')
            if not os.path.exists(products_file):
                return JsonResponse([], safe=False)
            
            with open(products_file, 'r') as f:
                products = json.load(f)
            
            return JsonResponse(products, safe=False)
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def list_my_products(request):
    """Lấy danh sách sản phẩm của người bán cụ thể"""
    if request.method == 'GET':
        try:
            seller_name = request.GET.get('seller_name')
            if not seller_name:
                return JsonResponse({'error': 'Seller name required'}, status=400)
            
            products_file = os.path.join(PRODUCTS_DIR, 'products.json')
            if not os.path.exists(products_file):
                return JsonResponse([], safe=False)
            
            with open(products_file, 'r') as f:
                all_products = json.load(f)
            
            # Lọc sản phẩm theo seller_name
            my_products = [p for p in all_products if p['seller_name'] == seller_name]
            
            return JsonResponse(my_products, safe=False)
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def list_my_invoices(request):
    """Lấy danh sách hóa đơn của người bán cụ thể"""
    if request.method == 'GET':
        try:
            seller_name = request.GET.get('seller_name')
            if not seller_name:
                return JsonResponse({'error': 'Seller name required'}, status=400)
            
            metadata_path = os.path.join(INVOICES_DIR, 'invoices.json')
            if not os.path.exists(metadata_path):
                return JsonResponse([], safe=False)

            with open(metadata_path, 'r') as f:
                all_invoices = json.load(f)

            # Lọc hóa đơn theo signer_name
            my_invoices = [{
                'id': inv['id'],
                'signer_name': inv['signer_name'],
                'timestamp': inv['timestamp']
            } for inv in all_invoices if inv['signer_name'] == seller_name]

            return JsonResponse(my_invoices, safe=False)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def list_my_orders(request):
    """Lấy danh sách order của người mua cụ thể"""
    if request.method == 'GET':
        try:
            buyer_name = request.GET.get('buyer_name')
            if not buyer_name:
                return JsonResponse({'error': 'Buyer name required'}, status=400)
            
            metadata_path = os.path.join(ORDERS_DIR, 'orders.json')
            if not os.path.exists(metadata_path):
                return JsonResponse([], safe=False)
            
            with open(metadata_path, 'r') as f:
                all_orders = json.load(f)
            
            # Lọc order theo buyer_name
            my_orders = [{
                'id': order['id'],
                'buyer_name': order['buyer_name'],
                'timestamp': order['timestamp']
            } for order in all_orders if order['buyer_name'] == buyer_name]
            
            return JsonResponse(my_orders, safe=False)
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)
