import sys
import os
import json
import logging
import requests
import base64
import io
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QLineEdit, QTabWidget,
    QMessageBox, QTextEdit, QGroupBox, QFormLayout, QInputDialog,
    QListWidget, QListWidgetItem, QDialog, QComboBox
)
from PyQt5.QtCore import Qt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from dilithium_py.ml_dsa import ML_DSA_44
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, TextStringObject
from datetime import datetime, timedelta
import qrcode
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO
import tempfile
import hashlib
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle, Paragraph, SimpleDocTemplate, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Unique identifier for our metadata
METADATA_IDENTIFIER = "MLDSA_METADATA_JSON:"

# Đường dẫn tuyệt đối hoặc tương đối đến file font
font_path = "DejaVuSans.ttf"  # Đặt file này cùng thư mục với script
pdfmetrics.registerFont(TTFont('DejaVu', font_path))
base_font = 'DejaVu'

def verify_certificate(certificate):
    """Verify a certificate using CA's public key"""
    try:
        # Read CA info from file
        ca_info_path = os.path.join(os.path.expanduser("~"), ".pdf_verifier", "keys", "ca_info.json")
        if not os.path.exists(ca_info_path):
            print("CA info file not found")
            return False
            
        with open(ca_info_path, 'r') as f:
            ca_info = json.load(f)
        
        # Use the verified CA public key
        ca_public_key = base64.b64decode(ca_info['ca_public_key'])
        
        # Extract payload and signature from certificate
        payload = certificate['payload']
        signature = base64.b64decode(certificate['signature'])
        
        # Verify signature
        return ML_DSA_44.verify(ca_public_key, json.dumps(payload, sort_keys=True).encode(), signature)
    except Exception as e:
        print(f"Error verifying certificate: {e}")
        return False

class PDFVerifier(QMainWindow):
    def __init__(self):
        super().__init__()
        self.API_BASE_URL = "http://localhost:8000"
        self.current_user = None
        self.current_user_role = None
        self.keys_dir = os.path.join(os.path.expanduser("~"), ".pdf_verifier", "keys")
        os.makedirs(self.keys_dir, exist_ok=True)
        self.init_ui()

    def init_ui(self):
        """Khởi tạo giao diện"""
        self.setWindowTitle('Hệ thống Ký và Xác thực PDF')
        self.setGeometry(100, 100, 1000, 600)

        # Widget chính
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        self.main_layout = QVBoxLayout(main_widget)

        # Tạo login widget
        self.login_widget = QWidget()
        self.init_login_ui()
        self.main_layout.addWidget(self.login_widget)

        # Tạo main content widget (sẽ ẩn ban đầu)
        self.content_widget = QWidget()
        self.init_content_ui()
        self.content_widget.hide()
        self.main_layout.addWidget(self.content_widget)

    def init_login_ui(self):
        """Khởi tạo giao diện đăng nhập"""
        login_layout = QVBoxLayout(self.login_widget)
        
        # Tạo group box cho phần đăng nhập
        login_group = QGroupBox("Đăng nhập")
        login_form = QFormLayout()
        
        self.username_input = QLineEdit()
        login_form.addRow("Username:", self.username_input)
        
        # Thêm layout ngang cho các nút
        button_layout = QHBoxLayout()
        
        login_btn = QPushButton("Đăng nhập")
        login_btn.clicked.connect(self.login)
        button_layout.addWidget(login_btn)
        
        register_btn = QPushButton("Đăng ký")
        register_btn.clicked.connect(self.show_register_dialog)
        button_layout.addWidget(register_btn)
        
        login_form.addRow("", button_layout)
        login_group.setLayout(login_form)
        
        # Thêm vào layout chính
        login_layout.addWidget(login_group)
        login_layout.addStretch()

    def init_content_ui(self):
        """Khởi tạo giao diện chính sau khi đăng nhập"""
        content_layout = QVBoxLayout(self.content_widget)
        
        # Thêm header với thông tin người dùng và nút đăng xuất
        header_layout = QHBoxLayout()
        self.user_label = QLabel()
        header_layout.addWidget(self.user_label)
        
        logout_btn = QPushButton("Đăng xuất")
        logout_btn.clicked.connect(self.logout)
        header_layout.addWidget(logout_btn)
        
        content_layout.addLayout(header_layout)
        
        # Tab widget
        self.tabs = QTabWidget()
        
        # Tab Bên bán (khởi tạo nhưng chưa thêm vào tabs)
        self.seller_tab = QWidget()
        seller_layout = QVBoxLayout()
        
        # Product management section
        product_group = QGroupBox("Quản lý sản phẩm")
        product_layout = QVBoxLayout()
        
        # Product input fields
        product_form = QFormLayout()
        self.product_name_input = QLineEdit()
        self.product_price_input = QLineEdit()
        self.product_price_input.setPlaceholderText("Ví dụ: 100000")
        product_form.addRow("Tên sản phẩm:", self.product_name_input)
        product_form.addRow("Giá (VNĐ):", self.product_price_input)
        product_layout.addLayout(product_form)
        
        # Add product button
        add_product_btn = QPushButton("Thêm sản phẩm")
        add_product_btn.clicked.connect(self.add_product)
        product_layout.addWidget(add_product_btn)
        
        # My products list
        self.my_products_list = QListWidget()
        product_layout.addWidget(QLabel("Sản phẩm của tôi:"))
        product_layout.addWidget(self.my_products_list)
        
        refresh_products_btn = QPushButton("Làm mới danh sách sản phẩm")
        refresh_products_btn.clicked.connect(self.refresh_my_products)
        product_layout.addWidget(refresh_products_btn)
        
        product_group.setLayout(product_layout)
        seller_layout.addWidget(product_group)
        
        # Thêm danh sách order từ bên mua
        order_group = QGroupBox("Danh sách order từ bên mua")
        order_layout = QVBoxLayout()
        self.order_list = QListWidget()
        self.order_list.itemDoubleClicked.connect(self.download_and_verify_order)
        order_layout.addWidget(self.order_list)
        refresh_order_btn = QPushButton("Làm mới danh sách order")
        refresh_order_btn.clicked.connect(self.refresh_order_list)
        order_layout.addWidget(refresh_order_btn)
        order_group.setLayout(order_layout)
        seller_layout.addWidget(order_group)
        
        # Thêm danh sách hóa đơn của tôi
        my_invoice_group = QGroupBox("Hóa đơn của tôi")
        my_invoice_layout = QVBoxLayout()
        self.my_invoice_list = QListWidget()
        self.my_invoice_list.itemDoubleClicked.connect(self.download_and_verify_invoice)
        my_invoice_layout.addWidget(self.my_invoice_list)
        refresh_my_invoice_btn = QPushButton("Làm mới danh sách hóa đơn")
        refresh_my_invoice_btn.clicked.connect(self.refresh_my_invoice_list)
        my_invoice_layout.addWidget(refresh_my_invoice_btn)
        my_invoice_group.setLayout(my_invoice_layout)
        seller_layout.addWidget(my_invoice_group)
        
        self.seller_tab.setLayout(seller_layout)

        # Tab Bên mua (khởi tạo nhưng chưa thêm vào tabs)
        self.buyer_tab = QWidget()
        buyer_layout = QVBoxLayout()
        
        # Shopping section
        shopping_group = QGroupBox("Mua sắm")
        shopping_layout = QVBoxLayout()
        
        # Products list
        self.products_list = QListWidget()
        self.products_list.itemDoubleClicked.connect(self.select_product_for_order)
        shopping_layout.addWidget(QLabel("Danh sách sản phẩm:"))
        shopping_layout.addWidget(self.products_list)
        
        refresh_products_btn = QPushButton("Làm mới danh sách sản phẩm")
        refresh_products_btn.clicked.connect(self.refresh_products)
        shopping_layout.addWidget(refresh_products_btn)
        
        # Shopping cart
        cart_group = QGroupBox("Giỏ hàng")
        cart_layout = QVBoxLayout()
        
        self.cart_list = QListWidget()
        cart_layout.addWidget(self.cart_list)
        
        # Total price
        self.total_price_label = QLabel("Tổng tiền: 0 VNĐ")
        cart_layout.addWidget(self.total_price_label)
        
        # Cart buttons
        cart_buttons_layout = QHBoxLayout()
        clear_cart_btn = QPushButton("Xóa giỏ hàng")
        clear_cart_btn.clicked.connect(self.clear_cart)
        create_order_btn = QPushButton("Tạo đơn hàng")
        create_order_btn.clicked.connect(self.create_order_from_cart)
        cart_buttons_layout.addWidget(clear_cart_btn)
        cart_buttons_layout.addWidget(create_order_btn)
        cart_layout.addLayout(cart_buttons_layout)
        
        cart_group.setLayout(cart_layout)
        shopping_layout.addWidget(cart_group)
        
        shopping_group.setLayout(shopping_layout)
        buyer_layout.addWidget(shopping_group)
        
        # Invoice list section
        invoice_group = QGroupBox("Danh sách hóa đơn")
        invoice_layout = QVBoxLayout()
        
        self.invoice_list = QListWidget()
        self.invoice_list.itemDoubleClicked.connect(self.download_and_verify_invoice)
        invoice_layout.addWidget(self.invoice_list)
        
        refresh_btn = QPushButton("Làm mới danh sách")
        refresh_btn.clicked.connect(self.refresh_invoice_list)
        invoice_layout.addWidget(refresh_btn)
        
        invoice_group.setLayout(invoice_layout)
        buyer_layout.addWidget(invoice_group)
        
        # Thêm danh sách order đã gửi
        my_order_group = QGroupBox("Order đã gửi")
        my_order_layout = QVBoxLayout()
        self.my_order_list = QListWidget()
        my_order_layout.addWidget(self.my_order_list)
        refresh_my_order_btn = QPushButton("Làm mới danh sách order")
        refresh_my_order_btn.clicked.connect(self.refresh_my_order_list)
        my_order_layout.addWidget(refresh_my_order_btn)
        my_order_group.setLayout(my_order_layout)
        buyer_layout.addWidget(my_order_group)
        
        self.buyer_tab.setLayout(buyer_layout)

        content_layout.addWidget(self.tabs)

    def login(self):
        """Đăng nhập với username"""
        username = self.username_input.text().strip()
        if not username:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập username")
            return
            
        try:
            # Kiểm tra user tồn tại và lấy vai trò
            response = requests.get(
                f"{self.API_BASE_URL}/check-user",
                params={"username": username}
            )
            response_data = response.json()
            
            if response.status_code == 200 and response_data.get('message') == 'User exists':
                self.current_user = username
                self.current_user_role = response_data.get('role')
                self.user_label.setText(f"Đã đăng nhập: {username} ({self.current_user_role})")
                
                # Ẩn login widget và hiện content widget
                self.login_widget.hide()
                self.content_widget.show()
                
                self.update_ui_for_role()
                
                QMessageBox.information(self, "Thành công", f"Đăng nhập thành công: {username}")
            else:
                QMessageBox.warning(self, "Lỗi", response_data.get('message', 'Username không tồn tại hoặc lỗi server'))
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi đăng nhập: {str(e)}")

    def logout(self):
        """Đăng xuất"""
        self.current_user = None
        self.current_user_role = None
        self.username_input.clear()
        
        # Xóa tất cả các tab khi đăng xuất
        self.tabs.clear()

        # Ẩn content widget và hiện login widget
        self.content_widget.hide()
        self.login_widget.show()
        
        QMessageBox.information(self, "Thông báo", "Đã đăng xuất thành công")

    def update_ui_for_role(self):
        """Cập nhật giao diện dựa trên vai trò của người dùng"""
        # Xóa tất cả các tab hiện có
        self.tabs.clear() 

        if self.current_user_role == 'seller':
            self.tabs.addTab(self.seller_tab, "Bên bán")
            self.tabs.setCurrentWidget(self.seller_tab)
            self.refresh_my_products()
            self.refresh_order_list()
            self.refresh_my_invoice_list()
        elif self.current_user_role == 'buyer':
            self.tabs.addTab(self.buyer_tab, "Bên mua")
            self.tabs.setCurrentWidget(self.buyer_tab)
            self.refresh_products()
            self.refresh_invoice_list()
            self.refresh_my_order_list()
        else:
            QMessageBox.warning(self, "Lỗi", "Vai trò người dùng không xác định. Vui lòng liên hệ quản trị viên.")

    def refresh_invoice_list(self):
        """Làm mới danh sách hóa đơn"""
        if not self.current_user:
            return

        try:
            response = requests.get(
                f"{self.API_BASE_URL}/list-invoices/"
            )
            response.raise_for_status()
            
            invoices = response.json()
            self.invoice_list.clear()
            
            for invoice in invoices:
                item = QListWidgetItem(
                    f"Hóa đơn từ {invoice['signer_name']} - {invoice['timestamp']}"
                )
                item.setData(Qt.UserRole, invoice)
                self.invoice_list.addItem(item)
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi lấy danh sách hóa đơn: {str(e)}")

    def download_and_verify_invoice(self, item):
        """Tải và xác thực hóa đơn PDF (đọc metadata nhúng trong PDF)"""
        from PyPDF2 import PdfReader, PdfWriter
        from PyPDF2.generic import NameObject, TextStringObject
        import hashlib
        import tempfile
        invoice = item.data(Qt.UserRole)
        try:
            # Tải invoice PDF
            response = requests.get(
                f"{self.API_BASE_URL}/download-invoice/{invoice['id']}"
            )
            response.raise_for_status()
            
            temp_path = os.path.join(os.path.expanduser("~"), "Downloads", f"invoice_{invoice['id']}_from_{invoice['signer_name']}.pdf")
            with open(temp_path, 'wb') as f:
                f.write(response.content)
            # Đọc metadata nhúng trong PDF
            reader = PdfReader(temp_path)
            metadata = reader.metadata.get('/MLDSA_Metadata')
            if metadata:
                metadata = json.loads(metadata)
                signature_b64 = metadata.get('signature')
                signature = base64.b64decode(signature_b64)
                signer_seller = metadata.get('signer')
                sign_time_seller = metadata.get('sign_time')
                # Lấy certificate của người bán
                response_cert = requests.get(
                    f"{self.API_BASE_URL}/get-certificate/",
                    params={'username': signer_seller}
                )
                response_cert.raise_for_status()
                seller_certificate = response_cert.json()['certificate']
                # Xác minh certificate
                if not verify_certificate(seller_certificate):
                    print(f"[DEBUG] Certificate không hợp lệ: {seller_certificate}")
                    QMessageBox.warning(self, "Lỗi", "Certificate của người bán không hợp lệ")
                    return
                public_key_seller = base64.b64decode(seller_certificate['payload']['public_key'])
                # Tạo file PDF tạm với metadata signature rỗng
                temp_pdf_no_sig = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
                metadata_no_sig = dict(metadata)
                metadata_no_sig['signature'] = ''
                reader = PdfReader(temp_path)
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)
                info_dict = writer._info.get_object()
                info_dict.update({
                    NameObject('/MLDSA_Metadata'): TextStringObject(json.dumps(metadata_no_sig, ensure_ascii=False))
                })
                with open(temp_pdf_no_sig.name, 'wb') as f:
                    writer.write(f)
                temp_pdf_no_sig.close()  # Đảm bảo file đã đóng
                # Đọc lại bytes PDF tạm này để xác thực
                with open(temp_pdf_no_sig.name, 'rb') as f:
                    pdf_bytes_to_verify = f.read()
                # Xác minh chữ ký
                try:
                    is_valid_seller_signature = ML_DSA_44.verify(public_key_seller, pdf_bytes_to_verify, signature)
                except Exception as verify_error:
                    print(f"[DEBUG] Lỗi xác thực PDF: {verify_error}")
                    is_valid_seller_signature = False
                # Hiển thị kết quả và debug nếu không hợp lệ
                result_text = f"Kết quả xác thực hóa đơn PDF:\n\n"
                result_text += f"Người bán: {signer_seller}\n"
                result_text += f"Thời gian ký: {sign_time_seller}\n"
                result_text += f"Chữ ký người bán: {'Hợp lệ' if is_valid_seller_signature else 'Không hợp lệ'}\n\n"
                if is_valid_seller_signature:
                    result_text += "✅ Hóa đơn PDF đã được xác thực thành công!"
                else:
                    result_text += "❌ Hóa đơn PDF không hợp lệ!\n"
                    print("[DEBUG] SHA256 PDF:", hashlib.sha256(pdf_bytes_to_verify).hexdigest())
                    print("[DEBUG] Signature (base64):", signature_b64)
                    print("[DEBUG] Public key (base64):", base64.b64encode(public_key_seller).decode())
                    print("[DEBUG] Metadata:", json.dumps(metadata, ensure_ascii=False))
                QMessageBox.information(self, "Kết quả xác thực PDF", result_text)
                # Xóa file tạm
                os.remove(temp_pdf_no_sig.name)
            else:
                print(f"[DEBUG] Không tìm thấy metadata nhúng trong PDF")
                QMessageBox.information(self, "Tải hóa đơn PDF", f"Đã tải hóa đơn PDF về: {temp_path}\nKhông tìm thấy metadata nhúng để xác thực tự động.")
        except Exception as e:
            print(f"[DEBUG] Lỗi khi tải hoặc xác thực PDF: {str(e)}")
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi tải hoặc xác thực hóa đơn PDF: {str(e)}")

    def get_key_paths(self, username=None):
        """Lấy đường dẫn đến file khóa"""
        # Sử dụng username được truyền vào hoặc current_user
        target_username = username or self.current_user
        if not target_username:
            return None, None
        
        private_key_path = os.path.join(self.keys_dir, f"{target_username}.private.pem")
        public_key_path = os.path.join(self.keys_dir, f"{target_username}.public.pem")
        return private_key_path, public_key_path

    def save_keys(self, public_key, private_key, password, username=None):
        """Lưu cặp khóa vào file"""
        try:
            # Đảm bảo thư mục keys tồn tại
            os.makedirs(self.keys_dir, exist_ok=True)
            
            # Sử dụng username được truyền vào hoặc current_user
            target_username = username or self.current_user
            if not target_username:
                print("Không có username để lưu khóa")  # Debug log
                return False
            
            private_key_path = os.path.join(self.keys_dir, f"{target_username}.private.pem")
            public_key_path = os.path.join(self.keys_dir, f"{target_username}.public.pem")
            
            print(f"Đang lưu khóa vào: {private_key_path} và {public_key_path}")  # Debug log

            # Lưu public key
            with open(public_key_path, 'w') as f:
                json.dump({
                    'public_key': base64.b64encode(public_key).decode('utf-8')
                }, f)

            # Mã hóa và lưu private key
            salt = get_random_bytes(16)
            iv = get_random_bytes(16)
            key = PBKDF2(password.encode(), salt, dkLen=32, count=10000)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Pad private key
            padded_sk = private_key + b'\0' * (16 - len(private_key) % 16)
            encrypted_sk = cipher.encrypt(padded_sk)

            with open(private_key_path, 'w') as f:
                json.dump({
                    'salt': base64.b64encode(salt).decode('utf-8'),
                    'iv': base64.b64encode(iv).decode('utf-8'),
                    'encrypted_key': base64.b64encode(encrypted_sk).decode('utf-8')
                }, f)

            return True
        except Exception as e:
            logging.error(f"Lỗi khi lưu khóa: {str(e)}")
            print(f"Chi tiết lỗi: {str(e)}")  # Debug log
            return False

    def load_private_key(self, password):
        """Đọc và giải mã private key"""
        try:
            private_key_path, _ = self.get_key_paths()
            if not private_key_path or not os.path.exists(private_key_path):
                return None

            with open(private_key_path, 'r') as f:
                key_data = json.load(f)
                salt = base64.b64decode(key_data['salt'])
                iv = base64.b64decode(key_data['iv'])
                encrypted_key = base64.b64decode(key_data['encrypted_key'])

            key = PBKDF2(password.encode(), salt, dkLen=32, count=10000)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_key = cipher.decrypt(encrypted_key)
            return decrypted_key.rstrip(b'\0')

        except Exception as e:
            logging.error(f"Lỗi khi đọc private key: {str(e)}")
            return None

    def sign_and_upload_order_txt(self):
        """Bên mua ký và upload Order TXT"""
        if not self.current_user:
            QMessageBox.warning(self, "Lỗi", "Vui lòng đăng nhập trước")
            return
        file_path = self.order_sign_path.text()
        if not file_path:
            QMessageBox.warning(self, "Lỗi", "Vui lòng chọn file Order TXT")
            return
        password, ok = QInputDialog.getText(
            self, "Nhập mật khẩu", "Mật khẩu:", QLineEdit.Password
        )
        if not ok or not password:
            return
        try:
            print(f"DEBUG: Bắt đầu ký file {file_path}")
            
            private_key = self.load_private_key(password)
            if not private_key:
                QMessageBox.critical(self, "Lỗi", "Không thể đọc private key")
                return
            
            with open(file_path, "r", encoding="utf-8") as f:
                order_content = f.read()
            timestamp = datetime.now().isoformat()

            # Bước 1: Tạo metadata
            metadata = {
                'buyer': self.current_user,
                'sign_time': timestamp
            }

            # Bước 2: Ghép nội dung file TXT mới
            txt_to_sign = (
                f"---ORDER METADATA---\n"
                f"{json.dumps(metadata, ensure_ascii=False)}\n"
                f"---ORDER CONTENT---\n"
                f"{order_content}\n"
            )
            bytes_to_sign = txt_to_sign.encode("utf-8")

            # Bước 3: Ký số
            signature = ML_DSA_44.sign(private_key, bytes_to_sign)
            signature_b64 = base64.b64encode(signature).decode('utf-8')

            # Bước 4: Lưu file TXT cuối cùng
            final_txt_path_for_upload = file_path.replace('.txt', '_signed.txt')
            with open(final_txt_path_for_upload, "w", encoding="utf-8") as f:
                f.write(txt_to_sign)
                f.write(f"---SIGNATURE---\n{signature_b64}\n")

            # Bước 5: Upload file đã ký
            with open(final_txt_path_for_upload, 'rb') as f:
                files = {'txt': f}
                data = {
                    'buyer_name': self.current_user,
                    'signature': signature_b64,
                    'timestamp': timestamp
                }
                response = requests.post(
                    f"{self.API_BASE_URL}/upload-order/",
                    files=files,
                    data=data
                )
                response.raise_for_status()
            
            print(f"DEBUG: Upload thành công, order ID: {response.json().get('id', 'unknown')}")
            
            QMessageBox.information(
                self, "Thành công",
                f"Ký và upload Order TXT thành công. File đã ký được lưu tại:\n{final_txt_path_for_upload}"
            )
            self.order_sign_path.clear()
            
        except Exception as e:
            print(f"DEBUG: Exception trong sign_and_upload_order_txt: {str(e)}")
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi ký và upload Order TXT: {str(e)}")

    def refresh_order_list(self):
        try:
            response = requests.get(f"{self.API_BASE_URL}/list-orders/")
            response.raise_for_status()
            orders = response.json()
            self.order_list.clear()
            for order in orders:
                item = QListWidgetItem(
                    f"Order từ {order['buyer_name']} - {order['timestamp']}"
                )
                item.setData(Qt.UserRole, order)
                self.order_list.addItem(item)
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi lấy danh sách order: {str(e)}")

    def refresh_my_order_list(self):
        try:
            response = requests.get(
                f"{self.API_BASE_URL}/list-my-orders/",
                params={'buyer_name': self.current_user}
            )
            response.raise_for_status()
            
            orders = response.json()
            self.my_order_list.clear()
            
            for order in orders:
                item = QListWidgetItem(
                    f"Order {order['id']} - {order['timestamp']}"
                )
                item.setData(Qt.UserRole, order)
                self.my_order_list.addItem(item)
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi lấy danh sách order: {str(e)}")

    def create_qr_code(self, seller_name, buyer_name, timestamp, invoice_number=None, order_number=None):
        """Tạo mã QR chứa thông tin cơ bản của cả bên bán và bên mua"""
        qr_data = {
            "seller": seller_name,
            "buyer": buyer_name,
            "timestamp": timestamp,
        }
        if invoice_number:
            qr_data["invoice_number"] = invoice_number
        if order_number:
            qr_data["order_number"] = order_number

        qr_data_str = json.dumps(qr_data)
        
        # Tạo mã QR
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data_str)
        qr.make(fit=True)
        
        # Tạo hình ảnh mã QR
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Chuyển đổi hình ảnh thành bytes
        img_byte_arr = BytesIO()
        qr_image.save(img_byte_arr, format='PNG')
        return img_byte_arr.getvalue()


    def download_and_verify_order(self, item):
        """Tải và xác thực order TXT"""
        order = item.data(Qt.UserRole)
        try:
            print(f"DEBUG: Bắt đầu xác thực order {order['id']} từ {order['buyer_name']}")
            temp_txt_path = os.path.join(os.path.expanduser("~"), "Downloads", f"order_{order['id']}_from_{order['buyer_name']}.txt")
            response = requests.get(
                f"{self.API_BASE_URL}/download-order/{order['id']}"
            )
            response.raise_for_status()
            content_type = response.headers.get('Content-Type', '')
            if 'text/plain' not in content_type and not order.get('file_path', '').endswith('.txt'):
                QMessageBox.warning(self, "Lỗi", "Chỉ hỗ trợ xác thực order TXT.")
                return
            with open(temp_txt_path, 'wb') as f:
                f.write(response.content)
            print(f"DEBUG: Đã tải order TXT về {temp_txt_path}, kích thước: {len(response.content)} bytes")
            with open(temp_txt_path, 'r', encoding='utf-8') as f:
                txt = f.read()

            try:
                sig_marker = '---SIGNATURE---'
                sig_idx = txt.index(sig_marker)
                txt_to_verify = txt[:sig_idx].rstrip('\r\n') + '\n'
                signature_b64 = txt[sig_idx + len(sig_marker):].strip()
            except Exception as e:
                QMessageBox.warning(self, "Lỗi", f"File TXT không đúng định dạng: {e}")
                return

            metadata_marker = '---ORDER METADATA---'
            content_marker = '---ORDER CONTENT---'
            try:
                meta_start = txt.index(metadata_marker) + len(metadata_marker)
                content_start = txt.index(content_marker)
                metadata_json = txt[meta_start:content_start].strip()
                metadata = json.loads(metadata_json)
            except Exception as e:
                QMessageBox.warning(self, "Lỗi", f"Không đọc được metadata: {e}")
                return

            signature = base64.b64decode(signature_b64)
            buyer = metadata.get('buyer')
            sign_time = metadata.get('sign_time')

            # Lấy certificate của người mua
            response_cert = requests.get(
                f"{self.API_BASE_URL}/get-certificate/",
                params={'username': buyer}
            )
            response_cert.raise_for_status()
            buyer_certificate = response_cert.json()['certificate']
            if not verify_certificate(buyer_certificate):
                QMessageBox.warning(self, "Lỗi", "Certificate của người mua không hợp lệ")
                return
            public_key_buyer = base64.b64decode(buyer_certificate['payload']['public_key'])

            # Xác minh chữ ký
            is_valid_signature = ML_DSA_44.verify(public_key_buyer, txt_to_verify.encode('utf-8'), signature)
            if not is_valid_signature:
                import hashlib
                print(f"DEBUG: txt_to_verify length: {len(txt_to_verify.encode('utf-8'))}")
                print(f"DEBUG: txt_to_verify hash: {hashlib.sha256(txt_to_verify.encode('utf-8')).hexdigest()}")
                print(f"DEBUG: Signature base64: {signature_b64[:40]}...")
                print(f"DEBUG: Metadata: {json.dumps(metadata, ensure_ascii=False)}")
                print(f"DEBUG: txt_to_verify preview: {txt_to_verify[:100]}")
            if is_valid_signature:
                reply = QMessageBox.information(
                    self, "Xác thực Order thành công!",
                    f"Order từ {buyer} - Thời gian: {sign_time}\nChữ ký của người mua hợp lệ.\n\nBạn có muốn ký và tạo Hóa đơn (Invoice) PDF từ Order này không?",
                    QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
                )
                if reply == QMessageBox.Yes:
                    self.sign_order_metadata_as_invoice_pdf(metadata, buyer)
                elif reply == QMessageBox.No:
                    QMessageBox.information(self, "Thông báo", "Order đã được tải về và xác thực.")
            else:
                QMessageBox.warning(self, "Lỗi", "Xác thực thất bại: Chữ ký của người mua không hợp lệ. (Xem debug console để biết chi tiết)")
        except Exception as e:
            print(f"DEBUG: Exception trong download_and_verify_order: {str(e)}")
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi tải và xác thực order: {str(e)}")

    def sign_order_metadata_as_invoice_pdf(self, order_metadata, buyer_name):
        """Người bán ký order TXT đã xác thực và tạo hóa đơn PDF có mã QR, nhúng metadata vào PDF, upload lên server"""
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import Table, TableStyle, Paragraph, SimpleDocTemplate, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        import qrcode
        import tempfile
        from PyPDF2 import PdfReader, PdfWriter
        from PyPDF2.generic import NameObject, TextStringObject
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.pdfbase import pdfmetrics
        import os
        password, ok = QInputDialog.getText(
            self, "Nhập mật khẩu", "Mật khẩu của bạn:", QLineEdit.Password
        )
        if not ok or not password:
            return
        try:
            # Đăng ký font Unicode (bắt buộc, không fallback)
            font_path = os.path.join(os.path.dirname(__file__), "DejaVuSans.ttf")
            if not os.path.exists(font_path):
                raise FileNotFoundError("Không tìm thấy file font DejaVuSans.ttf! Đặt file này cùng thư mục với script.")
            pdfmetrics.registerFont(TTFont('DejaVu', font_path))
            base_font = 'DejaVu'
            private_key = self.load_private_key(password)
            if not private_key:
                QMessageBox.critical(self, "Lỗi", "Không thể đọc private key của bạn.")
                return
            invoice_number = f"INV{datetime.now().strftime('%Y%m%d%H%M%S')}"
            invoice_date = datetime.now().strftime('%d/%m/%Y')
            pdf_path = os.path.join(os.path.expanduser("~"), "Downloads", f"invoice_{buyer_name}_from_{self.current_user}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
            elements = []
            styles = getSampleStyleSheet()
            styles.add(ParagraphStyle(name='VNTitle', fontName=base_font, fontSize=18, alignment=1, spaceAfter=12))
            styles.add(ParagraphStyle(name='VNNormal', fontName=base_font, fontSize=11, alignment=0))
            styles.add(ParagraphStyle(name='VNTable', fontName=base_font, fontSize=10, alignment=0))
            # Tiêu đề
            elements.append(Paragraph("<b>HÓA ĐƠN BÁN HÀNG</b>", styles['VNTitle']))
            # Thông tin hóa đơn
            info_data = [
                ["Số hóa đơn:", invoice_number, "Ngày:", invoice_date],
                ["Bên bán:", self.current_user, "Bên mua:", buyer_name],
                ["Địa chỉ:", "456 Đường XYZ, Quận 3, TP.HCM", "Email:", f"{self.current_user}@company.com"],
                ["Mã số thuế:", "9876543210", "Số điện thoại:", "0281234567"]
            ]
            info_table = Table(info_data, colWidths=[70, 150, 70, 150])
            info_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), base_font),
                ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
                ('TEXTCOLOR', (0,0), (-1,0), colors.black),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('BOTTOMPADDING', (0,0), (-1,0), 6),
                ('BACKGROUND', (0,1), (-1,-1), colors.whitesmoke),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
            ]))
            elements.append(info_table)
            elements.append(Spacer(1, 12))
            # Thông tin khách hàng
            customer_info = order_metadata.get('customer_info', {})
            customer_data = [
                ["Khách hàng:", customer_info.get('name', buyer_name)],
                ["Địa chỉ:", customer_info.get('address', '')],
                ["Email:", customer_info.get('email', '')],
                ["Mã số thuế:", customer_info.get('tax_code', '')],
                ["Số điện thoại:", customer_info.get('phone', '')]
            ]
            customer_table = Table(customer_data, colWidths=[100, 340])
            customer_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), base_font),
                ('BACKGROUND', (0,0), (0,-1), colors.lightgrey),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('BOTTOMPADDING', (0,0), (0,-1), 4),
                ('BACKGROUND', (1,0), (1,-1), colors.whitesmoke),
                ('GRID', (0,0), (-1,-1), 0.25, colors.grey)
            ]))
            elements.append(customer_table)
            elements.append(Spacer(1, 12))
            # Bảng sản phẩm
            product_data = [["STT", "Tên sản phẩm", "Số lượng", "Đơn giá", "Thành tiền"]]
            for idx, item in enumerate(order_metadata.get('order_items', [])):
                product_data.append([
                    str(idx+1), item['product_name'], str(item['quantity']), f"{item['price']:,}", f"{item['total']:,}"])
            product_table = Table(product_data, colWidths=[40, 180, 60, 80, 80])
            product_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), base_font),
                ('BACKGROUND', (0,0), (-1,0), colors.lightblue),
                ('TEXTCOLOR', (0,0), (-1,0), colors.black),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('BOTTOMPADDING', (0,0), (-1,0), 6),
                ('BACKGROUND', (0,1), (-1,-1), colors.white),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
            ]))
            elements.append(product_table)
            elements.append(Spacer(1, 12))
            # Tổng kết
            summary_data = [
                ["Tổng tiền hàng:", f"{order_metadata.get('subtotal', 0):,} VNĐ"],
                ["Phí vận chuyển:", f"{order_metadata.get('shipping_fee', 0):,} VNĐ"],
                ["Thuế VAT:", f"{order_metadata.get('tax_amount', 0):,} VNĐ"],
                ["Chiết khấu:", f"{order_metadata.get('discount', 0):,} VNĐ"],
                ["Tổng cộng phải trả:", f"{order_metadata.get('total_amount', 0):,} VNĐ"]
            ]
            summary_table = Table(summary_data, colWidths=[150, 290])
            summary_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), base_font),
                ('BACKGROUND', (0,0), (0,-1), colors.lightgrey),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTSIZE', (0,0), (-1,-1), 10),
                ('BOTTOMPADDING', (0,0), (0,-1), 4),
                ('BACKGROUND', (1,0), (1,-1), colors.whitesmoke),
                ('GRID', (0,0), (-1,-1), 0.25, colors.grey)
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 18))
            # QR code
            qr_data = {
                "seller": self.current_user,
                "buyer": buyer_name,
                "invoice_number": invoice_number,
                "timestamp": invoice_date,
                "total_amount": order_metadata.get('total_amount', 0)
            }
            qr_img = qrcode.make(json.dumps(qr_data, ensure_ascii=False))
            qr_temp = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
            qr_img.save(qr_temp)
            qr_temp.close()
            from reportlab.platypus import Image
            elements.append(Paragraph("<b>Quét mã QR để xem thông tin hóa đơn</b>", styles['VNNormal']))
            elements.append(Image(qr_temp.name, width=80, height=80))
            elements.append(Spacer(1, 12))
            # Footer
            elements.append(Paragraph("<font size=9 color=grey>Hóa đơn được ký số bởi hệ thống MLDSA</font>", styles['VNNormal']))
            doc.build(elements)
            os.remove(qr_temp.name)
            # B1: Nhúng metadata (chưa có chữ ký)
            metadata_invoice = {
                'signer': self.current_user,
                'sign_time': datetime.now().isoformat(),
                'invoice_number': invoice_number,
                'buyer_name': buyer_name,
                'order_metadata': order_metadata,
                'signature': ''
            }
            reader = PdfReader(pdf_path)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            info_dict = writer._info.get_object()
            info_dict.update({
                NameObject('/MLDSA_Metadata'): TextStringObject(json.dumps(metadata_invoice, ensure_ascii=False))
            })
            with open(pdf_path, 'wb') as f:
                writer.write(f)
            # B2: Đọc lại PDF, ký số trên bytes này
            with open(pdf_path, 'rb') as f:
                pdf_bytes = f.read()
            signature = ML_DSA_44.sign(private_key, pdf_bytes)
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            # B3: Nhúng lại metadata với chữ ký
            metadata_invoice['signature'] = signature_b64
            reader = PdfReader(pdf_path)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            info_dict = writer._info.get_object()
            info_dict.update({
                NameObject('/MLDSA_Metadata'): TextStringObject(json.dumps(metadata_invoice, ensure_ascii=False))
            })
            with open(pdf_path, 'wb') as f:
                writer.write(f)
            # UPLOAD PDF lên server
            with open(pdf_path, 'rb') as f:
                files = {'pdf': f}
                data = {
                    'signer_name': self.current_user,
                    'signature': signature_b64,
                    'timestamp': datetime.now().isoformat()
                }
                response = requests.post(
                    f"{self.API_BASE_URL}/upload-invoice/",
                    files=files,
                    data=data
                )
                response.raise_for_status()
            QMessageBox.information(self, "Thành công", f"Đã tạo và upload hóa đơn PDF thành công!\nFile: {pdf_path}")
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi tạo hoặc upload hóa đơn PDF: {str(e)}")

    def show_register_dialog(self):
        """Hiển thị dialog đăng ký"""
        dialog = RegisterDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_data()
            self.register_user(data)

    def register_user(self, data):
        """Xử lý đăng ký người dùng"""
        username = data['username']
        password = data['password']
        confirm_password = data['confirm_password']
        role = data['role']
        
        if not username or not password or not role:
            QMessageBox.warning(self, "Lỗi", "Vui lòng điền đầy đủ thông tin và chọn vai trò")
            return
        
        if password != confirm_password:
            QMessageBox.warning(self, "Lỗi", "Mật khẩu xác nhận không khớp")
            return
        
        try:
            # Tạo cặp khóa mới
            public_key, private_key = ML_DSA_44.keygen()
            
            # Lưu khóa
            if not self.save_keys(public_key, private_key, password, username):
                QMessageBox.critical(self, "Lỗi", "Không thể lưu khóa")
                return
            
            # Tạo payload cho proof of possession
            payload = {
                'username': username,
                'role': role,
                'timestamp': datetime.now().isoformat()
            }
            
            # Ký payload để chứng minh sở hữu private key
            signature = ML_DSA_44.sign(private_key, json.dumps(payload, sort_keys=True).encode())
            
            # Gửi request đăng ký
            response = requests.post(
                f"{self.API_BASE_URL}/register/",
                json={
                    'public_key': base64.b64encode(public_key).decode('utf-8'),
                    'payload': payload,
                    'signature': base64.b64encode(signature).decode('utf-8')
                }
            )
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Lưu CA info
                ca_info = {
                    'ca_public_key': response_data['ca_public_key'],
                    'ca_public_key_hash': response_data['ca_public_key_hash']
                }
                
                ca_info_path = os.path.join(self.keys_dir, 'ca_info.json')
                with open(ca_info_path, 'w') as f:
                    json.dump(ca_info, f)
                
                QMessageBox.information(
                    self, "Thành công",
                    f"Đăng ký thành công!\nUsername: {username}\nVai trò: {role}\n\nVui lòng đăng nhập để sử dụng hệ thống."
                )
            else:
                error_msg = response.json().get('error', 'Lỗi không xác định')
                QMessageBox.critical(self, "Lỗi", f"Đăng ký thất bại: {error_msg}")
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi đăng ký: {str(e)}")

    # Product management methods
    def add_product(self):
        """Thêm sản phẩm mới"""
        if not self.current_user:
            QMessageBox.warning(self, "Lỗi", "Vui lòng đăng nhập trước")
            return
            
        product_name = self.product_name_input.text().strip()
        price_text = self.product_price_input.text().strip()
        
        if not product_name or not price_text:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập đầy đủ tên sản phẩm và giá")
            return
            
        try:
            price = float(price_text)
            if price <= 0:
                QMessageBox.warning(self, "Lỗi", "Giá phải lớn hơn 0")
                return
        except ValueError:
            QMessageBox.warning(self, "Lỗi", "Giá không hợp lệ")
            return
            
        try:
            response = requests.post(
                f"{self.API_BASE_URL}/add-product/",
                data={
                    'seller_name': self.current_user,
                    'product_name': product_name,
                    'price': price
                }
            )
            
            if response.status_code == 200:
                QMessageBox.information(self, "Thành công", "Đã thêm sản phẩm thành công!")
                self.product_name_input.clear()
                self.product_price_input.clear()
                self.refresh_my_products()
            else:
                error_msg = response.json().get('error', 'Lỗi không xác định')
                QMessageBox.critical(self, "Lỗi", f"Thêm sản phẩm thất bại: {error_msg}")
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi thêm sản phẩm: {str(e)}")

    def refresh_my_products(self):
        """Làm mới danh sách sản phẩm của tôi"""
        if not self.current_user:
            return
            
        try:
            response = requests.get(
                f"{self.API_BASE_URL}/list-my-products/",
                params={'seller_name': self.current_user}
            )
            response.raise_for_status()
            
            products = response.json()
            self.my_products_list.clear()
            
            for product in products:
                item = QListWidgetItem(
                    f"{product['product_name']} - {product['price']:,} VNĐ"
                )
                item.setData(Qt.UserRole, product)
                self.my_products_list.addItem(item)
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi lấy danh sách sản phẩm: {str(e)}")

    def refresh_products(self):
        """Làm mới danh sách tất cả sản phẩm"""
        try:
            response = requests.get(f"{self.API_BASE_URL}/list-products/")
            response.raise_for_status()
            
            products = response.json()
            self.products_list.clear()
            
            for product in products:
                item = QListWidgetItem(
                    f"{product['product_name']} - {product['price']:,} VNĐ (Bán bởi: {product['seller_name']})"
                )
                item.setData(Qt.UserRole, product)
                self.products_list.addItem(item)
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi lấy danh sách sản phẩm: {str(e)}")

    def select_product_for_order(self, item):
        """Chọn sản phẩm để thêm vào giỏ hàng"""
        product = item.data(Qt.UserRole)
        
        quantity, ok = QInputDialog.getInt(
            self, "Chọn số lượng", 
            f"Số lượng {product['product_name']}:", 
            value=1, min=1, max=100
        )
        
        if ok:
            # Thêm vào giỏ hàng
            cart_item = {
                'product': product,
                'quantity': quantity,
                'total': product['price'] * quantity
            }
            
            # Kiểm tra xem sản phẩm đã có trong giỏ hàng chưa
            for i in range(self.cart_list.count()):
                existing_item = self.cart_list.item(i)
                existing_data = existing_item.data(Qt.UserRole)
                if existing_data['product']['id'] == product['id']:
                    # Cập nhật số lượng
                    existing_data['quantity'] += quantity
                    existing_data['total'] = product['price'] * existing_data['quantity']
                    existing_item.setText(
                        f"{product['product_name']} x{existing_data['quantity']} - {existing_data['total']:,}"
                    )
                    existing_item.setData(Qt.UserRole, existing_data)
                    self.update_cart_total()
                    return
            
            # Thêm mới vào giỏ hàng
            item = QListWidgetItem(
                f"{product['product_name']} x{quantity} - {cart_item['total']:,}"
            )
            item.setData(Qt.UserRole, cart_item)
            self.cart_list.addItem(item)
            self.update_cart_total()

    def update_cart_total(self):
        """Cập nhật tổng tiền giỏ hàng"""
        total = 0
        for i in range(self.cart_list.count()):
            item = self.cart_list.item(i)
            cart_data = item.data(Qt.UserRole)
            total += cart_data['total']
        
        self.total_price_label.setText(f"Tổng tiền: {total:,} VNĐ")

    def clear_cart(self):
        """Xóa giỏ hàng"""
        self.cart_list.clear()
        self.update_cart_total()

    def create_order_from_cart(self):
        """Tạo đơn hàng từ giỏ hàng (dạng TXT)"""
        if self.cart_list.count() == 0:
            QMessageBox.warning(self, "Lỗi", "Giỏ hàng trống")
            return
        if not self.current_user:
            QMessageBox.warning(self, "Lỗi", "Vui lòng đăng nhập trước")
            return
        password, ok = QInputDialog.getText(
            self, "Nhập mật khẩu", "Mật khẩu:", QLineEdit.Password
        )
        if not ok or not password:
            return
        try:
            private_key = self.load_private_key(password)
            if not private_key:
                QMessageBox.critical(self, "Lỗi", "Không thể đọc private key")
                return

            order_number = f"ORD{datetime.now().strftime('%Y%m%d%H%M%S')}"
            order_date = datetime.now().strftime('%d/%m/%Y')
            timestamp = datetime.now().isoformat()

            # Lấy seller_name từ sản phẩm đầu tiên trong giỏ hàng (nếu có)
            seller_name = ""
            if self.cart_list.count() > 0:
                first_item = self.cart_list.item(0)
                product_data = first_item.data(Qt.UserRole)['product']
                seller_name = product_data.get('seller') or product_data.get('seller_name') or ""

            # Tổng hợp thông tin sản phẩm
            order_items = []
            subtotal = 0
            order_content_lines = []
            order_content_lines.append(f"Mã số Đơn hàng: {order_number}")
            order_content_lines.append(f"Ngày đặt hàng: {order_date}")
            order_content_lines.append(f"Kênh đặt hàng: Hệ thống điện tử")
            order_content_lines.append(f"Phương thức thanh toán: Chuyển khoản ngân hàng")
            order_content_lines.append("")
            order_content_lines.append(f"Tên khách hàng: {self.current_user}")
            order_content_lines.append(f"Địa chỉ giao hàng: 123 Đường ABC, Quận 1, TP.HCM")
            order_content_lines.append(f"Số điện thoại: 0901234567")
            order_content_lines.append(f"Email: {self.current_user}@email.com")
            order_content_lines.append(f"Mã số thuế: 0123456789")
            order_content_lines.append("")
            order_content_lines.append("STT | Tên sản phẩm/Dịch vụ | Số lượng | Đơn giá | Thành tiền")
            for i in range(self.cart_list.count()):
                item = self.cart_list.item(i)
                cart_data = item.data(Qt.UserRole)
                product = cart_data['product']
                line = f"{i+1} | {product['product_name']} | {cart_data['quantity']} | {product['price']:,} | {cart_data['total']:,}"
                order_content_lines.append(line)
                subtotal += cart_data['total']
                order_items.append({
                    'product_id': product['id'],
                    'product_name': product['product_name'],
                    'quantity': cart_data['quantity'],
                    'price': product['price'],
                    'total': cart_data['total']
                })
            order_content_lines.append("")
            shipping_fee = 50000
            discount = 0
            tax_rate = 0.1
            tax_amount = subtotal * tax_rate
            total_amount = subtotal + shipping_fee + tax_amount - discount
            order_content_lines.append(f"Tổng tiền hàng (Subtotal): {subtotal:,} VNĐ")
            order_content_lines.append(f"Chiết khấu/Mã giảm giá: {discount:,} VNĐ")
            order_content_lines.append(f"Phí vận chuyển: {shipping_fee:,} VNĐ")
            order_content_lines.append(f"Thuế VAT (10%): {tax_amount:,} VNĐ")
            order_content_lines.append(f"Tổng cộng phải trả: {total_amount:,} VNĐ")
            order_content_lines.append(f"Phương thức thanh toán: Chuyển khoản ngân hàng")
            order_content = "\n".join(order_content_lines)

            # Metadata
            metadata = {
                'buyer': self.current_user,
                'sign_time': timestamp,
                'order_number': order_number,
                'order_date': order_date,
                'order_items': order_items,
                'subtotal': subtotal,
                'shipping_fee': shipping_fee,
                'tax_amount': tax_amount,
                'discount': discount,
                'total_amount': total_amount,
                'customer_info': {
                    'name': self.current_user,
                    'address': "123 Đường ABC, Quận 1, TP.HCM",
                    'phone': "0901234567",
                    'email': f"{self.current_user}@email.com",
                    'tax_code': "0123456789"
                }
            }

            # Ghép file TXT
            txt_to_sign = (
                f"---ORDER METADATA---\n"
                f"{json.dumps(metadata, ensure_ascii=False)}\n"
                f"---ORDER CONTENT---\n"
                f"{order_content}\n"
            )
            bytes_to_sign = txt_to_sign.encode("utf-8")

            # Ký số
            signature = ML_DSA_44.sign(private_key, bytes_to_sign)
            signature_b64 = base64.b64encode(signature).decode('utf-8')

            # Lưu file TXT
            order_path = os.path.join(os.path.expanduser("~"), "Downloads", f"order_{self.current_user}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(order_path, "w", encoding="utf-8") as f:
                f.write(txt_to_sign)
                f.write(f"---SIGNATURE---\n{signature_b64}\n")

            # Upload lên server
            with open(order_path, 'rb') as f:
                files = {'txt': f}
                data = {
                    'buyer_name': self.current_user,
                    'signature': signature_b64,
                    'timestamp': timestamp
                }
                response = requests.post(
                    f"{self.API_BASE_URL}/upload-order/",
                    files=files,
                    data=data
                )
                response.raise_for_status()

            QMessageBox.information(
                self, "Thành công",
                f"Đã tạo đơn hàng thành công!\nMã đơn hàng: {order_number}\nFile được lưu tại: {order_path}"
            )
            self.clear_cart()
            self.refresh_my_order_list()
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi tạo đơn hàng: {str(e)}")

    def refresh_my_invoice_list(self):
        """Làm mới danh sách hóa đơn của tôi"""
        if not self.current_user:
            return
            
        try:
            response = requests.get(
                f"{self.API_BASE_URL}/list-my-invoices/",
                params={'seller_name': self.current_user}
            )
            response.raise_for_status()
            
            invoices = response.json()
            self.my_invoice_list.clear()
            
            for invoice in invoices:
                item = QListWidgetItem(
                    f"Hóa đơn {invoice['id']} - {invoice['timestamp']}"
                )
                item.setData(Qt.UserRole, invoice)
                self.my_invoice_list.addItem(item)
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi lấy danh sách hóa đơn: {str(e)}")

    def refresh_my_order_list(self):
        """Làm mới danh sách order của tôi"""
        if not self.current_user:
            return
            
        try:
            response = requests.get(
                f"{self.API_BASE_URL}/list-my-orders/",
                params={'buyer_name': self.current_user}
            )
            response.raise_for_status()
            
            orders = response.json()
            self.my_order_list.clear()
            
            for order in orders:
                item = QListWidgetItem(
                    f"Order {order['id']} - {order['timestamp']}"
                )
                item.setData(Qt.UserRole, order)
                self.my_order_list.addItem(item)
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi lấy danh sách order: {str(e)}")


class RegisterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        """Khởi tạo giao diện dialog đăng ký"""
        self.setWindowTitle('Đăng ký người dùng mới')
        self.setModal(True)
        self.setFixedSize(300, 200)

        layout = QVBoxLayout(self)

        # Form layout
        form_layout = QFormLayout()

        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)

        form_layout.addRow("Username:", self.username_input)
        form_layout.addRow("Mật khẩu:", self.password_input)
        form_layout.addRow("Xác nhận mật khẩu:", self.confirm_password_input)

        # Role selection
        self.role_combo = QComboBox()
        self.role_combo.addItems(['buyer', 'seller'])
        form_layout.addRow("Vai trò:", self.role_combo)

        layout.addLayout(form_layout)

        # Buttons
        button_layout = QHBoxLayout()
        register_btn = QPushButton("Đăng ký")
        register_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Hủy")
        cancel_btn.clicked.connect(self.reject)

        button_layout.addWidget(register_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

    def get_data(self):
        """Lấy dữ liệu từ dialog"""
        return {
            'username': self.username_input.text().strip(),
            'password': self.password_input.text(),
            'confirm_password': self.confirm_password_input.text(),
            'role': self.role_combo.currentText()
        }


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PDFVerifier()
    window.show()
    sys.exit(app.exec_())