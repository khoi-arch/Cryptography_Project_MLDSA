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
    QListWidget, QListWidgetItem, QDialog
)
from PyQt5.QtCore import Qt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from dilithium_py.ml_dsa import ML_DSA_44
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, TextStringObject
from datetime import datetime
import qrcode
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO
import tempfile

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PDFVerifier(QMainWindow):
    def __init__(self):
        super().__init__()
        self.API_BASE_URL = "http://localhost:8000"
        self.current_user = None
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
        
        # Tab Bên bán
        seller_tab = QWidget()
        seller_layout = QVBoxLayout()
        
        # Sign section
        sign_group = QGroupBox("Ký và Upload PDF")
        sign_layout = QVBoxLayout()
        
        self.sign_path = QLineEdit()
        self.sign_path.setReadOnly(True)
        sign_select_btn = QPushButton("Chọn file PDF")
        sign_select_btn.clicked.connect(self.select_sign_file)
        
        sign_layout.addWidget(QLabel("File PDF:"))
        sign_layout.addWidget(self.sign_path)
        sign_layout.addWidget(sign_select_btn)
        
        sign_btn = QPushButton("Ký và Upload PDF")
        sign_btn.clicked.connect(self.sign_and_upload_pdf)
        sign_layout.addWidget(sign_btn)
        
        sign_group.setLayout(sign_layout)
        seller_layout.addWidget(sign_group)
        
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
        
        seller_tab.setLayout(seller_layout)
        self.tabs.addTab(seller_tab, "Bên bán")

        # Tab Bên mua
        buyer_tab = QWidget()
        buyer_layout = QVBoxLayout()
        
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
        
        # Thêm chức năng upload order PDF
        order_upload_group = QGroupBox("Ký và Upload Order PDF")
        order_upload_layout = QVBoxLayout()
        self.order_sign_path = QLineEdit()
        self.order_sign_path.setReadOnly(True)
        order_sign_select_btn = QPushButton("Chọn file Order PDF")
        order_sign_select_btn.clicked.connect(self.select_order_sign_file)
        order_upload_layout.addWidget(QLabel("File Order PDF:"))
        order_upload_layout.addWidget(self.order_sign_path)
        order_upload_layout.addWidget(order_sign_select_btn)
        order_sign_btn = QPushButton("Ký và Upload Order PDF")
        order_sign_btn.clicked.connect(self.sign_and_upload_order_pdf)
        order_upload_layout.addWidget(order_sign_btn)
        order_upload_group.setLayout(order_upload_layout)
        buyer_layout.addWidget(order_upload_group)
        
        # Thêm danh sách order đã gửi
        my_order_group = QGroupBox("Order đã gửi")
        my_order_layout = QVBoxLayout()
        self.my_order_list = QListWidget()
        my_order_layout.addWidget(self.my_order_list)
        my_order_group.setLayout(my_order_layout)
        buyer_layout.addWidget(my_order_group)
        
        buyer_tab.setLayout(buyer_layout)
        self.tabs.addTab(buyer_tab, "Bên mua")

        content_layout.addWidget(self.tabs)

    def login(self):
        """Đăng nhập với username"""
        username = self.username_input.text().strip()
        if not username:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập username")
            return
            
        try:
            # Kiểm tra user tồn tại
            response = requests.get(
                f"{self.API_BASE_URL}/check-user",
                params={"username": username}
            )
            
            if response.status_code == 200:
                self.current_user = username
                self.user_label.setText(f"Đã đăng nhập: {username}")
                
                # Ẩn login widget và hiện content widget
                self.login_widget.hide()
                self.content_widget.show()
                
                # Làm mới danh sách hóa đơn nếu đang ở tab bên mua
                if self.tabs.currentIndex() == 1:
                    self.refresh_invoice_list()
                
                QMessageBox.information(self, "Thành công", f"Đăng nhập thành công: {username}")
            else:
                QMessageBox.warning(self, "Lỗi", "Username không tồn tại")
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi đăng nhập: {str(e)}")

    def logout(self):
        """Đăng xuất"""
        self.current_user = None
        self.username_input.clear()
        
        # Ẩn content widget và hiện login widget
        self.content_widget.hide()
        self.login_widget.show()
        
        QMessageBox.information(self, "Thông báo", "Đã đăng xuất thành công")

    def select_sign_file(self):
        """Chọn file PDF để ký"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Chọn file PDF", "", "PDF files (*.pdf)"
        )
        if file_path:
            self.sign_path.setText(file_path)

    def sign_and_upload_pdf(self):
        """Ký và upload file PDF (đúng quy trình placeholder)"""
        if not self.current_user:
            QMessageBox.warning(self, "Lỗi", "Vui lòng đăng nhập trước")
            return
        file_path = self.sign_path.text()
        if not file_path:
            QMessageBox.warning(self, "Lỗi", "Vui lòng chọn file PDF")
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
            
            # Lấy public key
            public_key_path, _ = self.get_key_paths()
            with open(public_key_path, 'r') as f:
                key_data = json.load(f)
                public_key = base64.b64decode(key_data['public_key'])
            
            # 1. Đọc PDF, thêm placeholder vào metadata
            reader = PdfReader(file_path)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            metadata = reader.metadata or {}
            metadata = {str(k): str(v) for k, v in metadata.items()}
            metadata['/Signer'] = self.current_user
            metadata['/Signature'] = '__SIGNATURE_PLACEHOLDER__'
            metadata['/SignTime'] = datetime.now().isoformat()
            writer.add_metadata(metadata)
            buf = io.BytesIO()
            writer.write(buf)
            pdf_bytes_with_placeholder = buf.getvalue()
            
            # 2. Ký trên bytes này
            signature = ML_DSA_44.sign(private_key, pdf_bytes_with_placeholder)
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            # 3. Ghi lại file PDF với chữ ký thực sự
            reader2 = PdfReader(io.BytesIO(pdf_bytes_with_placeholder))
            writer2 = PdfWriter()
            for page in reader2.pages:
                writer2.add_page(page)
            metadata2 = reader2.metadata or {}
            metadata2 = {str(k): str(v) for k, v in metadata2.items()}
            metadata2['/Signature'] = signature_b64
            writer2.add_metadata(metadata2)
            signed_pdf_path = file_path.replace('.pdf', '_signed.pdf')
            with open(signed_pdf_path, 'wb') as f:
                writer2.write(f)
            
            # 4. Tạo và thêm mã QR
            qr_image = self.create_qr_code(public_key, self.current_user, metadata2['/SignTime'])
            final_pdf_path = self.add_qr_to_pdf(signed_pdf_path, qr_image)
            
            # Upload file đã ký lên server
            with open(final_pdf_path, 'rb') as f:
                files = {'pdf': f}
                data = {
                    'signer_name': self.current_user,
                    'signature': signature_b64,
                    'timestamp': metadata2['/SignTime']
                }
                response = requests.post(
                    f"{self.API_BASE_URL}/upload-invoice/",
                    files=files,
                    data=data
                )
                response.raise_for_status()
            
            QMessageBox.information(
                self, "Thành công",
                f"Ký và upload PDF thành công. File đã ký được lưu tại:\n{final_pdf_path}"
            )
            self.sign_path.clear()
            
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi ký và upload PDF: {str(e)}")

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
        """Tải và xác thực hóa đơn (đúng quy trình placeholder)"""
        invoice = item.data(Qt.UserRole)
        try:
            response = requests.get(
                f"{self.API_BASE_URL}/download-invoice/{invoice['id']}"
            )
            response.raise_for_status()
            temp_path = os.path.join(os.path.expanduser("~"), "Downloads", f"invoice_{invoice['id']}.pdf")
            with open(temp_path, 'wb') as f:
                f.write(response.content)
            # Đọc file PDF đã ký
            reader = PdfReader(temp_path)
            metadata = reader.metadata
            if not metadata or '/Signature' not in metadata:
                QMessageBox.warning(self, "Lỗi", "File PDF không có chữ ký")
                return
            signature_b64 = metadata['/Signature']
            signer = metadata['/Signer']
            sign_time = metadata['/SignTime']
            # Lấy public key từ server
            response = requests.get(
                f"{self.API_BASE_URL}/get-public-key/",
                params={'signer_name': signer}
            )
            response.raise_for_status()
            public_key = base64.b64decode(response.json()['public_key'])
            # Tạo lại bytes PDF với placeholder
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            metadata2 = dict(metadata)
            metadata2['/Signature'] = '__SIGNATURE_PLACEHOLDER__'
            writer.add_metadata(metadata2)
            buf = io.BytesIO()
            writer.write(buf)
            pdf_bytes_with_placeholder = buf.getvalue()
            # Xác thực chữ ký
            signature = base64.b64decode(signature_b64)
            is_valid = ML_DSA_44.verify(public_key, pdf_bytes_with_placeholder, signature)
            if is_valid:
                QMessageBox.information(
                    self, "Thành công",
                    f"Xác thực thành công!\nNgười ký: {signer}\nThời gian: {sign_time}"
                )
            else:
                QMessageBox.warning(self, "Lỗi", "Xác thực thất bại: Chữ ký không hợp lệ")
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi tải và xác thực hóa đơn: {str(e)}")

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

    def select_order_sign_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Chọn file Order PDF", "", "PDF files (*.pdf)"
        )
        if file_path:
            self.order_sign_path.setText(file_path)

    def sign_and_upload_order_pdf(self):
        if not self.current_user:
            QMessageBox.warning(self, "Lỗi", "Vui lòng đăng nhập trước")
            return
        file_path = self.order_sign_path.text()
        if not file_path:
            QMessageBox.warning(self, "Lỗi", "Vui lòng chọn file PDF")
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

            # Lấy public key từ server
            try:
                response = requests.get(
                    f"{self.API_BASE_URL}/get-public-key/",
                    params={'signer_name': self.current_user}
                )
                response.raise_for_status()
                public_key = base64.b64decode(response.json()['public_key'])
            except Exception as e:
                QMessageBox.critical(self, "Lỗi", f"Không thể lấy public key từ server: {str(e)}")
                return

            # 1. Đọc PDF, thêm placeholder vào metadata
            reader = PdfReader(file_path)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            metadata = reader.metadata or {}
            metadata = {str(k): str(v) for k, v in metadata.items()}
            metadata['/Buyer'] = self.current_user
            metadata['/Signature'] = '__SIGNATURE_PLACEHOLDER__'
            metadata['/SignTime'] = datetime.now().isoformat()
            writer.add_metadata(metadata)
            buf = io.BytesIO()
            writer.write(buf)
            pdf_bytes_with_placeholder = buf.getvalue()

            # 2. Ký trên bytes này
            signature = ML_DSA_44.sign(private_key, pdf_bytes_with_placeholder)
            signature_b64 = base64.b64encode(signature).decode('utf-8')

            # 3. Ghi lại file PDF với chữ ký thực sự
            reader2 = PdfReader(io.BytesIO(pdf_bytes_with_placeholder))
            writer2 = PdfWriter()
            for page in reader2.pages:
                writer2.add_page(page)
            metadata2 = reader2.metadata or {}
            metadata2 = {str(k): str(v) for k, v in metadata2.items()}
            metadata2['/Signature'] = signature_b64
            writer2.add_metadata(metadata2)
            signed_pdf_path = file_path.replace('.pdf', '_order_signed.pdf')
            with open(signed_pdf_path, 'wb') as f:
                writer2.write(f)

            # 4. Tạo và thêm mã QR
            qr_image = self.create_qr_code(public_key, self.current_user, metadata2['/SignTime'])
            final_pdf_path = self.add_qr_to_pdf(signed_pdf_path, qr_image)

            # Upload file đã ký lên server
            with open(final_pdf_path, 'rb') as f:
                files = {'pdf': f}
                data = {
                    'buyer_name': self.current_user,
                    'signature': signature_b64,
                    'timestamp': metadata2['/SignTime']
                }
                response = requests.post(
                    f"{self.API_BASE_URL}/upload-order/",
                    files=files,
                    data=data
                )
                response.raise_for_status()

            QMessageBox.information(
                self, "Thành công",
                f"Ký và upload Order PDF thành công. File đã ký được lưu tại:\n{final_pdf_path}"
            )
            self.order_sign_path.clear()
            self.refresh_my_order_list()

        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi ký và upload Order PDF: {str(e)}")

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

    def download_and_verify_order(self, item):
        order = item.data(Qt.UserRole)
        try:
            response = requests.get(
                f"{self.API_BASE_URL}/download-order/{order['id']}"
            )
            response.raise_for_status()
            temp_path = os.path.join(os.path.expanduser("~"), "Downloads", f"order_{order['id']}.pdf")
            with open(temp_path, 'wb') as f:
                f.write(response.content)
            reader = PdfReader(temp_path)
            metadata = reader.metadata
            if not metadata or '/Signature' not in metadata:
                QMessageBox.warning(self, "Lỗi", "File PDF không có chữ ký")
                return
            signature_b64 = metadata['/Signature']
            buyer = metadata['/Buyer']
            sign_time = metadata['/SignTime']
            # Lấy public key từ server
            response = requests.get(
                f"{self.API_BASE_URL}/get-public-key/",
                params={'signer_name': buyer}
            )
            response.raise_for_status()
            public_key = base64.b64decode(response.json()['public_key'])
            # Tạo lại bytes PDF với placeholder
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            metadata2 = dict(metadata)
            metadata2['/Signature'] = '__SIGNATURE_PLACEHOLDER__'
            writer.add_metadata(metadata2)
            buf = io.BytesIO()
            writer.write(buf)
            pdf_bytes_with_placeholder = buf.getvalue()
            signature = base64.b64decode(signature_b64)
            is_valid = ML_DSA_44.verify(public_key, pdf_bytes_with_placeholder, signature)
            if is_valid:
                QMessageBox.information(
                    self, "Thành công",
                    f"Xác thực order thành công!\nNgười mua: {buyer}\nThời gian: {sign_time}"
                )
            else:
                QMessageBox.warning(self, "Lỗi", "Xác thực thất bại: Chữ ký không hợp lệ")
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi tải và xác thực order: {str(e)}")

    def refresh_my_order_list(self):
        try:
            response = requests.get(f"{self.API_BASE_URL}/list-orders/")
            response.raise_for_status()
            orders = response.json()
            self.my_order_list.clear()
            for order in orders:
                if order['buyer_name'] == self.current_user:
                    item = QListWidgetItem(
                        f"Order đã gửi - {order['timestamp']}"
                    )
                    item.setData(Qt.UserRole, order)
                    self.my_order_list.addItem(item)
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi lấy danh sách order đã gửi: {str(e)}")

    def create_qr_code(self, public_key, signer_name, timestamp):
        """Tạo mã QR chứa thông tin khóa"""
        # Tạo dữ liệu cho mã QR
        qr_data = {
            "signer": signer_name,
            "timestamp": timestamp,
            "public_key": base64.b64encode(public_key).decode('utf-8')
        }
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

    def add_qr_to_pdf(self, pdf_path, qr_image_bytes):
        """Thêm mã QR vào trang cuối của PDF"""
        # Đọc PDF gốc
        reader = PdfReader(pdf_path)
        writer = PdfWriter()
        
        # Thêm tất cả các trang từ PDF gốc
        for page in reader.pages:
            writer.add_page(page)
        
        # Tạo một trang mới với mã QR
        packet = BytesIO()
        c = canvas.Canvas(packet, pagesize=letter)
        
        # Vẽ mã QR
        # Lưu mã QR vào tệp tạm thời và sử dụng đường dẫn tệp
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as temp_qr_file:
            temp_qr_file.write(qr_image_bytes)
            temp_qr_path = temp_qr_file.name

        c.drawImage(temp_qr_path, 50, 50, width=200, height=200)
        c.save()
        
        # Xóa tệp QR tạm thời
        os.remove(temp_qr_path)
        
        # Thêm trang mới vào PDF
        packet.seek(0)
        new_pdf = PdfReader(packet)
        writer.add_page(new_pdf.pages[0])
        
        # Lưu PDF mới
        output_path = pdf_path.replace('.pdf', '_with_qr.pdf')
        with open(output_path, 'wb') as output_file:
            writer.write(output_file)
        
        return output_path

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
        
        # Kiểm tra dữ liệu đầu vào
        if not username or not password:
            QMessageBox.warning(self, "Lỗi", "Vui lòng điền đầy đủ thông tin")
            return
        
        if password != confirm_password:
            QMessageBox.warning(self, "Lỗi", "Mật khẩu xác nhận không khớp")
            return
        
        try:
            # Kiểm tra username đã tồn tại chưa
            response = requests.get(
                f"{self.API_BASE_URL}/check-user",
                params={"username": username}
            )
            response_data = response.json()
            
            if response_data.get('message') == 'User exists':
                QMessageBox.warning(self, "Lỗi", "Tên đăng nhập đã tồn tại")
                return
            
            # Tạo cặp khóa mới
            try:
                pk, sk = ML_DSA_44.keygen()
                print("Đã tạo cặp khóa thành công")  # Debug log
            except Exception as e:
                print(f"Lỗi khi tạo cặp khóa: {str(e)}")  # Debug log
                raise Exception(f"Không thể tạo cặp khóa: {str(e)}")
            
            # Lưu khóa vào file local
            if not self.save_keys(pk, sk, password, username):
                raise Exception("Không thể lưu cặp khóa vào file")
            
            try:
                # Gửi public key và thông tin đăng ký lên server
                response = requests.post(
                    f"{self.API_BASE_URL}/register/",
                    json={
                        'username': username,
                        'public_key': base64.b64encode(pk).decode('utf-8')
                    }
                )
                response.raise_for_status()

                # Kiểm tra xem public key đã được lưu thành công chưa
                verify_response = requests.get(
                    f"{self.API_BASE_URL}/get-public-key/",
                    params={'signer_name': username}
                )
                verify_response.raise_for_status()
                
                QMessageBox.information(
                    self, "Thành công",
                    "Đăng ký thành công! Bạn có thể đăng nhập ngay bây giờ."
                )
                self.username_input.setText(username)
            except requests.exceptions.RequestException as e:
                # Nếu có lỗi khi gửi lên server, xóa file khóa local
                private_key_path, public_key_path = self.get_key_paths()
                if os.path.exists(private_key_path):
                    os.remove(private_key_path)
                if os.path.exists(public_key_path):
                    os.remove(public_key_path)
                raise Exception(f"Lỗi khi đăng ký với server: {str(e)}")
            
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi đăng ký: {str(e)}")

class RegisterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Đăng ký tài khoản")
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        layout = QFormLayout(self)
        
        # Thêm các trường nhập liệu
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        
        layout.addRow("Tên đăng nhập:", self.username_input)
        layout.addRow("Mật khẩu:", self.password_input)
        layout.addRow("Xác nhận mật khẩu:", self.confirm_password_input)
        
        # Thêm nút đăng ký
        register_btn = QPushButton("Đăng ký")
        register_btn.clicked.connect(self.accept)
        layout.addRow("", register_btn)

    def get_data(self):
        return {
            'username': self.username_input.text().strip(),
            'password': self.password_input.text(),
            'confirm_password': self.confirm_password_input.text()
        }

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PDFVerifier()
    window.show()
    sys.exit(app.exec_()) 