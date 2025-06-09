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
    QListWidget, QListWidgetItem
)
from PyQt5.QtCore import Qt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from dilithium_py.ml_dsa import ML_DSA_44
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, TextStringObject
from datetime import datetime

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
        layout = QVBoxLayout(main_widget)

        # Login section
        login_group = QGroupBox("Đăng nhập")
        login_layout = QFormLayout()
        
        self.username_input = QLineEdit()
        login_layout.addRow("Username:", self.username_input)
        
        login_btn = QPushButton("Đăng nhập")
        login_btn.clicked.connect(self.login)
        login_layout.addRow("", login_btn)
        
        login_group.setLayout(login_layout)
        layout.addWidget(login_group)

        # Tab widget
        self.tabs = QTabWidget()
        
        # Tab Bên bán
        seller_tab = QWidget()
        seller_layout = QVBoxLayout()
        
        # Key generation section
        key_group = QGroupBox("Tạo cặp khóa")
        key_layout = QFormLayout()
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        key_layout.addRow("Mật khẩu:", self.password_input)
        
        generate_btn = QPushButton("Tạo cặp khóa")
        generate_btn.clicked.connect(self.generate_keys)
        key_layout.addRow("", generate_btn)
        
        key_group.setLayout(key_layout)
        seller_layout.addWidget(key_group)
        
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

        layout.addWidget(self.tabs)
        
        # Status bar
        self.statusBar().showMessage('Sẵn sàng')

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
                self.statusBar().showMessage(f'Đã đăng nhập: {username}')
                QMessageBox.information(self, "Thành công", f"Đăng nhập thành công: {username}")
                # Làm mới danh sách hóa đơn nếu đang ở tab bên mua
                if self.tabs.currentIndex() == 1:
                    self.refresh_invoice_list()
            else:
                QMessageBox.warning(self, "Lỗi", "Username không tồn tại")
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi đăng nhập: {str(e)}")

    def generate_keys(self):
        """Tạo cặp khóa mới"""
        if not self.current_user:
            QMessageBox.warning(self, "Lỗi", "Vui lòng đăng nhập trước")
            return
            
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập mật khẩu")
            return

        try:
            # Tạo cặp khóa MLDSA44
            pk, sk = ML_DSA_44.keygen()
            
            # Lưu khóa vào file local
            if self.save_keys(pk, sk, password):
                # Gửi public key lên server
                response = requests.post(
                    f"{self.API_BASE_URL}/save-public-key/",
                    json={
                        'signer_name': self.current_user,
                        'public_key': base64.b64encode(pk).decode('utf-8')
                    }
                )
                response.raise_for_status()
                
                QMessageBox.information(self, "Thành công", "Tạo cặp khóa thành công")
                self.password_input.clear()
            else:
                QMessageBox.critical(self, "Lỗi", "Không thể lưu cặp khóa")
                
        except Exception as e:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi tạo cặp khóa: {str(e)}")

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
            # Upload file đã ký lên server
            with open(signed_pdf_path, 'rb') as f:
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
                f"Ký và upload PDF thành công. File đã ký được lưu tại:\n{signed_pdf_path}"
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

    def get_key_paths(self):
        """Lấy đường dẫn đến file khóa"""
        if not self.current_user:
            return None, None
        private_key_path = os.path.join(self.keys_dir, f"{self.current_user}.private.pem")
        public_key_path = os.path.join(self.keys_dir, f"{self.current_user}.public.pem")
        return private_key_path, public_key_path

    def save_keys(self, public_key, private_key, password):
        """Lưu cặp khóa vào file"""
        try:
            private_key_path, public_key_path = self.get_key_paths()
            if not private_key_path or not public_key_path:
                return False

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
            # Upload file đã ký lên server
            with open(signed_pdf_path, 'rb') as f:
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
                f"Ký và upload Order PDF thành công. File đã ký được lưu tại:\n{signed_pdf_path}"
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

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PDFVerifier()
    window.show()
    sys.exit(app.exec_()) 