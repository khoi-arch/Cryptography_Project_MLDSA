## 1. Giới thiệu
Đây là hệ thống ký số và xác thực hóa đơn điện tử sử dụng chữ ký số dựa trên ML-DSA, hỗ trợ giao tiếp giữa client (giao diện người dùng) và server (xử lý nghiệp vụ, lưu trữ, xác thực).

---

## 2. Hướng dẫn cài đặt & chạy hệ thống

### 2.1. Chuẩn bị môi trường

- **Yêu cầu:**  
  - Python 3.10 trở lên  
  - pip (trình quản lý gói Python)  
  - Hệ điều hành: Windows 10 trở lên  
  - (Khuyến nghị) Tạo môi trường ảo để tránh xung đột thư viện

#### a. Tạo môi trường ảo (tùy chọn)
```bash
python -m venv venv
venv\Scripts\activate
```

#### b. Cài đặt các thư viện cần thiết cho cả client và server
```bash
pip install -r requirements.txt
cd Server
pip install -r requirements.txt
```

---

### 2.2. Chạy server (Django)

1. **Di chuyển vào thư mục Server:**
    ```bash
    cd Server
    ```

2. **Khởi tạo database (chỉ cần làm lần đầu):**
    ```bash
    python manage.py migrate
    ```

3. **Chạy server:**
    ```bash
    python manage.py runserver
    ```
    - Server sẽ chạy tại địa chỉ: http://localhost:8000

---

### 2.3. Chạy client
 Chạy bằng file thực thi (Client.exe)
- Nhấp đúp vào file `Client.exe` (nếu đã được đóng gói).
- Đảm bảo file `DejaVuSans.ttf` nằm cùng thư mục với `Client.exe`.

---

## 3. Hướng dẫn sử dụng chi tiết

### 3.1. Đăng ký tài khoản
- Mở ứng dụng client.
- Nhấn nút **Đăng ký**.
- Nhập tên người dùng (username) và các thông tin cần thiết.
- Sau khi đăng ký thành công, bạn có thể đăng nhập.

### 3.2. Đăng nhập
- Nhập username đã đăng ký và nhấn **Đăng nhập**.
- Sau khi đăng nhập, giao diện sẽ hiển thị các chức năng phù hợp với vai trò (bên bán hoặc bên mua).

### 3.3. Quản lý sản phẩm (dành cho bên bán)
- Vào tab **Quản lý sản phẩm**.
- Nhập tên sản phẩm và giá, nhấn **Thêm sản phẩm**.
- Danh sách sản phẩm của bạn sẽ hiển thị bên dưới.
- Nhấn **Làm mới danh sách sản phẩm** để cập nhật.

### 3.4. Đặt hàng (dành cho bên mua)
- Chọn sản phẩm từ danh sách, thêm vào giỏ hàng.
- Nhấn **Tạo đơn hàng** để gửi đơn hàng đến bên bán.
- Có thể xem lại các đơn hàng đã đặt ở tab tương ứng.

### 3.5. Quản lý đơn hàng (dành cho bên bán)
- Vào tab **Danh sách order từ bên mua**.
- Nhấn **Làm mới danh sách order** để cập nhật.
- Nhấp đúp vào đơn hàng để tải về và xác thực.

### 3.6. Ký và xác thực hóa đơn PDF
- Khi tạo hóa đơn, hệ thống sẽ tự động ký số và sinh mã QR.
- Có thể tải về hóa đơn PDF đã ký và xác thực tính hợp lệ qua client.

### 3.7. Quản lý khóa cá nhân
- Ứng dụng sẽ tự động tạo và lưu trữ khóa cá nhân cho mỗi người dùng tại thư mục `~/.pdf_verifier/keys`.
- Không chia sẻ khóa cá nhân cho người khác.

---