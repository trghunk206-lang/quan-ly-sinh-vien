# Quản lý sinh viên (có đăng nhập & phân quyền)

Máy chủ Node.js + SQLite, **không cần cài thư viện nào** (`npm install` không cần thiết).
Yêu cầu: **Node.js 22.13 trở lên**.

## Chạy thử

```bash
node --disable-warning=ExperimentalWarning server.js     # hoặc: npm start
```

Lần chạy đầu tiên, máy chủ in ra tài khoản quản trị `admin` cùng **mật khẩu tạm ngẫu nhiên** (chỉ hiện một lần).
Mở http://127.0.0.1:3000, đăng nhập, hệ thống sẽ bắt đổi mật khẩu.
Quản trị viên có thể bấm **Dữ liệu & Sao lưu → Nạp dữ liệu mẫu** để dùng thử.

## Vai trò

| Vai trò | Quyền |
|---|---|
| Quản trị | Toàn quyền dữ liệu học vụ, quản lý tài khoản, sao lưu / khôi phục, nạp / xóa dữ liệu |
| Giảng viên | Thêm / sửa / xóa sinh viên, lớp, học kỳ, môn học, nhập điểm, xuất CSV |
| Sinh viên | Chỉ xem bảng điểm và GPA **của chính mình** (máy chủ chỉ trả dữ liệu của em đó) |

Tài khoản do quản trị tạo (không có đăng ký tự do). Tài khoản mới và tài khoản vừa được đặt lại mật khẩu
đều phải đổi mật khẩu ở lần đăng nhập kế tiếp. Muốn cấp tài khoản cho sinh viên: vào **Tài khoản → Vai trò: Sinh viên → chọn sinh viên**.

## Cấu hình (biến môi trường)

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `PORT` | `3000` | Cổng |
| `HOST` | `127.0.0.1` | Địa chỉ lắng nghe (đặt `0.0.0.0` nếu chạy trong container) |
| `DATA_DIR` | `./data` | Thư mục chứa file CSDL `qlsv.sqlite` |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / ngẫu nhiên | Chỉ dùng ở lần chạy đầu khi CSDL chưa có tài khoản nào |
| `NODE_ENV=production` | | Bật cookie `Secure` và HSTS (cần chạy qua HTTPS) |
| `COOKIE_SECURE` | theo `NODE_ENV` | `1` / `0` để ép bật / tắt cookie `Secure` |
| `TRUST_PROXY=1` | tắt | Bật khi chạy sau reverse proxy (nginx, Caddy, Cloudflare…) để lấy đúng IP khách |

## Đưa lên mạng thật (checklist)

1. **Bắt buộc dùng HTTPS.** Đặt máy chủ sau reverse proxy có chứng chỉ (Caddy là cách đơn giản nhất), rồi chạy với
   `NODE_ENV=production TRUST_PROXY=1 HOST=127.0.0.1`. Nếu không có HTTPS, mật khẩu đi qua mạng dạng chữ rõ.
2. Proxy phải **thêm** địa chỉ khách vào cuối `X-Forwarded-For` (nginx: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`).
   Chỉ bật `TRUST_PROXY=1` khi thật sự có proxy phía trước.
3. **Lưu `DATA_DIR` ở ổ đĩa bền vững** và sao lưu định kỳ (sao chép cả 3 file `qlsv.sqlite*`, hoặc dùng
   `sqlite3 qlsv.sqlite ".backup bak.sqlite"`). Ngoài ra quản trị viên có thể tải bản sao lưu JSON trong giao diện
   (bản JSON **không** gồm tài khoản đăng nhập).
4. Chỉ chạy **một bản** máy chủ cho một file CSDL (SQLite). Cần nhiều máy chủ thì phải chuyển sang PostgreSQL / MySQL.

### Docker

```bash
docker build -t qlsv .
docker run -d --name qlsv -p 127.0.0.1:3000:3000 -v qlsv-data:/data -e TRUST_PROXY=1 qlsv
docker logs qlsv        # xem mật khẩu quản trị tạm ở lần chạy đầu
```

## Quên mật khẩu quản trị

```bash
node --disable-warning=ExperimentalWarning reset-password.js admin
# trong Docker: docker exec -it qlsv node --disable-warning=ExperimentalWarning reset-password.js admin
```

## Bảo mật đã có

- Mật khẩu băm bằng scrypt có muối; không lưu mật khẩu gốc. Phiên đăng nhập là mã ngẫu nhiên, trong DB chỉ lưu bản băm.
- Cookie `HttpOnly` + `SameSite=Strict` (+ `Secure` ở production); phiên hết hạn sau 8 giờ.
- Chặn dò mật khẩu: sai 5 lần / 15 phút (theo IP + tên đăng nhập) là bị khóa tạm; có giới hạn theo IP.
- Chống CSRF (header `X-Requested-With` + kiểm tra `Origin`), CSP, `X-Frame-Options`, `nosniff`.
- Phân quyền kiểm tra ở **máy chủ** cho từng API; mọi dữ liệu vào đều được kiểm tra; giao diện escape mọi chuỗi hiển thị.
- Khóa / xóa tài khoản, đổi vai trò, đặt lại mật khẩu đều hủy các phiên đang đăng nhập.

## Giới hạn hiện tại (cần biết)

- Chưa có "quên mật khẩu qua email": quản trị viên đặt lại giúp người dùng.
- Bộ đếm chặn dò mật khẩu nằm trong bộ nhớ, mất khi khởi động lại máy chủ.
- Font, biểu tượng và Chart.js tải từ CDN (jsDelivr / Google Fonts); chưa gắn SRI. Muốn chạy offline hoặc chặt hơn,
  tải các file đó về `public/` rồi sửa đường dẫn trong `public/index.html` và CSP trong `server.js`.
- Không có nhật ký thao tác (audit log) và đăng nhập hai lớp (2FA).
- Cách xếp loại và quy đổi thang 4 theo mức phổ biến; hãy đối chiếu với quy chế của trường.

## Kiểm thử

```bash
npm test      # 16 bài kiểm tra API: đăng nhập, phân quyền, CSRF, giới hạn thử mật khẩu, sao lưu...
```

## Cấu trúc

```
server.js            máy chủ HTTP, đăng nhập, phân quyền, API
db.js                lược đồ SQLite, đọc / nhập dữ liệu, dữ liệu mẫu
auth.js              băm và kiểm tra mật khẩu
reset-password.js    đặt lại mật khẩu từ dòng lệnh
public/              giao diện (index.html, app.css, app.js)
test/api.test.js     kiểm thử API
```
