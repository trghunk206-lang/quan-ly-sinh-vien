'use strict';
// Đặt lại mật khẩu cho một tài khoản (ví dụ khi quên mật khẩu admin).
// Cách dùng:  node reset-password.js <tên-đăng-nhập> [mật-khẩu-mới]
// Nếu không nhập mật khẩu mới, hệ thống tạo ngẫu nhiên và yêu cầu đổi ở lần đăng nhập kế tiếp.
const path = require('node:path');
const { open } = require('./db');
const { hashPassword, randomPassword } = require('./auth');

(async () => {
  const username = (process.argv[2] || '').trim().toLowerCase();
  if (!username) {
    console.error('Cách dùng: node reset-password.js <tên-đăng-nhập> [mật-khẩu-mới]');
    process.exit(1);
  }
  const given = process.argv[3];
  if (given && (given.length < 8 || given.length > 128)) {
    console.error('Mật khẩu phải dài 8–128 ký tự.');
    process.exit(1);
  }
  const file = path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'qlsv.sqlite');
  const db = open(file);
  const user = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (!user) {
    console.error('Không tìm thấy tài khoản "' + username + '".');
    process.exit(1);
  }
  const password = given || randomPassword(16);
  db.prepare('UPDATE users SET pass_hash = ?, must_change = ?, active = 1 WHERE id = ?').run(await hashPassword(password), given ? 0 : 1, user.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
  console.log('Đã đặt lại mật khẩu cho "' + username + '".');
  if (!given) console.log('Mật khẩu tạm: ' + password + '  (sẽ bị yêu cầu đổi khi đăng nhập)');
})();
