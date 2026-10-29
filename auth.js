'use strict';
const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);
const N = 16384, R = 8, P = 1, KEYLEN = 64;

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, KEYLEN, { N, r: R, p: P });
  return ['scrypt', N, R, P, salt.toString('base64'), key.toString('base64')].join('$');
}

async function verifyPassword(password, stored) {
  try {
    const [alg, n, r, p, salt, key] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(key, 'base64');
    const actual = await scrypt(password, Buffer.from(salt, 'base64'), expected.length, { N: +n, r: +r, p: +p });
    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

// Mật khẩu ngẫu nhiên, bỏ các ký tự dễ nhầm (0/O, 1/l/I)
function randomPassword(len = 14) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[crypto.randomInt(chars.length)];
  return out;
}

let dummy;
// Dùng khi tên đăng nhập không tồn tại, để thời gian phản hồi không tiết lộ tài khoản có thật hay không
function dummyHash() {
  if (!dummy) dummy = hashPassword(randomPassword(20));
  return dummy;
}

module.exports = { hashPassword, verifyPassword, randomPassword, dummyHash };
