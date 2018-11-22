'use strict';
const crypto = require('crypto');

function PKCS7(msg) {
  let b = 16 - (msg.length % 16);
  return msg + String.fromCharCode(b).repeat(b);
}

function unPKCS7(msg) {
  return msg.slice(0, -(msg.slice(msg.length-1).charCodeAt(0)));
}

function encrypt(msg, key, iv) {
  let cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  let encryptedData = cipher.update(PKCS7(msg), 'utf8', 'hex');
  return encryptedData;
}

function decrypt(ct, key, iv) {
  let decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  decipher.setAutoPadding(false);
  let decryptedData = decipher.update(ct, 'hex', 'utf8');
  return unPKCS7(decryptedData);
}
