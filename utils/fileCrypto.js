const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

const ALGORITHM = 'aes-256-gcm';
const KEY = process.env.FILE_ENCRYPTION_KEY; // 32 bytes base64 or hex

if (!KEY) {
  console.warn('FILE_ENCRYPTION_KEY not set - files will not be encrypted');
}

const getKey = () => {
  if (!KEY) return null;
  try {
    // if base64, convert; if hex, Buffer.from will handle if provided accordingly by user
    const keyBuffer = Buffer.from(KEY, 'base64');
    // AES-256-GCM requires 32 bytes (256 bits)
    if (keyBuffer.length !== 32) {
      console.warn(`FILE_ENCRYPTION_KEY must be 32 bytes (256 bits). Current length: ${keyBuffer.length}. Encryption disabled.`);
      return null;
    }
    return keyBuffer;
  } catch (err) {
    console.error('Error parsing FILE_ENCRYPTION_KEY:', err.message);
    return null;
  }
};

const encryptFile = (inputPath, outputPath) => new Promise((resolve, reject) => {
  const key = getKey();
  if (!key) return resolve(false);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const input = fs.createReadStream(inputPath);
  const output = fs.createWriteStream(outputPath);
  
  input.on('error', reject);
  output.on('error', reject);
  
  input.pipe(cipher).pipe(output);
  output.on('finish', async () => {
    try {
      // append auth tag and iv to file as metadata (simple approach)
      const authTag = cipher.getAuthTag();
      const meta = Buffer.concat([iv, authTag]);
      await fs.promises.appendFile(outputPath, meta);
      resolve(true);
    } catch (err) {
      reject(err);
    }
  });
});

// Decrypt by creating a read stream that strips appended auth/iv
const createDecryptionStream = (filePath) => {
  const key = getKey();
  if (!key) return fs.createReadStream(filePath);
  const stats = fs.statSync(filePath);
  const metaLen = 12 + 16; // iv + authTag
  const dataLen = stats.size - metaLen;
  const fd = fs.openSync(filePath, 'r');
  // read iv and auth tag from end
  const metaBuf = Buffer.alloc(metaLen);
  fs.readSync(fd, metaBuf, 0, metaLen, dataLen);
  const iv = metaBuf.slice(0, 12);
  const authTag = metaBuf.slice(12);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  // create read stream for encrypted data portion only
  const encStream = fs.createReadStream(null, { fd, start: 0, end: dataLen - 1, autoClose: true });
  return encStream.pipe(decipher);
};

module.exports = {
  encryptFile,
  createDecryptionStream,
};
