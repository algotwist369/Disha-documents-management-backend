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
  if (!key) {
    // No encryption key, return plain file stream
    return fs.createReadStream(filePath);
  }
  
  try {
    // Check if file exists and get stats
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const stats = fs.statSync(filePath);
    if (!stats.isFile()) {
      throw new Error(`Path is not a file: ${filePath}`);
    }
    
    const metaLen = 12 + 16; // iv + authTag
    
    // If file is too small to contain metadata, it's not encrypted
    if (stats.size < metaLen) {
      return fs.createReadStream(filePath);
    }
    
    const dataLen = stats.size - metaLen;
    
    // Validate dataLen is positive
    if (dataLen <= 0) {
      console.warn('Invalid file size for decryption, returning plain stream');
      return fs.createReadStream(filePath);
    }
    
    const fd = fs.openSync(filePath, 'r');
    
    try {
      // read iv and auth tag from end
      const metaBuf = Buffer.alloc(metaLen);
      const bytesRead = fs.readSync(fd, metaBuf, 0, metaLen, dataLen);
      
      if (bytesRead !== metaLen) {
        fs.closeSync(fd);
        throw new Error(`Failed to read metadata: expected ${metaLen} bytes, got ${bytesRead}`);
      }
      
      const iv = metaBuf.slice(0, 12);
      const authTag = metaBuf.slice(12);

      const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
      decipher.setAuthTag(authTag);
      
      // Handle decipher errors
      decipher.on('error', (err) => {
        console.error('Decipher error:', err.message);
        fs.closeSync(fd);
      });

      // create read stream for encrypted data portion only
      const encStream = fs.createReadStream(null, { 
        fd, 
        start: 0, 
        end: dataLen - 1, 
        autoClose: true 
      });
      
      // Handle stream errors
      encStream.on('error', (err) => {
        console.error('Encrypted stream error:', err.message);
        try {
          fs.closeSync(fd);
        } catch (closeErr) {
          // Ignore close errors
        }
      });
      
      return encStream.pipe(decipher);
    } catch (metaError) {
      fs.closeSync(fd);
      throw metaError;
    }
  } catch (err) {
    // If decryption setup fails, return plain file stream
    console.error('Decryption stream setup error:', err.message);
    console.error('Error stack:', err.stack);
    console.error('Falling back to plain file stream for:', filePath);
    
    // Try to return plain stream as fallback
    try {
      return fs.createReadStream(filePath);
    } catch (fallbackError) {
      console.error('Fallback stream creation failed:', fallbackError.message);
      throw new Error(`Failed to create file stream: ${fallbackError.message}`);
    }
  }
};

module.exports = {
  encryptFile,
  createDecryptionStream,
};
