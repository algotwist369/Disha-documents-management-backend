const zlib = require('zlib');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

/**
 * Compress file using gzip if it's compressible
 * Returns compressed file path or original if compression didn't help
 */
const compressFile = async (inputPath, outputPath) => {
  try {
    const stats = await fs.promises.stat(inputPath);
    const originalSize = stats.size;
    
    // Only compress files larger than 1KB
    if (originalSize < 1024) {
      return { compressed: false, path: inputPath, size: originalSize };
    }
    
    // Check if file is already compressed (gzip, zip, etc.)
    const ext = path.extname(inputPath).toLowerCase();
    const alreadyCompressed = ['.gz', '.zip', '.rar', '.7z', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf'].includes(ext);
    
    if (alreadyCompressed) {
      return { compressed: false, path: inputPath, size: originalSize };
    }
    
    // Read file
    const fileBuffer = await fs.promises.readFile(inputPath);
    
    // Compress
    const compressed = await gzip(fileBuffer, { level: 6 }); // Level 6 is good balance
    
    // Only use compressed version if it's smaller
    if (compressed.length < originalSize * 0.9) { // At least 10% reduction
      await fs.promises.writeFile(outputPath, compressed);
      return {
        compressed: true,
        path: outputPath,
        size: compressed.length,
        originalSize: originalSize,
        ratio: (compressed.length / originalSize * 100).toFixed(2)
      };
    }
    
    return { compressed: false, path: inputPath, size: originalSize };
  } catch (error) {
    console.error('Compression error:', error);
    // Return original on error
    return { compressed: false, path: inputPath, error: error.message };
  }
};

/**
 * Decompress gzipped file
 */
const decompressFile = async (inputPath, outputPath) => {
  try {
    const compressed = await fs.promises.readFile(inputPath);
    const decompressed = await gunzip(compressed);
    await fs.promises.writeFile(outputPath, decompressed);
    return { success: true, path: outputPath };
  } catch (error) {
    console.error('Decompression error:', error);
    throw error;
  }
};

/**
 * Check if file is gzipped
 */
const isGzipped = async (filePath) => {
  try {
    const buffer = Buffer.allocUnsafe(2);
    const fd = await fs.promises.open(filePath, 'r');
    await fd.read(buffer, 0, 2, 0);
    await fd.close();
    // Gzip magic bytes: 0x1f 0x8b
    return buffer[0] === 0x1f && buffer[1] === 0x8b;
  } catch {
    return false;
  }
};

module.exports = {
  compressFile,
  decompressFile,
  isGzipped
};

