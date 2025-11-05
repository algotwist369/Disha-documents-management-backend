const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Ensure upload directory exists
const UPLOAD_DIR = path.join(__dirname, '..', 'upload');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// File magic bytes signatures for content validation
const FILE_SIGNATURES = {
  'image/jpeg': [0xFF, 0xD8, 0xFF],
  'image/png': [0x89, 0x50, 0x4E, 0x47],
  'image/gif': [0x47, 0x49, 0x46, 0x38],
  'image/webp': [0x52, 0x49, 0x46, 0x46], // WebP starts with RIFF
  'application/pdf': [0x25, 0x50, 0x44, 0x46], // %PDF
  'application/zip': [0x50, 0x4B, 0x03, 0x04], // ZIP
  'application/vnd.rar': [0x52, 0x61, 0x72, 0x21], // RAR
  'application/x-7z-compressed': [0x37, 0x7A, 0xBC, 0xAF], // 7z
  'application/msword': [0xD0, 0xCF, 0x11, 0xE0], // DOC
};

// Validate file content by magic bytes
const validateFileContent = (filePath, expectedMimeType) => {
  try {
    const buffer = Buffer.allocUnsafe(512); // Read first 512 bytes
    const fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buffer, 0, 512, 0);
    fs.closeSync(fd);
    
    const signature = FILE_SIGNATURES[expectedMimeType];
    if (!signature) return true; // If no signature defined, allow (for text files, etc.)
    
    // Check if buffer starts with signature
    for (let i = 0; i < signature.length; i++) {
      if (buffer[i] !== signature[i]) {
        return false;
      }
    }
    return true;
  } catch (error) {
    console.error('File content validation error:', error);
    return false;
  }
};

// Sanitize filename to prevent path traversal
const sanitizeFilename = (filename) => {
  // Remove path traversal attempts
  let sanitized = filename.replace(/\.\./g, '').replace(/\/+/g, '').replace(/\\+/g, '');
  // Remove any remaining dangerous characters
  sanitized = sanitized.replace(/[<>:"|?*\x00-\x1f]/g, '');
  // Limit length
  if (sanitized.length > 255) {
    const ext = path.extname(sanitized);
    sanitized = sanitized.substring(0, 255 - ext.length) + ext;
  }
  return sanitized;
};

// Default allowed mime types for common docs/images/archives
const DEFAULT_ALLOWED = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'text/plain',
  'application/zip',
  'application/x-7z-compressed',
  'application/vnd.rar'
];

// Create disk storage for fast, simple uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Ensure destination is within upload directory (prevent path traversal)
    const resolvedPath = path.resolve(UPLOAD_DIR);
    if (!resolvedPath.startsWith(path.resolve(__dirname, '..'))) {
      return cb(new Error('Invalid upload destination'));
    }
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // Sanitize original filename
    const sanitizedOriginal = sanitizeFilename(file.originalname);
    const ext = path.extname(sanitizedOriginal) || '';
    // Generate unique filename to prevent conflicts and path traversal
    const name = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
    // Ensure no path traversal in generated name
    const safeName = path.basename(name);
    cb(null, safeName);
  }
});

// Build multer instance with options
const createMulter = ({ maxFileSize = 20 * 1024 * 1024, allowed = DEFAULT_ALLOWED } = {}) =>
  multer({
    storage,
    limits: { 
      fileSize: maxFileSize,
      files: 1, // Only allow single file
      fields: 10, // Limit number of fields
      fieldSize: 1024 * 1024 // 1MB max per field
    },
    fileFilter: (req, file, cb) => {
      // Check MIME type
      if (!allowed || allowed.length === 0) return cb(null, true);
      if (!allowed.includes(file.mimetype)) {
        const err = new multer.MulterError('LIMIT_UNEXPECTED_FILE', file.fieldname);
        err.message = `File type not allowed: ${file.mimetype}`;
        return cb(err);
      }
      
      // Additional validation after file is saved (in post-processing)
      cb(null, true);
    }
  });

// Helper to delete a file by absolute path or relative filename in upload dir
// Prevents path traversal attacks
const deleteFile = (filePathOrName) => {
  try {
    let full;
    if (path.isAbsolute(filePathOrName)) {
      // Ensure absolute path is within upload directory
      const resolved = path.resolve(filePathOrName);
      const uploadResolved = path.resolve(UPLOAD_DIR);
      if (!resolved.startsWith(uploadResolved)) {
        console.warn('⚠️  Path traversal attempt detected in deleteFile:', filePathOrName);
        return false;
      }
      full = resolved;
    } else {
      // Sanitize relative path
      const sanitized = sanitizeFilename(filePathOrName);
      full = path.join(UPLOAD_DIR, path.basename(sanitized));
    }
    
    // Double check it's still within upload directory
    const uploadResolved = path.resolve(UPLOAD_DIR);
    const fileResolved = path.resolve(full);
    if (!fileResolved.startsWith(uploadResolved)) {
      console.warn('⚠️  Path traversal attempt detected in deleteFile:', filePathOrName);
      return false;
    }
    
    if (fs.existsSync(full)) {
      fs.unlinkSync(full);
      
      // Also try to delete encrypted temp file if exists
      const tempFile = full + '.enctmp';
      if (fs.existsSync(tempFile)) {
        try {
          fs.unlinkSync(tempFile);
        } catch (e) {
          // Ignore temp file deletion errors
        }
      }
      
      return true;
    }
    return false;
  } catch (error) {
    console.error('deleteFile error:', error);
    return false;
  }
};

// Middleware factories
const uploadSingle = (fieldName, options) => {
  const uploader = createMulter(options);
  return uploader.single(fieldName);
};

const uploadArray = (fieldName, maxCount = 10, options) => {
  const uploader = createMulter(options);
  return uploader.array(fieldName, maxCount);
};

const uploadFields = (fields, options) => {
  // fields: [{ name: 'photos', maxCount: 5 }, { name: 'docs', maxCount: 3 }]
  const uploader = createMulter(options);
  return uploader.fields(fields);
};

// Simple error handler middleware for multer errors
const multerErrorHandler = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ success: false, error: err.message || err.code });
  }
  return next(err);
};

module.exports = {
  uploadSingle,
  uploadArray,
  uploadFields,
  deleteFile,
  UPLOAD_DIR,
  createMulter,
  multerErrorHandler,
  validateFileContent,
  sanitizeFilename,
};
