const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Ensure upload directory exists
const UPLOAD_DIR = path.join(__dirname, '..', 'upload');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

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
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '';
    const name = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
    cb(null, name);
  }
});

// Build multer instance with options
const createMulter = ({ maxFileSize = 20 * 1024 * 1024, allowed = DEFAULT_ALLOWED } = {}) =>
  multer({
    storage,
    limits: { fileSize: maxFileSize },
    fileFilter: (req, file, cb) => {
      if (!allowed || allowed.length === 0) return cb(null, true);
      if (allowed.includes(file.mimetype)) return cb(null, true);
      const err = new multer.MulterError('LIMIT_UNEXPECTED_FILE', file.fieldname);
      err.message = `File type not allowed: ${file.mimetype}`;
      return cb(err);
    }
  });

// Helper to delete a file by absolute path or relative filename in upload dir
const deleteFile = (filePathOrName) => {
  const full = path.isAbsolute(filePathOrName)
    ? filePathOrName
    : path.join(UPLOAD_DIR, filePathOrName);
  if (fs.existsSync(full)) {
    fs.unlinkSync(full);
    return true;
  }
  return false;
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
};
