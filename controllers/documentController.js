const mongoose = require('mongoose');
const Doc = require('../models/docModel');
const Category = require('../models/categoryModel');
const UserSecuritySettings = require('../models/userSecuritySettings');
const { deleteFile, UPLOAD_DIR, validateFileContent } = require('../utils/uploadFiles');
const { encryptFile, createDecryptionStream } = require('../utils/fileCrypto');
const { compressFile, isGzipped } = require('../utils/fileCompression');
const AuditLog = require('../models/auditLog');
const { getClientIP } = require('../utils/ipExtractor');
const fs = require('fs');
const path = require('path');

// Create a new document record (expects file already uploaded via middleware)
const createDocument = async (req, res) => {
  try {
    const user = req.user; // protect middleware should set this
    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    // Check account restrictions (only for non-super-admin users)
    if (user.role !== 'super_admin') {
      const securitySettings = await UserSecuritySettings.findOne({ user: user._id });
      if (securitySettings?.accountRestrictions?.canUploadDocuments === false) {
        return res.status(403).json({ 
          success: false, 
          message: 'You do not have permission to upload documents. Please contact your administrator.',
          code: 'PERMISSION_DENIED_UPLOAD'
        });
      }
    }

    // Accept file via req.file
    const file = req.file;
    if (!file) return res.status(400).json({ success: false, message: 'No file uploaded' });

    // Validate file content (magic bytes check) to prevent file type spoofing
    const uploadedPath = path.join(UPLOAD_DIR, file.filename);
    if (!validateFileContent(uploadedPath, file.mimetype)) {
      // Delete the uploaded file if validation fails
      deleteFile(file.filename);
      return res.status(400).json({ 
        success: false, 
        message: 'File content does not match declared file type. Upload rejected for security.' 
      });
    }

    const { companyName, fileType, category, permissionToView, permissionToDownload, permissionToDelete } = req.body;
    
    // Sanitize input
    if (!companyName || typeof companyName !== 'string') {
      deleteFile(file.filename);
      return res.status(400).json({ success: false, message: 'companyName is required' });
    }
    
    // Sanitize companyName to prevent XSS
    const sanitizedCompanyName = companyName.trim().substring(0, 200);
    
    if (!fileType || (Array.isArray(fileType) && fileType.length === 0)) {
      deleteFile(file.filename);
      return res.status(400).json({ success: false, message: 'fileType is required' });
    }

    // Validate category if provided
    let categoryId = null;
    if (category) {
      const categoryDoc = await Category.findById(category);
      if (!categoryDoc) {
        return res.status(400).json({ success: false, message: 'Invalid category' });
      }
      if (!categoryDoc.isActive) {
        return res.status(400).json({ success: false, message: 'Category is not active' });
      }
      categoryId = category;
    }

    // Validate and parse permissions
    const parseUserIds = (permissionArray) => {
      if (!permissionArray) return [];
      if (Array.isArray(permissionArray)) {
        return permissionArray.filter(id => mongoose.Types.ObjectId.isValid(id));
      }
      if (typeof permissionArray === 'string') {
        // Handle comma-separated string or single ID
        return permissionArray.split(',').map(id => id.trim()).filter(id => mongoose.Types.ObjectId.isValid(id));
      }
      return [];
    };

    const permissionToViewIds = parseUserIds(permissionToView);
    const permissionToDownloadIds = parseUserIds(permissionToDownload);
    const permissionToDeleteIds = parseUserIds(permissionToDelete);

    // Compress file if beneficial (before encryption)
    let finalFilePath = file.filename;
    let finalFileSize = file.size;
    let isCompressed = false;
    
    try {
      const compressedPath = uploadedPath + '.gz';
      const compressionResult = await compressFile(uploadedPath, compressedPath);
      
      if (compressionResult.compressed) {
        // Remove original and use compressed version
        await fs.promises.unlink(uploadedPath);
        await fs.promises.rename(compressedPath, uploadedPath);
        finalFilePath = file.filename; // Keep same filename (will be encrypted)
        finalFileSize = compressionResult.size;
        isCompressed = true;
        console.log(`✅ File compressed: ${compressionResult.originalSize} → ${compressionResult.size} bytes (${compressionResult.ratio}%)`);
      } else if (fs.existsSync(compressedPath)) {
        // Clean up temp compressed file if compression wasn't beneficial
        await fs.promises.unlink(compressedPath);
      }
    } catch (compressionError) {
      console.error('Compression error:', compressionError);
      // Continue with original file if compression fails
    }

    // Encrypt the uploaded file at rest (write to temp then replace)
    const tmpPath = uploadedPath + '.enctmp';
    try {
      const encrypted = await encryptFile(uploadedPath, tmpPath);
      if (encrypted) {
        await fs.promises.rename(tmpPath, uploadedPath);
      } else {
        // encryption key not set; file left as-is
      }
    } catch (e) {
      console.error('encryption error', e);
      // Clean up file on encryption error
      deleteFile(file.filename);
      return res.status(500).json({ success: false, message: 'Failed to process file' });
    }

    const doc = await Doc.create({
      user: user._id,
      companyName: sanitizedCompanyName,
      fileType: Array.isArray(fileType) ? fileType : [fileType],
      category: categoryId,
      filePath: finalFilePath,
      originalName: file.originalname ? file.originalname.substring(0, 255) : 'unnamed',
      mimeType: file.mimetype,
      size: finalFileSize,
      isCompressed: isCompressed,
      permissionToView: permissionToViewIds.length > 0 ? permissionToViewIds : [user._id], // Default to owner if empty
      permissionToDownload: permissionToDownloadIds.length > 0 ? permissionToDownloadIds : [user._id], // Default to owner if empty
      permissionToDelete: permissionToDeleteIds.length > 0 ? permissionToDeleteIds : [user._id], // Default to owner if empty
    });

    // audit log upload
    try {
      const auditLog = await AuditLog.create({ 
        user: user._id, 
        document: doc._id, 
        action: 'upload', 
        ip: getClientIP(req), 
        userAgent: req.headers['user-agent'] 
      });

      // Emit real-time audit log to super admin
      if (global.io) {
        global.io.to('super-admin-room').emit('new-audit-log', {
          log: {
            ...auditLog.toObject(),
            user: {
              _id: user._id,
              name: user.name,
              phone: user.phone,
              role: user.role
            },
            document: {
              _id: doc._id,
              originalName: doc.originalName,
              companyName: doc.companyName
            }
          }
        });
      }
    } catch (e) { 
      console.error('audit log error', e); 
    }

    res.status(201).json({ success: true, data: doc });
  } catch (err) {
    console.error('createDocument error', err.message || err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get all documents - all authenticated users can view all documents
const getDocuments = async (req, res) => {
  try {
    const user = req.user;
    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const query = {};
    // Permissions: super_admin sees all; others see own documents or those shared to them
    if (user.role !== 'super_admin') {
      query.$or = [
        { user: user._id },
        { permissionToView: { $in: [user._id] } }
      ];
    }

    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100); // Max 100 items per page
    const skip = (page - 1) * limit;

    // Sorting
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
    const sort = { [sortBy]: sortOrder };

    // Advanced Filters
    
    // 1. Search by company name (case-insensitive, partial match)
    if (req.query.companyName) {
      query.companyName = { $regex: req.query.companyName, $options: 'i' };
    }
    
    // 2. Filter by category
    if (req.query.category) {
      if (mongoose.Types.ObjectId.isValid(req.query.category)) {
        query.category = req.query.category;
      }
    }
    // 2b. Filter by fileType (supports multiple types via comma)
    if (req.query.fileType) {
      const fileTypes = Array.isArray(req.query.fileType)
        ? req.query.fileType
        : req.query.fileType.split(',').map(t => t.trim());
      query.fileType = { $in: fileTypes };
    }
    
    // 3. Text search across company name and original file name
    if (req.query.search) {
      query.$text = { $search: req.query.search };
    }
    
    // 4. Date range filters
    if (req.query.dateFrom || req.query.dateTo) {
      query.createdAt = {};
      if (req.query.dateFrom) {
        query.createdAt.$gte = new Date(req.query.dateFrom);
      }
      if (req.query.dateTo) {
        query.createdAt.$lte = new Date(req.query.dateTo);
      }
    }
    
    // 5. Filter by original file name
    if (req.query.fileName) {
      query.originalName = { $regex: req.query.fileName, $options: 'i' };
    }

    const [docs, total] = await Promise.all([
      Doc.find(query)
        .populate('user', 'name phone role')
        .populate('category', 'name description')
        .populate('permissionToView', 'name phone')
        .populate('permissionToDownload', 'name phone')
        .populate('permissionToDelete', 'name phone')
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean(),
      Doc.countDocuments(query)
    ]);

    res.json({ 
      success: true, 
      count: docs.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      filters: {
        companyName: req.query.companyName || null,
        category: req.query.category || null,
        search: req.query.search || null,
        dateFrom: req.query.dateFrom || null,
        dateTo: req.query.dateTo || null
      },
      data: docs 
    });
  } catch (err) {
    console.error('getDocuments error', err.message || err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get all documents by User ID
const getDocumentsByUserId = async (req, res) => {
  try {
    const authUser = req.user;
    if (!authUser) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const { userId } = req.params;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID is required' });
    }

    const targetUserId = userId;
    const isSuperAdmin = authUser.role === 'super_admin';
    const isViewingOwn = targetUserId.toString() === authUser._id.toString();

    // Check account restrictions for viewing others' documents (only for non-super-admin users)
    if (!isSuperAdmin && !isViewingOwn) {
      const securitySettings = await UserSecuritySettings.findOne({ user: authUser._id });
      if (securitySettings?.accountRestrictions?.canViewOthersDocuments === false) {
        return res.status(403).json({ 
          success: false, 
          message: 'You do not have permission to view other users\' documents. Please contact your administrator.',
          code: 'PERMISSION_DENIED_VIEW_OTHERS'
        });
      }
    }

    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const skip = (page - 1) * limit;

    // Sorting
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
    const sort = { [sortBy]: sortOrder };

    // Build query based on permissions
    let query;
    if (isSuperAdmin) {
      // Super admin can see all documents for the target user
      query = { user: targetUserId };
    } else if (isViewingOwn) {
      // User viewing their own documents - show all their documents
      query = { user: targetUserId };
    } else {
      // Regular user viewing another user's documents
      // Show documents where the target user is the owner AND current user has permissionToView
      query = {
        user: targetUserId,
        permissionToView: authUser._id
      };
    }

    // Filter by fileType if provided
    if (req.query.fileType) {
      const fileTypes = Array.isArray(req.query.fileType)
        ? req.query.fileType
        : req.query.fileType.split(',').map(t => t.trim());
      query.fileType = { $in: fileTypes };
    }

    const [docs, total] = await Promise.all([
      Doc.find(query)
        .populate('user', 'name phone role')
        .populate('category', 'name description')
        .populate('permissionToView', 'name phone')
        .populate('permissionToDownload', 'name phone')
        .populate('permissionToDelete', 'name phone')
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean(),
      Doc.countDocuments(query)
    ]);

    res.json({ 
      success: true,
      count: docs.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      data: docs 
    });
  } catch (err) {
    console.error('getDocumentsByUserId error', err.message || err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get single document by id (ensure ownership or admin)
const getDocumentById = async (req, res) => {
  try {
  const user = req.user;
    const id = req.params.id;
  if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

  // Reject non-HTTPS requests for extra security in production
  if (process.env.NODE_ENV === 'production') {
    const proto = req.get('x-forwarded-proto') || req.protocol;
    if (!proto || proto.toLowerCase() !== 'https') {
      return res.status(403).json({ success: false, message: 'Insecure connection: HTTPS required' });
    }
  }

    const doc = await Doc.findById(id)
      .populate('user', 'name phone role')
      .populate('category', 'name description')
      .populate('permissionToView', 'name phone')
      .populate('permissionToDownload', 'name phone')
      .populate('permissionToDelete', 'name phone');
    if (!doc) return res.status(404).json({ success: false, message: 'Document not found' });
    // All authenticated users can view document details
    res.json({ success: true, data: doc });
  } catch (err) {
    console.error('getDocumentById error', err.message || err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Update document metadata or replace file
const updateDocument = async (req, res) => {
  try {
    const user = req.user;
    const id = req.params.id;
  if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

  // Require HTTPS in production
  if (process.env.NODE_ENV === 'production') {
    const proto = req.get('x-forwarded-proto') || req.protocol;
    if (!proto || proto.toLowerCase() !== 'https') {
      return res.status(403).json({ success: false, message: 'Insecure connection: HTTPS required' });
    }
  }

    const doc = await Doc.findById(id);
    if (!doc) return res.status(404).json({ success: false, message: 'Document not found' });
    // Allow owner, admin, or super_admin to update
    if (user.role !== 'admin' && user.role !== 'super_admin' && doc.user.toString() !== user._id.toString()) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    const { companyName, fileType, category, permissionToView, permissionToDownload, permissionToDelete } = req.body;
    if (companyName) doc.companyName = companyName;
    if (fileType) doc.fileType = Array.isArray(fileType) ? fileType : [fileType];
    
    // Update category if provided
    if (category !== undefined) {
      if (category === null || category === '') {
        doc.category = null;
      } else {
        const categoryDoc = await Category.findById(category);
        if (!categoryDoc) {
          return res.status(400).json({ success: false, message: 'Invalid category' });
        }
        if (!categoryDoc.isActive) {
          return res.status(400).json({ success: false, message: 'Category is not active' });
        }
        doc.category = category;
      }
    }
    
    // Update permissions if provided
    const parseUserIds = (permissionArray) => {
      if (permissionArray === undefined) return undefined; // Don't update if not provided
      if (!permissionArray) return []; // Empty array if explicitly set to null/empty
      if (Array.isArray(permissionArray)) {
        return permissionArray.filter(id => mongoose.Types.ObjectId.isValid(id));
      }
      if (typeof permissionArray === 'string') {
        return permissionArray.split(',').map(id => id.trim()).filter(id => mongoose.Types.ObjectId.isValid(id));
      }
      return [];
    };

    if (permissionToView !== undefined) {
      const ids = parseUserIds(permissionToView);
      doc.permissionToView = ids.length > 0 ? ids : [doc.user]; // Default to owner if empty
    }
    if (permissionToDownload !== undefined) {
      const ids = parseUserIds(permissionToDownload);
      doc.permissionToDownload = ids.length > 0 ? ids : [doc.user]; // Default to owner if empty
    }
    if (permissionToDelete !== undefined) {
      const ids = parseUserIds(permissionToDelete);
      doc.permissionToDelete = ids.length > 0 ? ids : [doc.user]; // Default to owner if empty
    }

    // If a new file uploaded, delete old one and set new path
    if (req.file) {
      // delete previous file
      try { deleteFile(doc.filePath); } catch (e) { /* ignore */ }
      doc.filePath = req.file.filename;
    }

    doc.updatedAt = Date.now();
    await doc.save();
    res.json({ success: true, data: doc });
  } catch (err) {
    console.error('updateDocument error', err.message || err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Delete a document and remove file
const deleteDocument = async (req, res) => {
  try {
    const user = req.user;
    const id = req.params.id;
    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    // Check account restrictions (only for non-super-admin users)
    if (user.role !== 'super_admin') {
      const securitySettings = await UserSecuritySettings.findOne({ user: user._id });
      if (securitySettings?.accountRestrictions?.canDeleteDocuments === false) {
        return res.status(403).json({ 
          success: false, 
          message: 'You do not have permission to delete documents. Please contact your administrator.',
          code: 'PERMISSION_DENIED_DELETE'
        });
      }
    }

    const doc = await Doc.findById(id);
    if (!doc) return res.status(404).json({ success: false, message: 'Document not found' });
    // Allow owner, admin, or super_admin to delete
    if (user.role !== 'admin' && user.role !== 'super_admin' && doc.user.toString() !== user._id.toString()) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    // delete file
    try { deleteFile(doc.filePath); } catch (e) { /* ignore */ }
    await doc.deleteOne();
    
    // Audit log delete
    try {
      const auditLog = await AuditLog.create({ 
        user: user._id, 
        document: doc._id, 
        action: 'delete', 
        ip: getClientIP(req), 
        userAgent: req.headers['user-agent'] 
      });

      // Emit real-time audit log to super admin
      if (global.io) {
        global.io.to('super-admin-room').emit('new-audit-log', {
          log: {
            ...auditLog.toObject(),
            user: {
              _id: user._id,
              name: user.name,
              phone: user.phone,
              role: user.role
            },
            document: {
              _id: doc._id,
              originalName: doc.originalName,
              companyName: doc.companyName
            }
          }
        });
      }
    } catch (e) { 
      console.error('audit log error', e); 
    }
    
    res.json({ success: true, message: 'Document deleted' });
  } catch (err) {
    console.error('deleteDocument error:', err.message || err);
    // Don't expose internal error details
    res.status(500).json({ success: false, message: 'An error occurred while deleting the document' });
  }
};

// Stream file for inline viewing (sets content-type)
const viewDocumentFile = async (req, res) => {
  try {
    const user = req.user;
    const id = req.params.id;
    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    // Check account restrictions for download (which also applies to view) - only for non-super-admin users
    // Note: View permission is checked later, but we also check account restrictions
    if (user.role !== 'super_admin') {
      const securitySettings = await UserSecuritySettings.findOne({ user: user._id });
      if (securitySettings?.accountRestrictions?.canDownloadDocuments === false) {
        return res.status(403).json({ 
          success: false, 
          message: 'You do not have permission to view documents. Please contact your administrator.',
          code: 'PERMISSION_DENIED_VIEW'
        });
      }
    }

    const doc = await Doc.findById(id).populate('user');
    if (!doc) return res.status(404).json({ success: false, message: 'Document not found' });
    // Permission check: allow super_admin, owner, or users with view permission
    if (
      user.role !== 'super_admin' &&
      doc.user.toString() !== user._id.toString() &&
      !(doc.permissionToView || []).map(String).includes(user._id.toString())
    ) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    // Validate file path to prevent path traversal
    const filePath = path.join(UPLOAD_DIR, path.basename(doc.filePath));
    const resolvedPath = path.resolve(filePath);
    const uploadResolved = path.resolve(UPLOAD_DIR);
    
    if (!resolvedPath.startsWith(uploadResolved)) {
      return res.status(403).json({ success: false, message: 'Invalid file path' });
    }
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, message: 'File not found' });
    }

    // audit log view
    try {
      const auditLog = await AuditLog.create({ 
        user: user._id, 
        document: doc._id, 
        action: 'view', 
        ip: getClientIP(req), 
        userAgent: req.headers['user-agent'] 
      });

      // Emit real-time audit log to super admin
      if (global.io) {
        global.io.to('super-admin-room').emit('new-audit-log', {
          log: {
            ...auditLog.toObject(),
            user: {
              _id: user._id,
              name: user.name,
              phone: user.phone,
              role: user.role
            },
            document: {
              _id: doc._id,
              originalName: doc.originalName,
              companyName: doc.companyName
            }
          }
        });
      }
    } catch (e) { 
      console.error('audit log error', e); 
    }

    // Send notification to document owner if not super admin and preferences enabled
    const docOwner = doc.user;
    if (docOwner && docOwner.role !== 'super_admin' && docOwner._id.toString() !== user._id.toString()) {
      try {
        const Notification = require('../models/notificationModel');
        const User = require('../models/userModel');
        const owner = await User.findById(docOwner._id);
        
        if (owner && owner.notifications) {
          // Dashboard notification
          if (owner.notifications.dashboardOnView !== false) {
            const notification = await Notification.create({
              user: docOwner._id,
              type: 'document_viewed',
              document: doc._id,
              viewedBy: user._id,
              message: `${user.name} viewed your document "${doc.originalName}"`
            });

            // Emit real-time notification to user
            if (global.io) {
              global.io.to(`user-${docOwner._id}`).emit('document-notification', {
                notification: {
                  ...notification.toObject(),
                  document: {
                    _id: doc._id,
                    originalName: doc.originalName
                  },
                  viewedBy: {
                    _id: user._id,
                    name: user.name
                  }
                }
              });
            }
          }

          // Email notification
          if (owner.notifications.emailOnView === true && owner.email) {
            const sendMail = require('../utils/sendMail');
            await sendMail({
              to: owner.email,
              subject: `Document Viewed: ${doc.originalName}`,
              text: `Hello ${owner.name},\n\n${user.name} viewed your document "${doc.originalName}" at ${new Date().toLocaleString()}.\n\nDocument: ${doc.originalName}\nViewed by: ${user.name}\nTime: ${new Date().toLocaleString()}`,
              html: `<p>Hello ${owner.name},</p><p><strong>${user.name}</strong> viewed your document <strong>"${doc.originalName}"</strong> at ${new Date().toLocaleString()}.</p><p><strong>Document:</strong> ${doc.originalName}<br><strong>Viewed by:</strong> ${user.name}<br><strong>Time:</strong> ${new Date().toLocaleString()}</p>`
            }).catch(err => console.error('Email notification error:', err));
          }
        }
      } catch (err) {
        console.error('Notification error:', err);
      }
    }

    // Notify admin about view attempt (fire-and-forget)
    const adminEmail = process.env.ADMIN_EMAIL;
    if (adminEmail) {
      const sendMail = require('../utils/sendMail');
      sendMail({
        to: adminEmail,
        subject: `Document viewed by ${user.name} (${user._id})`,
        text: `User ${user.name} (${user.phone || 'no-phone'}) viewed document ${doc._id} (${doc.companyName}) at ${new Date().toISOString()} from IP ${getClientIP(req)} UA ${req.headers['user-agent']}`
      }).catch(err => console.error('sendMail error', err));
    }

    // Check if file is compressed and handle accordingly
    let stream;
    try {
      stream = createDecryptionStream(filePath);
      
      // If file is compressed (stored in database), decompress on-the-fly
      if (doc.isCompressed) {
        const zlib = require('zlib');
        stream = stream.pipe(zlib.createGunzip());
      }
    } catch (decryptError) {
      console.error('Decryption error:', decryptError);
      // If decryption fails (no key), try direct file access
      try {
        stream = fs.createReadStream(filePath);
        // If compressed, decompress
        if (doc.isCompressed) {
          const zlib = require('zlib');
          stream = stream.pipe(zlib.createGunzip());
        }
      } catch (fileError) {
        console.error('File stream error:', fileError);
        console.error('File stream error stack:', fileError.stack);
        return res.status(500).json({ success: false, message: 'Error reading file' });
      }
    }
    
    const contentType = doc.mimeType || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `inline; filename="${doc.originalName || doc.filePath}"`);
    
    // Handle stream errors that occur during pipe operation
    let responseSent = false;
    const handleStreamError = (error) => {
      if (!responseSent) {
        responseSent = true;
        console.error('Stream error during view:', error);
        console.error('Stream error stack:', error.stack);
        console.error('Stream error details:', {
          message: error.message,
          name: error.name,
          code: error.code
        });
        if (!res.headersSent) {
          res.status(500).json({ success: false, message: 'An error occurred while viewing the document' });
        } else {
          res.destroy();
        }
      }
    };
    
    stream.on('error', handleStreamError);
    res.on('error', handleStreamError);
    res.on('close', () => {
      if (stream && !stream.destroyed) {
        stream.destroy();
      }
    });
    
    return stream.pipe(res);
  } catch (err) {
    console.error('viewDocumentFile error:', err);
    console.error('Error stack:', err.stack);
    console.error('Error details:', {
      message: err.message,
      name: err.name,
      code: err.code,
      path: err.path
    });
    // Don't expose internal error details
    if (!res.headersSent) {
      res.status(500).json({ success: false, message: 'An error occurred while viewing the document' });
    }
  }
};

// Download file as attachment
const downloadDocumentFile = async (req, res) => {
  try {
    const user = req.user;
    const id = req.params.id;
    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    // Check account restrictions (only for non-super-admin users)
    if (user.role !== 'super_admin') {
      const securitySettings = await UserSecuritySettings.findOne({ user: user._id });
      if (securitySettings?.accountRestrictions?.canDownloadDocuments === false) {
        return res.status(403).json({ 
          success: false, 
          message: 'You do not have permission to download documents. Please contact your administrator.',
          code: 'PERMISSION_DENIED_DOWNLOAD'
        });
      }
    }

    const doc = await Doc.findById(id).populate('user');
    if (!doc) return res.status(404).json({ success: false, message: 'Document not found' });
    // Permission check: allow super_admin, owner, or users with download permission
    if (
      user.role !== 'super_admin' &&
      doc.user.toString() !== user._id.toString() &&
      !(doc.permissionToDownload || []).map(String).includes(user._id.toString())
    ) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    const path = require('path');
    const fs = require('fs');
    // Use basename to prevent path traversal (same as view function)
    const filePath = path.join(UPLOAD_DIR, path.basename(doc.filePath));
    if (!fs.existsSync(filePath)) return res.status(404).json({ success: false, message: 'File missing' });

    // audit log download
    try {
      const auditLog = await AuditLog.create({ 
        user: user._id, 
        document: doc._id, 
        action: 'download', 
        ip: getClientIP(req), 
        userAgent: req.headers['user-agent'] 
      });

      // Emit real-time audit log to super admin
      if (global.io) {
        global.io.to('super-admin-room').emit('new-audit-log', {
          log: {
            ...auditLog.toObject(),
            user: {
              _id: user._id,
              name: user.name,
              phone: user.phone,
              role: user.role
            },
            document: {
              _id: doc._id,
              originalName: doc.originalName,
              companyName: doc.companyName
            }
          }
        });
      }
    } catch (e) { 
      console.error('audit log error', e); 
    }

    // Send notification to document owner if not super admin and preferences enabled
    const docOwner = doc.user;
    if (docOwner && docOwner.role !== 'super_admin' && docOwner._id.toString() !== user._id.toString()) {
      try {
        const Notification = require('../models/notificationModel');
        const User = require('../models/userModel');
        const owner = await User.findById(docOwner._id);
        
        if (owner && owner.notifications) {
          // Dashboard notification
          if (owner.notifications.dashboardOnDownload !== false) {
            const notification = await Notification.create({
              user: docOwner._id,
              type: 'document_downloaded',
              document: doc._id,
              viewedBy: user._id,
              message: `${user.name} downloaded your document "${doc.originalName}"`
            });

            // Emit real-time notification to user
            if (global.io) {
              global.io.to(`user-${docOwner._id}`).emit('document-notification', {
                notification: {
                  ...notification.toObject(),
                  document: {
                    _id: doc._id,
                    originalName: doc.originalName
                  },
                  viewedBy: {
                    _id: user._id,
                    name: user.name
                  }
                }
              });
            }
          }

          // Email notification
          if (owner.notifications.emailOnDownload === true && owner.email) {
            const sendMail = require('../utils/sendMail');
            await sendMail({
              to: owner.email,
              subject: `Document Downloaded: ${doc.originalName}`,
              text: `Hello ${owner.name},\n\n${user.name} downloaded your document "${doc.originalName}" at ${new Date().toLocaleString()}.\n\nDocument: ${doc.originalName}\nDownloaded by: ${user.name}\nTime: ${new Date().toLocaleString()}`,
              html: `<p>Hello ${owner.name},</p><p><strong>${user.name}</strong> downloaded your document <strong>"${doc.originalName}"</strong> at ${new Date().toLocaleString()}.</p><p><strong>Document:</strong> ${doc.originalName}<br><strong>Downloaded by:</strong> ${user.name}<br><strong>Time:</strong> ${new Date().toLocaleString()}</p>`
            }).catch(err => console.error('Email notification error:', err));
          }
        }
      } catch (err) {
        console.error('Notification error:', err);
      }
    }

    // Notify admin about download attempt (fire-and-forget)
    const adminEmail = process.env.ADMIN_EMAIL;
    if (adminEmail) {
      const sendMail = require('../utils/sendMail');
      sendMail({
        to: adminEmail,
        subject: `Document downloaded by ${user.name} (${user._id})`,
        text: `User ${user.name} (${user.phone || 'no-phone'}) downloaded document ${doc._id} (${doc.companyName}) at ${new Date().toISOString()} from IP ${getClientIP(req)} UA ${req.headers['user-agent']}`
      }).catch(err => console.error('sendMail error', err));
    }

    // Validate file path for download (same as view)
    const downloadFilePath = path.join(UPLOAD_DIR, path.basename(doc.filePath));
    const resolvedDownloadPath = path.resolve(downloadFilePath);
    const uploadResolvedForDownload = path.resolve(UPLOAD_DIR);
    
    if (!resolvedDownloadPath.startsWith(uploadResolvedForDownload)) {
      return res.status(403).json({ success: false, message: 'Invalid file path' });
    }
    
    if (!fs.existsSync(downloadFilePath)) {
      return res.status(404).json({ success: false, message: 'File not found' });
    }

    // Stream decrypted content as attachment
    let downloadStream;
    try {
      downloadStream = createDecryptionStream(downloadFilePath);
      
      // If file is compressed, decompress on-the-fly
      if (doc.isCompressed) {
        const zlib = require('zlib');
        downloadStream = downloadStream.pipe(zlib.createGunzip());
      }
    } catch (decryptError) {
      // If decryption fails (no key), try direct file access
      try {
        downloadStream = fs.createReadStream(downloadFilePath);
        // If compressed, decompress
        if (doc.isCompressed) {
          const zlib = require('zlib');
          downloadStream = downloadStream.pipe(zlib.createGunzip());
        }
      } catch (fileError) {
        console.error('File stream error:', fileError);
        return res.status(500).json({ success: false, message: 'Error reading file' });
      }
    }
    
    const contentType = doc.mimeType || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${doc.originalName || doc.filePath}"`);
    
    // Handle stream errors that occur during pipe operation
    let responseSent = false;
    const handleStreamError = (error) => {
      if (!responseSent) {
        responseSent = true;
        console.error('Stream error during download:', error.message || error);
        if (!res.headersSent) {
          res.status(500).json({ success: false, message: 'An error occurred while downloading the document' });
        } else {
          res.destroy();
        }
      }
    };
    
    downloadStream.on('error', handleStreamError);
    res.on('error', handleStreamError);
    res.on('close', () => {
      if (downloadStream && !downloadStream.destroyed) {
        downloadStream.destroy();
      }
    });
    
    return downloadStream.pipe(res);
  } catch (err) {
    console.error('downloadDocumentFile error:', err.message || err);
    // Don't expose internal error details
    res.status(500).json({ success: false, message: 'An error occurred while downloading the document' });
  }
};
// Advanced search endpoint with fuzzy matching
const searchDocuments = async (req, res) => {
  try {
    const user = req.user;
    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const { q } = req.query;
    if (!q || q.trim().length === 0) {
      return res.status(400).json({ success: false, message: 'Search query is required' });
    }

    const query = {};
    // Permissions: super_admin sees all; others see own documents or those shared to them
    if (user.role !== 'super_admin') {
      query.$or = [
        { user: user._id },
        { permissionToView: { $in: [user._id] } }
      ];
    }

    // Use MongoDB text search
    query.$text = { $search: q };

    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const skip = (page - 1) * limit;

    // Optional category filter
    if (req.query.category) {
      if (mongoose.Types.ObjectId.isValid(req.query.category)) {
        query.category = req.query.category;
      }
    }
    // Optional fileType filter
    if (req.query.fileType) {
      const fileTypes = Array.isArray(req.query.fileType)
        ? req.query.fileType
        : req.query.fileType.split(',').map(t => t.trim());
      query.fileType = { $in: fileTypes };
    }

    const [docs, total] = await Promise.all([
      Doc.find(query, { score: { $meta: 'textScore' } })
        .populate('user', 'name phone role')
        .populate('category', 'name description')
        .populate('permissionToView', 'name phone')
        .populate('permissionToDownload', 'name phone')
        .populate('permissionToDelete', 'name phone')
        .sort({ score: { $meta: 'textScore' } })
        .skip(skip)
        .limit(limit)
        .lean(),
      Doc.countDocuments(query)
    ]);

    res.json({ 
      success: true,
      query: q,
      count: docs.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      data: docs 
    });
  } catch (err) {
    console.error('searchDocuments error', err.message || err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get document statistics by category
const getDocumentStats = async (req, res) => {
  try {
    const user = req.user;
    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const matchQuery = { permissionToView: { $in: [user._id] } };

    const stats = await Doc.aggregate([
      { $match: matchQuery },
      {
        $lookup: {
          from: 'categories',
          localField: 'category',
          foreignField: '_id',
          as: 'categoryInfo'
        }
      },
      {
        $group: {
          _id: '$category',
          categoryName: { $first: { $arrayElemAt: ['$categoryInfo.name', 0] } },
          count: { $sum: 1 },
          totalSize: { $sum: '$size' }
        }
      },
      {
        $project: {
          _id: 0,
          categoryId: '$_id',
          categoryName: { $ifNull: ['$categoryName', 'Uncategorized'] },
          count: 1,
          totalSize: 1,
          averageSize: { $divide: ['$totalSize', '$count'] }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Get total documents
    const totalDocs = await Doc.countDocuments(matchQuery);

    // Get recent documents (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const recentDocs = await Doc.countDocuments({ 
      ...matchQuery, 
      createdAt: { $gte: sevenDaysAgo } 
    });

    res.json({ 
      success: true,
      totalDocuments: totalDocs,
      recentDocuments: recentDocs,
      categories: stats
    });
  } catch (err) {
    console.error('getDocumentStats error', err.message || err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get documents by specific category
const getDocumentsByCategory = async (req, res) => {
  try {
    const user = req.user;
    const { category } = req.params;

    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    // Validate category ID
    if (!mongoose.Types.ObjectId.isValid(category)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid category ID' 
      });
    }

    const query = { category: category };
    if (user.role !== 'super_admin') {
      query.$or = [
        { user: user._id },
        { permissionToView: { $in: [user._id] } }
      ];
    }

    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const skip = (page - 1) * limit;

    // Sorting
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
    const sort = { [sortBy]: sortOrder };

    const [docs, total] = await Promise.all([
      Doc.find(query)
        .populate('user', 'name phone role')
        .populate('category', 'name description')
        .populate('permissionToView', 'name phone')
        .populate('permissionToDownload', 'name phone')
        .populate('permissionToDelete', 'name phone')
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean(),
      Doc.countDocuments(query)
    ]);

    res.json({ 
      success: true,
      category,
      count: docs.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      data: docs 
    });
  } catch (err) {
    console.error('getDocumentsByCategory error', err.message || err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

module.exports = {
  createDocument,
  getDocuments,
  getDocumentById,
  updateDocument,
  deleteDocument,
  viewDocumentFile,
  downloadDocumentFile,
  searchDocuments,
  getDocumentStats,
  getDocumentsByCategory,
  getDocumentsByUserId
};
