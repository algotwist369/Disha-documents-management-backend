const Doc = require('../models/docModel');
const { deleteFile, UPLOAD_DIR } = require('../utils/uploadFiles');
const sendMail = require('../utils/sendMail');
const { encryptFile, createDecryptionStream } = require('../utils/fileCrypto');
const AuditLog = require('../models/auditLog');
const fs = require('fs');
const path = require('path');

// Create a new document record (expects file already uploaded via middleware)
const createDocument = async (req, res) => {
  try {
    const user = req.user; // protect middleware should set this
    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    // Accept file via req.file
    const file = req.file;
    if (!file) return res.status(400).json({ success: false, message: 'No file uploaded' });

    const { companyName, fileType } = req.body;
    if (!companyName || !fileType) return res.status(400).json({ success: false, message: 'companyName and fileType are required' });

    // Encrypt the uploaded file at rest (write to temp then replace)
    const uploadedPath = path.join(UPLOAD_DIR, file.filename);
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
      // proceed but log
    }

    const doc = await Doc.create({
      user: user._id,
      companyName: companyName,
      fileType: Array.isArray(fileType) ? fileType : [fileType],
      filePath: file.filename,
      originalName: file.originalname,
      mimeType: file.mimetype,
      size: file.size,
    });

    // audit log upload
    try {
      const auditLog = await AuditLog.create({ 
        user: user._id, 
        document: doc._id, 
        action: 'upload', 
        ip: req.ip, 
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
    // All authenticated users can see all documents (sharing enabled)

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
    
    // 2. Filter by file type (category) - supports multiple types
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
        fileType: req.query.fileType || null,
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

    const doc = await Doc.findById(id).populate('user', 'name phone role');
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

    const { companyName, fileType } = req.body;
    if (companyName) doc.companyName = companyName;
    if (fileType) doc.fileType = Array.isArray(fileType) ? fileType : [fileType];

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
        ip: req.ip, 
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
    console.error('deleteDocument error', err.message || err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Stream file for inline viewing (sets content-type)
const viewDocumentFile = async (req, res) => {
  try {
    const user = req.user;
    const id = req.params.id;
    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const doc = await Doc.findById(id);
    if (!doc) return res.status(404).json({ success: false, message: 'Document not found' });
    // All authenticated users can view any document

    const filePath = require('path').join(UPLOAD_DIR, doc.filePath);
    if (!require('fs').existsSync(filePath)) return res.status(404).json({ success: false, message: 'File missing' });

    // audit log view
    try {
      const auditLog = await AuditLog.create({ 
        user: user._id, 
        document: doc._id, 
        action: 'view', 
        ip: req.ip, 
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

    // Notify admin about view attempt (fire-and-forget)
    const adminEmail = process.env.ADMIN_EMAIL;
    if (adminEmail) {
      sendMail({
        to: adminEmail,
        subject: `Document viewed by ${user.name} (${user._id})`,
        text: `User ${user.name} (${user.phone || 'no-phone'}) viewed document ${doc._id} (${doc.companyName}) at ${new Date().toISOString()} from IP ${req.ip} UA ${req.headers['user-agent']}`
      }).catch(err => console.error('sendMail error', err));
    }

    // Stream decrypted content
    const stream = createDecryptionStream(filePath);
    const contentType = doc.mimeType || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `inline; filename="${doc.originalName || doc.filePath}"`);
    return stream.pipe(res);
  } catch (err) {
    console.error('viewDocumentFile error', err.message || err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Download file as attachment
const downloadDocumentFile = async (req, res) => {
  try {
    const user = req.user;
    const id = req.params.id;
    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const doc = await Doc.findById(id);
    if (!doc) return res.status(404).json({ success: false, message: 'Document not found' });
    // All authenticated users can download any document

    const path = require('path');
    const fs = require('fs');
    const filePath = path.join(UPLOAD_DIR, doc.filePath);
    if (!fs.existsSync(filePath)) return res.status(404).json({ success: false, message: 'File missing' });

    // audit log download
    try {
      const auditLog = await AuditLog.create({ 
        user: user._id, 
        document: doc._id, 
        action: 'download', 
        ip: req.ip, 
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

    // Notify admin about download attempt (fire-and-forget)
    const adminEmail = process.env.ADMIN_EMAIL;
    if (adminEmail) {
      sendMail({
        to: adminEmail,
        subject: `Document downloaded by ${user.name} (${user._id})`,
        text: `User ${user.name} (${user.phone || 'no-phone'}) downloaded document ${doc._id} (${doc.companyName}) at ${new Date().toISOString()} from IP ${req.ip} UA ${req.headers['user-agent']}`
      }).catch(err => console.error('sendMail error', err));
    }

    // Stream decrypted content as attachment
    const stream = createDecryptionStream(filePath);
    const contentType = doc.mimeType || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${doc.originalName || doc.filePath}"`);
    return stream.pipe(res);
  } catch (err) {
    console.error('downloadDocumentFile error', err.message || err);
    res.status(500).json({ success: false, message: 'Server error' });
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
    if (user.role !== 'admin') query.user = user._id;

    // Use MongoDB text search
    query.$text = { $search: q };

    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const skip = (page - 1) * limit;

    // Optional category filter
    if (req.query.fileType) {
      const fileTypes = Array.isArray(req.query.fileType) 
        ? req.query.fileType 
        : req.query.fileType.split(',').map(t => t.trim());
      query.fileType = { $in: fileTypes };
    }

    const [docs, total] = await Promise.all([
      Doc.find(query, { score: { $meta: 'textScore' } })
        .populate('user', 'name phone role')
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

// Get document statistics by category (fileType)
const getDocumentStats = async (req, res) => {
  try {
    const user = req.user;
    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    const matchQuery = {};
    if (user.role !== 'admin') matchQuery.user = user._id;

    const stats = await Doc.aggregate([
      { $match: matchQuery },
      { $unwind: '$fileType' },
      {
        $group: {
          _id: '$fileType',
          count: { $sum: 1 },
          totalSize: { $sum: '$size' }
        }
      },
      {
        $project: {
          _id: 0,
          category: '$_id',
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

// Get documents by specific category (fileType)
const getDocumentsByCategory = async (req, res) => {
  try {
    const user = req.user;
    const { category } = req.params;

    if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

    // Validate category
    const validCategories = ['ITR', 'GST', 'BankStatement', 'Other'];
    if (!validCategories.includes(category)) {
      return res.status(400).json({ 
        success: false, 
        message: `Invalid category. Valid categories: ${validCategories.join(', ')}` 
      });
    }

    const query = { fileType: category };
    if (user.role !== 'admin') query.user = user._id;

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
};
