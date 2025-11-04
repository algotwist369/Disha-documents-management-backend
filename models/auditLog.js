const mongoose = require('mongoose');

const auditSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  document: { type: mongoose.Schema.Types.ObjectId, ref: 'Document', required: false },
  action: { type: String, enum: ['view', 'download', 'delete', 'upload', 'login', 'logout', 'register'], required: true },
  ip: { type: String },
  userAgent: { type: String },
  createdAt: { type: Date, default: Date.now }
});

// Index for performance on common queries
auditSchema.index({ user: 1, createdAt: -1 });
auditSchema.index({ document: 1, createdAt: -1 });
auditSchema.index({ action: 1, createdAt: -1 });

const AuditLog = mongoose.model('AuditLog', auditSchema);
module.exports = AuditLog;
