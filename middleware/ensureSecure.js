// Reject non-HTTPS requests for sensitive endpoints.
const ensureSecure = (req, res, next) => {
  const proto = req.get('x-forwarded-proto') || req.protocol;
  if (proto && proto.toLowerCase() === 'https') return next();
  return res.status(403).json({ success: false, message: 'Insecure connection: HTTPS required' });
};

module.exports = ensureSecure;
