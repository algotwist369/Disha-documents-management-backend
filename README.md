# DOS Document Management Backend

A secure, performant, and reliable document management system backend built with Node.js, Express, and MongoDB.

## Features

### Security
- 🔐 JWT-based authentication
- 🛡️ Helmet.js security headers
- 🔒 File encryption at rest (AES-256-GCM)
- 🚦 Rate limiting on all endpoints
- 🔑 Password hashing with bcrypt
- 🚪 Account lockout after failed login attempts
- 📝 Comprehensive audit logging
- ✅ Input validation and sanitization
- 🌐 CORS configuration with origin whitelist

### Performance
- ⚡ Response compression
- 📊 Database indexing for fast queries
- 📄 Pagination support for large datasets
- 🔄 Async file operations
- 💾 Lean queries for better memory usage

### Reliability
- 🏥 Health check endpoint
- 🔄 Graceful shutdown handling
- 📋 Request logging (Morgan)
- 🔁 Database connection retry logic
- ⚠️ Global error handling
- 🛑 Uncaught exception handling

## Prerequisites

- Node.js v14 or higher
- MongoDB v4.4 or higher
- npm or yarn

## Installation

1. Clone the repository
```bash
cd backend
```

2. Install dependencies
```bash
npm install
```

3. Create environment file
```bash
cp env.example .env
```

4. Configure your environment variables in `.env` (see Configuration section)

5. Generate encryption key (optional but recommended)
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## Configuration

### Required Environment Variables

- `MONGO_URI`: MongoDB connection string
- `JWT_SECRET`: Secret key for JWT token signing (use a strong random string)

### Optional Environment Variables

- `PORT`: Server port (default: 5000)
- `NODE_ENV`: Environment (development/production)
- `JWT_EXPIRES_IN`: JWT token expiration (default: 7d)
- `FILE_ENCRYPTION_KEY`: 32-byte base64 key for file encryption
- `ADMIN_EMAIL`: Email for admin notifications
- `ALLOWED_ORIGINS`: Comma-separated CORS allowed origins
- SMTP configuration for email notifications (see env.example)

## Usage

### Development
```bash
npm run dev
```

### Production
```bash
npm start
```

### Health Check
```bash
curl http://localhost:9000/health
```

## API Endpoints

### Authentication
- `POST /api/users/register` - Register new user
- `POST /api/users/login` - Login user
- `DELETE /api/users/:userId` - Delete user (admin only)

### Documents
- `POST /api/documents` - Upload document
- `GET /api/documents` - List documents (with pagination)
- `GET /api/documents/:id` - Get document details
- `PUT /api/documents/:id` - Update document
- `DELETE /api/documents/:id` - Delete document
- `GET /api/documents/:id/view` - View document file
- `GET /api/documents/:id/download` - Download document file

### Query Parameters for Document List
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 10)
- `sortBy`: Sort field (default: createdAt)
- `sortOrder`: Sort order (asc/desc, default: desc)
- `companyName`: Filter by company name (partial match)
- `fileType`: Filter by file type

## Security Best Practices

1. **Always use HTTPS in production** - The app enforces HTTPS for sensitive endpoints
2. **Use strong JWT secret** - Generate with `openssl rand -base64 32`
3. **Enable file encryption** - Set FILE_ENCRYPTION_KEY in production
4. **Configure CORS properly** - Set ALLOWED_ORIGINS to your frontend domain
5. **Use strong passwords** - Minimum 8 characters enforced
6. **Monitor audit logs** - Review user actions regularly
7. **Keep dependencies updated** - Run `npm audit` regularly
8. **Use environment variables** - Never commit secrets to git
9. **Enable rate limiting** - Already configured but tune as needed
10. **Backup your database** - Regular MongoDB backups recommended

## Database Indexes

The following indexes are automatically created for performance:

### Users
- `phone` (unique)
- `role`

### Documents
- `user` + `createdAt` (compound)
- `companyName`
- `fileType`

### Audit Logs
- `user` + `createdAt` (compound)
- `document` + `createdAt` (compound)
- `action` + `createdAt` (compound)

## Error Handling

The application includes comprehensive error handling:
- Validation errors return 400 status
- Authentication errors return 401 status
- Authorization errors return 403 status
- Not found errors return 404 status
- Server errors return 500 status

All errors follow this format:
```json
{
  "success": false,
  "message": "Error description"
}
```

## Logging

- Development: Colored, concise logs
- Production: Apache-style combined logs
- Includes: timestamp, method, URL, status, response time

## Graceful Shutdown

The server handles the following signals gracefully:
- `SIGTERM` - Kubernetes/Docker stop
- `SIGINT` - Ctrl+C
- `uncaughtException` - Unhandled errors
- `unhandledRejection` - Unhandled promise rejections

Shutdown process:
1. Stop accepting new connections
2. Finish processing current requests
3. Close database connections
4. Exit process

## File Storage

Files are stored in the `upload/` directory with:
- Random filenames to prevent conflicts
- Size limit: 20MB (configurable in uploadFiles.js)
- Encryption at rest (if FILE_ENCRYPTION_KEY is set)
- Automatic cleanup on document deletion

## Audit Logging

All document actions are logged:
- Upload
- View
- Download
- Delete
- Login attempts

Logs include: user ID, document ID, action, IP address, user agent, timestamp

## Testing

```bash
# Run tests (when available)
npm test
```

## Troubleshooting

### MongoDB Connection Issues
- Verify MongoDB is running
- Check MONGO_URI in .env
- Ensure network connectivity
- Check MongoDB logs

### JWT Token Issues
- Verify JWT_SECRET is set
- Check token expiration
- Ensure Bearer token format in Authorization header

### File Upload Issues
- Check upload directory permissions
- Verify file size limits
- Check available disk space
- Review multer error messages

## License

ISC

## Support

For issues and questions, please open an issue in the repository.

