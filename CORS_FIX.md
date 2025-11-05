# CORS Fix Instructions

## Issue
CORS errors when accessing backend from frontend.

## Solution

1. **Verify .env file** - Make sure `backend/.env` has:
   ```
   ALLOWED_ORIGINS=https://369.ciphra.in
   NODE_ENV=production
   ```

2. **Restart the backend server** to pick up the new .env values:
   ```bash
   cd backend
   # If using PM2:
   pm2 restart dos-backend
   # Or if running directly:
   # Stop the server (Ctrl+C) and restart:
   npm start
   ```

3. **Check server logs** - You should see:
   ```
   🔒 CORS Configuration:
     - NODE_ENV: production
     - ALLOWED_ORIGINS: [ 'https://369.ciphra.in' ]
     - ALLOWED_ORIGINS from env: https://369.ciphra.in
   🔌 Socket.IO CORS configured
      Allowed origins: [ 'https://369.ciphra.in' ]
   ```

4. **Verify the backend is accessible**:
   - Test: `curl -I https://ddm.api.d0s369.co.in/health`
   - Should return 200 OK

5. **Check for reverse proxy issues**:
   - If using Nginx/Apache, make sure CORS headers aren't being stripped
   - Verify proxy passes through all headers

## Common Issues

### Issue: CORS still blocked after restart
- Check if `.env` file is being read (check server startup logs)
- Verify `NODE_ENV=production` is set
- Make sure there are no spaces in `ALLOWED_ORIGINS` value

### Issue: WebSocket connection fails
- Verify Socket.IO CORS matches Express CORS origins
- Check firewall allows WebSocket connections (port 443 for HTTPS)
- Verify SSL certificate is valid for `ddm.api.d0s369.co.in`

### Issue: Preflight OPTIONS request fails
- The CORS middleware should handle OPTIONS automatically
- Check if reverse proxy is blocking OPTIONS requests
- Verify `Access-Control-Allow-Methods` header is present

## Testing

Test CORS from browser console on `https://369.ciphra.in`:
```javascript
fetch('https://ddm.api.d0s369.co.in/api/health', {
  method: 'GET',
  credentials: 'include'
})
.then(r => r.json())
.then(console.log)
.catch(console.error);
```

Should return success without CORS errors.

