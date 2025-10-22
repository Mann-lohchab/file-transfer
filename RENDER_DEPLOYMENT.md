# Render Deployment Guide

This guide provides instructions for deploying the File Server application to Render.com.

## Required Environment Variables

The following environment variables must be configured in your Render service:

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `MONGO_URL` | MongoDB connection string | `mongodb+srv://user:pass@cluster.mongodb.net/dbname` |
| `JWT_SECRET` | Secret key for JWT token signing | `your-super-secret-jwt-key-minimum-32-characters-long` |

**⚠️ Important**: Without these variables, the application will not work. The admin panel will show "categories.forEach is not a function" errors.

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MAX_FILE_SIZE` | Maximum file upload size in bytes | `104857600` (100MB) |
| `CLIENT_URL` | CORS allowed origin | `http://localhost:4321` |
| `NODE_ENV` | Environment mode | `development` |
| `PORT` | Server port | `5000` (set automatically by Render) |

## Render Deployment Steps

### 1. Create a New Web Service

1. Go to [Render Dashboard](https://dashboard.render.com)
2. Click "New" → "Web Service"
3. Connect your GitHub repository
4. Select the repository containing this backend code

### 2. Configure Build Settings

- **Build Command**: `npm install`
- **Start Command**: `node server.js`
- **Root Directory**: `backend` (if your backend is in a subdirectory)

### 3. Add Environment Variables

In the Render dashboard, go to your service settings and add all required environment variables:

1. Click on your service
2. Go to "Environment" tab
3. Click "Add Environment Variable"
4. Add each variable listed above

### 4. Deploy

Click "Deploy" and wait for the deployment to complete.

## Database Setup

### MongoDB Atlas (Recommended)

1. Create a [MongoDB Atlas](https://www.mongodb.com/atlas) account
2. Create a new cluster
3. Get your connection string from "Connect" → "Connect your application"
4. Whitelist Render's IP addresses in MongoDB Atlas:
   - Go to Network Access in MongoDB Atlas
   - Add IP address: `0.0.0.0/0` (Allow Access from Anywhere)

### Connection String Format

```
mongodb+srv://username:password@cluster.mongodb.net/database?retryWrites=true&w=majority
```

Replace:
- `username`: Your MongoDB username
- `password`: Your MongoDB password
- `cluster`: Your cluster URL
- `database`: Your database name

## Troubleshooting

### Admin Panel Issues

**Problem**: Admin page shows "categories.forEach is not a function"
- **Cause**: Database connection failed or `MONGO_URL` not set correctly
- **Solution**: Check that `MONGO_URL` is correct and database is accessible

**Problem**: Login fails
- **Cause**: `JWT_SECRET` not set
- **Solution**: Ensure `JWT_SECRET` is set to a long random string (minimum 32 characters)

**Problem**: Files won't upload
- **Cause**: `MAX_FILE_SIZE` too small or uploads directory not writable
- **Solution**: Check `MAX_FILE_SIZE` setting and ensure uploads directory permissions

### Viewing Logs

1. Go to your Render service dashboard
2. Click on the "Logs" tab
3. Check for error messages and connection issues

### Common Error Messages

- **"Database not connected"**: Check `MONGO_URL` and MongoDB Atlas network access
- **"Authentication failed"**: Verify `JWT_SECRET` is set correctly
- **"File too large"**: Increase `MAX_FILE_SIZE` or reduce file size
- **"Connection timeout"**: Check MongoDB Atlas cluster status and network settings

## Production Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Configure `CLIENT_URL` to your frontend domain
- [ ] Set secure `JWT_SECRET` (minimum 32 characters)
- [ ] Verify `MONGO_URL` connection string
- [ ] Test admin panel functionality
- [ ] Check file upload/download features
- [ ] Verify CORS settings for frontend domain

## Security Notes

- Never commit `.env` files to version control
- Use strong, unique passwords for MongoDB
- Regularly rotate JWT secrets
- Monitor Render logs for security issues
- Keep MongoDB Atlas credentials secure

## Support

If you encounter issues:

1. Check the Render service logs
2. Verify all environment variables are set correctly
3. Test database connectivity
4. Review MongoDB Atlas settings and network access
5. Contact Render support if infrastructure issues persist