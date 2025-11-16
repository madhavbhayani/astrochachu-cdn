# CDN Server Deployment Guide - Hostinger VPS
## JWT-Protected Private URLs on Port 5000

---

## 📋 Overview

This CDN server provides **JWT-protected private URLs** for astrologer document uploads with:
- ✅ Advanced malware scanning
- ✅ Image sanitization and optimization  
- ✅ JWT authentication (no public access)
- ✅ Runs on port 5000
- ✅ Uses existing `/var/www/cdn/uploads` directory

---

## 🚀 Step-by-Step Deployment

### Step 1: Prepare Server Directory

```bash
# SSH into your Hostinger VPS
ssh your_user@your_server_ip

# Navigate to uploads directory
cd /var/www/cdn/uploads

# Create required subdirectories
sudo mkdir -p temp
sudo mkdir -p astrologers

# Set proper permissions
sudo chown -R www-data:www-data /var/www/cdn/uploads
sudo chmod -R 755 /var/www/cdn/uploads

# Verify structure
ls -la /var/www/cdn/uploads
# Should show: astrologers/, temp/
```

### Step 2: Upload CDN Server Files

```bash
# On your local machine, navigate to backend directory
cd "D:\Projects\astrochachu\Astrochachu - Astrologer Panel\astrochachu_astrologer_panel\backend"

# Upload files to server (replace with your server details)
scp cdnServer.js your_user@your_server:/var/www/astrochachu/backend/
scp package.json your_user@your_server:/var/www/astrochachu/backend/
scp .env your_user@your_server:/var/www/astrochachu/backend/

# OR use SFTP client like FileZilla to upload:
# - cdnServer.js
# - package.json  
# - .env (make sure it has production settings)
```

### Step 3: Update .env on Server

```bash
# SSH into server
ssh your_user@your_server_ip

# Edit .env file
cd /var/www/astrochachu/backend
nano .env
```

**Ensure these settings are correct:**
```env
# CDN Configuration (JWT-Protected Private URLs)
CDN_PORT=5000
CDN_HOST=0.0.0.0
CDN_BASE_PATH=/var/www/cdn/uploads
CDN_DOMAIN=https://cdn.astrochachu.com
ALLOWED_ORIGINS=https://astrochachu.com,http://localhost:3000

# JWT Configuration (MUST match your main server)
JWT_SECRET=4c01990d1edeb2e349c500ee136020c0c94af1a2d259f44fe4b7bcee926da53c84bdc0cd8e3226bdc3936e0853813142d3cee2d52920a16a71340e4f097c10bc
```

**Save and exit:** Press `Ctrl+X`, then `Y`, then `Enter`

### Step 4: Install Dependencies

```bash
# Make sure you're in backend directory
cd /var/www/astrochachu/backend

# Install Node.js dependencies
npm install

# Verify sharp package installed correctly (important for image processing)
npm list sharp
```

If `sharp` fails to install, try:
```bash
npm install --platform=linux --arch=x64 sharp
```

### Step 5: Configure Nginx

```bash
# Backup existing configuration
sudo cp /etc/nginx/sites-available/cdn.astrochachu.com /etc/nginx/sites-available/cdn.astrochachu.com.backup

# Edit Nginx configuration
sudo nano /etc/nginx/sites-available/cdn.astrochachu.com
```

**Replace entire content with:**
```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name cdn.astrochachu.com;
    return 301 https://$host$request_uri;
}

# CDN Server with JWT Authentication
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name cdn.astrochachu.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/cdn.astrochachu.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn.astrochachu.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    # Client body size limit
    client_max_body_size 10M;

    # Proxy to Node.js CDN Server (Port 5000)
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts for uploads
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering off;
        proxy_request_buffering off;
    }

    # Health check endpoint (public)
    location = /health {
        proxy_pass http://127.0.0.1:5000/health;
        access_log off;
    }

    # Block direct access to uploads
    location /uploads/ {
        return 403 "Access denied. Use authenticated API.";
    }

    # Logging
    access_log /var/log/nginx/cdn.astrochachu.com.access.log;
    error_log /var/log/nginx/cdn.astrochachu.com.error.log;
}
```

**Save and exit:** Press `Ctrl+X`, then `Y`, then `Enter`

### Step 6: Test and Restart Nginx

```bash
# Test Nginx configuration
sudo nginx -t

# If test passes, reload Nginx
sudo systemctl reload nginx

# Check Nginx status
sudo systemctl status nginx
```

### Step 7: Setup PM2 for CDN Server

```bash
# Navigate to backend directory
cd /var/www/astrochachu/backend

# Stop any existing PM2 processes for CDN
pm2 stop astrochachu-cdn 2>/dev/null || true
pm2 delete astrochachu-cdn 2>/dev/null || true

# Start CDN server with PM2
pm2 start cdnServer.js --name "astrochachu-cdn" --watch

# Save PM2 process list
pm2 save

# Setup PM2 to start on boot (if not already done)
pm2 startup

# Check if CDN server is running
pm2 list
pm2 logs astrochachu-cdn --lines 50
```

### Step 8: Verify Deployment

```bash
# Test 1: Health check (public - no JWT required)
curl https://cdn.astrochachu.com/health

# Expected response:
# {"success":true,"message":"CDN Server is running","timestamp":"..."}

# Test 2: Try to upload without JWT (should fail)
curl -X POST https://cdn.astrochachu.com/upload \
  -F "file=@/path/to/test.jpg" \
  -F "documentType=Profile Photo"

# Expected response:
# {"success":false,"message":"Access denied. No authentication token provided."}

# Test 3: Check server logs
pm2 logs astrochachu-cdn --lines 20
```

---

## 🔐 How JWT Authentication Works

### For Uploads (POST /upload or /upload-batch):
```http
POST https://cdn.astrochachu.com/upload
Headers:
  Authorization: Bearer <JWT_TOKEN>
  Content-Type: multipart/form-data
Body:
  file: <image_file>
  documentType: "Aadhar Card" | "Bank Passbook" | "Profile Photo" | "PAN Card"
```

### For File Access (GET /cdn/file/...):
```http
GET https://cdn.astrochachu.com/cdn/file/astrologers/123/Aadhar%20Card/filename.jpg
Headers:
  Authorization: Bearer <JWT_TOKEN>
```

**Important:** Users can only access their own files. The JWT token contains the `astrologerId`.

---

## 📁 Directory Structure on Server

```
/var/www/cdn/uploads/
├── temp/                          # Temporary upload processing
└── astrologers/
    └── {astrologer_id}/
        ├── Aadhar Card/
        │   └── {secure_filename}.jpg
        ├── Bank Passbook/
        │   └── {secure_filename}.jpg
        ├── Profile Photo/
        │   └── {secure_filename}.jpg
        └── PAN Card/
            └── {secure_filename}.jpg
```

---

## 🔧 Troubleshooting

### CDN Server Won't Start

```bash
# Check if port 5000 is already in use
sudo lsof -i :5000

# If something is using it, kill the process
sudo kill -9 <PID>

# Check PM2 logs
pm2 logs astrochachu-cdn --lines 50

# Restart PM2 process
pm2 restart astrochachu-cdn
```

### Permission Issues

```bash
# Fix ownership
sudo chown -R www-data:www-data /var/www/cdn/uploads

# Fix permissions
sudo chmod -R 755 /var/www/cdn/uploads

# Check current permissions
ls -la /var/www/cdn/uploads
```

### Nginx Issues

```bash
# Test configuration
sudo nginx -t

# Check error logs
sudo tail -f /var/log/nginx/cdn.astrochachu.com.error.log

# Restart Nginx
sudo systemctl restart nginx
```

### Sharp Package Issues

```bash
# Reinstall sharp for Linux platform
cd /var/www/astrochachu/backend
npm uninstall sharp
npm install --platform=linux --arch=x64 sharp
```

### JWT Token Issues

```bash
# Verify JWT_SECRET matches between servers
grep JWT_SECRET /var/www/astrochachu/backend/.env

# Test with a valid JWT token
# Get token from your main app login response
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://cdn.astrochachu.com/health
```

---

## 📊 Monitoring

### View Logs
```bash
# CDN server logs
pm2 logs astrochachu-cdn

# Nginx access logs
sudo tail -f /var/log/nginx/cdn.astrochachu.com.access.log

# Nginx error logs
sudo tail -f /var/log/nginx/cdn.astrochachu.com.error.log
```

### Monitor Performance
```bash
# PM2 monitoring dashboard
pm2 monit

# Check server resources
htop

# Check disk space
df -h /var/www/cdn/uploads
```

---

## 🛡️ Security Features

1. ✅ **JWT Authentication**: All uploads and file access require valid JWT token
2. ✅ **User Isolation**: Users can only access their own files
3. ✅ **Malware Scanning**: Multi-layer security checks before accepting files
4. ✅ **Rate Limiting**: 20 uploads per 15 minutes per IP
5. ✅ **HTTPS Only**: All traffic encrypted via SSL
6. ✅ **No Public Access**: Files are NOT publicly accessible without JWT
7. ✅ **Image Sanitization**: Strips metadata and re-encodes images

---

## 🔄 Updating the Server

```bash
# SSH into server
ssh your_user@your_server_ip

# Navigate to backend
cd /var/www/astrochachu/backend

# Backup current version
cp cdnServer.js cdnServer.js.backup

# Upload new cdnServer.js file (from local machine)
# Then on server:

# Restart PM2 process
pm2 restart astrochachu-cdn

# Check logs for errors
pm2 logs astrochachu-cdn --lines 20
```

---

## ✅ Success Checklist

- [ ] Server directory `/var/www/cdn/uploads` exists with correct permissions
- [ ] `cdnServer.js` uploaded to server
- [ ] `.env` file has correct production settings (port 5000, correct paths)
- [ ] Dependencies installed (`npm install` completed successfully)
- [ ] Nginx configuration updated and tested (`sudo nginx -t` passes)
- [ ] PM2 process running (`pm2 list` shows `astrochachu-cdn` online)
- [ ] Health check works: `curl https://cdn.astrochachu.com/health`
- [ ] Upload without JWT fails (returns 401)
- [ ] Server logs show no errors (`pm2 logs astrochachu-cdn`)

---

## 📞 Support

If you encounter issues:
1. Check PM2 logs: `pm2 logs astrochachu-cdn`
2. Check Nginx logs: `sudo tail -f /var/log/nginx/cdn.astrochachu.com.error.log`
3. Verify `.env` settings
4. Ensure JWT_SECRET matches between main server and CDN server
5. Test with `curl` commands to isolate the issue

---

**Deployment Date:** November 16, 2025  
**Server:** Hostinger VPS  
**Domain:** cdn.astrochachu.com  
**Port:** 5000  
**Authentication:** JWT Required  
**Public Access:** ❌ Disabled (All URLs are private)
