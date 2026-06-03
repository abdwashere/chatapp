# Pulse Chat — AWS Deployment Guide

## Architecture
- **EC2** (t3.small or t3.medium) — app server  
- **Nginx** — reverse proxy + SSL termination  
- **PM2** — process manager (auto-restart, clustering)  
- **S3** (optional) — for image storage at scale  
- **Data** — JSON file DB stored on EBS volume (upgrade to RDS/DynamoDB for production at scale)

---

## 1. Launch EC2 Instance

1. Go to **EC2 → Launch Instance**
2. Choose **Ubuntu Server 22.04 LTS**
3. Instance type: **t3.small** (2 vCPU, 2GB RAM) — enough for ~500 concurrent users
4. **Security Group** — open these ports:
   - `22` (SSH)
   - `80` (HTTP)
   - `443` (HTTPS)
5. Create/assign a key pair, download it
6. Allocate and associate an **Elastic IP**

---

## 2. Server Setup

```bash
# SSH in
ssh -i your-key.pem ubuntu@YOUR_ELASTIC_IP

# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install PM2 globally
sudo npm install -g pm2

# Install Nginx
sudo apt install -y nginx

# Install Certbot for SSL
sudo apt install -y certbot python3-certbot-nginx
```

---

## 3. Deploy App

```bash
# Create app directory
sudo mkdir -p /var/www/pulse-chat
sudo chown ubuntu:ubuntu /var/www/pulse-chat

# Upload your files (from local machine):
scp -i your-key.pem -r ./chat-app/* ubuntu@YOUR_IP:/var/www/pulse-chat/

# On the server:
cd /var/www/pulse-chat
npm install --production

# Create data directory with proper permissions
mkdir -p data public/uploads
chmod 755 public/uploads
```

---

## 4. Environment Variables

```bash
# Create .env file
cat > /var/www/pulse-chat/.env << 'EOF'
JWT_SECRET=your_very_long_random_secret_here_min_64_chars
PORT=3000
NODE_ENV=production
EOF

chmod 600 /var/www/pulse-chat/.env
```

Generate a strong JWT secret:
```bash
node -e "const crypto=require('crypto'); console.log(crypto.randomBytes(64).toString('hex'))"
```

---

## 5. PM2 Process Manager

```bash
# Start with PM2
cd /var/www/pulse-chat
pm2 start server.js --name pulse-chat --env production

# Auto-start on reboot
pm2 startup systemd -u ubuntu --hp /home/ubuntu
pm2 save

# Useful PM2 commands:
pm2 logs pulse-chat      # view logs
pm2 restart pulse-chat   # restart
pm2 status               # check status
pm2 monit                # live dashboard
```

**Cluster mode** (use all CPU cores):
```bash
pm2 start server.js --name pulse-chat -i max
```

---

## 6. Nginx Configuration

```bash
sudo nano /etc/nginx/sites-available/pulse-chat
```

Paste this config (replace `yourdomain.com`):

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    # Upload size limit
    client_max_body_size 10M;

    # Static files with caching
    location ~* \.(js|css|png|jpg|jpeg|gif|webp|ico|woff2)$ {
        root /var/www/pulse-chat/public;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }

    # Uploaded images
    location /uploads/ {
        alias /var/www/pulse-chat/public/uploads/;
        expires 30d;
    }

    # Proxy to Node.js
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;

        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for long-lived WebSocket connections
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_connect_timeout 60s;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/pulse-chat /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## 7. SSL with Let's Encrypt (Free HTTPS)

```bash
# Point your domain's A record to your Elastic IP first, then:
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Auto-renewal (already set up by certbot, verify with):
sudo certbot renew --dry-run
```

---

## 8. Firewall (UFW)

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
sudo ufw status
```

---

## 9. S3 for Image Storage (optional, for scale)

Install AWS SDK:
```bash
npm install @aws-sdk/client-s3 multer-s3
```

Replace the multer storage in `server.js`:
```javascript
const { S3Client } = require('@aws-sdk/client-s3');
const multerS3 = require('multer-s3');

const s3 = new S3Client({ region: 'us-east-1' });
const storage = multerS3({
  s3,
  bucket: 'your-bucket-name',
  key: (req, file, cb) => cb(null, `uploads/${uuidv4()}${path.extname(file.originalname)}`),
  contentType: multerS3.AUTO_CONTENT_TYPE
});
```

---

## 10. Monitoring & Backups

```bash
# Auto-backup data to S3 every hour (add to crontab):
crontab -e
# Add:
0 * * * * aws s3 sync /var/www/pulse-chat/data s3://your-bucket/backups/$(date +\%Y-\%m-\%d)/

# Monitor disk space
df -h

# Monitor memory
free -h

# View Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

---

## Scaling to Production DB

When you outgrow the JSON file DB (>10k users), migrate to:
- **PostgreSQL on RDS** — relational, strong consistency
- **DynamoDB** — serverless, scales infinitely, pay-per-use
- **Redis** — for in-memory state (online users, rate limits, typing)

---

## Estimated AWS Costs

| Resource | Monthly Cost |
|---|---|
| EC2 t3.small | ~$15 |
| Elastic IP | ~$3.6 |
| EBS 20GB gp3 | ~$1.60 |
| Data transfer (10GB) | ~$0.90 |
| **Total** | **~$21/mo** |

For free tier: use **t2.micro** for the first 12 months (750 hrs/month free).
