#!/bin/bash
set -e

echo "🔧 Updating and upgrading packages..."
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt upgrade -yq

echo "🔧 Installing system dependencies..."
sudo apt install -yq python3-pip sqlite3 nginx apache2-utils python3-venv expect sshpass openssl git

# Environment setup
export APP_DIR="/opt/network_manager"
export REPO_URL="https://github.com/airani051346/deployDev.git"
export APP_USER="www-data"

echo "📁 Creating application directory..."
sudo mkdir -p "$APP_DIR"
sudo chown "$USER:$USER" "$APP_DIR"

echo "📥 Cloning GitHub repository..."
git clone "$REPO_URL" "$APP_DIR"

echo "🐍 Creating virtual environment and installing Python packages..."
cd "$APP_DIR/app"
python3 -m venv venv
source venv/bin/activate
pip install flask gunicorn paramiko requests

echo "📦 Initializing SQLite database..."
cat > init_db.sql <<EOF

EOF

# sqlite3 zero_touch.db < init_db.sql

echo "🔐 Fixing permissions..."
sudo chown "$APP_USER:$APP_USER" "$APP_DIR/app/zero_touch.db"
sudo chmod 660 "$APP_DIR/app/zero_touch.db"
sudo chown -R "$APP_USER:$APP_USER" "$APP_DIR/app"
sudo chmod -R 770 "$APP_DIR/app"

echo "🛠️ Creating systemd service..."
sudo tee /etc/systemd/system/zero_touch-api.service > /dev/null <<EOF
[Unit]
Description=Zero Touch Flask API
After=network.target

[Service]
User=$APP_USER
WorkingDirectory=$APP_DIR/app
Environment="PATH=$APP_DIR/app/venv/bin"
ExecStart=$APP_DIR/app/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reexec
sudo systemctl enable zero_touch-api
sudo systemctl start zero_touch-api

echo "🔒 Generating self-signed SSL certificate..."
sudo mkdir -p "$APP_DIR/app/certs"
sudo openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout "$APP_DIR/app/certs/zero_touch.key" \
  -out "$APP_DIR/app/certs/zero_touch.crt" \
  -subj "/C=DE/ST=CP/L=emeateam/O=checkpoint/CN=zero-touch.local"

echo "🌐 Configuring Nginx as reverse proxy..."
sudo tee /etc/nginx/sites-available/zero_touch > /dev/null <<EOF
server {
    listen 443 ssl http2;
    server_name _;

    ssl_certificate     $APP_DIR/app/certs/zero_touch.crt;
    ssl_certificate_key $APP_DIR/app/certs/zero_touch.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/zero_touch /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

echo "✅ Zero Touch App successfully deployed at https://<your-server-ip>/"
echo "📋 View logs: sudo journalctl -u zero_touch-api -f"
