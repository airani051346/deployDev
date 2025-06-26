#!/bin/bash
set -e

echo "🔧 Updating and upgrading packages..."
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt upgrade -yq

echo "🔧 Installing system dependencies..."
sudo DEBIAN_FRONTEND=noninteractive apt install -yq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" python3-pip sqlite3 nginx apache2-utils python3-venv expect sshpass openssl git nmap

export REPO_URL="https://github.com/airani051346/deployDev.git"

# Environment setup
read -p "Enter application directory default: [/opt/network_manager]: " input_app_dir
export APP_DIR="${input_app_dir:-/opt/network_manager}"

# Ask for APP_USER
read -p "Enter application user default: [www-data]: " input_app_user
export APP_USER="${input_app_user:-www-data}"

echo "📁 Creating application directory..."
sudo mkdir -p "$APP_DIR"
sudo chown "$USER:$USER" "$APP_DIR"

echo "📥 Cloning GitHub repository..."
git clone "$REPO_URL" "$APP_DIR"

echo "🐍 Creating virtual environment and installing Python packages..."
cd "$APP_DIR/app"
python3 -m venv venv
source venv/bin/activate
pip install flask gunicorn paramiko requests python-nmap

sudo ln -s /usr/bin/nmap "$APPP_DIR/app/venv/bin/nmap"

# sqlite3 zero_touch.db < init_db.sql

echo "🔐 Fixing permissions..."
sudo chown "$APP_USER:$APP_USER" "$APP_DIR/app/zero_touch.db"
sudo chmod 660 "$APP_DIR/app/zero_touch.db"
sudo chown -R "$APP_USER:$APP_USER" "$APP_DIR/app"
sudo chmod -R 770 "$APP_DIR/app"

echo "🛠️ Creating systemd service..."
sudo cp "$APP_DIR/app/service/zero_touch-api.service" /etc/systemd/system/

sudo systemctl daemon-reexec
sudo systemctl enable zero_touch-api
sudo systemctl start zero_touch-api

echo "🔒 Generating self-signed SSL certificate..."
sudo openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout "$APP_DIR/app/certs/zero_touch.key" \
  -out "$APP_DIR/app/certs/zero_touch.crt" \
  -subj "/C=DE/ST=CP/L=emeateam/O=checkpoint/CN=zero-touch.local"

echo "🌐 Configuring Nginx as reverse proxy..."

sudo tee /etc/nginx/sites-available/zero_touch > /dev/null <<EOF
server {
    listen 443 ssl;
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
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
echo "🌐 Adding HTTP to HTTPS redirect..."
sudo tee /etc/nginx/sites-available/zero_touch_http_redirect > /dev/null <<EOF
server {
    listen 80 default_server;
    server_name _;

    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF


sudo ln -sf /etc/nginx/sites-available/zero_touch /etc/nginx/sites-enabled/
sudo ln -sf /etc/nginx/sites-available/zero_touch_http_redirect /etc/nginx/sites-enabled/

sudo nginx -t
sudo systemctl restart nginx

echo "✅ Zero Touch App successfully deployed at https://<your-server-ip>/"
echo "📋 View logs: sudo journalctl -u zero_touch-api -f"
