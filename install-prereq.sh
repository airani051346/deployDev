#!/bin/bash

set -e

echo "🔧 udpade available apt package..."
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt upgrade -yq

echo "🔧 Installing dependencies..."
sudo DEBIAN_FRONTEND=noninteractive apt install -yq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
    python3-pip sqlite3 nginx apache2-utils python3-venv expect sshpass openssl git

export APP_DIR="/opt/network_manager"
export REPO_URL="https://github.com/airani051346/deployDev.git"  # Replace with your actual repo
export APP_USER="www-data"

echo "📁 Creating application directory..."
sudo mkdir -p "$APP_DIR"
sudo chown "$APP_USER:$APP_USER" "$APP_DIR"

echo "📥 Cloning GitHub repository..."
sudo git clone "$REPO_URL" "$APP_DIR/app"

echo "🐍 Setting up virtual environment..."
cd "$APP_DIR/app"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt || pip install gunicorn flask paramiko requests

echo "📦 Initializing SQLite database..."
cat > init_db.sql <<EOF
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

CREATE TABLE networks (
  id INTEGER PRIMARY KEY,
  cidr TEXT,
  interval INTEGER,
  scan_status TEXT DEFAULT 'idle'
);
INSERT INTO networks VALUES (3,'192.168.178.0/24',2,'idle');
INSERT INTO networks VALUES (4,'192.168.178.172-192.168.178.173',20,'idle');

CREATE TABLE templates (
  id INTEGER PRIMARY KEY,
  name TEXT,
  content TEXT
);
INSERT INTO templates VALUES(1,'none','{{ empty | default(''empty'') }}');

INSERT INTO templates VALUES(
  2,'Spark-PTK',
  replace('set hostname {{hostname}}\nset expert password-hash \$5\$PH/SXNJh2.KjxrQO\$7mnNzCjfcPxEvySF7UW86aa/1DNhgwJwe1AbgbLo4gC\n\nexpert_commands:\n\nls -al /storage\n\nend_expert_commnds:\n\nshow diag','\n',char(10))
);

INSERT INTO templates VALUES(
  3,'Spark-SD-WAN',
  replace('set workstname {{hostname}}\nset interface name WANox {{Router_ip | default(''10.1.1.1'')}}\nset interface name LAN1 {{LAN1_ip | default(''172.168.99.1'')}} subnetmask  {{LAN1_subnetmask | default(''255.255.255.0'')}} \nset interface name LAN2 {{Megamon_ip | default(''10.0.0.1'')}}  subnetmask  {{LAN2_subnetmask | default(''255.255.255.128'')}} ','\n',char(10))
);

INSERT INTO templates VALUES(4,'Spark-Demo','xfxdb {{win | default(''xxx'')}}');

CREATE TABLE discovered (
  id INTEGER PRIMARY KEY,
  ip TEXT,
  name TEXT,
  template_id INTEGER,
  variables TEXT,
  status TEXT,
  hw_type TEXT,
  expert_cred_id INTEGER,
  setting_id INTEGER
);

CREATE TABLE scans (
  network_id INTEGER PRIMARY KEY,
  is_alive BOOLEAN NOT NULL
);

CREATE TABLE settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  is_default INTEGER DEFAULT 0,
  is_expert BOOLEAN DEFAULT 0
);
INSERT INTO settings VALUES(2,'admin','zubur1',1,0);
INSERT INTO settings VALUES(3,'rouser','zubur1',0,0);
INSERT INTO settings VALUES(6,'expert1','zubur1',0,1);

CREATE TABLE HWType (
  id INTEGER PRIMARY KEY,
  Type TEXT
);
INSERT INTO HWType VALUES(1,'embedded');
INSERT INTO HWType VALUES(2,'full');

CREATE TABLE workers (
  id INTEGER PRIMARY KEY,
  discovered_id INTEGER,
  log TEXT,
  storedconfig TEXT,
  last_line INTEGER DEFAULT 0,
  pid INTEGER
);

DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('settings',8);

CREATE UNIQUE INDEX idx_discovered_ip ON discovered(ip);
CREATE UNIQUE INDEX idx_unique_default_setting ON settings(is_default) WHERE is_default = 1;

COMMIT;
EOF

sqlite3 zero_touch.db < init_db.sql
rm init_db.sql

echo "🔐 Setting file permissions..."
sudo chown www-data:www-data "$APP_DIR/app/zero_touch.db"
sudo chmod 660 "$APP_DIR/app/zero_touch.db"
sudo chown -R www-data:www-data "$APP_DIR/app"
sudo chmod -R 770 "$APP_DIR/app"

echo "🛠️ Creating systemd service file..."
sudo tee /etc/systemd/system/zero_touch-api.service > /dev/null <<EOF
[Unit]
Description=Zero Touch Flask API
After=network.target

[Service]
User=www-data
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

echo "🌐 Configuring Nginx..."
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

echo "✅ Zero Touch App successfully installed at $APP_DIR"
echo "🔍 To view logs: sudo journalctl -u zero_touch-api -f"
