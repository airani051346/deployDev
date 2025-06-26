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
