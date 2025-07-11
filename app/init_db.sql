PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE networks (id INTEGER PRIMARY KEY, cidr TEXT, interval INTEGER, scan_status TEXT DEFAULT 'idle');
INSERT INTO networks VALUES(3,'192.168.178.0/24',2,'idle');
INSERT INTO networks VALUES(4,'192.168.178.172-192.168.178.173',20,'idle');
CREATE TABLE templates (id INTEGER PRIMARY KEY, name TEXT, content TEXT);
INSERT INTO templates VALUES(1,'none','{{ empty | default(''empty'') }}');
INSERT INTO templates VALUES(3,'Spark-SD-WAN',replace('set hostname {{hostname}}\nshow interfaces table\n\nset interface {{lan1_name | default(''eth1-01'')}} ipv4-adddress {{lan1_ipv4 | default (''10.1.1.9'')}} mask-length {{lan1_masklen | default (''24'')}}\nset interface {{lan2_name | default(''eth1'')}} ipv4-adddress {{lan2_ipv4 | default (''10.1.1.9'')}} mask-length {{lan2_masklen | default (''24'')}}\nset interface {{lan3_name | default(''vti'')}} ipv4-adddress {{lan3_ipv4 | default (''10.1.1.9'')}} mask-length {{lan3_masklen | default (''24'')}}\n\n!CONTROL: enter_expert_mode {"cmd": "expert", "expect": "Password:", "send_username": false, "prompt_success": "#"}\n\n!PROMPT: \[Expert@.*\]#\nls -al /storage\n\n!CONTROL: end_expert_commands {"cmd": "exit", "prompt_success": ">"}\n\nshow diag\n\n','\n',char(10)));
INSERT INTO templates VALUES(4,'Spark-Demo',replace('set Hostname {{hostname}}\n!CONTROL: enter_expert_mode {"cmd": "expert", "expect": "login:", "send_username": false, "expect2": "Password:", "prompt_success": "#"}\n','\n',char(10)));
CREATE TABLE discovered (id INTEGER PRIMARY KEY, ip TEXT, name TEXT, template_id INTEGER, variables TEXT, status TEXT, hw_type TEXT, expert_cred_id INTEGER, setting_id INTEGER);
INSERT INTO discovered VALUES(1,'192.168.178.172','',3,'{"hostname": "gw-2570-02", "Megamon_ip": "10.0.0.1", "LAN2_subnetmask": "255.255.255.128"}','discovered','cp-spark',6,2);
INSERT INTO discovered VALUES(2,'192.168.178.173','',4,'{"hostname": ""}','discovered','cp-spark',6,2);
CREATE TABLE scans (
  network_id INTEGER PRIMARY KEY,
  is_alive BOOLEAN NOT NULL
);
CREATE TABLE settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL, is_default INTEGER DEFAULT 0, is_expert BOOLEAN DEFAULT 0);
INSERT INTO settings VALUES(2,'admin','zubur1',1,0);
INSERT INTO settings VALUES(3,'rouser','zubur1',0,0);
INSERT INTO settings VALUES(6,'expert1','zubur1',0,1);
CREATE TABLE HWType (id INTEGER PRIMARY KEY, Type TEXT, err_keywords TEXT DEFAULT '');
INSERT INTO HWType VALUES(1,'cp-spark','"invalid","error","failed","permission\s*denied","command\s*not\s*found","not\s*recognized","cannot","denied","unexpected","syntax\s*error","Bad\s*parameter"');
INSERT INTO HWType VALUES(2,'cp-quantum','"invalid", "error", "failed", "permission\s*denied", "command\s*not\s*found", "not\s*recognized", "cannot", "denied", "unexpected", "syntax\s*error", "Bad\s*parameter"');
INSERT INTO HWType VALUES(3,'fortinet','"#",">"');
CREATE TABLE workers (
  id INTEGER PRIMARY KEY,
  discovered_id INTEGER,
  log TEXT,
  storedconfig TEXT,
  last_line INTEGER DEFAULT 0, pid INTEGER, stop INTEGER DEFAULT 0);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('settings',8);
CREATE UNIQUE INDEX idx_discovered_ip ON discovered(ip);
CREATE UNIQUE INDEX idx_unique_default_setting ON settings(is_default) WHERE is_default = 1;
COMMIT;