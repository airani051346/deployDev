from flask import Flask, request, jsonify, render_template, Response, url_for, stream_with_context
from jinja2 import Environment, BaseLoader, meta, exceptions as jinja2_exceptions
import os, sqlite3, json, threading, logging, nmap, requests, traceback, subprocess, time, signal, tempfile, ipaddress, paramiko, re, socket

# Constants
DEFAULT_TEMPLATE_ID = 1
PROMPT_PATTERN = re.compile(r'[\r\n][^\r\n]*[#>$%:] ?$')

# Initialize Flask app and define template/static folders
app = Flask(__name__, template_folder='../templates', static_folder='../templates')

# Define paths and global structures
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, '..', 'zero_touch.db')
TMP_DIR = os.path.join(BASE_DIR, 'tmp') 
os.makedirs(TMP_DIR, exist_ok=True)

# Initialize Jinja2 environment for template rendering
jinja_env = Environment(loader=BaseLoader())

# In-memory trackers
active_scans = {}
worker_processes = {}
process_registry = {}  # network_id -> thread
log_buffers = {}  # worker_id -> log buffer
active_sse_connections = {}
cancel_flags = {}
worker_processes = {}
worker_lock = threading.Lock()

def db():
    """
    Return a new SQLite database connection with dictionary-style row access.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def simplify_regex(pattern):
    # Replace regex spacing and unescape simple regex characters
    pattern = re.sub(r'\\s\*', ' ', pattern)
    pattern = re.sub(r'\\', '', pattern)  # remove remaining backslashes
    pattern = re.sub(r'\s+', ' ', pattern)  # collapse multiple spaces
    return pattern.strip()

def render_template_for_discovered(d_id, conn=None):
    local_conn = conn or db()
    c = local_conn.cursor()
    d = c.execute("SELECT * FROM discovered WHERE id=?", (d_id,)).fetchone()
    if not d:
        return None, "Discovered device not found"

    tpl_row = c.execute("SELECT content FROM templates WHERE id=?", (d['template_id'],)).fetchone()
    if not tpl_row:
        return None, "Template not found"

    tpl_content = tpl_row['content']
    variables = json.loads(d['variables'] or '{}')
    required_vars = meta.find_undeclared_variables(jinja_env.parse(tpl_content))
    missing = required_vars - set(variables)
    if missing:
        return None, f"Missing variables: {', '.join(missing)}"

    try:
        rendered = jinja_env.from_string(tpl_content).render(**variables)
    except Exception as e:
        return None, f"Template rendering error: {str(e)}"

    filtered = [line for line in rendered.splitlines() if '{{' not in line and '}}' not in line]
    return '\n'.join(filtered), None

def do_scan_process(network_id, cidr, interval):
    conn = db()
    c = conn.cursor()
    app.logger.info(f"🔍 Starting scan for Network ID {network_id}, CIDR: {cidr}")

    try:
        # Mark network as running
        conn.execute("UPDATE networks SET scan_status='running' WHERE id=?", (network_id,))
        conn.commit()

        # Determine scan targets
        targets = []
        if '/' in cidr:
            try:
                ip_net = ipaddress.ip_network(cidr, strict=False)
                targets = list(ip_net.hosts())
                app.logger.info(f"🔎 Parsed {len(targets)} hosts from CIDR {cidr}")
            except ValueError as e:
                app.logger.error(f"❌ Invalid CIDR: {cidr} — {e}")
                return
        elif '-' in cidr:
            try:
                start_str, end_str = cidr.split('-')
                start_ip = ipaddress.ip_address(start_str.strip())
                end_ip = ipaddress.ip_address(end_str.strip())
                if type(start_ip) != type(end_ip):
                    raise ValueError("Start and end IPs must be of the same type (IPv4/IPv6)")
                if start_ip > end_ip:
                    raise ValueError("Start IP must be ≤ End IP")
                nets = ipaddress.summarize_address_range(start_ip, end_ip)
                targets = [host for net in nets for host in net.hosts()]
                app.logger.info(f"🔎 Parsed {len(targets)} hosts from IP range {cidr}")
            except ValueError as e:
                app.logger.error(f"❌ Invalid range: {cidr} — {e}")
                return
        else:
            app.logger.error(f"❌ Unrecognized CIDR or range format: {cidr}")
            return

        # Initialize nmap scanner
        nm = nmap.PortScanner()

        for ip in targets:
            try:
                app.logger.debug(f"📡 Scanning {ip}...")
                nm.scan(hosts=str(ip), arguments='-sn')
                # nm.scan(hosts=str(ip), arguments='-sS -Pn -T4 --host-timeout 5s -p 22,80,443,4433')
                for host in nm.all_hosts():
                    if nm[host].state() == 'up':
                        app.logger.info(f"✅ Host is up: {host}")

                        try:
                            res = requests.post(
                                'http://127.0.0.1:5000/app/discovered',
                                json={
                                    'ip': host,
                                    'name': '',
                                    'template_id': 1,
                                    'variables': {}
                                },
                                headers={'Content-Type': 'application/json'},
                                timeout=3
                            )
                            if res.ok:
                                app.logger.info(f"📝 Inserted discovered host: {host}")
                            else:
                                app.logger.warning(f"⚠️ Failed to insert {host}: {res.status_code} — {res.text}")
                        except requests.exceptions.RequestException as e:
                            app.logger.warning(f"🚫 HTTP request failed for host {host}: {e}")
            except Exception as e:
                app.logger.warning(f"⚠️ nmap scan error for {ip}: {e}")

            # Sleep between scans if interval is set (optional)
            if interval > 0:
                time.sleep(interval)

    except Exception as e:
        app.logger.error(f"🔥 Unhandled error during scan of {cidr}: {e}")
    finally:
        # Cleanup
        conn.execute("UPDATE networks SET scan_status='idle' WHERE id=?", (network_id,))
        conn.commit()
        process_registry.pop(network_id, None)
        app.logger.info(f"🛑 Finished scan for Network ID {network_id}")
        
#def stream_output(pipe, buffer, label=''):
#    for line in iter(pipe.readline, ''):
#        buffer.append(f"{label}{line}")
#    pipe.close()

#def wait_and_stream_prompt(shell):
#    buffer = ''
#    start_time = time.time()
#    prompt_detected_time = None
#
#    while True:
#        if shell.recv_ready():
#            part = shell.recv(4096).decode(errors='ignore')
#            buffer += part
#
#            for line in part.splitlines():
#                yield f"data: {line}\n\n"
#
#            if PROMPT_PATTERN.search(buffer):
#                if not prompt_detected_time:
#                    prompt_detected_time = time.time()
#                elif time.time() - prompt_detected_time >= 1:
#                    break
#
#        elif prompt_detected_time:
#            break
#
#        elif time.time() - start_time > 10:
#            yield f"data: ⏱️ Timeout waiting for prompt\n\n"
#            break
#
#        time.sleep(0.2)
#
#    return buffer

# ###########################
# Route definition begin here
# ###########################
@app.route('/')
def index():
    try:
        return render_template('base.html')
    except Exception as e:
        app.logger.error(f"Error rendering / loading base.html: {e}")
        return str(e), 500

# ###########################
# templates Page
# ###########################
@app.route('/templates')
def templates_page():
    return render_template('templates.html')

@app.route('/app/templates', methods=['GET','POST'])
def templates():
    try:
        conn = db(); c = conn.cursor()
        if request.method == 'POST':
            name = request.json['name']
            content = request.json['content']
            try:
                jinja_env.parse(content)
            except jinja2_exceptions.TemplateSyntaxError as e:
                return jsonify(error=f"Template syntax error: {e.message} (line {e.lineno})"), 400
            c.execute("INSERT INTO templates(name, content) VALUES(?,?)", (name, content))
            conn.commit()
            return jsonify(status='ok')
        rows = c.execute("SELECT * FROM templates where id > 1 ").fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        app.logger.error("Error in /app/templates: %s\n%s", e, traceback.format_exc())
        return jsonify(error=str(e)), 500

@app.route('/app/templates/<int:id>', methods=['PUT'])
def update_template(id):
    conn = db(); c = conn.cursor()
    data = request.json
    c.execute("UPDATE templates SET name=?, content=? WHERE id=?", (data['name'], data['content'], id))
    conn.commit()
    return jsonify(status='ok')

@app.route('/app/templates/<int:id>', methods=['DELETE'])
def delete_template(id):
    conn = db(); c = conn.cursor()
    c.execute("DELETE FROM templates WHERE id=?", (id,))
    conn.commit()
    return jsonify(status='deleted', id=id)

# ###########################
# networks Page
# ###########################
@app.route('/networks')
def networks_page():
    return render_template('networks.html')

@app.route('/app/networks/<int:id>', methods=['DELETE'])
def delete_network(id):
    conn = db(); c = conn.cursor()
    c.execute("DELETE FROM networks WHERE id=?", (id,))
    conn.commit()
    return jsonify(status='deleted', id=id)

@app.route('/app/networks', methods=['GET','POST'])
def networks():
    conn = db(); c = conn.cursor()
    if request.method == 'POST':
        cidr = request.json['cidr']
        interval = int(request.json['interval'])
        c.execute("INSERT INTO networks(cidr, interval, scan_status) VALUES(?,?,?)", (cidr, interval, 'idle'))
        conn.commit()
        return jsonify(status='ok')
    rows = c.execute("SELECT * FROM networks").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/app/scan/<int:network_id>/start', methods=['POST'])
def scan_start(network_id):
    if network_id in process_registry:
        return jsonify(error='already running'), 400
    conn = db(); c = conn.cursor()
    r = c.execute("SELECT cidr, interval FROM networks WHERE id=?", (network_id,)).fetchone()
    if not r:
        return jsonify(error='Network not found'), 404
    t = threading.Thread(target=do_scan_process, args=(network_id, r['cidr'], r['interval']), daemon=True)
    t.start()
    process_registry[network_id] = t
    return jsonify(status='started')

@app.route('/app/scan/<int:network_id>/stop', methods=['POST'])
def scan_stop(network_id):
    if network_id not in process_registry:
        return jsonify(error='not running'), 400
    process_registry.pop(network_id, None)
    conn = db()
    conn.execute("UPDATE networks SET scan_status='idle' WHERE id=?", (network_id,))
    conn.commit()
    return jsonify(status='marked as stopped')

@app.route('/app/scan/status', methods=['GET'])
def scan_status():
    conn = db(); c = conn.cursor()
    rows = c.execute("SELECT id, scan_status FROM networks").fetchall()
    return jsonify({r['id']: {'running': r['scan_status'] == 'running'} for r in rows})

# ###########################
# discovered Page
# ###########################
@app.route('/discovered')
def discovered_page():
    return render_template('discovered.html')

@app.route('/app/discovered', methods=['GET', 'POST'])
def discovered():
    conn = db()
    c = conn.cursor()

    if request.method == 'POST':
        data = request.json
        d_id = data.get('id')

        if not d_id:
            # Insert new discovered
            ip = data.get('ip')
            name = data.get('name', '')
            template_id = data.get('template_id') or 1
            hw_type = data.get('hw_type') or None
            variables = json.dumps(data.get('variables') or {})
            status = data.get('status', 'discovered')
            if not ip:
                return jsonify(error="Missing 'ip'"), 400
            
            existing = c.execute("SELECT id FROM discovered WHERE ip=?", (ip,)).fetchone()
            if existing:
                return jsonify(status="skipped", id=existing['id'])
            
            try:
                c.execute("""
                    INSERT INTO discovered (ip, name, template_id, variables, status, hw_type)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (ip, name, template_id, variables, status, hw_type))
                conn.commit()
                return jsonify(status="inserted", id=c.lastrowid)
            except Exception as e:
                conn.rollback()
                app.logger.error(f"❌ Insert failed: {e}")
                return jsonify(error=f"Insert failed: {str(e)}"), 500

        # Update case
        row = c.execute("SELECT * FROM discovered WHERE id=?", (d_id,)).fetchone()
        if not row:
            return jsonify(error="Not found"), 404

        # Use old values if not explicitly set
        name = data.get('name', row['name'])
        template_id = data.get('template_id', row['template_id'])
        expert_cred_id = data.get('expert_cred_id') if 'expert_cred_id' in data else row['expert_cred_id']
        setting_id = data.get('setting_id') if 'setting_id' in data else row['setting_id']
        hw_type = data.get('hw_type') if 'hw_type' in data else row['hw_type']
        status = data.get('status', row['status'])

        try:
            current_vars = json.loads(row['variables'] or '{}')
        except Exception:
            current_vars = {}

        if 'variables' in data:
            current_vars.update(data['variables'] or {})

        try:
            c.execute("""
                UPDATE discovered SET  name=?, template_id=?, variables=?, status=?, hw_type=?,  expert_cred_id=?, setting_id=?  WHERE id=?
            """, (
                name, template_id, json.dumps(current_vars), status, hw_type, expert_cred_id, setting_id, d_id ))
            conn.commit()
            return jsonify(status="updated", id=d_id)
        except Exception as e:
            conn.rollback()
            return jsonify(error=f"Database update failed: {str(e)}"), 500

    # GET
    rows = c.execute("""
        SELECT d.*,
               CASE WHEN w.id IS NOT NULL THEN 1 ELSE 0 END AS has_worker  FROM discovered d LEFT JOIN workers w ON w.discovered_id = d.id
    """).fetchall()

    return jsonify([dict(r) for r in rows])

@app.route('/app/discovered/<int:id>', methods=['DELETE'])
def delete_discovered(id):
    conn = db(); c = conn.cursor()
    c.execute("DELETE FROM discovered WHERE id=?", (id,))
    conn.commit()
    return jsonify(status='deleted', id=id)

@app.route('/app/render/<int:discovered_id>', methods=['GET'])
def test_render(discovered_id):
    rendered, error = render_template_for_discovered(discovered_id)
    if error:
        return jsonify(error=error), 400
    return jsonify(rendered=rendered)

# ###########################
# workers Page
# ###########################
@app.route('/workers')
def workers_page():
    return render_template('workers.html')

@app.route('/app/workers', methods=['GET'])
def workers():
    conn = db(); c = conn.cursor()
    rows = c.execute("""
        SELECT w.*, d.ip AS discovered_ip, d.id AS discovered_id, d.status AS discovered_status
        FROM workers w
        JOIN discovered d ON w.discovered_id = d.id
    """).fetchall()
    creds = c.execute("SELECT id, username FROM settings").fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item['log'] = item.get('log') or ''
        with worker_lock:
            proc = worker_processes.get(row['id'])
            #item['pid'] = proc.pid if proc and proc.poll() is None else None
            item['pid'] = row['pid'] if row['pid'] else None

        result.append(item)
    return jsonify({"workers": result, "credentials": [dict(r) for r in creds]})

@app.route('/app/deploy/<int:d_id>', methods=['POST'])
def deploy(d_id):
    conn = db()
    expanded, error = render_template_for_discovered(d_id, conn)
    if error:
        return jsonify(error=error), 400

    data = request.get_json(silent=True) or {}
    setting_id = data.get("setting_id")

    c = conn.cursor()
    c.execute(
        "INSERT INTO workers(discovered_id, log, storedconfig) VALUES (?, ?, ?)",
        (d_id, '', expanded)
    )
    c.execute("UPDATE discovered SET status='claimed' WHERE id=?", (d_id,))
    conn.commit()
    return jsonify(status='queued', expanded=expanded)

@app.route('/app/worker/<int:worker_id>/sse')
def worker_sse(worker_id):
    def stream():
        last_len = 0
        conn = db()
        c = conn.cursor()

        while True:
            row = c.execute("SELECT log FROM workers WHERE id=?", (worker_id,)).fetchone()
            if not row:
                yield 'data: [SSE_END]\n\n'
                break

            log = row['log'] or ''
            if len(log) > last_len:
                new_part = log[last_len:]
                for line in new_part.splitlines():
                    yield f'data: {line}\n\n'
                last_len = len(log)

            # If the worker process has exited, stop streaming
            with worker_lock:
                proc = worker_processes.get(worker_id)
                if not proc or proc.poll() is not None:
                    yield 'data: [SSE_END]\n\n'
                    break

            time.sleep(1)

    return Response(stream_with_context(stream()), mimetype='text/event-stream')

@app.route('/app/workers/<int:id>/credential', methods=['POST'])
def update_worker_credential(id):
    setting_id = request.json.get('setting_id')
    conn = db(); c = conn.cursor()

    if setting_id == '':
        c.execute("UPDATE workers SET setting_id=NULL WHERE id=?", (id,))
    else:
        c.execute("UPDATE workers SET setting_id=? WHERE id=?", (setting_id, id))
    
    conn.commit(); conn.close()
    return jsonify(status='ok')

@app.route('/app/workers/<int:id>', methods=['DELETE'])
def delete_worker(id):
    conn = db(); c = conn.cursor()
    row = c.execute("SELECT discovered_id FROM workers WHERE id=?", (id,)).fetchone()
    if row:
        discovered_id = row['discovered_id']
        c.execute("UPDATE discovered SET status='discovered' WHERE id=?", (discovered_id,))

    # Now delete the worker
    c.execute("DELETE FROM workers WHERE id=?", (id,))
    conn.commit()
    return jsonify(status='deleted', id=id)

@app.route('/app/workers/<int:id>/log', methods=['GET'])
def worker_log(id):
    conn = db(); c = conn.cursor()
    row = c.execute("SELECT log FROM workers WHERE id=?", (id,)).fetchone()
    if not row:
        return jsonify(error='Worker not found'), 404
    return jsonify(log=row['log'])

@app.route('/app/workers/<int:id>/stop', methods=['POST'])
def stop_worker(id):
    conn = db()
    c = conn.cursor()
    row = c.execute("SELECT pid FROM workers WHERE id=?", (id,)).fetchone()
    if not row or not row['pid']:
        return jsonify(success=False, error="No PID")

    pid = row['pid']
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except ProcessLookupError:
        pass  # already dead

    c.execute("UPDATE workers SET pid=NULL WHERE id=?", (id,))
    conn.commit()
    conn.close()

    return jsonify(success=True)

@app.route('/app/workers/<int:id>/status', methods=['GET'])
def get_worker_status(id):
    conn = db(); c = conn.cursor()
    row = c.execute("""
        SELECT w.id, w.last_line, w.pid, d.status AS discovered_status
        FROM workers w
        JOIN discovered d ON w.discovered_id = d.id
        WHERE w.id = ?
    """, (id,)).fetchone()

    if not row:
        return jsonify(error="Worker not found"), 404

    # Check if process is still running
    with worker_lock:
        proc = worker_processes.get(id)
        alive = proc and proc.poll() is None

    return jsonify({
        "id": row["id"],
        "status": row["discovered_status"],
        "last_line": row["last_line"],
        "pid": row["pid"],
        "running": bool(alive)
    })

@app.route('/app/worker/<int:id>/log')
def get_worker_log(id):
    conn = db(); c = conn.cursor()
    row = c.execute("SELECT log FROM workers WHERE id = ?", (id,)).fetchone()
    return jsonify({"log": row['log'] if row else ''})

@app.route('/app/workers/<int:id>/start', methods=['POST'])
def start_worker(id):
    conn = db()
    c = conn.cursor()

    row = c.execute("SELECT * FROM workers WHERE id=?", (id,)).fetchone()
    if not row:
        return jsonify(error="Worker not found"), 404

    with worker_lock:
        # Already running?
        proc = worker_processes.get(id)
        if proc and proc.poll() is None:
            return jsonify(error="Already running"), 409

        # Clear old PID
        c.execute("UPDATE workers SET pid=NULL WHERE id=?", (id,))
        conn.commit()

        # Clear old log
        c.execute("UPDATE workers SET log='🔄 Starting configuration...\n' WHERE id=?", (id,))
        conn.commit()


        # Launch
        cmd = ["python3", os.path.join(BASE_DIR, "worker_subprocess.py"), str(id)]
        app.logger.info(f"🔨 Launch: {' '.join(cmd)}")

        proc = subprocess.Popen(cmd, preexec_fn=os.setsid)
        worker_processes[id] = proc

        # ✅ Save live PID
        c.execute("UPDATE workers SET pid=? WHERE id=?", (proc.pid, id))
        conn.commit()

    return jsonify(success=True, pid=proc.pid)

# ###########################
# hw-types Page
# ###########################
@app.route('/hwtypes')
def hwtypes_page():
    return render_template('hwtypes.html')

@app.route('/app/hwtypes', methods=['GET', 'POST'])
def hwtypes():
    conn = db(); c = conn.cursor()
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        err_keywords = data.get('err_keywords', '')
        if not name:
            return jsonify(error='Name required'), 400
        c.execute("INSERT INTO HWType(Type, err_keywords) VALUES (?, ?)", (name, err_keywords))
        conn.commit()
        return jsonify(status='ok')

    rows = c.execute("SELECT id, Type, err_keywords FROM HWType").fetchall()
    print([{"id": r["id"], "name": r["Type"], "err_keywords": r["err_keywords"]} for r in rows])
    return jsonify([{"id": r["id"], "name": r["Type"], "err_keywords": r["err_keywords"]} for r in rows])


@app.route('/app/hwtypes/<int:id>', methods=['PUT'])
def update_hwtype(id):
    data = request.get_json()
    name = data.get('name')
    err_keywords = data.get('err_keywords')
    if not name:
        return jsonify(error='Name required'), 400
    conn = db(); c = conn.cursor()
    c.execute("UPDATE HWType SET Type=?, err_keywords=? WHERE id=?", (name, err_keywords, id))
    conn.commit()
    return jsonify(status='updated')

@app.route('/app/hwtypes/<int:id>', methods=['DELETE'])
def delete_hwtype(id):
    conn = db(); c = conn.cursor()
    c.execute("DELETE FROM HWType WHERE id=?", (id,))
    conn.commit()
    return jsonify(status='deleted')

# ###########################
# settings Page
# ###########################
@app.route('/settings')
def settings_page():
    conn = db()
    users = conn.execute("SELECT * FROM settings").fetchall()
    conn.close()
    return render_template('settings.html', users=users)

@app.route('/app/settings/<int:id>/default', methods=['POST'])
def set_default_credential(id):
    conn = db()
    c = conn.cursor()
    # Reset all to 0, then set selected one to 1
    c.execute("UPDATE settings SET is_default=0")
    c.execute("UPDATE settings SET is_default=1 WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return jsonify(status="default set")

@app.route('/app/settings', methods=['GET'])
def get_settings():
    conn = db()
    settings = conn.execute('SELECT id, username, is_default, is_expert FROM settings').fetchall()
    conn.close()
    return jsonify([dict(row) for row in settings])

@app.route('/app/settings', methods=['POST'])
def add_setting():
    data = request.get_json()
    username = data.get("user")
    password = data.get("password")
    app.logger.info(f"Adding setting for user: {username} and password: {password}")
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    conn = db()
    c = conn.cursor()
    
    c.execute("INSERT INTO settings (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/app/settings/<int:id>', methods=['DELETE'])
def delete_setting(id):
    conn = db()
    conn.execute("DELETE FROM settings WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})

@app.route('/app/settings/<int:id>', methods=['PUT'])
def update_setting(id):
    data = request.get_json()
    password = data.get("password")
    is_expert = data.get("is_expert")

    if password is None and is_expert is None:
        return jsonify(error="Nothing to update"), 400

    conn = db()
    c = conn.cursor()

    if password is not None:
        c.execute("UPDATE settings SET password=? WHERE id=?", (password, id))
    if is_expert is not None:
        c.execute("UPDATE settings SET is_expert=? WHERE id=?", (int(is_expert), id))

    conn.commit()
    conn.close()
    return jsonify(status="updated")


if __name__ == '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
    app.run(host='127.0.0.1', port=5000)
