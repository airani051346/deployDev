import sys, time, os, re, json, sqlite3, paramiko

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, '..', 'zero_touch.db')

PROMPT_PATTERN = re.compile(r'[\r\n][^\r\n]*[#>$%:] ?$')
STOP_KEYWORDS_DEFAULT = ["error", "fail", "denied"]

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def wait_for_prompt(shell, pattern=None, timeout=10, grace_period=1, skip_grace=False):
    """
    Wait for shell prompt.
    - If pattern is given, use it.
    - Otherwise use PROMPT_PATTERN.
    """
    buffer = ''
    start_time = time.time()
    prompt_detected_time = None

    while True:
        if shell.recv_ready():
            part = shell.recv(4096).decode(errors='ignore')
            buffer += part
            print(part, end='', flush=True)

            if pattern:
                if pattern.search(buffer):
                    break
            else:
                if PROMPT_PATTERN.search(buffer):
                    if not prompt_detected_time:
                        prompt_detected_time = time.time()
                    elif skip_grace or time.time() - prompt_detected_time >= grace_period:
                        break

        elif prompt_detected_time:
            break

        elif time.time() - start_time > timeout:
            break

        time.sleep(0.2)

    return buffer.strip()

def process_lines(shell, lines, stop_keywords, expert_user, expert_pass, worker_id, start_line=0, current_log=''):
    stop_keywords = [kw.strip().strip('"').lower() for kw in (stop_keywords or [])]
    conn = db()
    c = conn.cursor()
    success = True

    def append(msg, commit=True):
        nonlocal current_log
        current_log += f"\n{msg}"
        print(msg, flush=True)
        if commit:
            c.execute("UPDATE workers SET log=? WHERE id=?", (current_log, worker_id))
            conn.commit()

    last_line_number = start_line
    current_prompt_pattern = None  # If set by !PROMPT:

    for line_num, line in enumerate(lines, start=start_line + 1):
        last_line_number = line_num
        stripped = line.strip()

        stop_row = c.execute("SELECT stop FROM workers WHERE id=?", (worker_id,)).fetchone()
        if stop_row and stop_row["stop"]:
            append("🛑 Stopped by user.")
            success = False
            break

        # Handle !PROMPT:
        if stripped.lower().startswith("!prompt:"):
            prompt_str = stripped.split(":", 1)[1].strip()
            current_prompt_pattern = re.compile(prompt_str)
            append(f"🔖 Custom prompt set for next line: `{prompt_str}`")
            continue

        # Handle !CONTROL:
        if stripped.lower().startswith("!control:"):
            parts = stripped.split(":", 1)
            ctrl_and_json = parts[1].strip()
            if " " in ctrl_and_json:
                ctrl, json_part = ctrl_and_json.split(" ", 1)
                ctrl = ctrl.strip().lower()
                ctrl_data = json.loads(json_part.strip())
            else:
                ctrl = ctrl_and_json.strip().lower()
                ctrl_data = {}

            if ctrl == "enter_expert_mode":
                # Required parts
                cmd = ctrl_data.get("cmd", "expert")
                expect = ctrl_data.get("expect")
                send_username = ctrl_data.get("send_username", False)
                expect2 = ctrl_data.get("expect2")
                prompt_success = ctrl_data.get("prompt_success", "#")

                append(f"🔖 Enter expert mode: sending `{cmd}`")
                shell.send(cmd + "\n")

                if expect:
                    output = wait_for_prompt(shell, pattern=re.compile(expect))
                    append(f"[expect: {expect}]\n{output}")
                else:
                    output = wait_for_prompt(shell)
                    append(output)

                if send_username:
                    shell.send(expert_user + "\n")
                    append(f"[SENT] {expert_user}")

                if expect2:
                    output = wait_for_prompt(shell, pattern=re.compile(expect2))
                    append(f"[expect2: {expect2}]\n{output}")

                # Always send expert password
                shell.send(expert_pass + "\n")
                output = wait_for_prompt(shell)
                append("[SENT] (expert password)\n" + output)

                if prompt_success and re.search(prompt_success, output):
                    append(f"✅ Expert mode entered — saw `{prompt_success}`.")
                else:
                    append(f"🛑 Failed to enter expert mode — `{prompt_success}` not found.")
                    success = False
                continue

            elif ctrl == "end_expert_commands":
                # same flexible JSON structure
                end_cmd = ctrl_data.get("cmd", "exit")
                prompt_success = ctrl_data.get("prompt_success", ">")

                shell.send(end_cmd + "\n")
                output = wait_for_prompt(shell)
                append(f"[SENT] {end_cmd}\n{output}")

                if prompt_success and re.search(prompt_success, output):
                    append(f"✅ Exited expert mode — saw `{prompt_success}`.")
                else:
                    append(f"⚠️ Could not confirm expert exit with `{prompt_success}`.")
                continue
            else:
                append(f"❌ Unknown CONTROL: {ctrl}")
                continue    
                
        # Normal command
        shell.send(stripped + "\n")
        output = wait_for_prompt(shell, pattern=current_prompt_pattern)
        append(f"[SENT] {stripped}\n{output}")

        # Reset custom pattern after use
        current_prompt_pattern = None

        # Check for stop keywords
        if any(re.search(kw, output, re.IGNORECASE) for kw in stop_keywords):
            append(f"🛑 Error keyword detected — stopping.")
            last_line_number = line_num - 1 if line_num > 0 else 0
            success = False
            break

        c.execute("UPDATE workers SET last_line=? WHERE id=?", (line_num, worker_id))
        conn.commit()

    if success:
        append("✅ Finished successfully!")

    conn.close()
    return success, last_line_number

def run_worker_lines(worker_id):
    conn = db()
    c = conn.cursor()
    my_pid = os.getpid()
    c.execute("UPDATE workers SET pid=? WHERE id=?", (my_pid, worker_id))
    conn.commit()

    try:
        row = c.execute("""
            SELECT COALESCE(s.username, def.username) AS user,
                   COALESCE(s.password, def.password) AS password,
                   d.ip, d.hw_type, d.expert_cred_id,
                   d.setting_id,
                   w.storedconfig, w.last_line
            FROM workers w
            JOIN discovered d ON w.discovered_id = d.id
            LEFT JOIN settings s ON d.setting_id = s.id
            LEFT JOIN settings def ON def.is_default = 1
            WHERE w.id = ?
        """, (worker_id,)).fetchone()

        if not row:
            print(f"❌ Worker ID {worker_id} not found.")
            return

        ip = row['ip']
        user = row['user']
        password = row['password']
        hw_type = row['hw_type'] or ''
        expert_cred_id = row['expert_cred_id']
        setting_id = row['setting_id']
        storedconfig = row['storedconfig'] or ''
        last_line = row['last_line'] or 0

        expert_user, expert_pass = user, password
        if expert_cred_id:
            expert_row = c.execute("SELECT username, password FROM settings WHERE id=?", (expert_cred_id,)).fetchone()
            if expert_row:
                expert_user = expert_row['username'] or user
                expert_pass = expert_row['password'] or password

        stop_keywords = load_stop_keywords(hw_type)

        info_header = "\n".join([
            f"ℹ️ HW-Type: {hw_type}",
            f"ℹ️ Using credentials from settings ID: {setting_id or 'default'}",
            f"ℹ️ Username: {user} | Expert Username: {expert_user}",
            f"ℹ️ keywords: {stop_keywords}",
            f"ℹ️ Resuming from line {last_line + 1}."
        ])
        current_log = info_header + "\n"
        c.execute("UPDATE workers SET log=? WHERE id=?", (current_log, worker_id))
        conn.commit()

        c.execute("""UPDATE discovered SET status = 'running'
                     WHERE id = (SELECT discovered_id FROM workers WHERE id=?)""", (worker_id,))
        conn.commit()

        lines = storedconfig.splitlines()
        if not lines:
            print(f"ℹ️ Worker {worker_id}: nothing to do.")
            return

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=user, password=password, timeout=10)
        shell = client.invoke_shell()
        shell.settimeout(2)

        
        wait_for_prompt(shell, timeout=5, skip_grace=True)

        success, final_line = process_lines(shell, lines[last_line:], stop_keywords, expert_user, expert_pass, worker_id, start_line=last_line, current_log=current_log)

        shell.close()
        client.close()

        c.execute("""UPDATE discovered
                     SET status = ?
                     WHERE id = (SELECT discovered_id FROM workers WHERE id=?)""",
                  ('finished' if success else 'stopped', worker_id))

        c.execute("UPDATE workers SET last_line=? WHERE id=?", (final_line, worker_id))
        conn.commit()

    finally:
        c.execute("UPDATE workers SET pid=NULL, stop=0 WHERE id=?", (worker_id,))
        conn.commit()
        conn.close()
        print(f"✅ Worker {worker_id} done. Stop-Flag reset.")

def load_stop_keywords(hw_type):
    conn = db()
    c = conn.cursor()
    keywords = []

    if hw_type:
        row = c.execute("SELECT err_keywords FROM HWType WHERE Type = ?", (hw_type,)).fetchone()
        if row and row['err_keywords']:
            raw = row['err_keywords']
            keywords = [kw.strip() for kw in raw.split(',') if kw.strip()]

    conn.close()

    if not keywords:
        keywords = ['"error"', '"fail"', '"denied"']

    return keywords

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: worker_subprocess.py <worker_id>")
        sys.exit(1)
    worker_id = int(sys.argv[1])
    run_worker_lines(worker_id)
