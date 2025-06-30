import sys, time, os, re, json, logging, sqlite3, paramiko

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, '..', 'zero_touch.db')

PROMPT_PATTERN = re.compile(r'[\r\n][^\r\n]*[#>$%:] ?$')
STOP_KEYWORDS_DEFAULT = ["error", "fail", "denied"]

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def wait_for_prompt(shell, timeout=10, grace_period=1, skip_grace=False):
    buffer = ''
    start_time = time.time()
    prompt_detected_time = None

    while True:
        if shell.recv_ready():
            part = shell.recv(4096).decode(errors='ignore')
            buffer += part
            print(part, end='', flush=True)

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

def process_lines(shell, lines, stop_keywords, expert_pass, worker_id, start_line=0, current_log=''):
    stop_keywords = [kw.lower() for kw in (stop_keywords or [])]
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

    def detect_prompt():
        return wait_for_prompt(shell, timeout=10, grace_period=1)

    last_line_number = start_line

    for line_num, line in enumerate(lines, start=start_line + 1):
        last_line_number = line_num
        stripped = line.strip()

        stop_row = c.execute("SELECT stop FROM workers WHERE id=?", (worker_id,)).fetchone()
        if stop_row and stop_row["stop"]:
            append("🛑 Stopped by user.")
            success = False
            break

        if stripped == "enter_expert_mode:":
            shell.send("expert\n")
            output = detect_prompt()
            append("> expert\n" + output)
            if "password" in output.lower():
                shell.send(expert_pass + "\n")
                output = detect_prompt()
                append("> (expert password)\n" + output)
            if "#" in output:
                append("✅ Expert mode entered.")
            else:
                append("🛑 Failed to enter expert mode.")
                success = False
            continue

        if stripped == "exit_expert_mode:":
            shell.send("exit\n")
            output = detect_prompt()
            append("> exit\n" + output)
            continue

        shell.send(stripped + "\n")
        output = detect_prompt()
        append(f"> {stripped}\n{output}")

        if any(re.search(kw, output, re.IGNORECASE) for kw in stop_keywords):
            append(f"🛑 Error keyword detected — stopping.")
            success = False
            break

        # ✅ update log + last_line after each line
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

        success, final_line = process_lines(shell, lines[last_line:], stop_keywords, expert_pass, worker_id, start_line=last_line, current_log=current_log)

        shell.close()
        client.close()

        c.execute("""UPDATE discovered
                     SET status = ?
                     WHERE id = (SELECT discovered_id FROM workers WHERE id=?)""",
                  ('finished' if success else 'stopped', worker_id))

        # ✅ keep last_line at last valid line
        c.execute("UPDATE workers SET last_line=? WHERE id=?", (final_line, worker_id))
        conn.commit()

    finally:
        c.execute("UPDATE workers SET pid=NULL, stop=0 WHERE id=?", (worker_id,))
        conn.commit()
        conn.close()
        print(f"✅ Worker {worker_id} done. Stop-Flag reset.")

def load_stop_keywords(hw_type):
    """
    Load stop keywords from HWType.err_keywords where Type matches hw_type.
    Keeps the double quotes.
    """
    conn = db()
    c = conn.cursor()
    keywords = []

    if hw_type:
        row = c.execute("SELECT err_keywords FROM HWType WHERE Type = ?", (hw_type,)).fetchone()
        if row and row['err_keywords']:
            raw = row['err_keywords']
            # Split by commas and keep quotes
            keywords = [kw.strip() for kw in raw.split(',') if kw.strip()]

    conn.close()

    if not keywords:
        # Fallback, also quoted for consistency
        keywords = ['"error"', '"fail"', '"denied"']

    return keywords


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: worker_subprocess.py <worker_id>")
        sys.exit(1)
    worker_id = int(sys.argv[1])
    run_worker_lines(worker_id)
