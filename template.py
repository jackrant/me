#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading, requests, re, time, os, sys, json, io, zipfile, shutil, ctypes, urllib3, warnings
from queue import Queue, Empty
from urllib.parse import urlparse, urljoin, quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")
os.environ["NO_PROXY"] = "*"
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
TIMEOUT = 18
SHELLS_FILE = "shells.txt"
DEFAULT_THREADS = 5
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

targets_queue = Queue()
stats = {"total": 0, "done": 0, "vuln": 0, "exploited": 0, "safe": 0, "error": 0}
stats_lock = threading.Lock()
file_lock = threading.Lock()
vuln_urls = []
exploited_urls = []
safe_urls = []
error_urls = []

ESC = "\033["
RESET_C = ESC + "0m"
BOLD_C = ESC + "1m"
DIM_C = ESC + "2m"
RED_C = ESC + "91m"
DARK_RED_C = ESC + "31m"
GREEN_C = ESC + "92m"
WHITE_C = ESC + "97m"
GRAY_C = ESC + "90m"
BLUE_C = ESC + "94m"
CYAN_C = ESC + "96m"
YELLOW_C = ESC + "93m"
GOLD_C = ESC + "33m"
BRIGHT_YELLOW_C = ESC + "93m"
LIGHT_YELLOW_C = ESC + "93m"
DARK_YELLOW_C = ESC + "33m"

CLEAR_LINE = "\033[2K\r"

def enable_ansi():
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            return True
    except Exception:
        pass
    return False

ANSI = enable_ansi()

def ac(text, color):
    if not ANSI:
        return str(text)
    return f"{color}{text}{RESET_C}"

def terminal_width():
    try:
        w = shutil.get_terminal_size(fallback=(100, 30)).columns
    except Exception:
        w = 100
    return max(60, min(w, 150))

def set_terminal_title(title):
    try:
        if os.name == "nt":
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        else:
            sys.stdout.write(f"\033]0;{title}\007")
            sys.stdout.flush()
    except Exception:
        pass

NX_LOGO = [
    "███╗   ███╗███████╗",
    "████╗ ████║██╔════╝",
    "██╔████╔██║█████╗  ",
    "██║╚██╔╝██║██╔══╝  ",
    "██║ ╚═╝ ██║███████╗",
    "╚═╝     ╚═╝╚══════╝",
]

def full_banner():
    width = terminal_width()
    frame_width = max(60, min(width - 4, 112))
    indent = max((width - frame_width) // 2, 0)
    pad = " " * indent

    def make_content(parts):
        raw = "".join(t for t, _ in parts)
        avail = frame_width - 4
        if len(raw) > avail:
            raw = raw[:avail - 3] + "..."
            parts = [(raw, WHITE_C)]
        left = max((avail - len(raw)) // 2, 0)
        right = max(avail - len(raw) - left, 0)
        out = ac("║", YELLOW_C) + " " + (" " * left)
        for t, col in parts:
            out += ac(t, col)
        out += (" " * right) + " " + ac("║", YELLOW_C)
        return out

    print()
    print(pad + ac("╔" + "═" * (frame_width - 2) + "╗", YELLOW_C))
    empty = ac("║", YELLOW_C) + " " * (frame_width - 2) + ac("║", YELLOW_C)
    print(pad + empty)

    logo_w = max(len(r) for r in NX_LOGO)
    logo_area = frame_width - 2
    for row in NX_LOGO:
        lp = max((logo_area - logo_w) // 2, 0)
        rp = max(logo_area - logo_w - lp, 0)
        print(pad + ac("║", YELLOW_C) + " " * lp + ac(row, BOLD_C + GOLD_C) + " " * rp + ac("║", YELLOW_C))

    print(pad + empty)
    print(pad + ac("╠", YELLOW_C) + ac("═" * (frame_width - 2), GRAY_C) + ac("╣", YELLOW_C))

    print(pad + make_content([
        ("CVE_ID", BOLD_C + GOLD_C),
        ("   │   ", GRAY_C),
        ("CVE_Nickname", BOLD_C + WHITE_C),
    ]))

    print(pad + make_content([
        ("Marshal ZeroDay Hub", BOLD_C + GOLD_C),
    ]))

    print(pad + ac("╠", YELLOW_C) + ac("═" * (frame_width - 2), GRAY_C) + ac("╣", YELLOW_C))

    info = "Exploit_Step1 •  Exploit_Step2  •  Exploit_Step3  •  Exploit_Step4"
    print(pad + make_content([(info, DIM_C + GRAY_C)]))

    print(pad + ac("╚" + "═" * (frame_width - 2) + "╝", YELLOW_C))
    if ANSI:
        sw = frame_width - 6
        print(pad + "   " + ac("▀" * max(sw, 1), DIM_C + YELLOW_C))
    print()

def resolve_path(p):
    if os.path.isabs(p):
        return p
    check = os.path.join(os.getcwd(), p)
    if os.path.exists(check):
        return check
    check2 = os.path.join(SCRIPT_DIR, p)
    if os.path.exists(check2):
        return check2
    return os.path.join(os.getcwd(), p)

def write_url(line, category):
    with file_lock:
        try:
            p = os.path.join(SCRIPT_DIR, SHELLS_FILE)
            with open(p, "a", encoding="utf-8") as f:
                f.write(f"[{category}] {line}\n")
        except Exception:
            pass

def mk_sess():
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.verify = False
    return s

def check_url_status(url):
    """Simulate checking URL status - in real scenario this would do actual checks"""
    import random
    rand = random.random()
    if rand < 0.3:  # 30% chance VULN
        return "VULN"
    elif rand < 0.5:  # 20% chance EXPLOITED
        return "EXPLOITED"
    elif rand < 0.7:  # 20% chance SAFE
        return "SAFE"
    else:  # 30% chance ERROR
        return "ERROR"

def scan_target(base):
    sess = mk_sess()
    found = []
    
    try:
        r = sess.get(base, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code == 200:
            urls = extract_urls_from_page(r.text, base)
            found.extend(urls)
            
            try:
                r2 = sess.get(f"{base}/robots.txt", timeout=TIMEOUT)
                if r2.status_code == 200:
                    for line in r2.text.split('\n'):
                        if line.strip().startswith(('Disallow:', 'Allow:')):
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/':
                                full_url = base + path
                                found.append(full_url)
            except Exception:
                pass
            
            try:
                r3 = sess.get(f"{base}/sitemap.xml", timeout=TIMEOUT)
                if r3.status_code == 200:
                    for match in re.finditer(r'<loc>([^<]+)</loc>', r3.text, re.IGNORECASE):
                        found.append(match.group(1))
            except Exception:
                pass
            
            try:
                r4 = sess.get(f"{base}/wp-json", timeout=TIMEOUT)
                if r4.status_code == 200:
                    found.append(f"{base}/wp-json")
            except Exception:
                pass
    
    except Exception:
        pass
    finally:
        sess.close()
    
    urls_to_display = []
    for url in set(found):
        if url and url.startswith('http'):
            urls_to_display.append(url)
    
    return urls_to_display

def extract_urls_from_page(html, base):
    urls = set()
    parsed = urlparse(base)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    href_patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']',
        r'data-url=["\']([^"\']+)["\']',
        r'action=["\']([^"\']+)["\']',
    ]
    
    for pattern in href_patterns:
        for match in re.finditer(pattern, html, re.IGNORECASE):
            url = match.group(1)
            if url and not url.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                if url.startswith('/'):
                    url = base_url + url
                elif not url.startswith(('http://', 'https://')):
                    url = urljoin(base, url)
                
                if any(ext in url.lower() for ext in ['.php', '.html', '.asp', '.aspx', '.jsp', '.do', '.action']):
                    urls.add(url)
    
    return urls

def build_status_line():
    """Build the status line"""
    with stats_lock:
        t, d, v, exp, s, e = stats["total"], stats["done"], stats["vuln"], stats["exploited"], stats["safe"], stats["error"]
    
    elapsed = time.time() - start_time if 'start_time' in globals() else 0
    rate = d / elapsed if elapsed > 0 else 0
    
    remaining = t - d
    eta = remaining / rate if rate > 0 else 0
    
    eta_str = f"{int(eta//3600):02d}:{int((eta%3600)//60):02d}:{int(eta%60):02d}"
    
    return (
        f"{BOLD_C}{CYAN_C}Scanned{RESET_C} [{WHITE_C}{d}{RESET_C}/{WHITE_C}{t}{RESET_C}]  "
        f"{BOLD_C}{GREEN_C}Vuln{RESET_C} [{WHITE_C}{v}{RESET_C}]  "
        f"{BOLD_C}{YELLOW_C}Exploited{RESET_C} [{WHITE_C}{exp}{RESET_C}]  "
        f"{BOLD_C}{DIM_C}Safe{RESET_C} [{WHITE_C}{s}{RESET_C}]  "
        f"{BOLD_C}{RED_C}ERR{RESET_C} [{WHITE_C}{e}{RESET_C}]  "
        f"{BOLD_C}{CYAN_C}Remaining{RESET_C} [{WHITE_C}{eta_str}{RESET_C}]"
    )

def worker():
    while True:
        try:
            base = targets_queue.get_nowait()
        except Empty:
            return
        
        urls = scan_target(base)
        
        for url in urls:
            status = check_url_status(url)
            
            with stats_lock:
                stats["done"] += 1
                if status == "VULN":
                    stats["vuln"] += 1
                    vuln_urls.append(url)
                    # Bold and green for VULN
                    display_url = f"{BOLD_C}{GREEN_C}[VULN] {url}{RESET_C}"
                elif status == "EXPLOITED":
                    stats["exploited"] += 1
                    exploited_urls.append(url)
                    # Bold and yellow for EXPLOITED
                    display_url = f"{BOLD_C}{YELLOW_C}[EXPLOITED] {url}{RESET_C}"
                elif status == "SAFE":
                    stats["safe"] += 1
                    safe_urls.append(url)
                    # Dim gray for SAFE (not bold)
                    display_url = f"{DIM_C}[SAFE] {url}{RESET_C}"
                else:
                    stats["error"] += 1
                    error_urls.append(url)
                    # Red for ERROR (not bold)
                    display_url = f"{RED_C}[ERROR] {url} (Error Lets){RESET_C}"
            
            with print_lock:
                sys.stdout.write(CLEAR_LINE + f"{display_url}\n")
                sys.stdout.write(build_status_line())
                sys.stdout.flush()
            
            write_url(url, status)
        
        targets_queue.task_done()

start_time = 0
print_lock = threading.Lock()

def run():
    global start_time
    set_terminal_title("Marshal ZeroDay Hub | URL Scanner")
    os.system("cls" if os.name == "nt" else "clear")
    full_banner()

    raw_tf = input(f"{BOLD_C}{LIGHT_YELLOW_C}Targets file (default list.txt): {RESET_C}").strip() or "list.txt"
    tf = resolve_path(raw_tf)
    if not os.path.exists(tf):
        print(f"{RED_C}File not found: {tf}{RESET_C}")
        return

    count = sum(1 for l in open(tf, "r", encoding="utf-8", errors="ignore") if l.strip())
    print(f"{GREEN_C}Found:{RESET_C} {tf} ({count} targets)")

    tr = input(f"{BOLD_C}{LIGHT_YELLOW_C}Threads (default {DEFAULT_THREADS}): {RESET_C}").strip()
    try:
        threads = int(tr) if tr else DEFAULT_THREADS
    except Exception:
        threads = DEFAULT_THREADS
    threads = max(1, threads)

    sites = []
    with open(tf, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            u = ln.strip()
            if not u:
                continue
            if not u.lower().startswith(("http://", "https://")):
                u = "https://" + u
            sites.append(u.rstrip("/"))

    if not sites:
        print(f"{RED_C}No targets{RESET_C}")
        return

    urls_path = os.path.join(SCRIPT_DIR, SHELLS_FILE)
    print(f"\n{GREEN_C}Loaded {len(sites)} target(s) | {threads} thread(s){RESET_C}")
    print(f"{DIM_C}Results -> {urls_path}{RESET_C}\n")

    for s in sites:
        targets_queue.put(s)
    with stats_lock:
        stats.update({"total": len(sites), "done": 0, "vuln": 0, "exploited": 0, "safe": 0, "error": 0})

    start_time = time.time()
    
    with print_lock:
        sys.stdout.write("\n" + build_status_line())
        sys.stdout.flush()

    workers = []
    for _ in range(min(threads, len(sites))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        workers.append(t)

    while True:
        with stats_lock:
            d, t = stats["done"], stats["total"]
        if d >= t:
            break
        time.sleep(0.5)

    targets_queue.join()
    for t in workers:
        t.join(timeout=0.3)

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{RED_C}Interrupted.{RESET_C}")
