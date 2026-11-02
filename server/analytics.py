import datetime
import getpass
import hashlib
import hmac
import html
import http.client
import http.cookies
import http.server
import json
import os
import re
import secrets
import shutil
import smtplib
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from email.errors import HeaderParseError
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid

STATE_DIR = os.environ.get("STATE_DIRECTORY", "./data")
DB_PATH = os.path.join(STATE_DIR, "analytics.db")
BIND_HOST = "127.0.0.1"
BIND_PORT = int(os.environ.get("ANALYTICS_PORT", "8090"))
ALLOWED_ORIGINS = {o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()}
APP_DIR = os.path.dirname(os.path.abspath(__file__))
BLOG_DIR = os.environ.get("BLOG_OUTPUT_DIR", "")
SITE_URL = "https://me.stupif.com"
SECRETS_FILE = os.environ.get("SECRETS_FILE", "/etc/analytics/secrets.json")
TURNSTILE_HOSTNAMES = {h.strip() for h in os.environ.get("TURNSTILE_HOSTNAMES", "").split(",") if h.strip()}
TURNSTILE_HOST = "challenges.cloudflare.com"
TURNSTILE_PATH = "/turnstile/v0/siteverify"
TURNSTILE_ACTION = "contact"
TURNSTILE_FIELD = "cf-turnstile-response"

RETENTION_DAYS = 180
MAX_VISITS_PER_DAY = 20000
MAX_EVENTS_PER_VISIT = 200
MAX_VISIT_SECONDS = 86400
MAX_ACTIVE_STEP = 30
SESSION_SECONDS = 12 * 3600
MIN_PASSWORD_LENGTH = 12
PAGE_SIZE = 50
MAX_COLLECT_BODY = 2048
MAX_FORM_BODY = 8192
MAX_CONTACT_BODY = 32768
MAX_NAME_LENGTH = 100
MAX_EMAIL_LENGTH = 254
MAX_MESSAGE_LENGTH = 4000
MAX_MESSAGES_PER_DAY = 200
MESSAGE_RETENTION_DAYS = 365
MAX_BLOG_FORM_BODY = 400000
MAX_TITLE_LENGTH = 150
MAX_SUMMARY_LENGTH = 300
MAX_POST_LENGTH = 100000
HOME_POST_COUNT = 4
MAX_TURNSTILE_TOKEN = 2048
TURNSTILE_TIMEOUT = 8
MAIL_TIMEOUT = 20
MAIL_BATCH = 20
MAIL_CHECK_SECONDS = 60
MAIL_RETRY_SECONDS = 60
MAX_MAIL_ATTEMPTS = 12
MAX_MAIL_DELAY = 6 * 3600

VISIT_ID = re.compile(r"[0-9a-f]{32}")
PATH = re.compile(r"/[A-Za-z0-9._~/-]{0,199}")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,63}")
COUNTRY = re.compile(r"[A-Z]{2}")
MAIL_HOST = re.compile(r"[A-Za-z0-9.-]{1,253}")
PLACE = re.compile(r"[\w .'-]{1,64}")
EMAIL = re.compile(r"[^\s@<>\"'(),:;\\]+@[^\s@<>\"'(),:;\\]+\.[^\s@<>\"'(),:;\\]+")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ud800-\udfff]")

SCRYPT = {"n": 2**15, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024, "dklen": 32}

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS owner (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    salt BLOB NOT NULL,
    password_hash BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS visits (
    id TEXT PRIMARY KEY,
    started_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    active_seconds INTEGER NOT NULL DEFAULT 0,
    path TEXT NOT NULL,
    country TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    city TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS visits_started ON visits (started_at);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visit_id TEXT NOT NULL REFERENCES visits (id) ON DELETE CASCADE,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    label TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_visit ON events (visit_id, at);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at INTEGER NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    message TEXT NOT NULL,
    mailed_at INTEGER,
    mail_attempts INTEGER NOT NULL DEFAULT 0,
    next_mail_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS messages_received ON messages (received_at);
CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    published_at INTEGER
);
"""


def connect():
    connection = sqlite3.connect(DB_PATH, timeout=5, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA secure_delete = ON")
    return connection


def init_db():
    os.makedirs(STATE_DIR, exist_ok=True)
    connection = connect()
    connection.execute("PRAGMA journal_mode = WAL")
    connection.executescript(SCHEMA)
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(messages)")}
    if "mailed_at" not in columns:
        connection.executescript(
            "BEGIN;"
            "ALTER TABLE messages ADD COLUMN mailed_at INTEGER;"
            "ALTER TABLE messages ADD COLUMN mail_attempts INTEGER NOT NULL DEFAULT 0;"
            "ALTER TABLE messages ADD COLUMN next_mail_at INTEGER NOT NULL DEFAULT 0;"
            "UPDATE messages SET mailed_at = 0;"
            "COMMIT;"
        )
    connection.close()


class Limiter:
    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self.hits = {}
        self.lock = threading.Lock()

    def reserve(self, key):
        now = time.monotonic()
        with self.lock:
            if len(self.hits) > 10000:
                self.hits = {k: v for k, v in self.hits.items() if v and v[-1] > now - self.window}
            recent = [t for t in self.hits.get(key, []) if t > now - self.window]
            if len(recent) >= self.limit:
                self.hits[key] = recent
                return False
            recent.append(now)
            self.hits[key] = recent
            return True

    def release(self, key):
        with self.lock:
            recent = self.hits.get(key, [])
            if recent:
                recent.pop()


login_by_address = Limiter(8, 900)
login_overall = Limiter(30, 900)
setup_overall = Limiter(10, 900)
contact_by_address = Limiter(5, 3600)

setup_code = None
site_secrets = {}
mail_wake = threading.Event()


def read_secrets():
    try:
        with open(SECRETS_FILE, encoding="utf-8") as file:
            loaded = json.load(file)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as error:
        print(f"Could not read the secrets file: {type(error).__name__}", flush=True)
        return {}
    return loaded if isinstance(loaded, dict) else {}


def tls_context():
    return ssl.create_default_context()


def mail_configured():
    if site_secrets.get("mail_api_token"):
        return bool(site_secrets.get("mail_api_mailbox") and site_secrets.get("mail_api_to"))
    return all(site_secrets.get(key) for key in ("mail_host", "mail_port", "mail_user", "mail_password", "mail_to", "mail_from"))


def base_mail(subject):
    sender = site_secrets["mail_from"]
    mail = EmailMessage()
    mail["Subject"] = subject
    mail["From"] = Address("Website contact form", addr_spec=sender)
    mail["To"] = site_secrets["mail_to"]
    mail["Date"] = format_datetime(datetime.datetime.now(datetime.timezone.utc))
    mail["Message-ID"] = make_msgid(domain=sender.rsplit("@", 1)[-1])
    return mail


def mail_api_client(token):
    import hostinger_mail_api

    return hostinger_mail_api.ApiClient(hostinger_mail_api.Configuration(access_token=token))


def api_mailbox(token):
    import hostinger_mail_api

    with mail_api_client(token) as client:
        account = hostinger_mail_api.AccountApi(client).get_current_account(_request_timeout=MAIL_TIMEOUT)
    if len(account.data.mailboxes) != 1:
        raise ValueError("The token must cover exactly one mailbox.")
    return account.data.mailboxes[0].resource_id, account.data.mailboxes[0].address


def send_api_mail(subject, text):
    import hostinger_mail_api

    request = hostinger_mail_api.V1SendRequest(
        to=[site_secrets["mail_api_to"]],
        display_name="Website contact form",
        subject=subject,
        text=text,
    )
    with mail_api_client(site_secrets["mail_api_token"]) as client:
        hostinger_mail_api.SendApi(client).send_email(site_secrets["mail_api_mailbox"], request, _request_timeout=MAIL_TIMEOUT)


def contact_content(row):
    name = " ".join(row["name"].split())
    received = datetime.datetime.fromtimestamp(row["received_at"], datetime.timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    return (
        f"Website message from {name}",
        f'To reply, email: {row["email"]}\nName: {name}\nReceived: {received}\n\n{row["message"]}\n',
    )


def contact_mail(row):
    subject, text = contact_content(row)
    mail = base_mail(subject)
    if row["email"].isascii():
        try:
            mail["Reply-To"] = Address(addr_spec=row["email"])
        except (ValueError, HeaderParseError):
            pass
    mail.set_content(text, cte="quoted-printable")
    return mail


def deliver_contact(row):
    if site_secrets.get("mail_api_token"):
        send_api_mail(*contact_content(row))
    else:
        send_mail(contact_mail(row))


def send_mail(mail):
    host = site_secrets["mail_host"]
    port = int(site_secrets["mail_port"])
    helo = site_secrets["mail_from"].rsplit("@", 1)[-1]
    context = tls_context()
    if port == 465:
        client = smtplib.SMTP_SSL(host, port, local_hostname=helo, timeout=MAIL_TIMEOUT, context=context)
    else:
        client = smtplib.SMTP(host, port, local_hostname=helo, timeout=MAIL_TIMEOUT)
    with client:
        if port != 465:
            client.starttls(context=context)
        client.login(site_secrets["mail_user"], site_secrets["mail_password"])
        client.send_message(mail)


def send_pending_mail():
    if not mail_configured():
        return
    now = int(time.time())
    connection = connect()
    try:
        rows = connection.execute(
            "SELECT * FROM messages WHERE mailed_at IS NULL AND next_mail_at <= ? AND mail_attempts < ? ORDER BY id LIMIT ?",
            (now, MAX_MAIL_ATTEMPTS, MAIL_BATCH),
        ).fetchall()
        for row in rows:
            try:
                deliver_contact(row)
            except Exception as error:
                print(f"Could not email message {row['id']}: {type(error).__name__}", flush=True)
                delay = min(MAIL_RETRY_SECONDS * 2 ** row["mail_attempts"], MAX_MAIL_DELAY)
                connection.execute(
                    "UPDATE messages SET mail_attempts = mail_attempts + 1, next_mail_at = ? WHERE id = ?",
                    (int(time.time()) + delay, row["id"]),
                )
                break
            connection.execute("UPDATE messages SET mailed_at = ? WHERE id = ?", (int(time.time()), row["id"]))
    finally:
        connection.close()


def mail_loop():
    while True:
        mail_wake.wait(MAIL_CHECK_SECONDS)
        mail_wake.clear()
        try:
            send_pending_mail()
        except Exception as error:
            print(f"Could not read the email queue: {type(error).__name__}", flush=True)


def turnstile_connection():
    return http.client.HTTPSConnection(TURNSTILE_HOST, timeout=TURNSTILE_TIMEOUT, context=tls_context())


def siteverify(secret, token, address=None):
    fields = {"secret": secret, "response": token}
    if address:
        fields["remoteip"] = address
    connection = turnstile_connection()
    try:
        connection.request(
            "POST",
            TURNSTILE_PATH,
            urllib.parse.urlencode(fields),
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        response = connection.getresponse()
        if response.status >= 500:
            return None
        result = json.loads(response.read(8192))
    except (OSError, http.client.HTTPException, ValueError) as error:
        print(f"Could not reach Turnstile: {type(error).__name__}", flush=True)
        return None
    finally:
        connection.close()
    return result if isinstance(result, dict) else None


def turnstile_passed(token, address):
    secret = site_secrets.get("turnstile_secret")
    if not secret or not TURNSTILE_HOSTNAMES:
        return None
    result = siteverify(secret, token, None if address == "unknown" else address)
    if result is None:
        return None
    if result.get("success") is True:
        return result.get("action") == TURNSTILE_ACTION and result.get("hostname") in TURNSTILE_HOSTNAMES
    codes = result.get("error-codes")
    if isinstance(codes, list) and {"missing-input-secret", "invalid-input-secret", "internal-error"} & {str(code) for code in codes}:
        print("Turnstile refused the server's request. Check the Turnstile secret.", flush=True)
        return None
    return False


def hash_password(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, **SCRYPT)


def token_hash(token):
    return hashlib.sha256(token.encode("ascii", "replace")).hexdigest()


def owner_exists():
    connection = connect()
    try:
        return connection.execute("SELECT 1 FROM owner WHERE id = 1").fetchone() is not None
    finally:
        connection.close()


def prepare_setup_code():
    global setup_code
    if owner_exists():
        setup_code = None
        return
    setup_code = secrets.token_urlsafe(18)
    print(f"First-run setup code: {setup_code}", flush=True)


def purge_loop():
    while True:
        now = int(time.time())
        connection = connect()
        try:
            connection.execute("DELETE FROM visits WHERE started_at < ?", (now - RETENTION_DAYS * 86400,))
            connection.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            connection.execute("DELETE FROM messages WHERE received_at < ?", (now - MESSAGE_RETENTION_DAYS * 86400,))
        finally:
            connection.close()
        time.sleep(3600)


def clean_place(value):
    if not value:
        return ""
    try:
        decoded = value.encode("latin-1").decode("utf-8")
    except UnicodeError:
        return ""
    return decoded if PLACE.fullmatch(decoded) else ""


def format_duration(seconds):
    if seconds < 60:
        return "under a minute"
    minutes = round(seconds / 60)
    if minutes < 60:
        return f"about {minutes} min"
    return f"about {minutes // 60} h {minutes % 60} min"


def format_time(timestamp):
    moment = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
    text = moment.strftime("%d %b %Y, %H:%M UTC")
    return f'<time datetime="{moment.isoformat()}">{text}</time>'


def visitor_name(visit_id):
    return "Visitor " + hashlib.sha256(visit_id.encode()).hexdigest()[:4].upper()


def page(title, body):
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex, nofollow">'
        f"<title>{html.escape(title)}</title>"
        '<link rel="stylesheet" href="/static/dashboard.css">'
        '<script src="/static/dashboard.js" defer></script>'
        f"</head><body>{body}</body></html>"
    )


def auth_form(title, intro, action, csrf, fields, button, error):
    error_html = f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ""
    inputs = "".join(
        f'<label for="{name}">{label}</label>'
        f'<input id="{name}" name="{name}" type="{kind}" autocomplete="{autocomplete}" required>'
        for name, label, kind, autocomplete in fields
    )
    return page(
        title,
        f'<main class="auth"><h1>{title}</h1><p class="muted">{intro}</p>{error_html}'
        f'<form method="post" action="{action}">'
        f'<input type="hidden" name="csrf" value="{html.escape(csrf)}">{inputs}'
        f'<button type="submit">{button}</button></form></main>',
    )


def clean_text(value, limit):
    if not isinstance(value, str):
        return None
    cleaned = CONTROL_CHARS.sub("", value).replace("\r\n", "\n").replace("\r", "\n").strip()
    return cleaned if 0 < len(cleaned) <= limit else None


def render_inline(text):
    pieces = []
    for part in re.split(r"(`[^`\n]+`)", text):
        if len(part) > 2 and part.startswith("`") and part.endswith("`"):
            pieces.append(f"<code>{html.escape(part[1:-1])}</code>")
        else:
            pieces.append(render_emphasis(html.escape(part)))
    return "".join(pieces)


def render_link(match):
    label, target = match.group(1), match.group(2)
    if not re.fullmatch(r"(https?://|mailto:|/|#)[^\s<>\"']*", html.unescape(target)):
        return label
    return f'<a href="{target}" rel="noopener noreferrer">{label}</a>'


def render_emphasis(text):
    text = re.sub(r"\[([^\]\n]+)\]\(([^()\s]+)\)", render_link, text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    return re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", text)


def render_markdown(source):
    output = []
    lines = source.split("\n")
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
        elif stripped.startswith("```"):
            index += 1
            code = []
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code.append(lines[index])
                index += 1
            index += 1
            output.append(f"<pre><code>{html.escape(chr(10).join(code))}</code></pre>")
        elif re.match(r"#{1,3} ", stripped):
            marks, text = stripped.split(" ", 1)
            level = "h3" if len(marks) == 3 else "h2"
            output.append(f"<{level}>{render_inline(text.strip())}</{level}>")
            index += 1
        elif re.match(r"[-*] ", stripped) or re.match(r"\d+\. ", stripped):
            ordered = bool(re.match(r"\d+\. ", stripped))
            pattern = r"\d+\. " if ordered else r"[-*] "
            items = []
            while index < len(lines) and re.match(pattern, lines[index].strip()):
                items.append(f"<li>{render_inline(re.sub(pattern, '', lines[index].strip(), count=1))}</li>")
                index += 1
            tag = "ol" if ordered else "ul"
            output.append(f"<{tag}>{''.join(items)}</{tag}>")
        elif stripped.startswith("> "):
            quoted = []
            while index < len(lines) and lines[index].strip().startswith("> "):
                quoted.append(lines[index].strip()[2:])
                index += 1
            output.append(f"<blockquote><p>{render_inline(' '.join(quoted))}</p></blockquote>")
        else:
            paragraph = []
            while index < len(lines):
                current = lines[index].strip()
                if not current or current.startswith(("```", "> ")) or re.match(r"#{1,3} |[-*] |\d+\. ", current):
                    break
                paragraph.append(current)
                index += 1
            output.append(f"<p>{render_inline(' '.join(paragraph))}</p>")
    return "".join(output)


def make_slug(title, connection, current_id=None):
    base = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:80].strip("-") or "post"
    slug = base
    suffix = 2
    while connection.execute("SELECT 1 FROM posts WHERE slug = ? AND id IS NOT ?", (slug, current_id)).fetchone():
        slug = f"{base}-{suffix}"
        suffix += 1
    return slug


def short_date(timestamp):
    moment = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
    return f"{moment.day} {moment.strftime('%b %Y')}"


def iso_date(timestamp):
    return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime("%Y-%m-%d")


def public_page(title, description, canonical, body):
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)} | TechieJack</title>"
        f'<meta name="description" content="{html.escape(description)}">'
        f'<meta property="og:title" content="{html.escape(title)}">'
        f'<meta property="og:description" content="{html.escape(description)}">'
        f'<link rel="canonical" href="{SITE_URL}/posts/{canonical}">'
        '<link rel="icon" href="../media/favicon.svg" type="image/svg+xml">'
        '<link rel="stylesheet" href="../styles.css">'
        '<script src="../config.js" defer></script><script src="../analytics.js" defer></script>'
        f'</head><body><main class="post">{body}</main></body></html>'
    )


def post_page(post):
    description = post["summary"] or post["title"]
    return public_page(
        post["title"],
        description,
        f'{post["slug"]}.html',
        '<a class="post-back" href="index.html">All posts</a><article><header>'
        f'<h1 class="name">{html.escape(post["title"])}</h1>'
        f'<time class="post-date" datetime="{iso_date(post["published_at"])}">{short_date(post["published_at"])}</time>'
        f'</header>{render_markdown(post["body"])}</article>',
    )


def post_row(post):
    summary = f'<span class="project-description">{html.escape(post["summary"])}</span>' if post["summary"] else ""
    return (
        f'<li><a class="project" href="{post["slug"]}.html"><span class="project-name">{html.escape(post["title"])}</span>'
        f'<span class="project-tech"><time datetime="{iso_date(post["published_at"])}">{short_date(post["published_at"])}</time></span>'
        f"{summary}</a></li>"
    )


def posts_index(posts):
    rows = "".join(post_row(post) for post in posts)
    listing = f'<ul class="project-list post-index">{rows}</ul>' if rows else '<p class="post-empty">No posts yet. Check back soon.</p>'
    return public_page(
        "Blog",
        "Posts by TechieJack.",
        "index.html",
        f'<a class="post-back" href="../index.html#blog">Back to home</a><header><h1 class="name">Blog</h1></header>{listing}',
    )


def write_public_file(name, content):
    handle, temporary = tempfile.mkstemp(prefix=".tmp-", dir=BLOG_DIR)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            file.write(content)
        os.chmod(temporary, 0o644)
        os.replace(temporary, os.path.join(BLOG_DIR, name))
    except OSError:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def publish_blog():
    if not BLOG_DIR:
        return True
    connection = connect()
    try:
        posts = connection.execute("SELECT * FROM posts WHERE published_at IS NOT NULL ORDER BY published_at DESC, id DESC").fetchall()
    finally:
        connection.close()
    try:
        expected = {"index.html", "posts.json"}
        for post in posts:
            expected.add(f'{post["slug"]}.html')
            write_public_file(f'{post["slug"]}.html', post_page(post))
        write_public_file("index.html", posts_index(posts))
        feed = {
            "total": len(posts),
            "posts": [
                {
                    "title": post["title"],
                    "summary": post["summary"],
                    "date": short_date(post["published_at"]),
                    "iso": iso_date(post["published_at"]),
                    "slug": post["slug"],
                }
                for post in posts[:HOME_POST_COUNT]
            ],
        }
        write_public_file("posts.json", json.dumps(feed))
        for name in os.listdir(BLOG_DIR):
            if name not in expected and (name.endswith(".html") or name.startswith(".tmp-")):
                os.unlink(os.path.join(BLOG_DIR, name))
    except OSError as error:
        print(f"Could not update published blog files: {error}", flush=True)
        return False
    return True


def plural(count, word):
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def page_header(token, current, message_count):
    def link(href, label, name):
        marker = ' aria-current="page"' if name == current else ""
        return f'<a href="{href}"{marker}>{label}</a>'

    return (
        '<header class="top"><nav class="tabs" aria-label="Dashboard">'
        f'{link("/", "Visits", "visits")}{link("/messages", f"Messages ({message_count})", "messages")}{link("/blog", "Blog", "blog")}</nav>'
        f'<form method="post" action="/logout"><input type="hidden" name="csrf" value="{html.escape(token)}">'
        '<button class="quiet" type="submit">Sign out</button></form></header>'
    )


def render_message(row, token):
    email = html.escape(row["email"], quote=True)
    reply = html.escape(urllib.parse.quote(row["email"], safe="@"), quote=True)
    delivery = {None: " &middot; Not emailed yet", 0: ""}.get(row["mailed_at"], " &middot; Emailed")
    return (
        '<li class="visit"><div class="visit-head">'
        f'<h2>{html.escape(row["name"])}</h2>'
        f'<a class="reply" href="mailto:{reply}">{email}</a></div>'
        f'<p class="muted">{format_time(row["received_at"])}{delivery}</p>'
        f'<p class="message-body">{html.escape(row["message"])}</p>'
        '<form class="delete" method="post" action="/messages/delete">'
        f'<input type="hidden" name="csrf" value="{html.escape(token)}">'
        f'<input type="hidden" name="id" value="{int(row["id"])}">'
        '<button class="quiet" type="submit">Delete message</button></form></li>'
    )


def render_visit(visit, events):
    place_parts = [html.escape(visit["city"]), html.escape(visit["region"])]
    place_parts = [p for p in place_parts if p]
    if visit["country"] == "LAN":
        place = "Local network"
    elif visit["country"]:
        place_parts.append(f'<span data-country="{html.escape(visit["country"])}">{html.escape(visit["country"])}</span>')
        place = ", ".join(place_parts)
    else:
        place = "Location unknown"

    if events:
        items = "".join(
            f'<li><span class="event-time">{format_time(e["at"])}</span> {html.escape(e["label"])}</li>'
            for e in events
        )
        activity = f'<ol class="events">{items}</ol>'
    else:
        activity = '<p class="muted none">No clicks.</p>'

    return (
        '<li class="visit"><div class="visit-head">'
        f'<h2>{visitor_name(visit["id"])}</h2><p class="duration">{format_duration(visit["active_seconds"])}</p>'
        f'</div><p class="muted">{format_time(visit["started_at"])} &middot; {place} &middot; {html.escape(visit["path"])}</p>'
        f"{activity}</li>"
    )


def public_post_url(host, slug):
    name = host.split(":")[0]
    return html.escape(f"https://{name}:8443/posts/{slug}.html", quote=True)


class Handler(http.server.BaseHTTPRequestHandler):
    timeout = 15
    server_version = "analytics"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    @property
    def route(self):
        return urllib.parse.urlsplit(self.path).path

    @property
    def is_public(self):
        return self.headers.get("X-Analytics-Channel") != "lan"

    @property
    def address(self):
        return self.headers.get("X-Real-IP") or "unknown"

    def send(self, status, body=b"", content_type=None, headers=None, private=True):
        self.send_response(status)
        if status >= 400:
            self.close_connection = True
            self.send_header("Connection", "close")
        replaced = {name for name, _ in headers or []}
        for name, value in SECURITY_HEADERS.items():
            if name not in replaced:
                self.send_header(name, value)
        if private:
            self.send_header("Cache-Control", "no-store")
        if content_type:
            self.send_header("Content-Type", content_type)
        for name, value in headers or []:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_html(self, markup, status=200, headers=None):
        self.send(status, markup.encode("utf-8"), "text/html; charset=utf-8", headers)

    def redirect(self, location, headers=None):
        self.send(303, headers=[("Location", location)] + (headers or []))

    def read_body(self, limit):
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return None
        if length < 0 or length > limit:
            return None
        return self.rfile.read(length)

    def cookies(self):
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return {}
        return {name: morsel.value for name, morsel in jar.items()}

    def csrf_token(self):
        return self.cookies().get("__Host-csrf") or secrets.token_urlsafe(32)

    def csrf_cookie(self, token):
        return ("Set-Cookie", f"__Host-csrf={token}; Path=/; Secure; HttpOnly; SameSite=Strict")

    def form(self, limit=MAX_FORM_BODY):
        body = self.read_body(limit)
        if body is None:
            return None
        try:
            parsed = urllib.parse.parse_qs(body.decode("utf-8"), max_num_fields=8, strict_parsing=False)
        except (UnicodeDecodeError, ValueError):
            return None
        return {key: values[0] for key, values in parsed.items()}

    def form_trusted(self, fields):
        origin = self.headers.get("Origin")
        if origin and origin != f"https://{self.headers.get('Host', '')}":
            return False
        cookie = self.cookies().get("__Host-csrf", "")
        supplied = fields.get("csrf", "")
        return bool(cookie) and hmac.compare_digest(cookie.encode(), supplied.encode())

    def signed_in(self):
        token = self.cookies().get("__Host-session")
        if not token:
            return False
        connection = connect()
        try:
            row = connection.execute(
                "SELECT 1 FROM sessions WHERE token_hash = ? AND expires_at > ?",
                (token_hash(token), int(time.time())),
            ).fetchone()
            return row is not None
        finally:
            connection.close()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if self.is_public:
            return self.send(404)
        route = self.route
        if route == "/healthz":
            return self.send(200, b"ok", "text/plain; charset=utf-8")
        if route == "/static/dashboard.css":
            return self.send_static("dashboard.css", "text/css; charset=utf-8")
        if route == "/static/dashboard.js":
            return self.send_static("dashboard.js", "text/javascript; charset=utf-8")
        if not owner_exists():
            return self.show_setup() if route == "/setup" else self.redirect("/setup")
        if route == "/login":
            return self.show_login()
        if route == "/":
            return self.show_dashboard() if self.signed_in() else self.redirect("/login")
        if route == "/messages":
            return self.show_messages() if self.signed_in() else self.redirect("/login")
        if route in ("/blog", "/blog/new", "/blog/edit", "/blog/preview"):
            if not self.signed_in():
                return self.redirect("/login")
            return {
                "/blog": self.show_blog,
                "/blog/new": self.show_editor,
                "/blog/edit": self.show_editor,
                "/blog/preview": self.show_preview,
            }[route]()
        return self.send(404)

    def do_POST(self):
        route = self.route
        if route == "/api/collect":
            return self.collect()
        if route == "/api/contact":
            return self.contact()
        if self.is_public:
            return self.send(404)
        if route == "/setup":
            return self.submit_setup()
        if route == "/login":
            return self.submit_login()
        if route == "/logout":
            return self.submit_logout()
        if route == "/messages/delete":
            return self.delete_message()
        if route == "/blog/save":
            return self.save_post()
        if route == "/blog/unpublish":
            return self.change_post("unpublish")
        if route == "/blog/delete":
            return self.change_post("delete")
        return self.send(404)

    def send_static(self, name, content_type):
        with open(os.path.join(APP_DIR, "static", name), "rb") as file:
            self.send(200, file.read(), content_type, private=False)

    def show_setup(self, error="", status=200):
        token = self.csrf_token()
        markup = auth_form(
            "Set up analytics",
            "Enter the setup code from the server log, then choose a password of at least 12 characters.",
            "/setup",
            token,
            [
                ("code", "Setup code", "text", "one-time-code"),
                ("password", "New password", "password", "new-password"),
                ("confirm", "Confirm password", "password", "new-password"),
            ],
            "Create password",
            error,
        )
        self.send_html(markup, status, [self.csrf_cookie(token)])

    def submit_setup(self):
        fields = self.form()
        if fields is None or not self.form_trusted(fields):
            return self.send(403)
        if owner_exists():
            return self.redirect("/login")
        if not setup_overall.reserve("setup"):
            return self.show_setup("Too many tries. Wait 15 minutes, then try again.", 429)
        if not setup_code or not hmac.compare_digest(fields.get("code", "").encode(), setup_code.encode()):
            return self.show_setup("That setup code is not right.", 403)
        setup_overall.release("setup")
        password = fields.get("password", "")
        if len(password) < MIN_PASSWORD_LENGTH:
            return self.show_setup(f"Use at least {MIN_PASSWORD_LENGTH} characters.", 400)
        if password != fields.get("confirm", ""):
            return self.show_setup("Those passwords do not match.", 400)
        salt = secrets.token_bytes(16)
        connection = connect()
        try:
            connection.execute(
                "INSERT OR IGNORE INTO owner (id, salt, password_hash) VALUES (1, ?, ?)",
                (salt, hash_password(password, salt)),
            )
        finally:
            connection.close()
        prepare_setup_code()
        self.redirect("/login")

    def show_login(self, error="", status=200):
        if not error and self.signed_in():
            return self.redirect("/")
        token = self.csrf_token()
        markup = auth_form(
            "Analytics",
            "Sign in to see visits.",
            "/login",
            token,
            [("password", "Password", "password", "current-password")],
            "Sign in",
            error,
        )
        self.send_html(markup, status, [self.csrf_cookie(token)])

    def submit_login(self):
        fields = self.form()
        if fields is None or not self.form_trusted(fields):
            return self.send(403)
        if not login_by_address.reserve(self.address):
            return self.show_login("Too many tries. Wait 15 minutes, then try again.", 429)
        if not login_overall.reserve("all"):
            login_by_address.release(self.address)
            return self.show_login("Too many tries. Wait 15 minutes, then try again.", 429)
        connection = connect()
        try:
            owner = connection.execute("SELECT salt, password_hash FROM owner WHERE id = 1").fetchone()
            if owner is None:
                return self.redirect("/setup")
            supplied = hash_password(fields.get("password", ""), owner["salt"])
            if not hmac.compare_digest(supplied, owner["password_hash"]):
                return self.show_login("That password is not right.", 403)
            login_by_address.release(self.address)
            login_overall.release("all")
            token = secrets.token_urlsafe(32)
            connection.execute(
                "INSERT INTO sessions (token_hash, expires_at) VALUES (?, ?)",
                (token_hash(token), int(time.time()) + SESSION_SECONDS),
            )
        finally:
            connection.close()
        self.redirect(
            "/",
            [("Set-Cookie", f"__Host-session={token}; Path=/; Max-Age={SESSION_SECONDS}; Secure; HttpOnly; SameSite=Strict")],
        )

    def submit_logout(self):
        fields = self.form()
        if fields is None or not self.form_trusted(fields):
            return self.send(403)
        token = self.cookies().get("__Host-session")
        if token:
            connection = connect()
            try:
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
            finally:
                connection.close()
        self.redirect(
            "/login",
            [("Set-Cookie", "__Host-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")],
        )

    def show_dashboard(self):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        try:
            page_number = max(1, min(int(query.get("page", ["1"])[0]), 100000))
        except ValueError:
            page_number = 1
        now = int(time.time())
        connection = connect()
        try:
            day = connection.execute("SELECT count(*) FROM visits WHERE started_at > ?", (now - 86400,)).fetchone()[0]
            week = connection.execute("SELECT count(*) FROM visits WHERE started_at > ?", (now - 7 * 86400,)).fetchone()[0]
            message_count = connection.execute("SELECT count(*) FROM messages").fetchone()[0]
            visits = connection.execute(
                "SELECT * FROM visits ORDER BY started_at DESC, id LIMIT ? OFFSET ?",
                (PAGE_SIZE + 1, (page_number - 1) * PAGE_SIZE),
            ).fetchall()
            has_more = len(visits) > PAGE_SIZE
            visits = visits[:PAGE_SIZE]
            rows = "".join(
                render_visit(
                    visit,
                    connection.execute(
                        "SELECT at, kind, label FROM events WHERE visit_id = ? ORDER BY at, id", (visit["id"],)
                    ).fetchall(),
                )
                for visit in visits
            )
        finally:
            connection.close()

        links = []
        if page_number > 1:
            links.append(f'<a href="/?page={page_number - 1}">Newer visits</a>')
        if has_more:
            links.append(f'<a href="/?page={page_number + 1}">Older visits</a>')
        pager = f'<nav class="pager">{"".join(links)}</nav>' if links else ""
        listing = f'<ol class="visits">{rows}</ol>' if rows else (
            '<p class="empty">No visits yet. They appear here as soon as someone opens the site.</p>'
        )
        token = self.csrf_token()
        markup = page(
            "Analytics",
            page_header(token, "visits", message_count)
            + f'<main><h1>Visits</h1><p class="totals"><strong>{plural(day, "visit")}</strong> in the last 24 hours, '
            f"<strong>{week}</strong> in the last 7 days. Visit times are estimates. "
            f"Visits are deleted after {RETENTION_DAYS} days.</p>{listing}{pager}</main>",
        )
        self.send_html(markup, headers=[self.csrf_cookie(token)])

    def show_messages(self):
        token = self.csrf_token()
        connection = connect()
        try:
            rows = connection.execute("SELECT * FROM messages ORDER BY received_at DESC, id DESC LIMIT 200").fetchall()
            total = connection.execute("SELECT count(*) FROM messages").fetchone()[0]
        finally:
            connection.close()
        listing = (
            f'<ol class="visits">{"".join(render_message(row, token) for row in rows)}</ol>'
            if rows
            else '<p class="empty">No messages yet. Anything sent through the contact form appears here.</p>'
        )
        markup = page(
            "Messages",
            page_header(token, "messages", total)
            + f'<main><h1>Messages</h1><p class="totals">Messages are deleted after {MESSAGE_RETENTION_DAYS} days. '
            f"Showing the newest 200.</p>{listing}</main>",
        )
        self.send_html(markup, headers=[self.csrf_cookie(token)])

    def delete_message(self):
        fields = self.form()
        if fields is None or not self.form_trusted(fields) or not self.signed_in():
            return self.send(403)
        try:
            message_id = int(fields.get("id", ""))
        except ValueError:
            return self.send(400)
        connection = connect()
        try:
            connection.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        finally:
            connection.close()
        self.redirect("/messages")

    def query_value(self, name):
        return urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get(name, [""])[0]

    def requested_post(self):
        try:
            post_id = int(self.query_value("id"))
        except ValueError:
            return None
        connection = connect()
        try:
            return connection.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
        finally:
            connection.close()

    def dashboard_page(self, title, current, body):
        token = self.csrf_token()
        connection = connect()
        try:
            count = connection.execute("SELECT count(*) FROM messages").fetchone()[0]
        finally:
            connection.close()
        markup = page(title, page_header(token, current, count) + f"<main>{body(token)}</main>")
        self.send_html(markup, headers=[self.csrf_cookie(token)])

    def show_blog(self):
        connection = connect()
        try:
            posts = connection.execute(
                "SELECT * FROM posts ORDER BY published_at IS NOT NULL, published_at DESC, updated_at DESC"
            ).fetchall()
        finally:
            connection.close()
        notice = ""
        if self.query_value("problem"):
            notice = '<p class="error" role="alert">Your post is saved, but the public blog files could not be updated. Check the server log, then save again.</p>'
        elif self.query_value("error"):
            notice = '<p class="error" role="alert">That post could not be found.</p>'
        rows = []
        for post in posts:
            if post["published_at"] is not None:
                status = f'Published {short_date(post["published_at"])}'
                view = f' &middot; <a href="{public_post_url(self.headers.get("Host", ""), post["slug"])}" target="_blank" rel="noopener">View</a>'
            else:
                status = f'Draft, saved {short_date(post["updated_at"])}'
                view = ""
            rows.append(
                f'<li class="visit"><div class="visit-head"><h2><a href="/blog/edit?id={int(post["id"])}">{html.escape(post["title"])}</a></h2></div>'
                f'<p class="muted">{status} &middot; <a href="/blog/preview?id={int(post["id"])}">Preview</a>{view}</p></li>'
            )
        listing = f'<ol class="visits">{"".join(rows)}</ol>' if rows else '<p class="empty">No posts yet. Write your first one and save it as a draft or publish it.</p>'
        self.dashboard_page(
            "Blog",
            "blog",
            lambda token: f'<div class="title-row"><h1>Blog</h1><a class="button-link" href="/blog/new">New post</a></div>{notice}{listing}',
        )

    def show_editor(self, error="", values=None, status=200):
        post = values if values is not None else (self.requested_post() if self.route == "/blog/edit" else None)
        if self.route == "/blog/edit" and post is None and values is None:
            return self.redirect("/blog?error=1")
        current = post or {"id": "", "title": "", "summary": "", "body": "", "published_at": None}
        is_published = current["published_at"] is not None
        primary = "Update post" if is_published else "Publish"
        secondary = "" if is_published else '<button class="quiet" type="submit" name="action" value="draft">Save draft</button>'
        error_html = f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ""
        post_id = str(current["id"]) if current["id"] else ""

        def body(token):
            field = f'<input type="hidden" name="csrf" value="{html.escape(token)}"><input type="hidden" name="id" value="{html.escape(post_id)}">'
            tools = ""
            if post_id:
                confirm = "Delete this post permanently?"
                unpublish = (
                    f'<form method="post" action="/blog/unpublish"><input type="hidden" name="csrf" value="{html.escape(token)}">'
                    f'<input type="hidden" name="id" value="{html.escape(post_id)}"><button class="quiet" type="submit">Unpublish</button></form>'
                    if is_published
                    else ""
                )
                tools = (
                    f'<div class="post-tools">{unpublish}<form method="post" action="/blog/delete" data-confirm="{confirm}">'
                    f'<input type="hidden" name="csrf" value="{html.escape(token)}"><input type="hidden" name="id" value="{html.escape(post_id)}">'
                    '<button class="quiet danger" type="submit">Delete post</button></form></div>'
                )
            heading = "Edit post" if post_id else "New post"
            return (
                f'<a class="back" href="/blog">All posts</a><h1>{heading}</h1>{error_html}'
                f'<form class="editor" method="post" action="/blog/save">{field}'
                f'<label for="title">Title</label><input id="title" name="title" type="text" maxlength="{MAX_TITLE_LENGTH}" value="{html.escape(current["title"])}" required>'
                f'<label for="summary">Summary</label><input id="summary" name="summary" type="text" maxlength="{MAX_SUMMARY_LENGTH}" value="{html.escape(current["summary"])}">'
                '<p class="muted hint">One sentence shown in the post list. Optional.</p>'
                f'<label for="body">Post</label><textarea id="body" name="body" rows="20" maxlength="{MAX_POST_LENGTH}">{html.escape(current["body"])}</textarea>'
                '<p class="muted hint">Markdown: ## Heading, **bold**, *italic*, [link](https://example.org), - list, 1. list, &gt; quote, `code`, and ``` for code blocks. Images are not supported yet.</p>'
                f'<div class="editor-actions"><button type="submit" name="action" value="publish">{primary}</button>{secondary}</div></form>{tools}'
            )

        if status != 200:
            token = self.csrf_token()
            connection = connect()
            try:
                count = connection.execute("SELECT count(*) FROM messages").fetchone()[0]
            finally:
                connection.close()
            markup = page("Edit post", page_header(token, "blog", count) + f"<main>{body(token)}</main>")
            return self.send_html(markup, status, [self.csrf_cookie(token)])
        self.dashboard_page("Edit post", "blog", body)

    def show_preview(self):
        post = self.requested_post()
        if post is None:
            return self.redirect("/blog?error=1")
        self.dashboard_page(
            "Preview",
            "blog",
            lambda token: (
                f'<a class="back" href="/blog/edit?id={int(post["id"])}">Back to editing</a>'
                f'<p class="muted preview-note">Preview. Fonts and colors differ slightly on the real site.</p>'
                f'<article class="preview"><h1>{html.escape(post["title"])}</h1>{render_markdown(post["body"])}</article>'
            ),
        )

    def save_post(self):
        fields = self.form(MAX_BLOG_FORM_BODY)
        if fields is None or not self.form_trusted(fields) or not self.signed_in():
            return self.send(403)
        action = fields.get("action")
        if action not in ("draft", "publish"):
            return self.send(400)
        raw_id = fields.get("id", "")
        try:
            post_id = int(raw_id) if raw_id else None
        except ValueError:
            return self.send(400)
        title = clean_text(fields.get("title", ""), MAX_TITLE_LENGTH)
        summary_raw = fields.get("summary", "").strip()
        summary = clean_text(summary_raw, MAX_SUMMARY_LENGTH) if summary_raw else ""
        body_raw = fields.get("body", "").strip()
        body = clean_text(body_raw, MAX_POST_LENGTH) if body_raw else ""
        now = int(time.time())
        connection = connect()
        try:
            existing = connection.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone() if post_id else None
            if post_id and existing is None:
                return self.redirect("/blog?error=1")
            published_at = existing["published_at"] if existing else None
            entered = {
                "id": post_id or "",
                "title": fields.get("title", "")[:MAX_TITLE_LENGTH],
                "summary": summary_raw[:MAX_SUMMARY_LENGTH],
                "body": body_raw[:MAX_POST_LENGTH],
                "published_at": published_at,
            }
            problem = ""
            if not title:
                problem = f"Add a title of up to {MAX_TITLE_LENGTH} characters."
            elif summary is None:
                problem = f"Keep the summary to {MAX_SUMMARY_LENGTH} characters."
            elif body is None:
                problem = f"Keep the post to {MAX_POST_LENGTH} characters."
            elif action == "publish" and not body:
                problem = "Write something before publishing."
            if problem:
                return self.show_editor(problem, entered, 400)
            if action == "publish" and published_at is None:
                published_at = now
            if existing:
                connection.execute(
                    "UPDATE posts SET title = ?, summary = ?, body = ?, updated_at = ?, published_at = ? WHERE id = ?",
                    (title, summary, body, now, published_at, post_id),
                )
                saved_id = post_id
            else:
                saved_id = connection.execute(
                    "INSERT INTO posts (slug, title, summary, body, created_at, updated_at, published_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (make_slug(title, connection), title, summary, body, now, now, published_at),
                ).lastrowid
        finally:
            connection.close()
        if not publish_blog():
            return self.redirect("/blog?problem=1")
        self.redirect("/blog" if action == "publish" else f"/blog/edit?id={saved_id}")

    def change_post(self, change):
        fields = self.form()
        if fields is None or not self.form_trusted(fields) or not self.signed_in():
            return self.send(403)
        try:
            post_id = int(fields.get("id", ""))
        except ValueError:
            return self.send(400)
        connection = connect()
        try:
            if change == "delete":
                connection.execute("DELETE FROM posts WHERE id = ?", (post_id,))
            else:
                connection.execute("UPDATE posts SET published_at = NULL WHERE id = ?", (post_id,))
        finally:
            connection.close()
        self.redirect("/blog" if publish_blog() else "/blog?problem=1")

    def contact_reply(self, status, origin):
        self.send(status, headers=[("Access-Control-Allow-Origin", origin), ("Vary", "Origin")])

    def contact(self):
        origin = self.headers.get("Origin")
        if origin not in ALLOWED_ORIGINS:
            return self.send(403)
        body = self.read_body(MAX_CONTACT_BODY)
        if body is None:
            return self.contact_reply(413, origin)
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, ValueError, RecursionError):
            return self.contact_reply(400, origin)
        if not isinstance(payload, dict):
            return self.contact_reply(400, origin)
        name = clean_text(payload.get("name"), MAX_NAME_LENGTH)
        email = clean_text(payload.get("email"), MAX_EMAIL_LENGTH)
        message = clean_text(payload.get("message"), MAX_MESSAGE_LENGTH)
        if not name or not email or not message or not EMAIL.fullmatch(email):
            return self.contact_reply(400, origin)
        token = payload.get(TURNSTILE_FIELD)
        if self.is_public and (not isinstance(token, str) or not 0 < len(token) <= MAX_TURNSTILE_TOKEN):
            return self.contact_reply(403, origin)
        if not contact_by_address.reserve(self.address):
            return self.contact_reply(429, origin)
        if payload.get("website"):
            return self.contact_reply(204, origin)
        if self.is_public:
            passed = turnstile_passed(token, self.address)
            if passed is None:
                contact_by_address.release(self.address)
                return self.contact_reply(503, origin)
            if not passed:
                return self.contact_reply(403, origin)
        now = int(time.time())
        connection = connect()
        try:
            stored = connection.execute(
                "INSERT INTO messages (received_at, name, email, message) SELECT ?, ?, ?, ? "
                "WHERE (SELECT count(*) FROM messages WHERE received_at > ?) < ?",
                (now, name, email, message, now - 86400, MAX_MESSAGES_PER_DAY),
            ).rowcount
        finally:
            connection.close()
        if stored:
            mail_wake.set()
        self.contact_reply(204 if stored else 429, origin)

    def collect_done(self):
        self.send(204, headers=[("Cross-Origin-Resource-Policy", "cross-origin")])

    def collect(self):
        if self.headers.get("Origin") not in ALLOWED_ORIGINS:
            return self.send(403)
        body = self.read_body(MAX_COLLECT_BODY)
        if body is None:
            return self.send(413)
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, ValueError, RecursionError):
            return self.send(400)
        if not isinstance(payload, dict):
            return self.send(400)
        visit_id = payload.get("v")
        kind = payload.get("t")
        if not isinstance(visit_id, str) or not VISIT_ID.fullmatch(visit_id):
            return self.send(400)
        now = int(time.time())
        connection = connect()
        try:
            if kind == "view":
                return self.record_view(connection, visit_id, payload.get("p"), now)
            if kind in ("ping", "leave"):
                self.touch_visit(connection, visit_id, now)
                return self.collect_done()
            if kind == "click":
                return self.record_click(connection, visit_id, payload.get("l"), now)
            return self.send(400)
        finally:
            connection.close()

    def record_view(self, connection, visit_id, path, now):
        if not isinstance(path, str) or not PATH.fullmatch(path):
            return self.send(400)
        count = connection.execute("SELECT count(*) FROM visits WHERE started_at > ?", (now - 86400,)).fetchone()[0]
        if count >= MAX_VISITS_PER_DAY:
            return self.collect_done()
        if self.is_public:
            country = self.headers.get("X-Visitor-Country", "")
            country = country if COUNTRY.fullmatch(country) and country not in ("XX", "T1") else ""
            region = clean_place(self.headers.get("X-Visitor-Region"))
            city = clean_place(self.headers.get("X-Visitor-City"))
        else:
            country, region, city = "LAN", "", ""
        connection.execute(
            "INSERT OR IGNORE INTO visits (id, started_at, last_seen, path, country, region, city) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (visit_id, now, now, path, country, region, city),
        )
        self.collect_done()

    def touch_visit(self, connection, visit_id, now):
        return connection.execute(
            "UPDATE visits SET active_seconds = active_seconds + min(max(? - last_seen, 0), ?), last_seen = ? "
            "WHERE id = ? AND started_at > ?",
            (now, MAX_ACTIVE_STEP, now, visit_id, now - MAX_VISIT_SECONDS),
        ).rowcount

    def record_click(self, connection, visit_id, label, now):
        if not isinstance(label, str) or not LABEL.fullmatch(label):
            return self.send(400)
        if self.touch_visit(connection, visit_id, now):
            connection.execute(
                "INSERT INTO events (visit_id, at, kind, label) SELECT ?, ?, 'click', ? "
                "WHERE (SELECT count(*) FROM events WHERE visit_id = ?) < ?",
                (visit_id, now, label, visit_id, MAX_EVENTS_PER_VISIT),
            )
        self.collect_done()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


def reset_owner():
    init_db()
    connection = connect()
    try:
        connection.execute("DELETE FROM owner")
        connection.execute("DELETE FROM sessions")
    finally:
        connection.close()
    print("Owner password removed. Restart the service to get a new setup code.")


def run_checks():
    failed = False
    if mail_configured():
        subject, text = "Website contact form test", "Your website can send email to this inbox.\n"
        try:
            if site_secrets.get("mail_api_token"):
                send_api_mail(subject, text)
            else:
                mail = base_mail(subject)
                mail.set_content(text)
                send_mail(mail)
            print("Email: test message sent. Check your inbox.")
        except Exception as error:
            print(f"Email: failed, {type(error).__name__}")
            failed = True
    else:
        print("Email: not set up.")
        failed = True
    secret = site_secrets.get("turnstile_secret")
    if secret:
        result = siteverify(secret, "XXXX.DUMMY.TOKEN.XXXX") or {}
        codes = result.get("error-codes") or []
        if "invalid-input-response" in codes and "invalid-input-secret" not in codes:
            print("Turnstile: secret accepted.")
        else:
            print("Turnstile: failed, the secret was not accepted or Cloudflare could not be reached.")
            failed = True
    else:
        print("Turnstile: not set up.")
        failed = True
    return 1 if failed else 0


def save_secrets(settings):
    handle, temporary = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(SECRETS_FILE))
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            json.dump(settings, file)
        os.chmod(temporary, 0o640)
        shutil.chown(temporary, "root", "analytics")
        os.replace(temporary, SECRETS_FILE)
    except OSError:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    subprocess.run(["systemctl", "restart", "analytics"], check=True)
    site_secrets.update(settings)
    print("Saved. Running checks.")
    return run_checks()


def api_settings(token):
    mailbox, address = api_mailbox(token)
    return {"mail_api_token": token, "mail_api_mailbox": mailbox, "mail_api_to": address}


def set_mail_token():
    settings = read_secrets()
    settings.update(api_settings(sys.stdin.read().strip()))
    return save_secrets(settings)


def configure():
    current = read_secrets()

    def ask(label, key, fallback="", hidden=False):
        existing = current.get(key) or fallback
        if hidden:
            answer = getpass.getpass(f"{label}{' [keep current]' if existing else ''}: ")
        else:
            answer = input(f"{label}{f' [{existing}]' if existing else ''}: ")
        return answer.strip() or existing

    settings = dict(current)
    method = input("Send email with Hostinger's api or smtp [api]: ").strip().lower() or "api"
    if method == "api":
        token = ask("Hostinger Mail API token", "mail_api_token", hidden=True)
        if not token:
            sys.exit("The token is required.")
        settings.update(api_settings(token))
    elif method == "smtp":
        for key in ("mail_api_token", "mail_api_mailbox", "mail_api_to"):
            settings.pop(key, None)
        settings["mail_host"] = ask("Mail server for sending (SMTP)", "mail_host")
        settings["mail_port"] = ask("SMTP port, 465 or 587", "mail_port", "465")
        settings["mail_user"] = ask("Mailbox login", "mail_user")
        settings["mail_password"] = ask("Mailbox password", "mail_password", hidden=True)
        settings["mail_to"] = ask("Send website messages to", "mail_to", settings["mail_user"])
        settings["mail_from"] = ask("Send them from", "mail_from", settings["mail_user"])
        if not MAIL_HOST.fullmatch(settings["mail_host"]):
            sys.exit("That mail server name is not valid.")
        if settings["mail_port"] not in ("465", "587"):
            sys.exit("The port must be 465 or 587.")
        if not settings["mail_password"]:
            sys.exit("The mailbox password is required.")
        if not EMAIL.fullmatch(settings["mail_to"]) or not EMAIL.fullmatch(settings["mail_from"]):
            sys.exit("Those email addresses are not valid.")
    else:
        sys.exit("Choose api or smtp.")
    settings["turnstile_secret"] = ask("Turnstile secret key, or Enter to add it later", "turnstile_secret", hidden=True)
    return save_secrets(settings)


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "reset-owner":
        return reset_owner()
    if command == "configure":
        sys.exit(configure())
    if command == "set-mail-token":
        sys.exit(set_mail_token())
    site_secrets.update(read_secrets())
    if command == "check":
        sys.exit(run_checks())
    if not ALLOWED_ORIGINS:
        sys.exit("ALLOWED_ORIGINS must list at least one site origin.")
    init_db()
    prepare_setup_code()
    publish_blog()
    threading.Thread(target=purge_loop, daemon=True).start()
    threading.Thread(target=mail_loop, daemon=True).start()
    Server((BIND_HOST, BIND_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
