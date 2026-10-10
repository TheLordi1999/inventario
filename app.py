import json
import base64
import getpass
import hashlib
import hmac
import math
import os
import secrets
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("INVENTORY_DATA_DIR", str(BASE_DIR)))
DATA_FILE = DATA_DIR / "inventario.json"
ACCESS_FILE = DATA_DIR / "acceso.json"
MAX_REQUEST_SIZE = 1_000_000
SESSION_SECONDS = 8 * 60 * 60
LOGIN_WINDOW_SECONDS = 15 * 60
MAX_LOGIN_ATTEMPTS = 5
ACTIVE_SESSIONS = {}
LOGIN_ATTEMPTS = {}
ACCESS_CONFIG = None


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)


def initialize_access():
    global ACCESS_CONFIG
    if ACCESS_FILE.exists():
        try:
            with ACCESS_FILE.open("r", encoding="utf-8") as access_file:
                config = json.load(access_file)
            salt = base64.b64decode(config["salt"], validate=True)
            digest = base64.b64decode(config["password_hash"], validate=True)
            secret = base64.b64decode(config["session_secret"], validate=True)
            if len(salt) != 16 or len(digest) != 32 or len(secret) != 32:
                raise ValueError("El archivo de acceso tiene valores inválidos.")
            ACCESS_CONFIG = {"salt": salt, "password_hash": digest, "session_secret": secret}
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise RuntimeError(
                f"No se pudo leer {ACCESS_FILE.name}. Corrige el archivo o elimínalo para configurar una nueva contraseña."
            ) from error
        return

    configured_password = os.environ.get("INVENTORY_PASSWORD")
    if configured_password is not None:
        if len(configured_password) < 12:
            raise RuntimeError("INVENTORY_PASSWORD debe tener al menos 12 caracteres.")
        password = configured_password
        print("Configurando el acceso con la contraseña de INVENTORY_PASSWORD.")
    else:
        print("Configura una contraseña compartida para proteger el inventario.")
        password = None

    while True:
        if password is None:
            password = getpass.getpass("Nueva contraseña (mínimo 12 caracteres): ")
            if len(password) < 12:
                print("La contraseña debe tener al menos 12 caracteres.")
                continue
            confirmation = getpass.getpass("Confirma la contraseña: ")
            if password != confirmation:
                print("Las contraseñas no coinciden. Inténtalo de nuevo.")
                password = None
                continue
        salt = secrets.token_bytes(16)
        ACCESS_CONFIG = {
            "salt": salt,
            "password_hash": password_hash(password, salt),
            "session_secret": secrets.token_bytes(32),
        }
        config = {
            "salt": base64.b64encode(ACCESS_CONFIG["salt"]).decode("ascii"),
            "password_hash": base64.b64encode(ACCESS_CONFIG["password_hash"]).decode("ascii"),
            "session_secret": base64.b64encode(ACCESS_CONFIG["session_secret"]).decode("ascii"),
        }
        temporary_file = ACCESS_FILE.with_suffix(".tmp")
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            with temporary_file.open("w", encoding="utf-8") as access_file:
                json.dump(config, access_file)
                access_file.write("\n")
            temporary_file.replace(ACCESS_FILE)
        except OSError as error:
            ACCESS_CONFIG = None
            raise RuntimeError(f"No se pudo guardar la configuración de acceso: {error}") from error
        print("Contraseña configurada. Compártela solo con las personas autorizadas.")
        return


def make_session(session_id, expires_at):
    message = f"{session_id}.{expires_at}".encode("ascii")
    signature = hmac.new(ACCESS_CONFIG["session_secret"], message, hashlib.sha256).hexdigest()
    return f"{session_id}.{expires_at}.{signature}"


def valid_session(cookie_header):
    if not cookie_header:
        return None
    cookies = {}
    for part in cookie_header.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator:
            cookies[name] = value
    token = cookies.get("inventario_session", "")
    session_id, separator, remaining = token.partition(".")
    expires_text, separator, signature = remaining.partition(".")
    if not session_id or not separator or not expires_text or not signature:
        return None
    try:
        expires_at = int(expires_text)
    except ValueError:
        return None
    if expires_at <= int(time.time()) or ACTIVE_SESSIONS.get(session_id) != expires_at:
        ACTIVE_SESSIONS.pop(session_id, None)
        return None
    expected_token = make_session(session_id, expires_at)
    if not hmac.compare_digest(token, expected_token):
        return None
    return session_id


def read_items():
    if not DATA_FILE.exists():
        return []
    try:
        with DATA_FILE.open("r", encoding="utf-8") as data_file:
            items = json.load(data_file)
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"No se pudo leer {DATA_FILE.name}: {error}") from error
    if not isinstance(items, list):
        raise RuntimeError(f"El formato de {DATA_FILE.name} no es válido.")
    return items


def write_items(items):
    temporary_file = DATA_FILE.with_suffix(".tmp")
    try:
        with temporary_file.open("w", encoding="utf-8") as data_file:
            json.dump(items, data_file, ensure_ascii=False, indent=2)
            data_file.write("\n")
        temporary_file.replace(DATA_FILE)
    except OSError as error:
        raise RuntimeError(f"No se pudo guardar {DATA_FILE.name}: {error}") from error


def validate_item(data, items, current_id=None):
    if not isinstance(data, dict):
        raise ValueError("Los datos del producto no tienen un formato válido.")

    name = data.get("name")
    sku = data.get("sku")
    category = data.get("category")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 100:
        raise ValueError("Escribe un nombre de producto de 1 a 100 caracteres.")
    if not isinstance(sku, str) or not sku.strip() or len(sku.strip()) > 40:
        raise ValueError("Escribe un SKU de 1 a 40 caracteres.")
    if not isinstance(category, str) or not category.strip() or len(category.strip()) > 60:
        raise ValueError("Escribe una categoría de 1 a 60 caracteres.")

    normalized_sku = sku.strip().casefold()
    if any(
        item["id"] != current_id and item["sku"].casefold() == normalized_sku
        for item in items
    ):
        raise ValueError("Ya existe un producto con ese SKU.")

    numbers = {}
    for key, label, allow_decimal in (
        ("quantity", "Las existencias", False),
        ("min_stock", "El stock mínimo", False),
        ("price", "El precio", True),
    ):
        value = data.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{label} debe ser un número válido.")
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"{label} no puede ser negativo.")
        if not allow_decimal and not float(value).is_integer():
            raise ValueError(f"{label} debe ser un número entero.")
        numbers[key] = value if allow_decimal else int(value)

    return {
        "id": current_id or uuid.uuid4().hex,
        "name": name.strip(),
        "sku": sku.strip(),
        "category": category.strip(),
        **numbers,
    }


class InventoryHandler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("El tamaño de la solicitud no es válido.") from error
        if length <= 0 or length > MAX_REQUEST_SIZE:
            raise ValueError("La solicitud está vacía o supera el tamaño permitido.")
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("El contenido enviado no es JSON válido.") from error

    def is_authenticated(self):
        self.session_id = valid_session(self.headers.get("Cookie"))
        return self.session_id is not None

    def require_authentication(self):
        if self.is_authenticated():
            return True
        self.send_json(401, {"error": "Inicia sesión para continuar."})
        return False

    def send_session_cookie(self, value, max_age):
        secure = self.headers.get("X-Forwarded-Proto", "").lower() == "https"
        cookie = (
            f"inventario_session={value}; Path=/; HttpOnly; SameSite=Strict; "
            f"Max-Age={max_age}"
        )
        if secure:
            cookie += "; Secure"
        self.send_header("Set-Cookie", cookie)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self.send_json(200, {"status": "ok"})
            return
        if path == "/api/items":
            if not self.require_authentication():
                return
            try:
                self.send_json(200, {"items": read_items()})
            except RuntimeError as error:
                self.send_json(500, {"error": str(error)})
            return

        static_files = {
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
        }
        if path in ("/", "/inventario.html"):
            if not self.is_authenticated():
                self.send_response(303)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            static_files[path] = ("inventario.html", "text/html; charset=utf-8")
        elif path == "/login":
            if self.is_authenticated():
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                return
            static_files[path] = ("login.html", "text/html; charset=utf-8")
        requested_file = static_files.get(path)
        if requested_file is None:
            self.send_json(404, {"error": "No se encontró la página solicitada."})
            return
        filename, content_type = requested_file
        try:
            body = (BASE_DIR / filename).read_bytes()
        except OSError as error:
            self.send_json(500, {"error": f"No se pudo leer {filename}: {error}"})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/login":
            self.login()
            return
        if path == "/api/logout":
            self.logout()
            return
        if not self.require_authentication():
            return
        if path != "/api/items":
            self.send_json(404, {"error": "No se encontró el recurso solicitado."})
            return
        try:
            items = read_items()
            item = validate_item(self.read_json_body(), items)
            items.append(item)
            write_items(items)
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return
        except RuntimeError as error:
            self.send_json(500, {"error": str(error)})
            return
        self.send_json(201, {"item": item})

    def do_PUT(self):
        if not self.require_authentication():
            return
        item_id = self.item_id_from_path()
        if item_id is None:
            self.send_json(404, {"error": "No se encontró el recurso solicitado."})
            return
        try:
            items = read_items()
            index = next(
                (index for index, item in enumerate(items) if item.get("id") == item_id),
                None,
            )
            if index is None:
                self.send_json(404, {"error": "No se encontró el producto solicitado."})
                return
            item = validate_item(self.read_json_body(), items, item_id)
            items[index] = item
            write_items(items)
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return
        except RuntimeError as error:
            self.send_json(500, {"error": str(error)})
            return
        self.send_json(200, {"item": item})

    def do_DELETE(self):
        if not self.require_authentication():
            return
        item_id = self.item_id_from_path()
        if item_id is None:
            self.send_json(404, {"error": "No se encontró el recurso solicitado."})
            return
        try:
            items = read_items()
            remaining = [item for item in items if item.get("id") != item_id]
            if len(remaining) == len(items):
                self.send_json(404, {"error": "No se encontró el producto solicitado."})
                return
            write_items(remaining)
        except RuntimeError as error:
            self.send_json(500, {"error": str(error)})
            return
        self.send_json(200, {"deleted": item_id})

    def login(self):
        try:
            data = self.read_json_body()
            password = data.get("password") if isinstance(data, dict) else None
            if not isinstance(password, str) or len(password) > 1024:
                raise ValueError("Escribe una contraseña válida.")
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return

        client_ip = self.client_address[0]
        now = time.time()
        attempts = [timestamp for timestamp in LOGIN_ATTEMPTS.get(client_ip, []) if now - timestamp < LOGIN_WINDOW_SECONDS]
        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            LOGIN_ATTEMPTS[client_ip] = attempts
            self.send_json(429, {"error": "Demasiados intentos. Espera 15 minutos antes de volver a intentar."})
            return

        supplied_hash = password_hash(password, ACCESS_CONFIG["salt"])
        if not hmac.compare_digest(supplied_hash, ACCESS_CONFIG["password_hash"]):
            attempts.append(now)
            LOGIN_ATTEMPTS[client_ip] = attempts
            self.send_json(401, {"error": "La contraseña no es correcta."})
            return

        LOGIN_ATTEMPTS.pop(client_ip, None)
        session_id = secrets.token_urlsafe(32)
        expires_at = int(now) + SESSION_SECONDS
        ACTIVE_SESSIONS[session_id] = expires_at
        self.send_response(200)
        self.send_session_cookie(make_session(session_id, expires_at), SESSION_SECONDS)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        body = json.dumps({"ok": True}).encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def logout(self):
        self.is_authenticated()
        if self.session_id:
            ACTIVE_SESSIONS.pop(self.session_id, None)
        self.send_response(200)
        self.send_session_cookie("", 0)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        body = b'{"ok":true}'
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def item_id_from_path(self):
        parts = urlparse(self.path).path.split("/")
        if len(parts) == 4 and parts[1:3] == ["api", "items"] and parts[3]:
            return unquote(parts[3])
        return None

    def do_OPTIONS(self):
        self.send_json(405, {"error": "Método no permitido."})

    def log_message(self, format_string, *args):
        print(f"{self.log_date_time_string()} - {format_string % args}")


if __name__ == "__main__":
    try:
        initialize_access()
    except RuntimeError as error:
        raise SystemExit(str(error)) from error
    host = os.environ.get("HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("PORT", "8000"))
    except ValueError as error:
        raise SystemExit("PORT debe ser un número de puerto válido.") from error
    server = HTTPServer((host, port), InventoryHandler)
    display_host = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
    print(f"Inventario disponible en http://{display_host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        server.server_close()
