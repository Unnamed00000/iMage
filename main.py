"""Secret Image JSON - hide encrypted JSON data inside a JPEG image."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image, ImageOps, UnidentifiedImageError


APP_NAME = "Secret Image JSON"
# V2 marker is deliberately non-textual. It is a fixed 16-byte binary
# signature used only to locate the encrypted payload at the end of a JPEG.
SECRET_MARKER = bytes.fromhex("9f3a7cc2e84d11b6a501d8734ef092bd")
LEGACY_SECRET_MARKER = b"---SECRET_JSON_START_V1---"
SALT_SIZE = 16
PBKDF2_ITERATIONS = 600_000
AUTH_ITERATIONS = 600_000


def _auth_file_path() -> Path:
    """Return the per-user path used for the local administrator account."""
    app_data = os.environ.get("APPDATA")
    if app_data:
        return Path(app_data) / "SecretImageJSON" / "auth.json"
    return Path.home() / ".secret_image_json" / "auth.json"


AUTH_FILE = _auth_file_path()


def _auth_digest(password: str, salt: bytes) -> bytes:
    """Create a one-way password digest for the local login screen."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, AUTH_ITERATIONS, dklen=32
    )


def _credential_record(username: str, password: str, role: str) -> dict:
    """Build one password-hash record without storing a plain password."""
    username = username.strip()
    if not username:
        raise ValueError("Login cannot be empty")
    if len(password) < 6:
        raise ValueError("Password must contain at least 6 characters")
    if role not in {"admin", "user"}:
        raise ValueError("Unknown account role")

    salt = os.urandom(SALT_SIZE)
    return {
        "username": username,
        "role": role,
        "salt": base64.b64encode(salt).decode("ascii"),
        "password_hash": base64.b64encode(_auth_digest(password, salt)).decode(
            "ascii"
        ),
    }


def _load_credentials() -> dict:
    """Load all profiles and transparently understand the original format."""
    try:
        data = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
        if data.get("version") == 1:
            users = [
                {
                    "username": data["username"],
                    "role": "admin",
                    "salt": data["salt"],
                    "password_hash": data["password_hash"],
                }
            ]
        elif data.get("version") == 2 and isinstance(data.get("users"), list):
            users = data["users"]
        else:
            raise ValueError

        for user in users:
            if not isinstance(user["username"], str) or user["role"] not in {
                "admin",
                "user",
            }:
                raise ValueError
            base64.b64decode(user["salt"], validate=True)
            base64.b64decode(user["password_hash"], validate=True)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("The account settings file is damaged") from exc
    return {"version": 2, "users": users}


def _write_credentials(data: dict) -> None:
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTH_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def save_admin_credentials(username: str, password: str) -> None:
    """Create the first local administrator account."""
    _write_credentials(
        {"version": 2, "users": [_credential_record(username, password, "admin")]}
    )


def create_user_credentials(username: str, password: str, role: str) -> None:
    """Add an administrator or user profile to the local account file."""
    data = _load_credentials()
    normalized = username.strip().casefold()
    if any(user["username"].casefold() == normalized for user in data["users"]):
        raise ValueError("A profile with this login already exists")
    data["users"].append(_credential_record(username, password, role))
    _write_credentials(data)


def authenticate_user(username: str, password: str) -> dict | None:
    """Return a safe profile summary when the supplied password is correct."""
    normalized = username.strip().casefold()
    for user in _load_credentials()["users"]:
        if user["username"].casefold() != normalized:
            continue
        salt = base64.b64decode(user["salt"], validate=True)
        stored_digest = base64.b64decode(user["password_hash"], validate=True)
        if hmac.compare_digest(_auth_digest(password, salt), stored_digest):
            return {"username": user["username"], "role": user["role"]}
        return None
    return None


def verify_admin_credentials(username: str, password: str) -> bool:
    """Compatibility helper used by the desktop login screen."""
    return authenticate_user(username, password) is not None


def validate_json(json_text: str):
    """Parse JSON text and return the resulting Python value.

    json.JSONDecodeError is raised when the text is not valid JSON.
    """
    return json.loads(json_text)


def make_key(password: str, salt: bytes) -> bytes:
    """Create a Fernet-compatible key from a password and salt."""
    if not password:
        raise ValueError("Password cannot be empty")
    if len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _image_as_jpeg_bytes(image_bytes: bytes) -> bytes:
    """Decode a JPG/PNG and return a clean, viewer-compatible JPEG."""
    with Image.open(io.BytesIO(image_bytes)) as source:
        image = ImageOps.exif_transpose(source)

        # JPEG has no transparency. Put transparent pixels on a white background.
        if image.mode in ("RGBA", "LA") or (
            image.mode == "P" and "transparency" in image.info
        ):
            rgba = image.convert("RGBA")
            background = Image.new("RGBA", rgba.size, "white")
            image = Image.alpha_composite(background, rgba).convert("RGB")
        else:
            image = image.convert("RGB")

        output = io.BytesIO()
        image.save(output, format="JPEG", quality=95, optimize=True)
        return output.getvalue()


def _save_as_jpeg(image_path: str | Path, output_path: str | Path) -> None:
    """Path-based wrapper used by the desktop interface."""
    if Path(image_path).resolve() == Path(output_path).resolve():
        raise ValueError("Please save the secret image under a new file name")
    Path(output_path).write_bytes(
        _image_as_jpeg_bytes(Path(image_path).read_bytes())
    )


def create_secret_image_bytes(
    image_bytes: bytes, json_text: str, password: str
) -> bytes:
    """Return a JPEG containing a binary encrypted payload entirely in memory."""
    validate_json(json_text)
    salt = os.urandom(SALT_SIZE)
    fernet_token = Fernet(make_key(password, salt)).encrypt(json_text.encode("utf-8"))
    encrypted_json = base64.urlsafe_b64decode(fernet_token)
    return _image_as_jpeg_bytes(image_bytes) + SECRET_MARKER + salt + encrypted_json


def create_secret_image(
    image_path: str | Path,
    json_text: str,
    password: str,
    output_path: str | Path,
) -> None:
    """Create a JPEG whose trailing bytes contain encrypted JSON."""
    output_path = Path(output_path)
    if Path(image_path).resolve() == output_path.resolve():
        raise ValueError("Please save the secret image under a new file name")
    output_path.write_bytes(
        create_secret_image_bytes(Path(image_path).read_bytes(), json_text, password)
    )


def extract_secret_json_bytes(image_bytes: bytes, password: str) -> str:
    """Extract and decrypt JSON directly from in-memory image bytes."""
    marker_position = image_bytes.rfind(SECRET_MARKER)
    legacy_format = marker_position == -1
    marker = LEGACY_SECRET_MARKER if legacy_format else SECRET_MARKER
    if legacy_format:
        marker_position = image_bytes.rfind(marker)
    if marker_position == -1:
        raise LookupError("Secret payload not found")

    payload = image_bytes[marker_position + len(marker) :]
    if len(payload) <= SALT_SIZE:
        raise InvalidToken

    salt = payload[:SALT_SIZE]
    encrypted_json = payload[SALT_SIZE:]
    if not legacy_format:
        encrypted_json = base64.urlsafe_b64encode(encrypted_json)
    try:
        decrypted = Fernet(make_key(password, salt)).decrypt(encrypted_json)
        json_text = decrypted.decode("utf-8")
        validate_json(json_text)
    except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise InvalidToken from exc

    return json_text


def extract_secret_json(image_path: str | Path, password: str) -> str:
    """Extract, decrypt, and validate JSON stored in an image."""
    return extract_secret_json_bytes(Path(image_path).read_bytes(), password)


class SecretImageApp(tk.Tk):
    """Tkinter user interface for creating and reading secret images."""

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("850x690")
        self.minsize(680, 570)

        self.create_image_path = tk.StringVar()
        self.extract_image_path = tk.StringVar()
        self.create_password = tk.StringVar()
        self.extract_password = tk.StringVar()
        self.loaded_secret_image: str | None = None

        self._configure_style()
        self._show_auth_screen()

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("TButton", padding=(12, 7))
        style.configure("Primary.TButton", padding=(14, 9))
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Hint.TLabel", foreground="#5f6368")

    def _clear_window(self) -> None:
        for child in self.winfo_children():
            child.destroy()

    def _show_auth_screen(self) -> None:
        self._clear_window()
        self.create_password.set("")
        self.extract_password.set("")

        outer = ttk.Frame(self, padding=24)
        outer.pack(fill="both", expand=True)
        card = ttk.Frame(outer, padding=30)
        card.place(relx=0.5, rely=0.48, anchor="center")

        if AUTH_FILE.exists():
            self._build_login_form(card)
        else:
            self._build_setup_form(card)

    def _build_login_form(self, card: ttk.Frame) -> None:
        self.login_username = tk.StringVar()
        self.login_password = tk.StringVar()

        ttk.Label(card, text=APP_NAME, style="Title.TLabel").grid(
            row=0, column=0, columnspan=2, pady=(0, 5)
        )
        ttk.Label(
            card,
            text="Administrator login",
            style="Hint.TLabel",
        ).grid(row=1, column=0, columnspan=2, pady=(0, 22))
        ttk.Label(card, text="Login").grid(row=2, column=0, sticky="w", padx=(0, 12))
        login_entry = ttk.Entry(card, textvariable=self.login_username, width=34)
        login_entry.grid(row=2, column=1, sticky="ew", pady=5)
        ttk.Label(card, text="Password").grid(
            row=3, column=0, sticky="w", padx=(0, 12)
        )
        password_entry = ttk.Entry(
            card, textvariable=self.login_password, show="\u2022", width=34
        )
        password_entry.grid(row=3, column=1, sticky="ew", pady=5)
        ttk.Button(
            card, text="Log in", style="Primary.TButton", command=self._login
        ).grid(row=4, column=0, columnspan=2, sticky="e", pady=(20, 0))

        login_entry.bind("<Return>", lambda _event: password_entry.focus_set())
        password_entry.bind("<Return>", lambda _event: self._login())
        login_entry.focus_set()

    def _build_setup_form(self, card: ttk.Frame) -> None:
        self.setup_username = tk.StringVar(value="admin")
        self.setup_password = tk.StringVar()
        self.setup_password_confirm = tk.StringVar()

        ttk.Label(card, text=APP_NAME, style="Title.TLabel").grid(
            row=0, column=0, columnspan=2, pady=(0, 5)
        )
        ttk.Label(
            card,
            text="Create the administrator account for first launch",
            style="Hint.TLabel",
        ).grid(row=1, column=0, columnspan=2, pady=(0, 22))
        ttk.Label(card, text="Login").grid(row=2, column=0, sticky="w", padx=(0, 12))
        ttk.Entry(card, textvariable=self.setup_username, width=34).grid(
            row=2, column=1, sticky="ew", pady=5
        )
        ttk.Label(card, text="Password").grid(
            row=3, column=0, sticky="w", padx=(0, 12)
        )
        ttk.Entry(
            card, textvariable=self.setup_password, show="\u2022", width=34
        ).grid(row=3, column=1, sticky="ew", pady=5)
        ttk.Label(card, text="Confirm password").grid(
            row=4, column=0, sticky="w", padx=(0, 12)
        )
        confirm_entry = ttk.Entry(
            card, textvariable=self.setup_password_confirm, show="\u2022", width=34
        )
        confirm_entry.grid(row=4, column=1, sticky="ew", pady=5)
        ttk.Button(
            card,
            text="Create account",
            style="Primary.TButton",
            command=self._register_admin,
        ).grid(row=5, column=0, columnspan=2, sticky="e", pady=(20, 0))
        confirm_entry.bind("<Return>", lambda _event: self._register_admin())

    def _register_admin(self) -> None:
        username = self.setup_username.get()
        password = self.setup_password.get()
        if password != self.setup_password_confirm.get():
            messagebox.showerror(
                "Account not created", "Passwords do not match", parent=self
            )
            return
        try:
            save_admin_credentials(username, password)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Account not created", str(exc), parent=self)
            return

        self.setup_password.set("")
        self.setup_password_confirm.set("")
        messagebox.showinfo(
            "Account created", "Administrator account created successfully", parent=self
        )
        self._show_auth_screen()

    def _login(self) -> None:
        username = self.login_username.get()
        password = self.login_password.get()
        try:
            authenticated = verify_admin_credentials(username, password)
        except ValueError as exc:
            messagebox.showerror("Login failed", str(exc), parent=self)
            return
        finally:
            self.login_password.set("")

        if not authenticated:
            messagebox.showerror("Login failed", "Wrong login or password", parent=self)
            return
        self._build_ui()

    def _log_out(self) -> None:
        self.create_image_path.set("")
        self.extract_image_path.set("")
        self.loaded_secret_image = None
        self._show_auth_screen()

    def _build_ui(self) -> None:
        self._clear_window()
        outer = ttk.Frame(self, padding=16)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 12))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            header,
            text="Hide, open, and edit encrypted JSON inside ordinary JPG files.",
            style="Hint.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))
        ttk.Button(header, text="Log out", command=self._log_out).grid(
            row=0, column=1, rowspan=2, sticky="e", padx=(15, 0)
        )
        ttk.Button(header, text="Exit", command=self.destroy).grid(
            row=0, column=2, rowspan=2, sticky="e", padx=(8, 0)
        )

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)

        create_tab = ttk.Frame(notebook, padding=16)
        extract_tab = ttk.Frame(notebook, padding=16)
        notebook.add(create_tab, text="Create Secret Image")
        notebook.add(extract_tab, text="Open / Edit Secret Image")

        self._build_create_tab(create_tab)
        self._build_extract_tab(extract_tab)

    @staticmethod
    def _add_path_row(
        parent: ttk.Frame,
        row: int,
        variable: tk.StringVar,
        button_text: str,
        command,
    ) -> None:
        ttk.Button(parent, text=button_text, command=command).grid(
            row=row, column=0, sticky="w", padx=(0, 10)
        )
        ttk.Entry(parent, textvariable=variable, state="readonly").grid(
            row=row, column=1, sticky="ew"
        )

    def _build_create_tab(self, tab: ttk.Frame) -> None:
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(2, weight=1)

        self._add_path_row(
            tab,
            0,
            self.create_image_path,
            "Choose Image",
            self._choose_source_image,
        )

        ttk.Label(tab, text="JSON content").grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(16, 5)
        )
        json_frame = ttk.Frame(tab)
        json_frame.grid(row=2, column=0, columnspan=2, sticky="nsew")
        json_frame.columnconfigure(0, weight=1)
        json_frame.rowconfigure(0, weight=1)
        self.create_json_text = tk.Text(
            json_frame,
            wrap="none",
            undo=True,
            font=("Consolas", 10),
            padx=8,
            pady=8,
        )
        create_scroll_y = ttk.Scrollbar(
            json_frame, orient="vertical", command=self.create_json_text.yview
        )
        create_scroll_x = ttk.Scrollbar(
            json_frame, orient="horizontal", command=self.create_json_text.xview
        )
        self.create_json_text.configure(
            yscrollcommand=create_scroll_y.set, xscrollcommand=create_scroll_x.set
        )
        self.create_json_text.grid(row=0, column=0, sticky="nsew")
        create_scroll_y.grid(row=0, column=1, sticky="ns")
        create_scroll_x.grid(row=1, column=0, sticky="ew")

        ttk.Button(tab, text="Validate JSON", command=self._validate_create_json).grid(
            row=3, column=0, sticky="w", pady=(12, 0)
        )

        password_frame = ttk.Frame(tab)
        password_frame.grid(
            row=4, column=0, columnspan=2, sticky="ew", pady=(14, 0)
        )
        password_frame.columnconfigure(1, weight=1)
        ttk.Label(password_frame, text="Password").grid(
            row=0, column=0, sticky="w", padx=(0, 10)
        )
        ttk.Entry(
            password_frame,
            textvariable=self.create_password,
            show="\u2022",
        ).grid(row=0, column=1, sticky="ew")

        ttk.Button(
            tab,
            text="Create Secret Image",
            style="Primary.TButton",
            command=self._create_secret_image,
        ).grid(row=5, column=0, columnspan=2, sticky="e", pady=(18, 0))

    def _build_extract_tab(self, tab: ttk.Frame) -> None:
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(4, weight=1)

        self._add_path_row(
            tab,
            0,
            self.extract_image_path,
            "Choose Secret Image",
            self._choose_secret_image,
        )

        password_frame = ttk.Frame(tab)
        password_frame.grid(
            row=1, column=0, columnspan=2, sticky="ew", pady=(16, 0)
        )
        password_frame.columnconfigure(1, weight=1)
        ttk.Label(password_frame, text="Password").grid(
            row=0, column=0, sticky="w", padx=(0, 10)
        )
        ttk.Entry(
            password_frame,
            textvariable=self.extract_password,
            show="\u2022",
        ).grid(row=0, column=1, sticky="ew")

        ttk.Button(
            tab,
            text="Extract JSON",
            style="Primary.TButton",
            command=self._extract_json,
        ).grid(row=2, column=0, columnspan=2, sticky="e", pady=(14, 0))

        ttk.Label(tab, text="Extracted JSON").grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(16, 5)
        )
        result_frame = ttk.Frame(tab)
        result_frame.grid(row=4, column=0, columnspan=2, sticky="nsew")
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        self.result_text = tk.Text(
            result_frame,
            wrap="none",
            state="disabled",
            font=("Consolas", 10),
            padx=8,
            pady=8,
        )
        result_scroll_y = ttk.Scrollbar(
            result_frame, orient="vertical", command=self.result_text.yview
        )
        result_scroll_x = ttk.Scrollbar(
            result_frame, orient="horizontal", command=self.result_text.xview
        )
        self.result_text.configure(
            yscrollcommand=result_scroll_y.set, xscrollcommand=result_scroll_x.set
        )
        self.result_text.grid(row=0, column=0, sticky="nsew")
        result_scroll_y.grid(row=0, column=1, sticky="ns")
        result_scroll_x.grid(row=1, column=0, sticky="ew")

        actions = ttk.Frame(tab)
        actions.grid(row=5, column=0, columnspan=2, sticky="e", pady=(14, 0))
        self.save_json_button = ttk.Button(
            actions, text="Save JSON", command=self._save_json, state="disabled"
        )
        self.save_json_button.pack(side="left")
        self.save_updated_image_button = ttk.Button(
            actions,
            text="Save Updated Secret Image",
            style="Primary.TButton",
            command=self._save_updated_secret_image,
            state="disabled",
        )
        self.save_updated_image_button.pack(side="left", padx=(10, 0))

    def _choose_source_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose Image",
            filetypes=[
                ("Image files", "*.jpg *.jpeg *.png"),
                ("JPEG files", "*.jpg *.jpeg"),
                ("PNG files", "*.png"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.create_image_path.set(path)

    def _choose_secret_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose Secret Image",
            filetypes=[
                ("JPEG images", "*.jpg *.jpeg"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.extract_image_path.set(path)
            self.loaded_secret_image = None
            self.result_text.configure(state="normal")
            self.result_text.delete("1.0", "end")
            self.result_text.configure(state="disabled")
            self.save_json_button.configure(state="disabled")
            self.save_updated_image_button.configure(state="disabled")

    def _validate_create_json(self) -> bool:
        json_text = self.create_json_text.get("1.0", "end-1c")
        try:
            validate_json(json_text)
        except json.JSONDecodeError as exc:
            messagebox.showerror(
                "Invalid JSON",
                f"Invalid JSON at line {exc.lineno}, column {exc.colno}:\n{exc.msg}",
                parent=self,
            )
            return False
        messagebox.showinfo("Valid JSON", "JSON is valid", parent=self)
        return True

    def _create_secret_image(self) -> None:
        image_path = self.create_image_path.get()
        json_text = self.create_json_text.get("1.0", "end-1c")
        password = self.create_password.get()

        if not image_path:
            messagebox.showerror("Missing image", "Please choose a JPG or PNG image.")
            return
        if not password:
            messagebox.showerror("Missing password", "Please enter a password.")
            return
        try:
            validate_json(json_text)
        except json.JSONDecodeError as exc:
            messagebox.showerror(
                "Invalid JSON",
                f"Invalid JSON at line {exc.lineno}, column {exc.colno}:\n{exc.msg}",
            )
            return

        source = Path(image_path)
        output_path = filedialog.asksaveasfilename(
            title="Save Secret Image As",
            defaultextension=".jpg",
            initialfile=f"{source.stem}_secret.jpg",
            filetypes=[("JPEG image", "*.jpg *.jpeg")],
        )
        if not output_path:
            return

        try:
            create_secret_image(image_path, json_text, password, output_path)
        except (OSError, UnidentifiedImageError, ValueError) as exc:
            messagebox.showerror("Could not create image", str(exc), parent=self)
            return

        messagebox.showinfo(
            "Success", "Secret image created successfully", parent=self
        )

    def _extract_json(self) -> None:
        image_path = self.extract_image_path.get()
        password = self.extract_password.get()
        if not image_path:
            messagebox.showerror(
                "Missing image", "Please choose a secret image.", parent=self
            )
            return
        if not password:
            messagebox.showerror(
                "Missing password", "Please enter a password.", parent=self
            )
            return

        try:
            extracted = extract_secret_json(image_path, password)
        except LookupError:
            messagebox.showerror(
                "Ошибка извлечения",
                "Неверный пароль или секрет не найден",
                parent=self,
            )
            return
        except (InvalidToken, OSError, ValueError):
            messagebox.showerror(
                "Ошибка извлечения",
                "Неверный пароль или секрет не найден",
                parent=self,
            )
            return

        parsed = validate_json(extracted)
        display_json = json.dumps(parsed, ensure_ascii=False, indent=2)
        self.loaded_secret_image = image_path
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", display_json)
        self.save_json_button.configure(state="normal")
        self.save_updated_image_button.configure(state="normal")

    def _edited_json(self) -> str | None:
        json_text = self.result_text.get("1.0", "end-1c")
        try:
            validate_json(json_text)
        except json.JSONDecodeError as exc:
            messagebox.showerror(
                "Invalid JSON",
                f"Invalid JSON at line {exc.lineno}, column {exc.colno}:\n{exc.msg}",
                parent=self,
            )
            return None
        return json_text

    def _save_updated_secret_image(self) -> None:
        if self.loaded_secret_image is None:
            return
        json_text = self._edited_json()
        if json_text is None:
            return
        password = self.extract_password.get()
        if not password:
            messagebox.showerror(
                "Missing password", "Please enter a password.", parent=self
            )
            return

        source = Path(self.loaded_secret_image)
        output_path = filedialog.asksaveasfilename(
            title="Save Updated Secret Image As",
            defaultextension=".jpg",
            initialfile=f"{source.stem}_updated.jpg",
            filetypes=[("JPEG image", "*.jpg *.jpeg")],
        )
        if not output_path:
            return
        try:
            create_secret_image(source, json_text, password, output_path)
        except (OSError, UnidentifiedImageError, ValueError) as exc:
            messagebox.showerror("Could not save image", str(exc), parent=self)
            return
        messagebox.showinfo(
            "Success", "Secret image updated successfully", parent=self
        )

    def _save_json(self) -> None:
        if self.loaded_secret_image is None:
            return
        json_text = self._edited_json()
        if json_text is None:
            return
        output_path = filedialog.asksaveasfilename(
            title="Save JSON",
            defaultextension=".json",
            initialfile="extracted.json",
            filetypes=[("JSON file", "*.json"), ("All files", "*.*")],
        )
        if not output_path:
            return
        try:
            Path(output_path).write_text(json_text + "\n", encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Could not save JSON", str(exc), parent=self)
            return
        messagebox.showinfo("Saved", "JSON saved successfully", parent=self)


def main() -> None:
    app = SecretImageApp()
    app.mainloop()


if __name__ == "__main__":
    main()
