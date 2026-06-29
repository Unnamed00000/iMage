"""Local browser interface for Secret Image JSON."""

from __future__ import annotations

import io
import json
import os
from functools import wraps
from pathlib import Path

from cryptography.fernet import InvalidToken
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from PIL import UnidentifiedImageError

import main as core


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.urandom(32),
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
)

TEXT_FORMAT = "secret_text_v1"


def _plain_text_to_json(text: str) -> str:
    """Wrap arbitrary user text in valid JSON without exposing JSON syntax."""
    if not text.strip():
        raise ValueError("Please enter the secret text")
    return json.dumps(
        {"_format": TEXT_FORMAT, "text": text}, ensure_ascii=False, indent=2
    )


def _json_to_plain_text(json_text: str) -> str:
    """Return plain text from our wrapper, while keeping old JSON readable."""
    parsed = core.validate_json(json_text)
    if (
        isinstance(parsed, dict)
        and parsed.get("_format") == TEXT_FORMAT
        and isinstance(parsed.get("text"), str)
    ):
        return parsed["text"]
    # Compatibility with simple files created in the earlier interface.
    if (
        isinstance(parsed, dict)
        and set(parsed) == {"message"}
        and isinstance(parsed["message"], str)
    ):
        return parsed["message"]
    return json.dumps(parsed, ensure_ascii=False, indent=2)


def api_login_required(view):
    """Return a JSON error instead of exposing APIs before login."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify(error="Please log in again"), 401
        return view(*args, **kwargs)

    return wrapped


def _uploaded_image(field_name: str) -> tuple[bytes, str]:
    upload = request.files.get(field_name)
    if upload is None or not upload.filename:
        raise ValueError("Please choose an image")
    return upload.read(), upload.filename


def _image_response(image_bytes: bytes, filename: str):
    response = send_file(
        io.BytesIO(image_bytes),
        mimetype="image/jpeg",
        as_attachment=True,
        download_name=filename,
    )
    response.headers["X-Download-Name"] = filename
    return response


@app.get("/")
def index():
    if not core.AUTH_FILE.exists():
        return render_template("index.html", mode="setup")
    if not session.get("authenticated"):
        return render_template("index.html", mode="login")
    return render_template(
        "index.html",
        mode="workspace",
        current_user=session.get("username"),
        current_role=session.get("role"),
    )


@app.post("/setup")
def setup():
    if core.AUTH_FILE.exists():
        return redirect(url_for("index"))
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    confirmation = request.form.get("password_confirm", "")
    if password != confirmation:
        flash("Passwords do not match", "error")
        return redirect(url_for("index"))
    try:
        core.save_admin_credentials(username, password)
    except (OSError, ValueError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))
    flash("Administrator account created. Please log in.", "success")
    return redirect(url_for("index"))


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    try:
        profile = core.authenticate_user(username, password)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))
    if profile is None:
        flash("Wrong login or password", "error")
        return redirect(url_for("index"))
    session.clear()
    session["authenticated"] = True
    session["username"] = profile["username"]
    session["role"] = profile["role"]
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if not core.AUTH_FILE.exists():
        return redirect(url_for("index"))

    session_admin = session.get("authenticated") and session.get("role") == "admin"
    if request.method == "GET":
        return render_template(
            "index.html", mode="register", authorized_session=session_admin
        )

    if not session_admin:
        admin_username = request.form.get("admin_username", "")
        admin_password = request.form.get("admin_password", "")
        try:
            authorizer = core.authenticate_user(admin_username, admin_password)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("register"))
        if authorizer is None or authorizer["role"] != "admin":
            flash("Administrator login or password is incorrect", "error")
            return redirect(url_for("register"))

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    confirmation = request.form.get("password_confirm", "")
    role = request.form.get("role", "user")
    if password != confirmation:
        flash("Passwords do not match", "error")
        return redirect(url_for("register"))
    try:
        core.create_user_credentials(username, password, role)
    except (OSError, ValueError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("register"))

    flash(f"Profile {username.strip()} created successfully", "success")
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.post("/api/validate")
@api_login_required
def api_validate():
    json_text = (request.get_json(silent=True) or {}).get("json", "")
    try:
        core.validate_json(json_text)
    except json.JSONDecodeError as exc:
        return jsonify(
            error=f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ), 400
    return jsonify(message="JSON is valid")


@app.post("/api/create")
@api_login_required
def api_create():
    try:
        image_bytes, original_filename = _uploaded_image("image")
        plain_text = request.form.get("text")
        json_text = (
            _plain_text_to_json(plain_text)
            if plain_text is not None
            else request.form.get("json", "")
        )
        password = request.form.get("password", "")
        result_bytes = core.create_secret_image_bytes(image_bytes, json_text, password)
    except json.JSONDecodeError as exc:
        return jsonify(
            error=f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ), 400
    except (OSError, UnidentifiedImageError, ValueError) as exc:
        return jsonify(error=str(exc)), 400
    original_name = Path(original_filename).stem
    return _image_response(result_bytes, f"{original_name}_secret.jpg")


@app.post("/api/extract")
@api_login_required
def api_extract():
    try:
        image_bytes, _filename = _uploaded_image("image")
        password = request.form.get("password", "")
        if not password:
            raise ValueError("Please enter a password")
        extracted = core.extract_secret_json_bytes(image_bytes, password)
        plain_text = _json_to_plain_text(extracted)
    except (LookupError, InvalidToken, OSError, ValueError):
        return jsonify(error="Неверный пароль или секрет не найден"), 400
    return jsonify(text=plain_text)


@app.post("/api/update")
@api_login_required
def api_update():
    try:
        image_bytes, original_filename = _uploaded_image("image")
        plain_text = request.form.get("text")
        json_text = (
            _plain_text_to_json(plain_text)
            if plain_text is not None
            else request.form.get("json", "")
        )
        password = request.form.get("password", "")
        result_bytes = core.create_secret_image_bytes(image_bytes, json_text, password)
    except json.JSONDecodeError as exc:
        return jsonify(
            error=f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ), 400
    except (OSError, UnidentifiedImageError, ValueError) as exc:
        return jsonify(error=str(exc)), 400
    original_name = Path(original_filename).stem
    return _image_response(result_bytes, f"{original_name}_updated.jpg")


@app.errorhandler(413)
def file_too_large(_error):
    if request.path.startswith("/api/"):
        return jsonify(error="The selected file is larger than 50 MB"), 413
    return "The selected file is larger than 50 MB", 413


def run() -> None:
    app.run(host="127.0.0.1", port=5055, debug=False)


if __name__ == "__main__":
    run()
