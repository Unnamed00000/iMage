import { PBKDF2_ITERATIONS, bytesToBase64, deriveKeyBytes, randomBytes } from "./pwa-crypto.js";

const USERS_KEY = "secret-image-json-users-v2";
const SESSION_KEY = "secret-image-json-session-v2";
const DOWNLOAD_LABELS = {
  ru: {
    image: "Скачать изображение",
    zip: "Скачать ZIP",
    imageReady: "Изображение скачано",
    missing: "Сначала создайте или обновите секретное изображение",
    warning: "Можно скачать отдельное изображение или ZIP-архив. Для отправки через мессенджер безопаснее использовать ZIP или отправлять изображение как файл/документ.",
  },
  en: {
    image: "Download image",
    zip: "Download ZIP",
    imageReady: "Image downloaded",
    missing: "Create or update a secret image first",
    warning: "You can download the image itself or a ZIP archive. For messengers, ZIP is safer, or send the image as a file/document.",
  },
  da: {
    image: "Hent billede",
    zip: "Hent ZIP",
    imageReady: "Billedet er hentet",
    missing: "Opret eller opdater først et hemmeligt billede",
    warning: "Du kan hente selve billedet eller et ZIP-arkiv. Til beskedapps er ZIP mere sikkert, eller send billedet som fil/dokument.",
  },
};

function currentLanguage() {
  const value = document.documentElement.lang || localStorage.getItem("secret-image-json-language-v1") || "ru";
  return Object.hasOwn(DOWNLOAD_LABELS, value) ? value : "ru";
}

function text() {
  return DOWNLOAD_LABELS[currentLanguage()];
}

function users() {
  try {
    const value = JSON.parse(localStorage.getItem(USERS_KEY) || "[]");
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

function saveUsers(value) {
  localStorage.setItem(USERS_KEY, JSON.stringify(value));
}

function showToast(message, error = false) {
  const toast = document.querySelector("#toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.toggle("error", error);
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 3500);
}

function injectStyles() {
  const style = document.createElement("style");
  style.textContent = `
    .download-choice {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 9px;
      margin-top: 12px;
    }
    .download-choice .secondary { width: 100%; }
    .security-downloads { margin-top: 12px; }
    .build-code-line {
      margin-top: 9px !important;
      font-family: "Cascadia Code", Consolas, monospace;
      font-size: 11px;
      letter-spacing: .04em;
    }
    .auth-link-row {
      display: grid;
      grid-template-columns: 1fr;
      gap: 9px;
      margin-top: 12px;
    }
    .auth-link-row .ghost,
    .auth-link-row .secondary { width: 100%; }
    .auth-help-text { margin-top: 12px; color: var(--muted); font-size: 13px; line-height: 1.5; }
    @media (max-width: 420px) {
      .download-choice { grid-template-columns: 1fr; }
    }
  `;
  document.head.appendChild(style);
}

function authCard(id) {
  ["login-card", "public-register-card", "forgot-password-card"].forEach((name) => {
    const card = document.querySelector("#" + name);
    if (card) card.classList.toggle("hidden", name !== id);
  });
}

async function createPublicUser(event) {
  event.preventDefault();
  const username = document.querySelector("#public-username").value.trim();
  const password = document.querySelector("#public-password").value;
  const confirm = document.querySelector("#public-confirm").value;
  try {
    if (!username) throw new Error("Введите логин");
    if (password.length < 6) throw new Error("Пароль должен быть минимум 6 символов");
    if (password !== confirm) throw new Error("Пароли не совпадают");
    const allUsers = users();
    if (allUsers.some((user) => user.username.toLocaleLowerCase() === username.toLocaleLowerCase())) {
      throw new Error("Такой профиль уже существует");
    }
    const salt = randomBytes(16);
    const hash = await deriveKeyBytes(password, salt, PBKDF2_ITERATIONS);
    const user = { username, role: "user", salt: bytesToBase64(salt), passwordHash: bytesToBase64(hash) };
    allUsers.push(user);
    saveUsers(allUsers);
    sessionStorage.setItem(SESSION_KEY, username);
    showToast("Профиль создан");
    setTimeout(() => window.location.reload(), 350);
  } catch (error) {
    showToast(error.message, true);
  }
}

function installAuthExtras() {
  const loginCard = document.querySelector("#login-card");
  const loginForm = document.querySelector("#login-form");
  const authView = document.querySelector("#auth-view");
  if (!loginCard || !loginForm || !authView || document.querySelector("#public-register-card")) return;

  const links = document.createElement("div");
  links.className = "auth-link-row";
  links.innerHTML = `
    <button id="open-public-register" class="secondary wide" type="button">Создать профиль</button>
    <button id="open-forgot-password" class="ghost wide" type="button">Забыли пароль?</button>`;
  loginForm.insertAdjacentElement("afterend", links);

  const registerCard = document.createElement("section");
  registerCard.id = "public-register-card";
  registerCard.className = "auth-card hidden";
  registerCard.innerHTML = `
    <div class="brand-mark">＋</div>
    <p class="eyebrow">NEW USER PROFILE</p>
    <h1>Создать профиль</h1>
    <p class="lead">Этот профиль будет создан как обычный пользователь. Администратором его можно сделать только в админке.</p>
    <form id="public-register-form" class="stack-form">
      <label>Логин<input id="public-username" required autocomplete="username"></label>
      <label>Пароль<input id="public-password" type="password" minlength="6" required autocomplete="new-password"></label>
      <label>Повторите пароль<input id="public-confirm" type="password" minlength="6" required autocomplete="new-password"></label>
      <button class="primary wide" type="submit">Создать профиль</button>
      <button id="public-register-back" class="ghost wide" type="button">Назад</button>
    </form>`;

  const forgotCard = document.createElement("section");
  forgotCard.id = "forgot-password-card";
  forgotCard.className = "auth-card hidden";
  forgotCard.innerHTML = `
    <div class="brand-mark">?</div>
    <p class="eyebrow">PASSWORD RECOVERY</p>
    <h1>Восстановление пароля</h1>
    <p class="lead">Пароль не хранится в открытом виде, поэтому приложение не может показать старый пароль.</p>
    <p class="auth-help-text">Создайте новый обычный профиль или попросите администратора добавить новый профиль в разделе 04 Админка.</p>
    <button id="forgot-create-profile" class="primary wide" type="button">Создать профиль</button>
    <button id="forgot-back" class="ghost wide" type="button">Назад</button>`;

  authView.append(registerCard, forgotCard);
  document.querySelector("#open-public-register").addEventListener("click", () => authCard("public-register-card"));
  document.querySelector("#open-forgot-password").addEventListener("click", () => authCard("forgot-password-card"));
  document.querySelector("#public-register-back").addEventListener("click", () => authCard("login-card"));
  document.querySelector("#forgot-back").addEventListener("click", () => authCard("login-card"));
  document.querySelector("#forgot-create-profile").addEventListener("click", () => authCard("public-register-card"));
  document.querySelector("#public-register-form").addEventListener("submit", createPublicUser);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function filenameFromText(value, fallback) {
  const match = String(value || "").match(/[\w\-.() ]+\.(?:jpe?g|png)/i);
  return match ? match[0].trim() : fallback;
}

function createdImageName() {
  const copy = document.querySelector("#created-copy")?.textContent || "";
  const extractName = document.querySelector("#extract-file-name")?.textContent || "";
  return filenameFromText(copy, filenameFromText(extractName, "iMage_secret.jpg"));
}

function updatedImageName() {
  const extractName = document.querySelector("#extract-file-name")?.textContent || "";
  const cleanName = extractName.includes("→") ? extractName.split("→").pop() : extractName;
  return filenameFromText(cleanName, "iMage_updated.jpg");
}

async function downloadPreviewImage(previewSelector, fallbackName) {
  const image = document.querySelector(previewSelector);
  if (!image || !image.src || image.classList.contains("hidden")) {
    showToast(text().missing, true);
    return;
  }
  try {
    const response = await fetch(image.src);
    const blob = await response.blob();
    downloadBlob(blob, fallbackName());
    showToast(text().imageReady);
  } catch {
    showToast(text().missing, true);
  }
}

function syncVisibility(zipButtonId, imageButtonId) {
  const zipButton = document.querySelector(zipButtonId);
  const imageButton = document.querySelector(imageButtonId);
  if (!zipButton || !imageButton) return;
  const sync = () => imageButton.classList.toggle("hidden", zipButton.classList.contains("hidden"));
  new MutationObserver(sync).observe(zipButton, { attributes: true, attributeFilter: ["class"] });
  sync();
}

function applyDownloadLabels() {
  const labels = text();
  const createdImage = document.querySelector("#download-created-image");
  const createdZip = document.querySelector("#download-created");
  const updatedImage = document.querySelector("#download-updated-image");
  const updatedZip = document.querySelector("#download-updated");
  if (createdImage) createdImage.textContent = labels.image;
  if (createdZip) createdZip.textContent = labels.zip;
  if (updatedImage) updatedImage.textContent = labels.image;
  if (updatedZip) updatedZip.textContent = labels.zip;
  const warning = document.querySelector("#transfer-warning");
  if (warning) warning.textContent = labels.warning;
}

injectStyles();
installAuthExtras();
applyDownloadLabels();
syncVisibility("#download-created", "#download-created-image");
syncVisibility("#download-updated", "#download-updated-image");

document.querySelector("#download-created-image")?.addEventListener("click", () =>
  downloadPreviewImage("#created-preview", createdImageName));

document.querySelector("#download-updated-image")?.addEventListener("click", () =>
  downloadPreviewImage("#edit-preview", updatedImageName));

document.querySelector("#language-select")?.addEventListener("change", () =>
  setTimeout(applyDownloadLabels, 0));
