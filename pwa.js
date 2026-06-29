import {
  PBKDF2_ITERATIONS, base64ToBytes, bytesToBase64, concatBytes,
  createSecretPayload, deriveKeyBytes, extractSecretJson, jsonToPlainText,
  plainTextToJson, randomBytes,
} from "./pwa-crypto.js";

const USERS_KEY = "secret-image-json-users-v2";
const SESSION_KEY = "secret-image-json-session-v2";
const MAX_SIZE = 50 * 1024 * 1024;
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);
let currentUser = null;
let registerFromWorkspace = false;
let currentSecretBlob = null;
let currentSecretName = "secret-image.jpg";
let selectedSecretFile = null;
let installPrompt = null;
let toastTimer = null;

function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", error);
  element.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.remove("show"), 4000);
}

function users() {
  try {
    const value = JSON.parse(localStorage.getItem(USERS_KEY) || "[]");
    return Array.isArray(value) ? value : [];
  } catch { return []; }
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a[i] ^ b[i];
  return difference === 0;
}

async function makeUser(username, password, role) {
  username = username.trim();
  if (!username) throw new Error("Введите логин");
  if (password.length < 6) throw new Error("Пароль должен содержать минимум 6 символов");
  const salt = randomBytes(16);
  const hash = await deriveKeyBytes(password, salt, PBKDF2_ITERATIONS);
  return { username, role, salt: bytesToBase64(salt), passwordHash: bytesToBase64(hash) };
}

async function authenticate(username, password) {
  const normalized = username.trim().toLocaleLowerCase();
  const user = users().find((item) => item.username.toLocaleLowerCase() === normalized);
  if (!user) return null;
  const hash = await deriveKeyBytes(password, base64ToBytes(user.salt), PBKDF2_ITERATIONS);
  return sameBytes(hash, base64ToBytes(user.passwordHash)) ? user : null;
}

function authCard(id) {
  $("#auth-view").classList.remove("hidden");
  $("#workspace-view").classList.add("hidden");
  ["setup-card", "login-card", "register-card"].forEach((name) =>
    $("#" + name).classList.toggle("hidden", name !== id));
}

function showLogin() {
  authCard("login-card");
  $("#login-password").value = "";
}

function showWorkspace(user) {
  currentUser = user;
  sessionStorage.setItem(SESSION_KEY, user.username);
  $("#auth-view").classList.add("hidden");
  $("#workspace-view").classList.remove("hidden");
  $("#profile-chip").textContent = user.username + " · " +
    (user.role === "admin" ? "администратор" : "пользователь");
  $("#new-profile").classList.toggle("hidden", user.role !== "admin");
}

function showRegister(fromWorkspace) {
  registerFromWorkspace = fromWorkspace;
  authCard("register-card");
  $("#admin-proof").classList.toggle("hidden", fromWorkspace);
}

function restoreView() {
  const allUsers = users();
  if (!allUsers.length) return authCard("setup-card");
  const username = sessionStorage.getItem(SESSION_KEY);
  const user = allUsers.find((item) => item.username === username);
  return user ? showWorkspace(user) : showLogin();
}

$("#setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    if ($("#setup-password").value !== $("#setup-confirm").value)
      throw new Error("Пароли не совпадают");
    const user = await makeUser($("#setup-username").value, $("#setup-password").value, "admin");
    localStorage.setItem(USERS_KEY, JSON.stringify([user]));
    showWorkspace(user);
  } catch (error) { toast(error.message, true); }
});

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const user = await authenticate($("#login-username").value, $("#login-password").value);
    if (!user) throw new Error("Неверный логин или пароль");
    showWorkspace(user);
  } catch (error) { toast(error.message, true); }
});

$("#open-register").addEventListener("click", () => showRegister(false));
$("#new-profile").addEventListener("click", () => showRegister(true));
$("#register-back").addEventListener("click", () =>
  registerFromWorkspace && currentUser ? showWorkspace(currentUser) : showLogin());

$("#register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    if (!registerFromWorkspace) {
      const admin = await authenticate($("#proof-username").value, $("#proof-password").value);
      if (!admin || admin.role !== "admin") throw new Error("Неверные данные администратора");
    } else if (!currentUser || currentUser.role !== "admin") {
      throw new Error("Требуются права администратора");
    }
    if ($("#new-password").value !== $("#new-confirm").value)
      throw new Error("Пароли не совпадают");
    const allUsers = users();
    const username = $("#new-username").value.trim();
    if (allUsers.some((item) => item.username.toLocaleLowerCase() === username.toLocaleLowerCase()))
      throw new Error("Профиль с таким логином уже существует");
    const user = await makeUser(username, $("#new-password").value, $("#new-role").value);
    allUsers.push(user);
    localStorage.setItem(USERS_KEY, JSON.stringify(allUsers));
    toast("Профиль " + user.username + " создан");
    registerFromWorkspace && currentUser ? showWorkspace(currentUser) : showLogin();
  } catch (error) { toast(error.message, true); }
});

$("#logout").addEventListener("click", () => {
  currentUser = null;
  sessionStorage.removeItem(SESSION_KEY);
  showLogin();
});

function switchTab(id) {
  $$(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === id));
  $$(".panel").forEach((panel) => panel.classList.toggle("active", panel.id === id));
}

$$(".tab").forEach((tab) => tab.addEventListener("click", () => switchTab(tab.dataset.tab)));

function busy(button, state, label) {
  if (state) {
    button.dataset.label = button.textContent;
    button.textContent = label;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.label || button.textContent;
    button.disabled = false;
  }
}

function checkedFile(file) {
  if (!file) throw new Error("Выберите изображение");
  if (file.size > MAX_SIZE) throw new Error("Изображение больше 50 MB");
  return file;
}

async function jpegBytes(file) {
  checkedFile(file);
  const url = URL.createObjectURL(file);
  try {
    const image = new Image();
    image.src = url;
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    const context = canvas.getContext("2d", { alpha: false });
    context.fillStyle = "#fff";
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.drawImage(image, 0, 0);
    const blob = await new Promise((resolve, reject) =>
      canvas.toBlob((value) => value ? resolve(value) :
        reject(new Error("Не удалось преобразовать изображение")), "image/jpeg", 0.95));
    return new Uint8Array(await blob.arrayBuffer());
  } finally { URL.revokeObjectURL(url); }
}

function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function showPreview(blob, name, created = false) {
  currentSecretBlob = blob;
  currentSecretName = name;
  selectedSecretFile = null;
  $("#extract-image").value = "";
  $("#extract-file-name").textContent = name;
  $("#created-source-note").classList.remove("hidden");
  const url = URL.createObjectURL(blob);
  $("#edit-preview").src = url;
  $("#edit-preview").classList.remove("hidden");
  if (created) {
    $("#created-preview").src = url;
    $("#created-card").classList.add("has-image");
    $("#created-title").textContent = "Секретное изображение создано";
    $("#created-copy").textContent = name + " готов к скачиванию.";
    $("#download-created").classList.remove("hidden");
  }
}

function selectedImage() {
  if (selectedSecretFile) return selectedSecretFile;
  return currentSecretBlob ?
    new File([currentSecretBlob], currentSecretName, { type: "image/jpeg" }) : null;
}

$("#create-image").addEventListener("change", (event) => {
  const file = event.target.files[0];
  $("#create-file-name").textContent = file ? file.name : "JPG или PNG · до 50 MB";
});

$("#extract-image").addEventListener("change", (event) => {
  selectedSecretFile = event.target.files[0] || null;
  if (selectedSecretFile) {
    $("#extract-file-name").textContent = selectedSecretFile.name;
    $("#created-source-note").classList.add("hidden");
    $("#edit-preview").src = URL.createObjectURL(selectedSecretFile);
    $("#edit-preview").classList.remove("hidden");
  }
  $("#extract-text").value = "";
  $("#extract-text").disabled = true;
  $("#save-text").disabled = true;
  $("#save-updated").disabled = true;
});

$("#create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#create-submit");
  busy(button, true, "Шифрование…");
  try {
    const source = checkedFile($("#create-image").files[0]);
    const jpeg = await jpegBytes(source);
    const payload = await createSecretPayload(
      plainTextToJson($("#create-text").value), $("#create-password").value);
    const blob = new Blob([concatBytes(jpeg, payload)], { type: "image/jpeg" });
    showPreview(blob, source.name.replace(/\.[^.]+$/, "") + "_secret.jpg", true);
    toast("Секретное изображение создано");
  } catch (error) { toast(error.message, true); }
  finally { busy(button, false); }
});

$("#download-created").addEventListener("click", () => {
  if (currentSecretBlob) download(currentSecretBlob, currentSecretName);
});

$("#extract-submit").addEventListener("click", async () => {
  const button = $("#extract-submit");
  busy(button, true, "Расшифровка…");
  try {
    const image = checkedFile(selectedImage());
    const json = await extractSecretJson(
      new Uint8Array(await image.arrayBuffer()), $("#extract-password").value);
    $("#extract-text").value = jsonToPlainText(json);
    $("#extract-text").disabled = false;
    $("#save-text").disabled = false;
    $("#save-updated").disabled = false;
    toast("Текст расшифрован");
  } catch { toast("Неверный пароль или секрет не найден", true); }
  finally { busy(button, false); }
});

$("#save-text").addEventListener("click", () =>
  download(new Blob([$("#extract-text").value], { type: "text/plain;charset=utf-8" }),
    "secret-text.txt"));

$("#save-updated").addEventListener("click", async () => {
  const button = $("#save-updated");
  busy(button, true, "Сохранение…");
  try {
    const jpeg = await jpegBytes(checkedFile(selectedImage()));
    const payload = await createSecretPayload(
      plainTextToJson($("#extract-text").value), $("#extract-password").value);
    const blob = new Blob([concatBytes(jpeg, payload)], { type: "image/jpeg" });
    showPreview(blob, currentSecretName.replace(/\.jpg$/i, "") + "_updated.jpg");
    $("#download-updated").classList.remove("hidden");
    toast("Обновлённое изображение создано");
  } catch (error) { toast(error.message, true); }
  finally { busy(button, false); }
});

$("#download-updated").addEventListener("click", () => {
  if (currentSecretBlob) download(currentSecretBlob, currentSecretName);
});

window.addEventListener("beforeinstallprompt", (event) => {
  event.preventDefault();
  installPrompt = event;
});

$("#install-app").addEventListener("click", async () => {
  if (installPrompt) {
    installPrompt.prompt();
    await installPrompt.userChoice;
    installPrompt = null;
  } else {
    toast(/iphone|ipad|ipod/i.test(navigator.userAgent) ?
      "iPhone: нажмите Поделиться → На экран Домой" :
      "Откройте меню браузера и выберите «Установить приложение»");
  }
});

if ("serviceWorker" in navigator)
  window.addEventListener("load", () =>
    navigator.serviceWorker.register("./service-worker.js")
      .catch(() => toast("Не удалось включить офлайн-режим", true)));

if (window.matchMedia("(display-mode: standalone)").matches)
  $("#install-app").classList.add("hidden");

restoreView();
