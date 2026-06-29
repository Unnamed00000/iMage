import {
  PBKDF2_ITERATIONS, base64ToBytes, bytesToBase64, concatBytes,
  createSecretPayload, deriveKeyBytes, extractSecretJson, jsonToPlainText,
  plainTextToJson, randomBytes,
} from "./pwa-crypto.js";

const USERS_KEY = "secret-image-json-users-v2";
const SESSION_KEY = "secret-image-json-session-v2";
const THEME_KEY = "secret-image-json-theme-v1";
const LANGUAGE_KEY = "secret-image-json-language-v1";
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);
let currentUser = null;
let registerFromWorkspace = false;
let currentSecretBlob = null;
let currentSecretName = "secret-image.jpg";
let selectedSecretFile = null;
let selectedSearchFile = null;
let passwordWorker = null;
let installPrompt = null;
let toastTimer = null;
let settingsOpenedAt = 0;

function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", error);
  element.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.remove("show"), 4000);
}

const TRANSLATIONS = {
  ru: {
    tabs: ["Создать", "Открыть и изменить", "Поиск пароля"],
    headings: ["Спрятать текст в изображение", "Расшифровать и изменить текст", "Поиск пароля"],
    choose: "Выбрать изображение", secretJpg: "Секретный JPG", imageHint: "JPG или PNG",
    min: "Минимальная длина пароля", max: "Максимальная длина пароля",
    modes: "Режимы поиска", options: ["Проверить цифры", "Проверить популярные пароли", "Проверить популярные комбинации", "Проверить маски", "Полный перебор"],
    start: "Узнать пароль", pause: "Пауза", resume: "Продолжить", stop: "Остановить",
    explanation: "Программа не достаёт пароль напрямую из файла. Она проверяет разные варианты и показывает пароль только если подходящий вариант найден.",
    progress: ["Текущий режим поиска", "Текущий проверяемый пароль", "Вариантов проверено", "Скорость проверки", "Примерное оставшееся время"],
    progressTitle: "ПРОГРЕСС", settingsEyebrow: "НАСТРОЙКИ ПРИЛОЖЕНИЯ",
    waiting: "Ожидание", resultPlaceholder: "Результат появится здесь",
    settings: "Настройки", theme: "Тема", themeHint: "Светлое или тёмное оформление",
    language: "Язык", languageHint: "Язык интерфейса приложения",
    appHint: "Версия PWA · обработка только на устройстве",
    install: "Установить приложение", update: "Принудительно обновить", newProfile: "Создать новый профиль", logout: "Выйти",
    create: "Создать секретное изображение", extract: "Извлечь текст", saveText: "Скачать .txt", saveImage: "Сохранить изменения в JPG",
    auth: {
      setupTitle: "Создайте администратора", setupLead: "Профиль хранится только на этом устройстве. Пароль сохраняется как соль и защищённый хэш.",
      loginTitle: "Вход", loginLead: "Все данные и профили остаются локально на этом устройстве.",
      registerTitle: "Новый профиль", registerLead: "Новый профиль должен подтвердить существующий администратор.",
      setupLabels: ["Логин", "Пароль", "Повторите пароль"], loginLabels: ["Логин", "Пароль"],
      registerLabels: ["Логин администратора", "Пароль администратора", "Логин нового профиля", "Тип профиля", "Новый пароль", "Повторите пароль"],
      setupButton: "Создать аккаунт", loginButton: "Войти", or: "или", proof: "Подтверждение администратора", createProfile: "Создать профиль", back: "Назад",
      roles: ["Пользователь", "Администратор"],
    },
    createCopy: ["Обработка выполняется на телефоне. Изображение и пароль никуда не отправляются.", "Выбрать изображение", "Секретный текст", "Введите обычный текст. Можно использовать несколько строк и любые символы.", "Пароль изображения", "Здесь появится результат", "Готовый JPG можно скачать или сразу открыть во второй вкладке.", "Скачать секретный JPG"],
    editCopy: ["Используйте результат первой вкладки или выберите сохранённый JPG.", "Выбрать секретный JPG", "Файл с зашифрованными данными", "Используется результат первой вкладки", "Пароль изображения", "Расшифрованный текст", "Текст появится здесь…", "Работает без сервера", "PBKDF2-SHA256 и Fernet выполняются через Web Crypto прямо на устройстве.", "Совместимо с Python V2", "Работает офлайн", "Пароль не сохраняется", "Скачать обновлённый JPG"],
    searchDescription: "Проверка выполняется локально и не отправляет изображение или найденный пароль в интернет.",
    speedLabel: "Скорость поиска", speedHint: "Чем выше значение, тем больше нагрузка на устройство.", speedRate: "паролей/с",
    runtime: { updating: "Обновление…", updateFailed: "Не удалось обновить приложение", lengthError: "Укажите длину пароля от 1 до 12", modeError: "Выберите хотя бы один режим поиска", preparing: "Подготовка", searching: "Поиск выполняется…", paused: "Пауза", found: "Пароль найден", notFound: "Пароль не найден", stopped: "Остановлено", searchStopped: "Поиск остановлен", missingSecret: "Неверный пароль или секрет не найден", searchError: "Ошибка поиска пароля", veryLong: "очень долго", lessSecond: "меньше секунды", showPassword: "Показать пароль", hidePassword: "Скрыть пароль" },
  },
  en: {
    tabs: ["Create", "Open and edit", "Password search"],
    headings: ["Hide text in an image", "Decrypt and edit text", "Password search"],
    choose: "Choose image", secretJpg: "Secret JPG", imageHint: "JPG or PNG",
    min: "Minimum password length", max: "Maximum password length",
    modes: "Search modes", options: ["Check digits", "Check popular passwords", "Check popular combinations", "Check masks", "Full brute force"],
    start: "Find password", pause: "Pause", resume: "Continue", stop: "Stop",
    explanation: "The app cannot read a password directly from the file. It tries different candidates and shows a password only when a matching one is found.",
    progress: ["Current search mode", "Current password candidate", "Candidates checked", "Check speed", "Estimated time remaining"],
    progressTitle: "PROGRESS", settingsEyebrow: "APP SETTINGS",
    waiting: "Waiting", resultPlaceholder: "The result will appear here",
    settings: "Settings", theme: "Theme", themeHint: "Light or dark appearance",
    language: "Language", languageHint: "Application interface language",
    appHint: "PWA version · on-device processing only",
    install: "Install app", update: "Force update", newProfile: "Create new profile", logout: "Log out",
    create: "Create secret image", extract: "Extract text", saveText: "Download .txt", saveImage: "Save changes to JPG",
    auth: {
      setupTitle: "Create an administrator", setupLead: "The profile stays on this device. The password is stored only as a salted protected hash.",
      loginTitle: "Sign in", loginLead: "All data and profiles remain locally on this device.",
      registerTitle: "New profile", registerLead: "An existing administrator must approve a new profile.",
      setupLabels: ["Username", "Password", "Repeat password"], loginLabels: ["Username", "Password"],
      registerLabels: ["Administrator username", "Administrator password", "New profile username", "Profile type", "New password", "Repeat password"],
      setupButton: "Create account", loginButton: "Sign in", or: "or", proof: "Administrator approval", createProfile: "Create profile", back: "Back",
      roles: ["User", "Administrator"],
    },
    createCopy: ["Processing happens on this device. The image and password are never uploaded.", "Choose image", "Secret text", "Enter plain text. You can use multiple lines and any characters.", "Image password", "Your result will appear here", "Download the finished JPG or open it directly in the second tab.", "Download secret JPG"],
    editCopy: ["Use the result from the first tab or select a saved JPG.", "Choose secret JPG", "File with encrypted data", "Using the result from the first tab", "Image password", "Decrypted text", "Text will appear here…", "Works without a server", "PBKDF2-SHA256 and Fernet run with Web Crypto directly on the device.", "Compatible with Python V2", "Works offline", "Password is not saved", "Download updated JPG"],
    searchDescription: "The check runs locally and does not send the image or recovered password to the internet.",
    speedLabel: "Search speed", speedHint: "Higher values use more processing power on the device.", speedRate: "passwords/s",
    runtime: { updating: "Updating…", updateFailed: "App update failed", lengthError: "Set password length from 1 to 12", modeError: "Select at least one search mode", preparing: "Preparing", searching: "Searching…", paused: "Paused", found: "Password found", notFound: "Password not found", stopped: "Stopped", searchStopped: "Search stopped", missingSecret: "Wrong password or secret not found", searchError: "Password search error", veryLong: "very long", lessSecond: "less than a second", showPassword: "Show password", hidePassword: "Hide password" },
  },
  da: {
    tabs: ["Opret", "Åbn og rediger", "Søg adgangskode"],
    headings: ["Skjul tekst i et billede", "Dekryptér og rediger tekst", "Søg efter adgangskode"],
    choose: "Vælg billede", secretJpg: "Hemmelig JPG", imageHint: "JPG eller PNG",
    min: "Mindste adgangskodelængde", max: "Største adgangskodelængde",
    modes: "Søgemetoder", options: ["Kontrollér cifre", "Kontrollér populære adgangskoder", "Kontrollér populære kombinationer", "Kontrollér mønstre", "Fuld brute force"],
    start: "Find adgangskode", pause: "Pause", resume: "Fortsæt", stop: "Stop",
    explanation: "Programmet henter ikke adgangskoden direkte fra filen. Det afprøver forskellige muligheder og viser kun adgangskoden, hvis der findes et match.",
    progress: ["Aktuel søgemetode", "Adgangskode der afprøves", "Muligheder afprøvet", "Testhastighed", "Anslået resterende tid"],
    progressTitle: "FREMSKRIDT", settingsEyebrow: "APPINDSTILLINGER",
    waiting: "Venter", resultPlaceholder: "Resultatet vises her",
    settings: "Indstillinger", theme: "Tema", themeHint: "Lyst eller mørkt udseende",
    language: "Sprog", languageHint: "Sprog i appens brugerflade",
    appHint: "PWA-version · behandling kun på enheden",
    install: "Installér app", update: "Gennemtving opdatering", newProfile: "Opret ny profil", logout: "Log ud",
    create: "Opret hemmeligt billede", extract: "Udpak tekst", saveText: "Hent .txt", saveImage: "Gem ændringer i JPG",
    auth: {
      setupTitle: "Opret en administrator", setupLead: "Profilen gemmes kun på denne enhed. Adgangskoden gemmes som et beskyttet hash med salt.",
      loginTitle: "Log ind", loginLead: "Alle data og profiler forbliver lokalt på denne enhed.",
      registerTitle: "Ny profil", registerLead: "En eksisterende administrator skal godkende en ny profil.",
      setupLabels: ["Brugernavn", "Adgangskode", "Gentag adgangskode"], loginLabels: ["Brugernavn", "Adgangskode"],
      registerLabels: ["Administratorens brugernavn", "Administratorens adgangskode", "Den nye profils brugernavn", "Profiltype", "Ny adgangskode", "Gentag adgangskode"],
      setupButton: "Opret konto", loginButton: "Log ind", or: "eller", proof: "Administratorgodkendelse", createProfile: "Opret profil", back: "Tilbage",
      roles: ["Bruger", "Administrator"],
    },
    createCopy: ["Behandlingen foregår på enheden. Billedet og adgangskoden uploades aldrig.", "Vælg billede", "Hemmelig tekst", "Skriv almindelig tekst. Du kan bruge flere linjer og alle tegn.", "Billedets adgangskode", "Dit resultat vises her", "Hent den færdige JPG, eller åbn den direkte i den anden fane.", "Hent hemmelig JPG"],
    editCopy: ["Brug resultatet fra den første fane, eller vælg en gemt JPG.", "Vælg hemmelig JPG", "Fil med krypterede data", "Bruger resultatet fra den første fane", "Billedets adgangskode", "Dekrypteret tekst", "Teksten vises her…", "Virker uden en server", "PBKDF2-SHA256 og Fernet kører med Web Crypto direkte på enheden.", "Kompatibel med Python V2", "Virker offline", "Adgangskoden gemmes ikke", "Hent opdateret JPG"],
    searchDescription: "Kontrollen kører lokalt og sender ikke billedet eller den fundne adgangskode til internettet.",
    speedLabel: "Søgehastighed", speedHint: "En højere værdi bruger mere processorkraft på enheden.", speedRate: "adgangskoder/s",
    runtime: { updating: "Opdaterer…", updateFailed: "Appen kunne ikke opdateres", lengthError: "Angiv en adgangskodelængde fra 1 til 12", modeError: "Vælg mindst én søgemetode", preparing: "Forbereder", searching: "Søger…", paused: "Pause", found: "Adgangskode fundet", notFound: "Adgangskoden blev ikke fundet", stopped: "Stoppet", searchStopped: "Søgningen er stoppet", missingSecret: "Forkert adgangskode eller ingen hemmelighed fundet", searchError: "Fejl under adgangskodesøgning", veryLong: "meget lang tid", lessSecond: "under ét sekund", showPassword: "Vis adgangskode", hidePassword: "Skjul adgangskode" },
  },
};

const MESSAGES = {
  ru: { enterLogin: "Введите логин", passwordMin: "Пароль должен содержать минимум 6 символов", mismatch: "Пароли не совпадают", invalidLogin: "Неверный логин или пароль", invalidAdmin: "Неверные данные администратора", adminRequired: "Требуются права администратора", profileExists: "Профиль с таким логином уже существует", profileCreated: (name) => `Профиль ${name} создан`, chooseImage: "Выберите изображение", convertFailed: "Не удалось преобразовать изображение", createdTitle: "Секретное изображение создано", readyDownload: (name) => `${name} готов к скачиванию.`, encrypting: "Шифрование…", created: "Секретное изображение создано", decrypting: "Расшифровка…", decrypted: "Текст расшифрован", saving: "Сохранение…", updated: "Обновлённое изображение создано", iosInstall: "iPhone: нажмите Поделиться → На экран Домой", browserInstall: "Откройте меню браузера и выберите «Установить приложение»", offlineFailed: "Не удалось включить офлайн-режим" },
  en: { enterLogin: "Enter a username", passwordMin: "The password must contain at least 6 characters", mismatch: "Passwords do not match", invalidLogin: "Wrong username or password", invalidAdmin: "Wrong administrator credentials", adminRequired: "Administrator rights are required", profileExists: "A profile with this username already exists", profileCreated: (name) => `Profile ${name} created`, chooseImage: "Choose an image", convertFailed: "The image could not be converted", createdTitle: "Secret image created", readyDownload: (name) => `${name} is ready to download.`, encrypting: "Encrypting…", created: "Secret image created", decrypting: "Decrypting…", decrypted: "Text decrypted", saving: "Saving…", updated: "Updated image created", iosInstall: "iPhone: tap Share → Add to Home Screen", browserInstall: "Open the browser menu and select “Install app”", offlineFailed: "Offline mode could not be enabled" },
  da: { enterLogin: "Indtast et brugernavn", passwordMin: "Adgangskoden skal indeholde mindst 6 tegn", mismatch: "Adgangskoderne er ikke ens", invalidLogin: "Forkert brugernavn eller adgangskode", invalidAdmin: "Forkerte administratoroplysninger", adminRequired: "Administratorrettigheder er påkrævet", profileExists: "Der findes allerede en profil med dette brugernavn", profileCreated: (name) => `Profilen ${name} er oprettet`, chooseImage: "Vælg et billede", convertFailed: "Billedet kunne ikke konverteres", createdTitle: "Det hemmelige billede er oprettet", readyDownload: (name) => `${name} er klar til at blive hentet.`, encrypting: "Krypterer…", created: "Det hemmelige billede er oprettet", decrypting: "Dekrypterer…", decrypted: "Teksten er dekrypteret", saving: "Gemmer…", updated: "Det opdaterede billede er oprettet", iosInstall: "iPhone: tryk på Del → Føj til hjemmeskærm", browserInstall: "Åbn browsermenuen, og vælg “Installér app”", offlineFailed: "Offlinetilstand kunne ikke aktiveres" },
};

function language() {
  const value = localStorage.getItem(LANGUAGE_KEY);
  return ["ru", "en", "da"].includes(value) ? value : "ru";
}

function messages() {
  return MESSAGES[language()];
}

function replaceLabelText(label, value) {
  const node = [...label.childNodes].find((item) => item.nodeType === Node.TEXT_NODE && item.textContent.trim());
  if (node) node.textContent = value;
}

function updatePasswordToggle(button) {
  const input = button.parentElement.querySelector("input");
  const fieldLabel = input.closest("label");
  const labelNode = fieldLabel && [...fieldLabel.childNodes]
    .find((item) => item.nodeType === Node.TEXT_NODE && item.textContent.trim());
  if (labelNode) input.setAttribute("aria-label", labelNode.textContent.trim());
  const revealed = input.type === "text";
  button.classList.toggle("revealed", revealed);
  const label = TRANSLATIONS[language()].runtime[revealed ? "hidePassword" : "showPassword"];
  button.setAttribute("aria-label", label);
  button.title = label;
}

function installPasswordToggles() {
  $$('input[type="password"]').forEach((input) => {
    if (input.parentElement.classList.contains("password-control")) return;
    const wrapper = document.createElement("span");
    wrapper.className = "password-control";
    input.parentNode.insertBefore(wrapper, input);
    wrapper.appendChild(input);
    const button = document.createElement("button");
    button.type = "button";
    button.className = "password-toggle";
    button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.6"/><path class="eye-slash" d="m4 3 16 18"/></svg>';
    button.addEventListener("click", () => {
      input.type = input.type === "password" ? "text" : "password";
      updatePasswordToggle(button);
      input.focus();
    });
    wrapper.appendChild(button);
    updatePasswordToggle(button);
  });
}

function concealPasswords() {
  $$(".password-control input").forEach((input) => {
    input.type = "password";
    updatePasswordToggle(input.parentElement.querySelector(".password-toggle"));
  });
}

function applyLanguage(code) {
  const selected = ["ru", "en", "da"].includes(code) ? code : "ru";
  const copy = TRANSLATIONS[selected];
  localStorage.setItem(LANGUAGE_KEY, selected);
  document.documentElement.lang = selected;
  $("#language-select").value = selected;
  $("#setup-card h1").textContent = copy.auth.setupTitle;
  $("#setup-card .lead").textContent = copy.auth.setupLead;
  [...$$("#setup-card label")].forEach((label, index) => replaceLabelText(label, copy.auth.setupLabels[index]));
  $("#setup-form button[type='submit']").textContent = copy.auth.setupButton;
  $("#login-card h1").textContent = copy.auth.loginTitle;
  $("#login-card .lead").textContent = copy.auth.loginLead;
  [...$$("#login-card label")].forEach((label, index) => replaceLabelText(label, copy.auth.loginLabels[index]));
  $("#login-form button[type='submit']").textContent = copy.auth.loginButton;
  $(".auth-divider span").textContent = copy.auth.or;
  $("#open-register").textContent = copy.newProfile;
  $("#register-card h1").textContent = copy.auth.registerTitle;
  $("#register-card .lead").textContent = copy.auth.registerLead;
  $("#admin-proof legend").textContent = copy.auth.proof;
  [...$$("#register-card label")].forEach((label, index) => replaceLabelText(label, copy.auth.registerLabels[index]));
  [...$$("#new-role option")].forEach((option, index) => { option.textContent = copy.auth.roles[index]; });
  $("#register-form button[type='submit']").textContent = copy.auth.createProfile;
  $("#register-back").textContent = copy.auth.back;
  [...$$('.tab')].forEach((tab, index) => { tab.innerHTML = `<span>0${index + 1}</span> ${copy.tabs[index]}`; });
  [...$$('.panel-heading h2')].forEach((heading, index) => { heading.textContent = copy.headings[index]; });
  const panelDescriptions = $$(".panel-heading > p");
  panelDescriptions[0].textContent = copy.createCopy[0];
  panelDescriptions[1].textContent = copy.editCopy[0];
  panelDescriptions[2].textContent = copy.searchDescription;
  $("#create-image").closest("label").querySelector("strong").textContent = copy.createCopy[1];
  if (!$("#create-image").files[0]) $("#create-file-name").textContent = copy.imageHint;
  $("label[for='create-text']").textContent = copy.createCopy[2];
  $("#create-text").placeholder = copy.createCopy[3];
  replaceLabelText($("#create-password").closest("label"), copy.createCopy[4]);
  if (!currentSecretBlob) {
    $("#created-title").textContent = copy.createCopy[5];
    $("#created-copy").textContent = copy.createCopy[6];
  }
  $("#download-created").textContent = copy.createCopy[7];
  $("#extract-image").closest("label").querySelector("strong").textContent = copy.editCopy[1];
  if (!selectedSecretFile && !currentSecretBlob) $("#extract-file-name").textContent = copy.editCopy[2];
  replaceLabelText($("#created-source-note"), ` ${copy.editCopy[3]}`);
  replaceLabelText($("#extract-password").closest("label"), copy.editCopy[4]);
  $("label[for='extract-text']").textContent = copy.editCopy[5];
  $("#extract-text").placeholder = copy.editCopy[6];
  $(".security-card h3").textContent = copy.editCopy[7];
  $(".security-card > p:not(.eyebrow)").textContent = copy.editCopy[8];
  [...$$(".security-card li")].forEach((item, index) => { item.textContent = copy.editCopy[index + 9]; });
  $("#download-updated").textContent = copy.editCopy[12];
  $("#search-image").closest("label").querySelector("strong").textContent = copy.choose;
  $("#search-file-name").textContent = selectedSearchFile ? selectedSearchFile.name : copy.secretJpg;
  const lengthLabels = $$(".length-grid label");
  replaceLabelText(lengthLabels[0], copy.min);
  replaceLabelText(lengthLabels[1], copy.max);
  $(".search-options legend").textContent = copy.modes;
  [...$$(".search-options label")].forEach((label, index) => replaceLabelText(label, ` ${copy.options[index]}`));
  $(".speed-control label > span").textContent = copy.speedLabel;
  $("#search-intensity-hint").textContent = copy.speedHint;
  $("#search-start").textContent = copy.start;
  $("#search-pause").textContent = copy.pause;
  $("#search-resume").textContent = copy.resume;
  $("#search-stop").textContent = copy.stop;
  $(".search-explanation").textContent = copy.explanation;
  $(".progress-card .eyebrow").textContent = copy.progressTitle;
  [...$$(".progress-list dt")].forEach((item, index) => { item.textContent = copy.progress[index]; });
  if (!passwordWorker) {
    $("#search-mode").textContent = copy.waiting;
    $("#search-result").textContent = copy.resultPlaceholder;
    $("#search-speed").textContent = `0 ${copy.speedRate}`;
  }
  $$(".password-toggle").forEach(updatePasswordToggle);
  $("#settings-title").textContent = copy.settings;
  $(".settings-header .eyebrow").textContent = copy.settingsEyebrow;
  $("#settings-button").setAttribute("aria-label", copy.settings);
  const sections = $$(".settings-section");
  sections[0].querySelector("strong").textContent = copy.theme;
  sections[0].querySelector("small").textContent = copy.themeHint;
  sections[1].querySelector("strong").textContent = copy.language;
  sections[1].querySelector("small").textContent = copy.languageHint;
  sections[2].querySelector("small").textContent = copy.appHint;
  $("#install-app").textContent = copy.install;
  $("#force-update").textContent = copy.update;
  $("#new-profile").textContent = copy.newProfile;
  $("#logout").textContent = copy.logout;
  $("#create-submit").textContent = copy.create;
  $("#extract-submit").textContent = copy.extract;
  $("#save-text").textContent = copy.saveText;
  $("#save-updated").textContent = copy.saveImage;
}

function applyTheme(theme) {
  const selected = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = selected;
  $("#theme-toggle").checked = selected === "dark";
  localStorage.setItem(THEME_KEY, selected);
}

function openSettings() {
  $("#language-select").value = language();
  $("#theme-toggle").checked = document.documentElement.dataset.theme === "dark";
  settingsOpenedAt = performance.now();
  $("#settings-modal").classList.remove("hidden");
  $("#settings-close").focus();
}

function closeSettings(force = false) {
  if (!force && performance.now() - settingsOpenedAt < 350) return;
  $("#settings-modal").classList.add("hidden");
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
  if (!username) throw new Error(messages().enterLogin);
  if (password.length < 6) throw new Error(messages().passwordMin);
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
  concealPasswords();
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
  $("#new-profile").classList.toggle("hidden", user.role !== "admin");
}

function showRegister(fromWorkspace) {
  closeSettings(true);
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
      throw new Error(messages().mismatch);
    const user = await makeUser($("#setup-username").value, $("#setup-password").value, "admin");
    localStorage.setItem(USERS_KEY, JSON.stringify([user]));
    showWorkspace(user);
  } catch (error) { toast(error.message, true); }
});

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const user = await authenticate($("#login-username").value, $("#login-password").value);
    if (!user) throw new Error(messages().invalidLogin);
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
      if (!admin || admin.role !== "admin") throw new Error(messages().invalidAdmin);
    } else if (!currentUser || currentUser.role !== "admin") {
      throw new Error(messages().adminRequired);
    }
    if ($("#new-password").value !== $("#new-confirm").value)
      throw new Error(messages().mismatch);
    const allUsers = users();
    const username = $("#new-username").value.trim();
    if (allUsers.some((item) => item.username.toLocaleLowerCase() === username.toLocaleLowerCase()))
      throw new Error(messages().profileExists);
    const user = await makeUser(username, $("#new-password").value, $("#new-role").value);
    allUsers.push(user);
    localStorage.setItem(USERS_KEY, JSON.stringify(allUsers));
    toast(messages().profileCreated(user.username));
    registerFromWorkspace && currentUser ? showWorkspace(currentUser) : showLogin();
  } catch (error) { toast(error.message, true); }
});

$("#logout").addEventListener("click", () => {
  closeSettings(true);
  currentUser = null;
  sessionStorage.removeItem(SESSION_KEY);
  showLogin();
});

$("#settings-button").addEventListener("click", openSettings);
$("#settings-close").addEventListener("click", () => closeSettings());
$("#settings-backdrop").addEventListener("click", () => closeSettings());
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeSettings();
});

$("#theme-toggle").addEventListener("change", (event) =>
  applyTheme(event.target.checked ? "dark" : "light"));

$("#language-select").addEventListener("change", (event) =>
  applyLanguage(event.target.value));

$("#force-update").addEventListener("click", async () => {
  const button = $("#force-update");
  busy(button, true, TRANSLATIONS[language()].runtime.updating);
  try {
    if ("serviceWorker" in navigator) {
      const registrations = await navigator.serviceWorker.getRegistrations();
      await Promise.all(registrations.map((registration) => registration.update()));
    }
    const names = await caches.keys();
    await Promise.all(names.filter((name) =>
      name.startsWith("secret-image-json-") || name.startsWith("image-pwa-"))
      .map((name) => caches.delete(name)));
    window.location.reload();
  } catch {
    busy(button, false);
    toast(TRANSLATIONS[language()].runtime.updateFailed, true);
  }
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
  if (!file) throw new Error(messages().chooseImage);
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
        reject(new Error(messages().convertFailed)), "image/jpeg", 0.95));
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
    $("#created-title").textContent = messages().createdTitle;
    $("#created-copy").textContent = messages().readyDownload(name);
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
  $("#create-file-name").textContent = file ? file.name : TRANSLATIONS[language()].imageHint;
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
  busy(button, true, messages().encrypting);
  try {
    const source = checkedFile($("#create-image").files[0]);
    const jpeg = await jpegBytes(source);
    const payload = await createSecretPayload(
      plainTextToJson($("#create-text").value), $("#create-password").value);
    const blob = new Blob([concatBytes(jpeg, payload)], { type: "image/jpeg" });
    showPreview(blob, source.name.replace(/\.[^.]+$/, "") + "_secret.jpg", true);
    toast(messages().created);
  } catch (error) { toast(error.message, true); }
  finally { busy(button, false); }
});

$("#download-created").addEventListener("click", () => {
  if (currentSecretBlob) download(currentSecretBlob, currentSecretName);
});

$("#extract-submit").addEventListener("click", async () => {
  const button = $("#extract-submit");
  busy(button, true, messages().decrypting);
  try {
    const image = checkedFile(selectedImage());
    const json = await extractSecretJson(
      new Uint8Array(await image.arrayBuffer()), $("#extract-password").value);
    $("#extract-text").value = jsonToPlainText(json);
    $("#extract-text").disabled = false;
    $("#save-text").disabled = false;
    $("#save-updated").disabled = false;
    toast(messages().decrypted);
  } catch { toast(TRANSLATIONS[language()].runtime.missingSecret, true); }
  finally { busy(button, false); }
});

$("#save-text").addEventListener("click", () =>
  download(new Blob([$("#extract-text").value], { type: "text/plain;charset=utf-8" }),
    "secret-text.txt"));

$("#save-updated").addEventListener("click", async () => {
  const button = $("#save-updated");
  busy(button, true, messages().saving);
  try {
    const jpeg = await jpegBytes(checkedFile(selectedImage()));
    const payload = await createSecretPayload(
      plainTextToJson($("#extract-text").value), $("#extract-password").value);
    const blob = new Blob([concatBytes(jpeg, payload)], { type: "image/jpeg" });
    showPreview(blob, currentSecretName.replace(/\.jpg$/i, "") + "_updated.jpg");
    $("#download-updated").classList.remove("hidden");
    toast(messages().updated);
  } catch (error) { toast(error.message, true); }
  finally { busy(button, false); }
});

$("#download-updated").addEventListener("click", () => {
  if (currentSecretBlob) download(currentSecretBlob, currentSecretName);
});

function formatCount(value) {
  if (!Number.isFinite(value)) return "∞";
  const locale = { ru: "ru-RU", en: "en-US", da: "da-DK" }[language()];
  return new Intl.NumberFormat(locale, {
    maximumFractionDigits: 0,
    notation: value >= 1e9 ? "compact" : "standard",
  }).format(value);
}

function formatDuration(seconds) {
  const copy = TRANSLATIONS[language()].runtime;
  if (!Number.isFinite(seconds) || seconds > 3153600000) return copy.veryLong;
  if (seconds < 2) return copy.lessSecond;
  const units = {
    ru: [[86400, "д"], [3600, "ч"], [60, "мин"], [1, "с"]],
    en: [[86400, "d"], [3600, "h"], [60, "min"], [1, "s"]],
    da: [[86400, "d"], [3600, "t"], [60, "min"], [1, "s"]],
  }[language()];
  let remaining = Math.ceil(seconds);
  const parts = [];
  for (const [size, suffix] of units) {
    const amount = Math.floor(remaining / size);
    if (amount && parts.length < 2) parts.push(`${amount} ${suffix}`);
    remaining %= size;
  }
  return parts.join(" ") || copy.lessSecond;
}

const MODE_NAMES = {
  "Популярные пароли": { ru: "Популярные пароли", en: "Popular passwords", da: "Populære adgangskoder" },
  "Популярные комбинации": { ru: "Популярные комбинации", en: "Popular combinations", da: "Populære kombinationer" },
  "Маски": { ru: "Маски", en: "Masks", da: "Mønstre" },
  "Цифровой перебор": { ru: "Цифровой перебор", en: "Digit search", da: "Ciffersøgning" },
  "Полный перебор": { ru: "Полный перебор", en: "Full brute force", da: "Fuld brute force" },
};

function localizedMode(value) {
  return MODE_NAMES[value]?.[language()] || value;
}

function searchIntensity() {
  return Math.min(10, Math.max(1, Number.parseInt($("#search-intensity").value, 10) || 1));
}

$("#search-intensity").addEventListener("input", () => {
  const value = searchIntensity();
  $("#search-intensity-value").textContent = value;
  passwordWorker?.postMessage({ type: "speed", value });
});

function setSearchButtons(state) {
  const running = state === "running";
  const paused = state === "paused";
  $("#search-start").disabled = running || paused;
  $("#search-pause").disabled = !running;
  $("#search-resume").disabled = !paused;
  $("#search-stop").disabled = !(running || paused);
}

function finishSearch(result, error = false) {
  if (passwordWorker) passwordWorker.terminate();
  passwordWorker = null;
  setSearchButtons("idle");
  $("#search-result").textContent = result;
  $("#search-result").classList.toggle("found", !error && result.includes(":"));
  $("#search-result").classList.toggle("failed", error);
}

$("#search-image").addEventListener("change", (event) => {
  selectedSearchFile = event.target.files[0] || null;
  $("#search-file-name").textContent = selectedSearchFile ? selectedSearchFile.name : TRANSLATIONS[language()].secretJpg;
});

$("#search-start").addEventListener("click", async () => {
  try {
    const text = TRANSLATIONS[language()];
    const image = checkedFile(selectedSearchFile);
    const min = Number.parseInt($("#search-min").value, 10);
    const max = Number.parseInt($("#search-max").value, 10);
    if (!Number.isInteger(min) || !Number.isInteger(max) || min < 1 || max > 12 || min > max)
      throw new Error(text.runtime.lengthError);
    const options = {
      min, max,
      digits: $("#search-digits").checked,
      popular: $("#search-popular").checked,
      combinations: $("#search-combinations").checked,
      masks: $("#search-masks").checked,
      brute: $("#search-brute").checked,
      speedLevel: searchIntensity(),
    };
    if (![options.digits, options.popular, options.combinations, options.masks, options.brute].some(Boolean))
      throw new Error(text.runtime.modeError);

    if (passwordWorker) passwordWorker.terminate();
    passwordWorker = new Worker("./password-worker.js", { type: "module" });
    setSearchButtons("running");
    $("#search-mode").textContent = text.runtime.preparing;
    $("#search-current").textContent = "—";
    $("#search-checked").textContent = "0";
    $("#search-speed").textContent = `0 ${text.speedRate}`;
    $("#search-eta").textContent = "—";
    $("#search-result").textContent = text.runtime.searching;
    $("#search-result").classList.remove("found", "failed");

    passwordWorker.addEventListener("message", (event) => {
      const data = event.data;
      const activeText = TRANSLATIONS[language()];
      if (data.type === "mode") $("#search-mode").textContent = localizedMode(data.mode);
      if (data.type === "progress") {
        $("#search-mode").textContent = localizedMode(data.mode);
        $("#search-current").textContent = data.candidate || "—";
        $("#search-checked").textContent = `${formatCount(data.checked)} / ${formatCount(data.total)}`;
        $("#search-speed").textContent = `${data.speed.toFixed(2)} ${activeText.speedRate}`;
        $("#search-eta").textContent = formatDuration(data.remaining);
      } else if (data.type === "paused") {
        setSearchButtons("paused");
        $("#search-mode").textContent = activeText.runtime.paused;
      } else if (data.type === "resumed") {
        setSearchButtons("running");
      } else if (data.type === "found") {
        finishSearch(`${activeText.runtime.found}: ${data.password}`);
      } else if (data.type === "notFound") {
        finishSearch(activeText.runtime.notFound, true);
      } else if (data.type === "stopped") {
        $("#search-mode").textContent = activeText.runtime.stopped;
        finishSearch(activeText.runtime.searchStopped, true);
      } else if (data.type === "error") {
        finishSearch(activeText.runtime.missingSecret, true);
      }
    });
    passwordWorker.addEventListener("error", () =>
      finishSearch(TRANSLATIONS[language()].runtime.searchError, true));
    const imageBuffer = await image.arrayBuffer();
    passwordWorker.postMessage({ type: "start", imageBuffer, options }, [imageBuffer]);
  } catch (error) {
    setSearchButtons("idle");
    toast(error.message, true);
  }
});

$("#search-pause").addEventListener("click", () => passwordWorker?.postMessage({ type: "pause" }));
$("#search-resume").addEventListener("click", () => passwordWorker?.postMessage({ type: "resume" }));
$("#search-stop").addEventListener("click", () => passwordWorker?.postMessage({ type: "stop" }));

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
      messages().iosInstall : messages().browserInstall);
  }
});

if ("serviceWorker" in navigator)
  window.addEventListener("load", () =>
    navigator.serviceWorker.register("./service-worker.js")
      .catch(() => toast(messages().offlineFailed, true)));

if (window.matchMedia("(display-mode: standalone)").matches)
  $("#install-app").classList.add("hidden");

installPasswordToggles();
applyTheme(localStorage.getItem(THEME_KEY) ||
  (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
applyLanguage(language());
restoreView();
