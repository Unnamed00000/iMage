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
    @media (max-width: 420px) {
      .download-choice { grid-template-columns: 1fr; }
    }
  `;
  document.head.appendChild(style);
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
applyDownloadLabels();
syncVisibility("#download-created", "#download-created-image");
syncVisibility("#download-updated", "#download-updated-image");

document.querySelector("#download-created-image")?.addEventListener("click", () =>
  downloadPreviewImage("#created-preview", createdImageName));

document.querySelector("#download-updated-image")?.addEventListener("click", () =>
  downloadPreviewImage("#edit-preview", updatedImageName));

document.querySelector("#language-select")?.addEventListener("change", () =>
  setTimeout(applyDownloadLabels, 0));
