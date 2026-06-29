(() => {
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => document.querySelectorAll(selector);
  let currentSecretBlob = null;
  let currentSecretName = "secret-image.jpg";
  let selectedSecretFile = null;
  let toastTimer = null;

  function showToast(message, isError = false) {
    const toast = $("#toast");
    toast.textContent = message;
    toast.classList.toggle("error", isError);
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 3500);
  }

  function switchTab(panelId) {
    $$(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === panelId));
    $$(".panel").forEach((panel) => panel.classList.toggle("active", panel.id === panelId));
  }

  $$(".tab").forEach((tab) => tab.addEventListener("click", () => switchTab(tab.dataset.tab)));

  function setBusy(button, busy, busyText) {
    if (busy) {
      button.dataset.label = button.textContent;
      button.textContent = busyText;
      button.disabled = true;
    } else {
      button.textContent = button.dataset.label || button.textContent;
      button.disabled = false;
    }
  }

  async function errorFrom(response) {
    try {
      const data = await response.json();
      return data.error || "Не удалось выполнить действие";
    } catch (_error) {
      return "Не удалось выполнить действие";
    }
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function nameFrom(response, fallback) {
    return response.headers.get("X-Download-Name") || fallback;
  }

  function showSecretPreview(blob, name, created = false) {
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
      $("#created-title").textContent = "Secret image created successfully";
      $("#created-copy").textContent = name + " готов к скачиванию и уже доступен во второй вкладке.";
      $("#download-created").classList.remove("hidden");
    }
  }

  function selectedImage() {
    if (selectedSecretFile) return selectedSecretFile;
    if (currentSecretBlob) return new File([currentSecretBlob], currentSecretName, { type: "image/jpeg" });
    return null;
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
      const url = URL.createObjectURL(selectedSecretFile);
      $("#edit-preview").src = url;
      $("#edit-preview").classList.remove("hidden");
    }
    $("#extract-text").value = "";
    $("#extract-text").disabled = true;
    $("#save-text").disabled = true;
    $("#save-updated").disabled = true;
  });

  $("#create-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const image = $("#create-image").files[0];
    if (!image) return showToast("Выберите JPG или PNG", true);
    const data = new FormData();
    data.append("image", image);
    data.append("text", $("#create-text").value);
    data.append("password", $("#create-password").value);
    const button = $("#create-submit");
    setBusy(button, true, "Создание…");
    try {
      const response = await fetch("/api/create", { method: "POST", body: data });
      if (!response.ok) throw new Error(await errorFrom(response));
      const blob = await response.blob();
      showSecretPreview(blob, nameFrom(response, "secret-image.jpg"), true);
      showToast("Secret image created successfully");
    } catch (error) {
      showToast(error.message, true);
    } finally {
      setBusy(button, false);
    }
  });

  $("#download-created").addEventListener("click", () => {
    if (currentSecretBlob) downloadBlob(currentSecretBlob, currentSecretName);
  });

  $("#extract-submit").addEventListener("click", async () => {
    const image = selectedImage();
    if (!image) return showToast("Выберите секретное изображение", true);
    const password = $("#extract-password").value;
    if (!password) return showToast("Введите пароль изображения", true);
    const data = new FormData();
    data.append("image", image);
    data.append("password", password);
    const button = $("#extract-submit");
    setBusy(button, true, "Расшифровка…");
    try {
      const response = await fetch("/api/extract", { method: "POST", body: data });
      if (!response.ok) throw new Error(await errorFrom(response));
      const result = await response.json();
      $("#extract-text").value = result.text;
      $("#extract-text").disabled = false;
      $("#save-text").disabled = false;
      $("#save-updated").disabled = false;
      showToast("JSON успешно расшифрован");
    } catch (error) {
      showToast(error.message, true);
    } finally {
      setBusy(button, false);
    }
  });

  $("#save-text").addEventListener("click", () => {
    const blob = new Blob([$("#extract-text").value], { type: "text/plain;charset=utf-8" });
    downloadBlob(blob, "secret-text.txt");
  });

  $("#save-updated").addEventListener("click", async () => {
    const image = selectedImage();
    if (!image) return showToast("Выберите секретное изображение", true);
    const data = new FormData();
    data.append("image", image);
    data.append("text", $("#extract-text").value);
    data.append("password", $("#extract-password").value);
    const button = $("#save-updated");
    setBusy(button, true, "Сохранение…");
    try {
      const response = await fetch("/api/update", { method: "POST", body: data });
      if (!response.ok) throw new Error(await errorFrom(response));
      const blob = await response.blob();
      showSecretPreview(blob, nameFrom(response, "secret-image-updated.jpg"));
      $("#download-updated").classList.remove("hidden");
      showToast("Secret image updated successfully");
    } catch (error) {
      showToast(error.message, true);
    } finally {
      setBusy(button, false);
    }
  });

  $("#download-updated").addEventListener("click", () => {
    if (currentSecretBlob) downloadBlob(currentSecretBlob, currentSecretName);
  });
})();
