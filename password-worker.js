import { parseSecretPayload, verifySecretPassword } from "./pwa-crypto.js";

let paused = false;
let stopped = false;
let running = false;
let resumeWaiters = [];

const POPULAR = [
  "123456", "12345678", "123456789", "000000", "111111", "password",
  "qwerty", "qwerty123", "abc123", "admin", "admin123", "letmein",
  "welcome", "iloveyou", "monkey", "dragon", "secret", "пароль",
];
const BASE_WORDS = ["admin", "user", "secret", "image", "json", "home", "love", "phone"];
const SUFFIXES = ["", "1", "12", "123", "321", "2024", "2025", "2026", "!", "@"];
const MASKS = [
  "Password1", "Password123", "Admin1", "Admin123", "Secret1", "Secret123",
  "Qwerty1", "Qwerty123", "Aa123456", "1q2w3e4r", "1qaz2wsx", "1234qwer",
];
const FULL_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-+=";

function unique(values) {
  return [...new Set(values)];
}

function inLength(value, min, max) {
  return value.length >= min && value.length <= max;
}

function* fixedLength(alphabet, length) {
  const indexes = new Array(length).fill(0);
  while (true) {
    yield indexes.map((index) => alphabet[index]).join("");
    let position = length - 1;
    while (position >= 0) {
      indexes[position] += 1;
      if (indexes[position] < alphabet.length) break;
      indexes[position] = 0;
      position -= 1;
    }
    if (position < 0) return;
  }
}

function* rangeCandidates(alphabet, min, max) {
  for (let length = min; length <= max; length += 1) {
    yield* fixedLength(alphabet, length);
  }
}

function countRange(base, min, max) {
  let total = 0;
  for (let length = min; length <= max; length += 1) {
    total += Math.pow(base, length);
    if (!Number.isFinite(total)) return Infinity;
  }
  return total;
}

function modes(options) {
  const result = [];
  if (options.popular) {
    const values = POPULAR.filter((value) => inLength(value, options.min, options.max));
    result.push({ name: "Популярные пароли", candidates: values, total: values.length });
  }
  if (options.combinations) {
    const values = unique(BASE_WORDS.flatMap((word) =>
      SUFFIXES.flatMap((suffix) => [word + suffix, word[0].toUpperCase() + word.slice(1) + suffix])))
      .filter((value) => inLength(value, options.min, options.max));
    result.push({ name: "Популярные комбинации", candidates: values, total: values.length });
  }
  if (options.masks) {
    const values = MASKS.filter((value) => inLength(value, options.min, options.max));
    result.push({ name: "Маски", candidates: values, total: values.length });
  }
  if (options.digits) {
    result.push({
      name: "Цифровой перебор",
      candidates: rangeCandidates("0123456789", options.min, options.max),
      total: countRange(10, options.min, options.max),
    });
  }
  if (options.brute) {
    result.push({
      name: "Полный перебор",
      candidates: rangeCandidates(FULL_ALPHABET, options.min, options.max),
      total: countRange(FULL_ALPHABET.length, options.min, options.max),
    });
  }
  return result;
}

async function waitWhilePaused() {
  if (!paused) return;
  await new Promise((resolve) => resumeWaiters.push(resolve));
}

function emitProgress(mode, candidate, checked, total, startedAt) {
  const elapsed = Math.max((performance.now() - startedAt) / 1000, 0.001);
  const speed = checked / elapsed;
  const remaining = Number.isFinite(total) && speed > 0 ? Math.max(0, (total - checked) / speed) : Infinity;
  self.postMessage({ type: "progress", mode, candidate, checked, total, speed, remaining });
}

async function runSearch(imageBuffer, options) {
  running = true;
  paused = false;
  stopped = false;
  let payload;
  try {
    payload = parseSecretPayload(new Uint8Array(imageBuffer));
  } catch {
    self.postMessage({ type: "error", message: "Неверный пароль или секрет не найден" });
    running = false;
    return;
  }

  const selectedModes = modes(options);
  const total = selectedModes.reduce((sum, mode) => sum + mode.total, 0);
  let checked = 0;
  let lastProgress = 0;
  const startedAt = performance.now();

  for (const mode of selectedModes) {
    self.postMessage({ type: "mode", mode: mode.name, total });
    for (const candidate of mode.candidates) {
      if (stopped) {
        self.postMessage({ type: "stopped", checked });
        running = false;
        return;
      }
      await waitWhilePaused();
      if (stopped) continue;
      checked += 1;
      if (await verifySecretPassword(payload, candidate)) {
        emitProgress(mode.name, candidate, checked, total, startedAt);
        self.postMessage({ type: "found", password: candidate, checked });
        running = false;
        return;
      }
      const now = performance.now();
      if (now - lastProgress >= 400) {
        emitProgress(mode.name, candidate, checked, total, startedAt);
        lastProgress = now;
      }
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
  self.postMessage({ type: "notFound", checked });
  running = false;
}

self.addEventListener("message", (event) => {
  if (event.data.type === "start" && !running) {
    runSearch(event.data.imageBuffer, event.data.options);
  } else if (event.data.type === "pause" && running) {
    paused = true;
    self.postMessage({ type: "paused" });
  } else if (event.data.type === "resume" && running) {
    paused = false;
    const waiters = resumeWaiters;
    resumeWaiters = [];
    waiters.forEach((resolve) => resolve());
    self.postMessage({ type: "resumed" });
  } else if (event.data.type === "stop" && running) {
    stopped = true;
    paused = false;
    const waiters = resumeWaiters;
    resumeWaiters = [];
    waiters.forEach((resolve) => resolve());
  }
});
