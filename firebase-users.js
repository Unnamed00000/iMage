import { deleteApp, getApp, getApps, initializeApp } from "https://www.gstatic.com/firebasejs/12.15.0/firebase-app.js";
import {
  browserLocalPersistence,
  createUserWithEmailAndPassword,
  deleteUser,
  getAuth,
  inMemoryPersistence,
  onAuthStateChanged,
  sendPasswordResetEmail,
  setPersistence,
  signInWithEmailAndPassword,
  signOut,
} from "https://www.gstatic.com/firebasejs/12.15.0/firebase-auth.js";
import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  getFirestore,
  runTransaction,
  serverTimestamp,
  updateDoc,
  writeBatch,
} from "https://www.gstatic.com/firebasejs/12.15.0/firebase-firestore.js";
import { firebaseConfig } from "./firebase-config.js";

const app = getApps().length ? getApp() : initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);

const USERNAME_PATTERN = /^[\p{L}\p{N}_-]{3,32}$/u;
const TECHNICAL_EMAIL_DOMAIN = "no-email.image-5e192.local";

function accountError(code, fallback = "Firebase request failed") {
  const error = new Error(fallback);
  error.code = code;
  return error;
}

export function normalizeUsername(value) {
  const username = String(value || "").trim();
  const usernameLower = username.toLocaleLowerCase();
  if (!USERNAME_PATTERN.test(username)) throw accountError("app/invalid-username");
  return { username, usernameLower };
}

export function normalizeEmail(value) {
  return String(value || "").trim().toLocaleLowerCase();
}

function technicalEmail(usernameLower) {
  return `${usernameLower}@${TECHNICAL_EMAIL_DOMAIN}`;
}

function isTechnicalEmail(email) {
  return normalizeEmail(email).endsWith(`@${TECHNICAL_EMAIL_DOMAIN}`);
}

async function resolveUsernameAccount(identifier) {
  const { usernameLower } = normalizeUsername(identifier);
  const snapshot = await getDoc(doc(db, "usernames", usernameLower));
  if (!snapshot.exists()) throw accountError("auth/invalid-credential");
  return snapshot.data();
}

export async function resolveEmail(identifier) {
  const normalized = String(identifier || "").trim();
  if (!normalized) throw accountError("app/missing-identifier");
  if (normalized.includes("@")) return normalizeEmail(normalized);
  const account = await resolveUsernameAccount(normalized);
  const authEmail = normalizeEmail(account.authEmail || account.email);
  if (!authEmail) throw accountError("auth/invalid-credential");
  return authEmail;
}

export async function signInAccount(identifier, password) {
  const email = await resolveEmail(identifier);
  return signInWithEmailAndPassword(auth, email, password);
}

export async function signOutAccount() {
  return signOut(auth);
}

export async function sendResetForIdentifier(identifier) {
  const normalized = String(identifier || "").trim();
  if (!normalized) throw accountError("app/missing-identifier");
  let email;
  if (normalized.includes("@")) {
    email = normalizeEmail(normalized);
    if (isTechnicalEmail(email)) throw accountError("app/no-recovery-email");
  } else {
    const account = await resolveUsernameAccount(normalized);
    const hasRealEmail = account.hasRealEmail ?? Boolean(account.email);
    email = normalizeEmail(account.email);
    if (!hasRealEmail || !email) throw accountError("app/no-recovery-email");
  }
  await sendPasswordResetEmail(auth, email);
  return email;
}

export async function sendResetForEmail(email) {
  const normalized = normalizeEmail(email);
  if (!normalized || isTechnicalEmail(normalized)) throw accountError("app/no-recovery-email");
  await sendPasswordResetEmail(auth, normalized);
  return normalized;
}

export async function getUserProfile(uid) {
  const snapshot = await getDoc(doc(db, "users", uid));
  if (!snapshot.exists()) throw accountError("app/profile-not-found");
  return { id: snapshot.id, ...snapshot.data() };
}

export async function observeAuthState(callback) {
  await setPersistence(auth, browserLocalPersistence);
  return onAuthStateChanged(auth, callback);
}

export async function createFirebaseUser({ username: rawUsername, email: rawEmail, phone: rawPhone = "", password }) {
  const { username, usernameLower } = normalizeUsername(rawUsername);
  const email = normalizeEmail(rawEmail);
  const phone = String(rawPhone || "").trim();
  const hasRealEmail = Boolean(email);
  const authEmail = hasRealEmail ? email : technicalEmail(usernameLower);
  const recoveryMode = hasRealEmail ? "email" : "adminOnly";

  const existing = await getDoc(doc(db, "usernames", usernameLower));
  if (existing.exists()) throw accountError("app/username-taken");

  const secondaryName = `registration-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const secondaryApp = initializeApp(firebaseConfig, secondaryName);
  const secondaryAuth = getAuth(secondaryApp);
  const secondaryDb = getFirestore(secondaryApp);
  await setPersistence(secondaryAuth, inMemoryPersistence);

  let credential = null;
  let profileCreated = false;
  try {
    credential = await createUserWithEmailAndPassword(secondaryAuth, authEmail, password);
    const uid = credential.user.uid;
    await runTransaction(secondaryDb, async (transaction) => {
      const usernameRef = doc(secondaryDb, "usernames", usernameLower);
      const usernameSnapshot = await transaction.get(usernameRef);
      if (usernameSnapshot.exists()) throw accountError("app/username-taken");

      transaction.set(doc(secondaryDb, "users", uid), {
        uid,
        email,
        authEmail,
        hasRealEmail,
        username,
        usernameLower,
        phone,
        role: "user",
        recoveryMode,
        settings: { theme: "light", language: "ru" },
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      transaction.set(usernameRef, {
        uid,
        email,
        authEmail,
        hasRealEmail,
        createdAt: serverTimestamp(),
      });
    });
    profileCreated = true;
    return {
      uid, email, authEmail, hasRealEmail, username, usernameLower, phone,
      role: "user", recoveryMode, settings: { theme: "light", language: "ru" },
    };
  } catch (error) {
    if (credential?.user && !profileCreated) await deleteUser(credential.user).catch(() => {});
    throw error;
  } finally {
    await signOut(secondaryAuth).catch(() => {});
    await deleteApp(secondaryApp).catch(() => {});
  }
}

export async function listUserProfiles() {
  const snapshot = await getDocs(collection(db, "users"));
  return snapshot.docs
    .map((item) => ({ id: item.id, ...item.data() }))
    .sort((left, right) => String(left.username || left.email).localeCompare(String(right.username || right.email)));
}

export async function changeUserRole(uid, role) {
  if (!["user", "admin"].includes(role)) throw accountError("app/invalid-role");
  await updateDoc(doc(db, "users", uid), { role, updatedAt: serverTimestamp() });
}

export async function removeUserProfile(profile) {
  const batch = writeBatch(db);
  batch.delete(doc(db, "users", profile.uid));
  if (profile.usernameLower) batch.delete(doc(db, "usernames", profile.usernameLower));
  await batch.commit();
}

export async function saveProfileSettings(uid, settings) {
  const patch = { updatedAt: serverTimestamp() };
  if (settings.theme) patch["settings.theme"] = settings.theme;
  if (settings.language) patch["settings.language"] = settings.language;
  await updateDoc(doc(db, "users", uid), patch);
}

export async function updateProfilePhone(uid, phone) {
  await updateDoc(doc(db, "users", uid), { phone: String(phone || "").trim(), updatedAt: serverTimestamp() });
}
