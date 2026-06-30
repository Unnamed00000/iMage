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

export async function resolveEmail(identifier) {
  const normalized = String(identifier || "").trim();
  if (!normalized) throw accountError("app/missing-identifier");
  if (normalized.includes("@")) return normalizeEmail(normalized);
  const { usernameLower } = normalizeUsername(normalized);
  const snapshot = await getDoc(doc(db, "usernames", usernameLower));
  if (!snapshot.exists() || !snapshot.data().email) throw accountError("auth/invalid-credential");
  return normalizeEmail(snapshot.data().email);
}

export async function signInAccount(identifier, password) {
  const email = await resolveEmail(identifier);
  return signInWithEmailAndPassword(auth, email, password);
}

export async function signOutAccount() {
  return signOut(auth);
}

export async function sendResetForIdentifier(identifier) {
  const email = await resolveEmail(identifier);
  await sendPasswordResetEmail(auth, email);
  return email;
}

export async function sendResetForEmail(email) {
  const normalized = normalizeEmail(email);
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

export async function createFirebaseUser({ username: rawUsername, email: rawEmail, password }) {
  const { username, usernameLower } = normalizeUsername(rawUsername);
  const email = normalizeEmail(rawEmail);
  if (!email) throw accountError("auth/invalid-email");

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
    credential = await createUserWithEmailAndPassword(secondaryAuth, email, password);
    const uid = credential.user.uid;
    await runTransaction(secondaryDb, async (transaction) => {
      const usernameRef = doc(secondaryDb, "usernames", usernameLower);
      const usernameSnapshot = await transaction.get(usernameRef);
      if (usernameSnapshot.exists()) throw accountError("app/username-taken");

      transaction.set(doc(secondaryDb, "users", uid), {
        uid,
        email,
        username,
        usernameLower,
        phone: "",
        role: "user",
        settings: { theme: "light", language: "ru" },
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      transaction.set(usernameRef, {
        uid,
        email,
        createdAt: serverTimestamp(),
      });
    });
    profileCreated = true;
    return { uid, email, username, usernameLower, role: "user", phone: "", settings: { theme: "light", language: "ru" } };
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
