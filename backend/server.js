import crypto from "node:crypto";
import os from "node:os";
import { fileURLToPath } from "node:url";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import fs from "fs-extra";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from "@simplewebauthn/server";

dotenv.config({ path: fileURLToPath(new URL("./.env", import.meta.url)) });

const app = express();
const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 3000);
const DB_FILE = fileURLToPath(new URL("./db.json", import.meta.url));
const FRONTEND_DIR = fileURLToPath(new URL("../frontend/", import.meta.url));
const WEBAUTHN_BUNDLE_DIR = fileURLToPath(new URL("./node_modules/@simplewebauthn/browser/dist/bundle/", import.meta.url));
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const USERNAME = process.env.APP_USERNAME || "akter";
const PASSWORD = process.env.APP_PASSWORD || "1234";
const LAN_IPS = Object.values(os.networkInterfaces())
  .flatMap(entries => entries || [])
  .filter(details => details.family === "IPv4" && details.internal === false)
  .map(details => `http://${details.address}:${PORT}`);
const CORS_ORIGINS = Array.from(new Set([
  ...(process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(",") : ["http://localhost:3000", "http://127.0.0.1:3000"]),
  ...LAN_IPS,
  `http://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`
].map(origin => origin.trim()).filter(Boolean)));
const DEFAULT_ORIGIN = `http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}`;
const ORIGIN = process.env.WEBAUTHN_ORIGIN || process.env.APP_ORIGIN || DEFAULT_ORIGIN;
const RP_ID = process.env.WEBAUTHN_RP_ID || new URL(ORIGIN).hostname;
const FACE_MATCH_THRESHOLD = 0.5;
const EMPTY_DB = {
  lockStatus: "LOCKED",
  faceTemplate: null,
  history: [],
  users: [],
  alarms: [],
  webauthnChallenges: {}
};
const loginFailures = new Map();

if (!process.env.JWT_SECRET) console.warn("JWT_SECRET is unset; using a temporary key for this run.");
if (!process.env.APP_PASSWORD) console.warn("APP_PASSWORD is unset; using the demo password. Configure backend/.env.");

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (CORS_ORIGINS.includes(origin)) return callback(null, true);
    if (origin.endsWith(".local") || /^(http|https):\/\/\d+\.\d+\.\d+\.\d+(:\d+)?$/.test(origin)) {
      return callback(null, true);
    }
    callback(new Error("CORS policy: this origin is not allowed"));
  },
  credentials: true
}));
app.use(express.json({ limit: "16kb" }));
app.use("/vendor/webauthn", express.static(WEBAUTHN_BUNDLE_DIR));
app.use(express.static(FRONTEND_DIR));
app.get("/", (req, res) => res.sendFile(fileURLToPath(new URL("../frontend/index.html", import.meta.url))));

async function loadDB() {
  let db;
  let changed = false;
  try {
    db = await fs.readJson(DB_FILE);
  } catch (error) {
    if (error.code !== "ENOENT" && !(error instanceof SyntaxError)) throw error;
    db = { ...EMPTY_DB };
  }

  if (Array.isArray(db.familyInvites)) {
    delete db.familyInvites;
    changed = true;
  }
  Object.assign(db, {
    ...EMPTY_DB,
    ...db,
    users: Array.isArray(db.users) ? db.users : [],
    alarms: Array.isArray(db.alarms) ? db.alarms : [],
    history: Array.isArray(db.history) ? db.history : [],
    webauthnChallenges: db.webauthnChallenges && typeof db.webauthnChallenges === "object"
      ? db.webauthnChallenges
      : {}
  });

  if (!db.users.some(user => user.username === USERNAME)) {
    db.users.push({
      id: crypto.randomUUID(),
      username: USERNAME,
      displayName: process.env.APP_DISPLAY_NAME || "管理者",
      passwordHash: await bcrypt.hash(PASSWORD, 12),
      role: "admin",
      passkeys: []
    });
    changed = true;
  }
  for (const user of db.users) {
    if (!user.id) {
      user.id = crypto.randomUUID();
      changed = true;
    }
    if (!Array.isArray(user.passkeys)) {
      user.passkeys = [];
      changed = true;
    }
    if (user.faceTemplate === undefined) {
      user.faceTemplate = null;
      changed = true;
    }
  }
  const admin = db.users.find(user => user.username === USERNAME);
  if (Array.isArray(db.faceTemplate) && admin && !admin.faceTemplate) {
    admin.faceTemplate = db.faceTemplate;
    db.faceTemplate = null;
    changed = true;
  }
  if (changed) await saveDB(db);
  return db;
}

async function saveDB(db) {
  await fs.writeJson(DB_FILE, db, { spaces: 2 });
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    role: user.role,
    passkeyCount: user.passkeys.length
  };
}

function signInToken(user) {
  return jwt.sign(
    { id: user.id, user: user.username, displayName: user.displayName, role: user.role },
    JWT_SECRET,
    { expiresIn: "2h" }
  );
}

function addHistory(db, title, detail, type = "safe") {
  db.history.push({ title, detail, time: new Date().toISOString(), type });
  db.history = db.history.slice(-100);
}

function raiseAlarm(db, category, title, detail) {
  const now = Date.now();
  const recentDuplicate = db.alarms.find(alarm =>
    alarm.category === category && !alarm.acknowledgedAt && now - Date.parse(alarm.time) < 30000
  );
  if (recentDuplicate) return recentDuplicate;

  const alarm = {
    id: crypto.randomUUID(),
    category,
    title,
    detail,
    time: new Date(now).toISOString(),
    acknowledgedAt: null
  };
  db.alarms.push(alarm);
  db.alarms = db.alarms.slice(-100);
  addHistory(db, title, detail, "unknown");
  return alarm;
}

function isValidFamilyMember({ username, displayName, password }) {
  return typeof username === "string"
    && /^[a-zA-Z0-9._-]{3,32}$/.test(username)
    && typeof displayName === "string"
    && displayName.trim().length >= 1
    && displayName.trim().length <= 60
    && typeof password === "string"
    && password.length >= 8
    && password.length <= 128;
}

function isValidUserRegistration({ name, password, confirmPassword }) {
  return typeof name === "string"
    && name.trim().length >= 1
    && name.trim().length <= 60
    && typeof password === "string"
    && password.length >= 8
    && password.length <= 128
    && password === confirmPassword;
}

function getCredential(user, credentialId) {
  return user.passkeys.find(passkey => passkey.id === credentialId);
}

function isValidDescriptor(descriptor) {
  return Array.isArray(descriptor)
    && descriptor.length === 128
    && descriptor.every(value => Number.isFinite(value) && Math.abs(value) <= 2);
}

function storeChallenge(db, key, challenge) {
  db.webauthnChallenges[key] = { challenge, expiresAt: Date.now() + 5 * 60 * 1000 };
}

function consumeChallenge(db, key) {
  const entry = db.webauthnChallenges[key];
  delete db.webauthnChallenges[key];
  return entry && entry.expiresAt > Date.now() ? entry.challenge : null;
}

function toWebAuthnCredential(passkey) {
  return {
    id: passkey.id,
    publicKey: new Uint8Array(Buffer.from(passkey.publicKey, "base64url")),
    counter: passkey.counter,
    transports: passkey.transports
  };
}

function completePasskeyUnlock(db, user, passkey, newCounter) {
  passkey.counter = newCounter;
  db.lockStatus = "UNLOCKED";
  addHistory(db, "指紋認証で解錠", `${user.displayName} の端末認証に成功しました`);
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.post("/api/login", asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  const normalizedUsername = typeof username === "string" ? username.trim().toLowerCase() : "";
  const db = await loadDB();
  const user = db.users.find(account => account.username.toLowerCase() === normalizedUsername);
  const validPassword = user && await bcrypt.compare(typeof password === "string" ? password : "", user.passwordHash);
  if (!validPassword) {
    const key = normalizedUsername || "unknown";
    const attempt = loginFailures.get(key) || { count: 0, startedAt: Date.now() };
    if (Date.now() - attempt.startedAt > 10 * 60 * 1000) {
      attempt.count = 0;
      attempt.startedAt = Date.now();
    }
    attempt.count += 1;
    loginFailures.set(key, attempt);
    if (attempt.count >= 3) {
      raiseAlarm(db, "login-failure", "ログイン失敗が続いています", `${key} の認証に複数回失敗しました`);
      await saveDB(db);
    }
    return res.status(401).json({ error: "ユーザー名またはパスワードが違います" });
  }
  loginFailures.delete(String(username).toLowerCase());
  return res.json({ token: signInToken(user), user: publicUser(user) });
}));

async function auth(req, res, next) {
  const [scheme, value] = (req.headers.authorization || "").split(" ");
  if (scheme !== "Bearer" || !value) return res.status(401).json({ error: "ログインが必要です" });
  try {
    req.user = jwt.verify(value, JWT_SECRET);
    const db = await loadDB();
    const activeUser = db.users.find(user => user.id === req.user.id);
    if (!activeUser) return res.status(403).json({ error: "このアカウントは無効です" });
    req.user.role = activeUser.role;
    next();
  } catch {
    const db = await loadDB();
    raiseAlarm(db, "invalid-token", "不正な認証要求", "無効なセッションで保護APIへアクセスしました");
    await saveDB(db);
    res.status(403).json({ error: "認証の有効期限が切れています" });
  }
}

app.get("/api/status", auth, asyncRoute(async (req, res) => {
  const db = await loadDB();
  const user = db.users.find(account => account.id === req.user.id);
  res.json({
    status: db.lockStatus,
    faceEnrolled: Boolean(user?.faceTemplate),
    user: user ? publicUser(user) : null,
    unacknowledgedAlarms: db.alarms.filter(alarm => !alarm.acknowledgedAt).length
  });
}));

app.get("/api/family/members", auth, asyncRoute(async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "管理者のみ利用できます" });
  const db = await loadDB();
  res.json(db.users.map(publicUser));
}));

app.post("/api/family/members", auth, asyncRoute(async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "管理者のみ利用できます" });
  const { username, displayName, password } = req.body || {};
  if (!isValidFamilyMember({ username, displayName, password })) {
    return res.status(400).json({ error: "表示名、ユーザー名、8文字以上のパスワードを確認してください" });
  }

  const db = await loadDB();
  if (db.users.some(user => user.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: "そのユーザー名は登録済みです" });
  }
  const user = {
    id: crypto.randomUUID(),
    username,
    displayName: displayName.trim(),
    passwordHash: await bcrypt.hash(password, 12),
    role: "member",
    faceTemplate: null,
    passkeys: []
  };
  db.users.push(user);
  addHistory(db, "家族メンバーを登録", `${user.displayName} のアカウントを追加しました`);
  await saveDB(db);
  res.status(201).json(publicUser(user));
}));

app.post("/api/register", asyncRoute(async (req, res) => {
  const { name, password, confirmPassword } = req.body || {};
  if (!isValidUserRegistration({ name, password, confirmPassword })) {
    return res.status(400).json({ error: "名前を入力し、8文字以上の同じパスワードを2回入力してください" });
  }

  const db = await loadDB();
  const username = name.trim();
  if (db.users.some(user => user.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: "その名前はすでに登録されています" });
  }
  const user = {
    id: crypto.randomUUID(),
    username,
    displayName: username,
    passwordHash: await bcrypt.hash(password, 12),
    role: "member",
    faceTemplate: null,
    passkeys: []
  };
  db.users.push(user);
  addHistory(db, "ユーザー登録", `${user.displayName} がアカウントを作成しました`);
  await saveDB(db);
  res.status(201).json({ registered: true, token: signInToken(user), user: publicUser(user) });
}));

app.delete("/api/family/members/:id", auth, asyncRoute(async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "管理者のみ利用できます" });
  const db = await loadDB();
  const memberIndex = db.users.findIndex(user => user.id === req.params.id && user.role === "member");
  if (memberIndex < 0) return res.status(404).json({ error: "家族メンバーが見つかりません" });
  const [member] = db.users.splice(memberIndex, 1);
  delete db.webauthnChallenges[`register:${member.id}`];
  delete db.webauthnChallenges[`unlock:${member.id}`];
  addHistory(db, "家族メンバーを削除", `${member.displayName} のアカウントを削除しました`);
  await saveDB(db);
  res.json({ removed: true });
}));

app.get("/api/alarms", auth, asyncRoute(async (req, res) => {
  const db = await loadDB();
  res.json([...db.alarms].reverse());
}));

app.post("/api/alarms/:id/acknowledge", auth, asyncRoute(async (req, res) => {
  const db = await loadDB();
  const alarm = db.alarms.find(item => item.id === req.params.id);
  if (!alarm) return res.status(404).json({ error: "警報が見つかりません" });
  alarm.acknowledgedAt = new Date().toISOString();
  alarm.acknowledgedBy = req.user.user;
  await saveDB(db);
  res.json({ alarm });
}));

app.post("/api/unlock", auth, asyncRoute(async (req, res) => {
  const db = await loadDB();
  db.lockStatus = "UNLOCKED";
  const viaFace = req.body?.reason === "face";
  addHistory(db, "解錠", viaFace ? "顔認証に成功して解錠しました" : "アプリから解錠しました");
  await saveDB(db);
  res.json({ status: db.lockStatus });
}));

app.post("/api/lock", auth, asyncRoute(async (req, res) => {
  const db = await loadDB();
  db.lockStatus = "LOCKED";
  addHistory(db, "施錠", "アプリから施錠しました");
  await saveDB(db);
  res.json({ status: db.lockStatus });
}));

app.get("/api/history", auth, asyncRoute(async (req, res) => {
  const db = await loadDB();
  res.json(db.history);
}));

app.post("/api/face/enroll", auth, asyncRoute(async (req, res) => {
  const { descriptor } = req.body || {};
  if (!isValidDescriptor(descriptor)) {
    return res.status(400).json({ error: "顔データが不正です。カメラでもう一度撮影してください" });
  }

  const db = await loadDB();
  const user = db.users.find(account => account.id === req.user.id);
  if (!user) return res.status(404).json({ error: "ユーザーが見つかりません" });
  user.faceTemplate = descriptor;
  addHistory(db, "顔を登録", `${user.displayName} の顔特徴量を登録しました`);
  await saveDB(db);
  res.json({ enrolled: true, message: `${user.displayName} の顔を登録しました` });
}));

app.post("/api/face/identify", auth, asyncRoute(async (req, res) => {
  const { descriptor } = req.body || {};
  if (!isValidDescriptor(descriptor)) {
    return res.status(400).json({ error: "顔データが不正です。カメラでもう一度撮影してください" });
  }

  const db = await loadDB();
  const user = db.users.find(account => account.id === req.user.id);
  if (!isValidDescriptor(user?.faceTemplate)) {
    return res.status(409).json({ error: "先に設定画面から顔を登録してください" });
  }

  const distance = Math.sqrt(descriptor.reduce((sum, value, index) => {
    const difference = value - user.faceTemplate[index];
    return sum + difference * difference;
  }, 0));
  const recognized = distance <= FACE_MATCH_THRESHOLD;
  const message = recognized ? "登録済みの顔を確認しました" : "登録済みの顔と一致しません";
  if (recognized) addHistory(db, "顔認証成功", `${user.displayName} を確認しました`);
  else raiseAlarm(db, "unknown-face", "未確認の顔を検知しました", "登録済みの顔と一致しません。ドアは解錠されていません");
  await saveDB(db);
  res.json({ visitorType: recognized ? "safe" : "unknown", recognized, message });
}));

app.post("/api/face/login", asyncRoute(async (req, res) => {
  const { descriptor } = req.body || {};
  if (!isValidDescriptor(descriptor)) {
    return res.status(400).json({ error: "顔データが不正です。もう一度撮影してください" });
  }

  const db = await loadDB();
  let matchedUser = null;
  let bestDistance = FACE_MATCH_THRESHOLD;
  for (const user of db.users) {
    if (!isValidDescriptor(user.faceTemplate)) continue;
    const distance = Math.sqrt(descriptor.reduce((sum, value, index) => {
      const difference = value - user.faceTemplate[index];
      return sum + difference * difference;
    }, 0));
    if (distance <= bestDistance) {
      bestDistance = distance;
      matchedUser = user;
    }
  }

  if (!matchedUser) {
    raiseAlarm(db, "unknown-face-login", "顔ログインに失敗しました", "登録済みの顔と一致しないログイン試行がありました");
    await saveDB(db);
    return res.status(401).json({ error: "登録済みの顔と一致しません。先にパスワードでログインし、顔を登録してください" });
  }

  addHistory(db, "顔ログイン", `${matchedUser.displayName} が顔認証でログインしました`);
  await saveDB(db);
  res.json({ token: signInToken(matchedUser), user: publicUser(matchedUser) });
}));

app.post("/api/webauthn/register/options", auth, asyncRoute(async (req, res) => {
  const db = await loadDB();
  const user = db.users.find(account => account.id === req.user.id);
  if (!user) return res.status(404).json({ error: "ユーザーが見つかりません" });

  const options = await generateRegistrationOptions({
    rpName: "未来Lock",
    rpID: RP_ID,
    userID: new TextEncoder().encode(user.id),
    userName: user.username,
    userDisplayName: user.displayName,
    attestationType: "none",
    excludeCredentials: user.passkeys.map(passkey => ({ id: passkey.id, transports: passkey.transports })),
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "required",
      userVerification: "required"
    }
  });
  storeChallenge(db, `register:${user.id}`, options.challenge);
  await saveDB(db);
  res.json(options);
}));

app.post("/api/webauthn/register/verify", auth, asyncRoute(async (req, res) => {
  const db = await loadDB();
  const user = db.users.find(account => account.id === req.user.id);
  const expectedChallenge = consumeChallenge(db, `register:${req.user.id}`);
  if (!user || !expectedChallenge) {
    await saveDB(db);
    return res.status(400).json({ error: "認証要求の期限が切れました。もう一度お試しください" });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true
    });
  } catch {
    raiseAlarm(db, "invalid-passkey-registration", "認証器登録に失敗しました", `${user.displayName} の認証器登録を検証できませんでした`);
    await saveDB(db);
    return res.status(400).json({ error: "認証器を検証できませんでした" });
  }

  if (!verification.verified || !verification.registrationInfo) {
    raiseAlarm(db, "invalid-passkey-registration", "認証器登録に失敗しました", `${user.displayName} の登録署名が無効でした`);
    await saveDB(db);
    return res.status(400).json({ error: "認証器の署名が無効です" });
  }

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  if (db.users.some(account => account.passkeys.some(passkey => passkey.id === credential.id))) {
    await saveDB(db);
    return res.status(409).json({ error: "この認証器はすでに登録されています" });
  }
  user.passkeys.push({
    id: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString("base64url"),
    counter: credential.counter,
    transports: req.body.response?.transports || [],
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp
  });
  addHistory(db, "指紋認証器を登録", `${user.displayName} が端末認証器を登録しました`);
  await saveDB(db);
  res.json({ verified: true, passkeyCount: user.passkeys.length });
}));

app.post("/api/webauthn/login/options", asyncRoute(async (req, res) => {
  const db = await loadDB();
  if (!db.users.some(user => user.passkeys.length)) {
    return res.status(409).json({ error: "先にログインして設定から指紋認証器を登録してください" });
  }
  const options = await generateAuthenticationOptions({ rpID: RP_ID, userVerification: "required" });
  storeChallenge(db, "passkey-login", options.challenge);
  await saveDB(db);
  res.json(options);
}));

app.post("/api/webauthn/login/verify", asyncRoute(async (req, res) => {
  const db = await loadDB();
  const expectedChallenge = consumeChallenge(db, "passkey-login");
  const user = db.users.find(account => getCredential(account, req.body?.id));
  const passkey = user && getCredential(user, req.body.id);
  if (!expectedChallenge || !user || !passkey) {
    raiseAlarm(db, "unknown-passkey", "未登録の指紋認証器を検知", "登録されていない認証器でログインが試みられました");
    await saveDB(db);
    return res.status(401).json({ error: "この認証器は登録されていません" });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: toWebAuthnCredential(passkey),
      requireUserVerification: true
    });
    if (!verification.verified) throw new Error("認証に失敗しました");
    completePasskeyUnlock(db, user, passkey, verification.authenticationInfo.newCounter);
    await saveDB(db);
    return res.json({ status: db.lockStatus, token: signInToken(user), user: publicUser(user) });
  } catch {
    raiseAlarm(db, "invalid-passkey", "指紋認証に失敗しました", `${user.displayName} の認証署名を確認できませんでした`);
    await saveDB(db);
    return res.status(401).json({ error: "認証に失敗しました。警報に記録しました" });
  }
}));

app.post("/api/webauthn/unlock/options", auth, asyncRoute(async (req, res) => {
  const db = await loadDB();
  const user = db.users.find(account => account.id === req.user.id);
  if (!user?.passkeys.length) return res.status(409).json({ error: "設定からこの端末の指紋認証器を登録してください" });
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: "required",
    allowCredentials: user.passkeys.map(passkey => ({ id: passkey.id, transports: passkey.transports }))
  });
  storeChallenge(db, `unlock:${user.id}`, options.challenge);
  await saveDB(db);
  res.json(options);
}));

app.post("/api/webauthn/unlock/verify", auth, asyncRoute(async (req, res) => {
  const db = await loadDB();
  const user = db.users.find(account => account.id === req.user.id);
  const expectedChallenge = consumeChallenge(db, `unlock:${req.user.id}`);
  const passkey = user && getCredential(user, req.body?.id);
  if (!expectedChallenge || !passkey) {
    raiseAlarm(db, "unknown-passkey", "未登録の指紋認証器を検知", "解錠時に登録されていない認証器が使われました");
    await saveDB(db);
    return res.status(401).json({ error: "認証器が登録されていないか、要求の期限が切れました" });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: toWebAuthnCredential(passkey),
      requireUserVerification: true
    });
    if (!verification.verified) throw new Error("認証に失敗しました");
    completePasskeyUnlock(db, user, passkey, verification.authenticationInfo.newCounter);
    await saveDB(db);
    return res.json({ status: db.lockStatus });
  } catch {
    raiseAlarm(db, "invalid-passkey", "指紋認証に失敗しました", `${user.displayName} の解錠署名を確認できませんでした`);
    await saveDB(db);
    return res.status(401).json({ error: "認証に失敗しました。警報に記録しました" });
  }
}));

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: "サーバー内部でエラーが発生しました" });
});

await loadDB();
app.listen(PORT, HOST, () => console.log(`SmartLock API running at http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}`));