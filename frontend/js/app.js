const API = window.SMARTLOCK_API || `${window.location.protocol}//${window.location.hostname}:3000/api`;
const MODEL_URL = "https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.15/model";
const video = document.getElementById("cameraVideo");
const appContainer = document.querySelector(".app-container");

let token = null;
let activeUser = null;
let cameraStream = null;
let faceLoginStream = null;
let faceLoginRequestId = 0;
let faceModelsReady = false;
let toastTimer;
let seenAlarmIds = new Set();
let alarmBaselineLoaded = false;
let alarmAudioContext = null;

appContainer.inert = true;
appContainer.setAttribute("aria-hidden", "true");

async function request(path, options = {}) {
  const headers = { ...(options.body ? { "Content-Type": "application/json" } : {}) };
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(`${API}${path}`, {
    ...options,
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `API error (${response.status})`);
  return data;
}

async function login(event) {
  event.preventDefault();
  prepareAlarmAudio();
  const loginButton = document.getElementById("loginButton");
  const loginError = document.getElementById("loginError");
  loginButton.disabled = true;
  loginError.textContent = "";
  try {
    const data = await request("/login", {
      method: "POST",
      body: {
        username: document.getElementById("usernameInput").value,
        password: document.getElementById("passwordInput").value
      }
    });
    await enterApp(data);
  } catch (error) {
    loginError.textContent = error instanceof TypeError
      ? `APIに接続できません。バックエンドを起動してください（${API.slice(0, -4)}）。`
      : error.message;
  } finally {
    loginButton.disabled = false;
  }
}

function showUserRegistration() {
  document.getElementById("loginForm").hidden = true;
  document.getElementById("userRegisterForm").hidden = false;
  document.getElementById("userRegisterMessage").textContent = "";
}

function showLoginForm() {
  document.getElementById("userRegisterForm").hidden = true;
  document.getElementById("loginForm").hidden = false;
  document.getElementById("loginError").textContent = "";
}

async function registerUserFromLogin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = document.getElementById("submitUserRegisterButton");
  const message = document.getElementById("userRegisterMessage");
  button.disabled = true;
  message.textContent = "";
  try {
    const values = Object.fromEntries(new FormData(form));
    if (values.password !== values.confirmPassword) {
      throw new Error("パスワードが一致しません");
    }
    const result = await request("/register", { method: "POST", body: values });
    form.reset();
    await enterApp(result);
    showToast("✓", `登録しました。ようこそ、${result.user.displayName}さん`);
  } catch (error) {
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function enterApp(data) {
  token = data.token;
  activeUser = data.user || null;
  try {
    await Promise.all([syncStatus(), loadHistory(), loadAlarms()]);
    if (data.user?.role === "admin") await loadFamilyMembers();
    if (data.status) updateLockUI(data.status, true);
    document.getElementById("loginOverlay").hidden = true;
    appContainer.inert = false;
    appContainer.removeAttribute("aria-hidden");
  } catch (error) {
    token = null;
    activeUser = null;
    throw error;
  }
}

async function passkeyLogin() {
  prepareAlarmAudio();
  const loginError = document.getElementById("loginError");
  const button = document.getElementById("passkeyLoginButton");
  button.disabled = true;
  loginError.textContent = "";
  try {
    const options = await request("/webauthn/login/options", { method: "POST" });
    const assertion = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options });
    const data = await request("/webauthn/login/verify", { method: "POST", body: assertion });
    await enterApp(data);
  } catch (error) {
    loginError.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function startFaceLogin() {
  const requestId = ++faceLoginRequestId;
  const panel = document.getElementById("faceLoginPanel");
  const status = document.getElementById("faceLoginStatus");
  const button = document.getElementById("faceLoginButton");
  button.disabled = true;
  panel.hidden = false;
  status.textContent = "カメラへのアクセスを確認しています…";
  try {
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error("顔ログインにはlocalhostまたはHTTPSでのアクセスが必要です。");
    }
    const stream = faceLoginStream || await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: { facingMode: "user", width: { ideal: 640 }, height: { ideal: 480 } }
    });
    if (requestId !== faceLoginRequestId) {
      stream.getTracks().forEach(track => track.stop());
      return;
    }
    faceLoginStream = stream;
    const loginVideo = document.getElementById("loginFaceVideo");
    loginVideo.srcObject = faceLoginStream;
    await loginVideo.play();
    status.textContent = "明るい場所で正面を向き、「顔を確認してログイン」を押してください。";
  } catch (error) {
    if (requestId === faceLoginRequestId) status.textContent = error.message;
  } finally {
    if (requestId === faceLoginRequestId) button.disabled = false;
  }
}

async function submitFaceLogin() {
  const button = document.getElementById("submitFaceLoginButton");
  const status = document.getElementById("faceLoginStatus");
  button.disabled = true;
  try {
    if (!faceLoginStream) throw new Error("先にカメラを開始してください。");
    await ensureFaceModels();
    const result = await faceapi
      .detectSingleFace(document.getElementById("loginFaceVideo"), new faceapi.TinyFaceDetectorOptions())
      .withFaceLandmarks()
      .withFaceDescriptor();
    if (!result) throw new Error("顔を検出できません。明るい場所で正面を向いてください。");
    const data = await request("/face/login", {
      method: "POST",
      body: { descriptor: Array.from(result.descriptor) }
    });
    stopFaceLoginCamera();
    await enterApp(data);
    showToast("✓", `顔を確認しました。ようこそ、${data.user.displayName}さん`);
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

function stopFaceLoginCamera() {
  faceLoginRequestId += 1;
  document.getElementById("faceLoginButton").disabled = false;
  faceLoginStream?.getTracks().forEach(track => track.stop());
  faceLoginStream = null;
  document.getElementById("loginFaceVideo").srcObject = null;
  document.getElementById("faceLoginPanel").hidden = true;
}

async function syncStatus() {
  const data = await request("/status");
  activeUser = data.user ? { ...data.user, faceEnrolled: data.faceEnrolled } : activeUser;
  updateLockUI(data.status);
  updateEnrollmentStatus(data.faceEnrolled);
  if (data.user) {
    document.getElementById("currentUserLabel").textContent = `${data.user.displayName} (${data.user.role === "admin" ? "管理者" : "家族"})`;
    document.getElementById("passkeyStatus").textContent = data.user.passkeyCount
      ? `登録済み ${data.user.passkeyCount}件`
      : "未登録";
    document.getElementById("unlockWithPasskeyButton").hidden = data.user.passkeyCount === 0;
    document.getElementById("familyAdminSection").hidden = data.user.role !== "admin";
    updateProfileUI();
  }
  document.getElementById("alarmCount").textContent = String(data.unacknowledgedAlarms || 0);
}

function updateProfileUI() {
  if (!activeUser) return;
  const displayName = activeUser.displayName || activeUser.username;
  const initial = Array.from(displayName)[0]?.toLocaleUpperCase() || "?";
  document.getElementById("profileButton").textContent = initial;
  document.getElementById("profileButton").setAttribute("aria-label", `${displayName}のプロフィールを開く`);
  document.getElementById("profileInitial").textContent = initial;
  document.getElementById("profileDisplayName").textContent = displayName;
  document.getElementById("profileUsername").textContent = `@${activeUser.username}`;
  document.getElementById("profileRole").textContent = activeUser.role === "admin" ? "管理者" : "ユーザー";
  document.getElementById("profileFaceStatus").textContent = activeUser.faceEnrolled ? "登録済み" : "未登録";
  document.getElementById("profilePasskeyStatus").textContent = activeUser.passkeyCount
    ? `登録済み ${activeUser.passkeyCount}件`
    : "未登録";
}

function openProfile() {
  if (!activeUser) return;
  updateProfileUI();
  document.getElementById("profileModal").classList.add("show");
  document.getElementById("closeProfileButton").focus();
}

function closeProfile() {
  document.getElementById("profileModal").classList.remove("show");
  document.getElementById("profileButton").focus();
}

function logout() {
  const previousUser = activeUser;
  token = null;
  activeUser = null;
  stopCamera();
  stopFaceLoginCamera();
  document.getElementById("profileModal").classList.remove("show");
  appContainer.inert = true;
  appContainer.setAttribute("aria-hidden", "true");
  document.getElementById("loginOverlay").hidden = false;
  document.getElementById("passwordInput").value = "";
  document.getElementById("usernameInput").value = previousUser?.username || "";
  showLoginForm();
}

function updateLockUI(status, notify = false) {
  const isLocked = status === "LOCKED";
  document.getElementById("lockStateText").textContent = status;
  document.getElementById("lockEmoji").textContent = isLocked ? "🔒" : "🔓";
  document.getElementById("lockActionIcon").textContent = isLocked ? "lock_open" : "lock";
  document.getElementById("lockAction").textContent = isLocked ? "解錠" : "施錠";
  if (notify) showToast(isLocked ? "🔒" : "🔓", isLocked ? "施錠しました" : "解錠しました");
}

function updateEnrollmentStatus(enrolled) {
  const label = enrolled ? "登録済み" : "未登録";
  document.getElementById("faceEnrollmentStatus").textContent = label;
  document.getElementById("cameraStatus").textContent = cameraStream
    ? `カメラ起動中 · 顔認証 ${label}`
    : `カメラは停止中 · 顔認証 ${label}`;
}

async function toggleLock() {
  if (!token) return showToast("!", "APIに接続してください");
  const locked = document.getElementById("lockStateText").textContent === "LOCKED";
  try {
    const data = await request(locked ? "/unlock" : "/lock", {
      method: "POST",
      body: locked ? { reason: "manual" } : undefined
    });
    updateLockUI(data.status, true);
    await loadHistory();
  } catch (error) {
    showToast("!", error.message);
  }
}

async function loadHistory() {
  const history = await request("/history");
  const container = document.querySelector(".history-list");
  container.replaceChildren();

  for (const item of [...history].reverse()) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "history-item";
    addButtonIcon(row, "info");

    const main = document.createElement("span");
    main.className = "history-main";
    const title = document.createElement("span");
    title.textContent = item.title;
    const time = document.createElement("time");
    time.className = "history-time";
    time.dateTime = item.time;
    time.textContent = new Date(item.time).toLocaleString();
    main.append(title, time);

    const detail = document.createElement("span");
    detail.className = `history-sub${item.type === "unknown" ? " warning" : ""}`;
    detail.textContent = item.detail;
    row.append(main, detail);
    row.addEventListener("click", () => openVisitorModal(item.title, item.detail));
    container.appendChild(row);
  }
}

async function loadAlarms({ notifyNew = false } = {}) {
  const alarms = await request("/alarms");
  const pending = alarms.filter(alarm => !alarm.acknowledgedAt);
  const newestPending = pending[0];
  const banner = document.getElementById("alarmBanner");
  document.getElementById("alarmCount").textContent = String(pending.length);
  banner.hidden = !newestPending;
  if (newestPending) {
    document.getElementById("alarmBannerMessage").textContent = `${newestPending.title}: ${newestPending.detail}`;
    if (notifyNew && alarmBaselineLoaded && !seenAlarmIds.has(newestPending.id)) playAlarmTone();
  }
  if (!alarmBaselineLoaded) alarmBaselineLoaded = true;
  for (const alarm of alarms) seenAlarmIds.add(alarm.id);

  const container = document.getElementById("alarmList");
  container.replaceChildren();
  if (!alarms.length) {
    const empty = document.createElement("p");
    empty.textContent = "警報はありません";
    container.appendChild(empty);
    return;
  }

  for (const alarm of alarms) {
    const row = document.createElement("article");
    row.className = `alarm-item${alarm.acknowledgedAt ? " acknowledged" : ""}`;
    const heading = document.createElement("h4");
    heading.textContent = alarm.title;
    const detail = document.createElement("p");
    detail.textContent = alarm.detail;
    const time = document.createElement("time");
    time.dateTime = alarm.time;
    time.textContent = new Date(alarm.time).toLocaleString();
    row.append(heading, detail, time);
    if (!alarm.acknowledgedAt) {
      const acknowledge = document.createElement("button");
      acknowledge.type = "button";
      acknowledge.className = "secondary-btn";
      acknowledge.textContent = "確認済みにする";
      addButtonIcon(acknowledge, "task_alt");
      acknowledge.addEventListener("click", () => acknowledgeAlarm(alarm.id));
      row.appendChild(acknowledge);
    } else {
      const acknowledged = document.createElement("p");
      acknowledged.className = "alarm-acknowledged-label";
      acknowledged.textContent = `確認済み: ${alarm.acknowledgedBy || "ユーザー"}`;
      row.appendChild(acknowledged);
    }
    container.appendChild(row);
  }
}

async function acknowledgeAlarm(id) {
  try {
    await request(`/alarms/${encodeURIComponent(id)}/acknowledge`, { method: "POST" });
    await Promise.all([loadAlarms(), syncStatus()]);
  } catch (error) {
    showToast("!", error.message);
  }
}

function playAlarmTone() {
  const AudioContextType = window.AudioContext || window.webkitAudioContext;
  if (!AudioContextType) return;
  try {
    alarmAudioContext ||= new AudioContextType();
    if (alarmAudioContext.state === "suspended") alarmAudioContext.resume();
    const oscillator = alarmAudioContext.createOscillator();
    const gain = alarmAudioContext.createGain();
    oscillator.type = "square";
    oscillator.frequency.value = 880;
    gain.gain.setValueAtTime(0.12, alarmAudioContext.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, alarmAudioContext.currentTime + 0.45);
    oscillator.connect(gain);
    gain.connect(alarmAudioContext.destination);
    oscillator.start();
    oscillator.stop(alarmAudioContext.currentTime + 0.45);
  } catch {
    showToast("🚨", "新しいセキュリティ警報があります");
  }
}

function prepareAlarmAudio() {
  const AudioContextType = window.AudioContext || window.webkitAudioContext;
  if (!AudioContextType || alarmAudioContext) return;
  try {
    alarmAudioContext = new AudioContextType();
    alarmAudioContext.resume().catch(() => {});
  } catch {
    alarmAudioContext = null;
  }
}

async function loadFamilyMembers() {
  const members = await request("/family/members");
  const container = document.getElementById("familyList");
  container.replaceChildren();
  for (const member of members) {
    const row = document.createElement("div");
    row.className = "family-member-row";
    const label = document.createElement("p");
    label.textContent = `${member.displayName} · ${member.username} · ${member.role === "admin" ? "管理者" : "ユーザー"} · 指紋認証器 ${member.passkeyCount}件`;
    row.appendChild(label);
    if (member.role === "member") {
      const removeButton = document.createElement("button");
      removeButton.type = "button";
      removeButton.className = "secondary-btn";
      removeButton.textContent = "削除";
      addButtonIcon(removeButton, "delete");
      removeButton.addEventListener("click", () => removeFamilyMember(member));
      row.appendChild(removeButton);
    }
    container.appendChild(row);
  }
}

async function removeFamilyMember(member) {
  if (!window.confirm(`${member.displayName} のユーザーIDを削除しますか？`)) return;
  try {
    await request(`/family/members/${encodeURIComponent(member.id)}`, { method: "DELETE" });
    await loadFamilyMembers();
  } catch (error) {
    showToast("!", error.message);
  }
}

async function addFamilyMember(event) {
  event.preventDefault();
  const message = document.getElementById("familyFormMessage");
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  try {
    await request("/family/members", { method: "POST", body: values });
    form.reset();
    message.textContent = "ユーザーIDを登録しました。本人がログインし、認証器を登録できます。";
    await loadFamilyMembers();
  } catch (error) {
    message.textContent = error.message;
  }
}

async function registerPasskey() {
  const button = document.getElementById("registerPasskeyButton");
  button.disabled = true;
  try {
    if (!window.SimpleWebAuthnBrowser) throw new Error("認証ライブラリを読み込めませんでした");
    const options = await request("/webauthn/register/options", { method: "POST" });
    const registration = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: options });
    await request("/webauthn/register/verify", { method: "POST", body: registration });
    await syncStatus();
    if (!document.getElementById("familyAdminSection").hidden) await loadFamilyMembers();
    showToast("✓", "端末の指紋認証器を登録しました");
  } catch (error) {
    showToast("!", error.message);
  } finally {
    button.disabled = false;
  }
}

async function unlockWithPasskey() {
  const button = document.getElementById("unlockWithPasskeyButton");
  button.disabled = true;
  try {
    const options = await request("/webauthn/unlock/options", { method: "POST" });
    const assertion = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options });
    const result = await request("/webauthn/unlock/verify", { method: "POST", body: assertion });
    updateLockUI(result.status, true);
    await loadHistory();
  } catch (error) {
    showToast("🚨", error.message);
    await loadAlarms();
  } finally {
    button.disabled = false;
  }
}

async function ensureFaceModels() {
  if (faceModelsReady) return;
  if (!window.faceapi) throw new Error("顔認証モデルを読み込めません。インターネット接続を確認してください。");

  document.getElementById("cameraStatus").textContent = "顔認証モデルを読み込み中…";
  await Promise.all([
    faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
    faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
    faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL)
  ]);
  faceModelsReady = true;
}

async function ensureCameraAccess() {
  if (!video) {
    throw new Error("カメラ用のvideo要素が見つかりません。");
  }
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new Error("カメラにはHTTPSまたはlocalhostでのアクセスが必要です。");
  }
  if (!cameraStream) {
    cameraStream = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: { facingMode: "user", width: { ideal: 640 }, height: { ideal: 480 } }
    });
    video.srcObject = cameraStream;
    await video.play();
  }
  document.getElementById("startCameraButton").textContent = "カメラを停止";
  document.getElementById("cameraStatus").textContent = "カメラ起動中。正面を向いてください。";
}

async function startCamera() {
  if (cameraStream) return;
  await ensureCameraAccess();
}

function stopCamera() {
  cameraStream?.getTracks().forEach(track => track.stop());
  cameraStream = null;
  video.srcObject = null;
  document.getElementById("startCameraButton").textContent = "カメラを開始";
  document.getElementById("cameraStatus").textContent = "カメラは停止中です";
}

async function captureFaceDescriptor() {
  if (!cameraStream) await startCamera();
  await ensureFaceModels();
  const result = await faceapi
    .detectSingleFace(video, new faceapi.TinyFaceDetectorOptions())
    .withFaceLandmarks()
    .withFaceDescriptor();
  if (!result) throw new Error("顔を検出できません。明るい場所で正面を向いてください。");
  return Array.from(result.descriptor);
}

async function enrollFace() {
  if (!token) return showToast("!", "APIに接続してください");
  setCameraButtonsDisabled(true);
  try {
    const descriptor = await captureFaceDescriptor();
    const result = await request("/face/enroll", { method: "POST", body: { descriptor } });
    updateEnrollmentStatus(true);
    openVisitorModal("顔を登録しました", result.message);
    await loadHistory();
  } catch (error) {
    showToast("!", error.message);
    document.getElementById("cameraStatus").textContent = error.message;
  } finally {
    setCameraButtonsDisabled(false);
  }
}

async function recognizeFace() {
  if (!token) return showToast("!", "APIに接続してください");
  setCameraButtonsDisabled(true);
  try {
    const descriptor = await captureFaceDescriptor();
    const result = await request("/face/identify", { method: "POST", body: { descriptor } });
    if (result.recognized) {
      const lock = await request("/unlock", { method: "POST", body: { reason: "face" } });
      updateLockUI(lock.status, true);
      openVisitorModal("顔認証に成功しました", `${result.message} ドアを解錠しました。`);
    } else {
      openVisitorModal("未確認の顔です", `${result.message} 解錠していません。`);
    }
    await Promise.all([loadHistory(), loadAlarms({ notifyNew: true })]);
  } catch (error) {
    showToast("!", error.message);
    document.getElementById("cameraStatus").textContent = error.message;
  } finally {
    setCameraButtonsDisabled(false);
  }
}

function setCameraButtonsDisabled(disabled) {
  for (const id of ["startCameraButton", "enrollFaceButton", "recognizeFaceButton"]) {
    document.getElementById(id).disabled = disabled;
  }
}

function showScreen(screen) {
  document.querySelectorAll(".panel").forEach(panel => panel.classList.remove("active"));
  const panel = document.getElementById(`screen-${screen}`);
  panel.classList.add("active");
  if (screen !== "camera") stopCamera();
  const heading = panel.querySelector("h3");
  if (heading) {
    heading.tabIndex = -1;
    window.requestAnimationFrame(() => {
      panel.scrollIntoView({ behavior: "smooth", block: "start" });
      heading.focus({ preventScroll: true });
    });
  }
}

function showToast(icon, message) {
  const toast = document.getElementById("toast");
  document.getElementById("toastIcon").textContent = icon;
  document.getElementById("toastMsg").textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 3500);
}

function openVisitorModal(title, detail) {
  document.getElementById("visitorTitle").textContent = title;
  document.getElementById("visitorDetail").textContent = detail;
  document.getElementById("visitorModal").classList.add("show");
}

function closeVisitorModal() {
  document.getElementById("visitorModal").classList.remove("show");
}

document.getElementById("toggleLockButton").addEventListener("click", toggleLock);
document.getElementById("faceLoginButton").addEventListener("click", startFaceLogin);
document.getElementById("submitFaceLoginButton").addEventListener("click", submitFaceLogin);
document.getElementById("cancelFaceLoginButton").addEventListener("click", stopFaceLoginCamera);
document.getElementById("profileButton").addEventListener("click", openProfile);
document.getElementById("closeProfileButton").addEventListener("click", closeProfile);
document.getElementById("logoutButton").addEventListener("click", logout);
document.getElementById("profileModal").addEventListener("click", event => {
  if (event.target.id === "profileModal") closeProfile();
});
document.addEventListener("keydown", event => {
  if (event.key === "Escape" && document.getElementById("profileModal").classList.contains("show")) {
    closeProfile();
  }
});
document.getElementById("passkeyLoginButton").addEventListener("click", passkeyLogin);
document.getElementById("unlockWithPasskeyButton").addEventListener("click", unlockWithPasskey);
document.getElementById("registerPasskeyButton").addEventListener("click", registerPasskey);
document.getElementById("familyForm").addEventListener("submit", addFamilyMember);
document.getElementById("viewAlarmsButton").addEventListener("click", () => showScreen("alarms"));
document.getElementById("startCameraButton").addEventListener("click", async () => {
  try {
    if (cameraStream) {
      stopCamera();
      document.getElementById("startCameraButton").textContent = "カメラを開始";
    } else {
      await ensureCameraAccess();
    }
  } catch (error) {
    showToast("!", error.message);
    document.getElementById("cameraStatus").textContent = error.message;
  }
});
document.getElementById("enrollFaceButton").addEventListener("click", async () => {
  try {
    await ensureCameraAccess();
    await enrollFace();
  } catch (error) {
    showToast("!", error.message);
    document.getElementById("cameraStatus").textContent = error.message;
  }
});
document.getElementById("recognizeFaceButton").addEventListener("click", async () => {
  try {
    await ensureCameraAccess();
    await recognizeFace();
  } catch (error) {
    showToast("!", error.message);
    document.getElementById("cameraStatus").textContent = error.message;
  }
});
document.getElementById("detectVisitorButton").addEventListener("click", () => {
  showScreen("camera");
  recognizeFace();
});
document.getElementById("settingsCameraButton").addEventListener("click", () => showScreen("camera"));
document.getElementById("closeVisitorModalButton").addEventListener("click", closeVisitorModal);
document.getElementById("visitorModal").addEventListener("click", event => {
  if (event.target.id === "visitorModal") closeVisitorModal();
});
document.querySelectorAll("[data-screen]").forEach(button => {
  button.addEventListener("click", () => showScreen(button.dataset.screen));
});

document.getElementById("loginForm").addEventListener("submit", login);
document.getElementById("showUserRegisterButton").addEventListener("click", showUserRegistration);
document.getElementById("backToLoginButton").addEventListener("click", showLoginForm);
document.getElementById("userRegisterForm").addEventListener("submit", registerUserFromLogin);

function addButtonIcon(button, symbol) {
  const icon = document.createElement("span");
  icon.className = "material-symbols-outlined button-icon";
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = symbol;
  button.prepend(icon);
}

const buttonIcons = {
  loginButton: "login",
  passkeyLoginButton: "fingerprint",
  faceLoginButton: "face",
  submitFaceLoginButton: "face_unlock",
  cancelFaceLoginButton: "close",
  showUserRegisterButton: "person_add",
  submitUserRegisterButton: "how_to_reg",
  backToLoginButton: "arrow_back",
  unlockWithPasskeyButton: "fingerprint",
  viewAlarmsButton: "notifications_active",
  startCameraButton: "videocam",
  enrollFaceButton: "face_retouching_natural",
  recognizeFaceButton: "lock_open_right",
  registerPasskeyButton: "fingerprint",
  settingsCameraButton: "photo_camera",
  createUserButton: "person_add",
  closeVisitorModalButton: "close",
  closeProfileButton: "close",
  logoutButton: "logout"
};

for (const [id, symbol] of Object.entries(buttonIcons)) {
  const button = document.getElementById(id);
  if (button) addButtonIcon(button, symbol);
}

window.setInterval(() => {
  if (token) {
    Promise.all([syncStatus(), loadAlarms({ notifyNew: true })])
      .catch(error => showToast("!", error.message));
  }
}, 10000);