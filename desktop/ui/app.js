const invoke = window.__TAURI__.core.invoke;

const byId = (id) => document.getElementById(id);
const terminalStates = new Set(["unsealed", "failed", "expired"]);

let currentSessionId = null;
let pollHandle = null;
let busy = false;

function serverUrl() {
  return byId("server").value.trim() || "http://127.0.0.1:50051";
}

function appendLog(message, kind = "info") {
  const item = document.createElement("li");
  item.className = kind;

  const time = document.createElement("time");
  time.textContent = new Date().toLocaleTimeString();

  const text = document.createElement("span");
  text.textContent = message;

  item.append(time, text);
  byId("log").prepend(item);
}

function setBadge(state) {
  const badge = byId("state-badge");
  badge.textContent = state;
  badge.dataset.state = state;
}

function setBusy(value) {
  busy = value;
  for (const id of ["start-btn", "submit-btn", "seal-btn"]) {
    byId(id).disabled = value;
  }
}

function render(view) {
  if (!view) {
    return;
  }

  if (view.session_id) {
    currentSessionId = view.session_id;
    byId("session-id").textContent = view.session_id;
  }
  if (view.nonce_hex) {
    byId("nonce").textContent = view.nonce_hex;
  }

  byId("collected").textContent = view.shares_collected ?? 0;
  byId("threshold").textContent = view.threshold ?? "–";

  const percent =
    view.threshold > 0
      ? Math.min(100, Math.round((view.shares_collected / view.threshold) * 100))
      : 0;
  byId("progress-bar").style.width = `${percent}%`;

  byId("expires").textContent = view.expires_at
    ? new Date(view.expires_at * 1000).toLocaleString()
    : "—";

  setBadge(view.state || "sealed");

  if (terminalStates.has(view.state)) {
    stopPolling();
  }
}

function resetView() {
  currentSessionId = null;
  byId("session-id").textContent = "—";
  byId("nonce").textContent = "—";
  byId("expires").textContent = "—";
  byId("collected").textContent = "0";
  byId("threshold").textContent = "–";
  byId("progress-bar").style.width = "0";
  setBadge("sealed");
}

async function invokeCommand(command, args) {
  return invoke(command, args);
}

function startPolling() {
  stopPolling();
  if (!currentSessionId) {
    return;
  }

  pollHandle = setInterval(async () => {
    if (!currentSessionId) {
      return;
    }
    try {
      const view = await invokeCommand("get_status", {
        server_url: serverUrl(),
        session_id: currentSessionId,
      });
      render(view);
    } catch (error) {
      appendLog(String(error), "error");
      stopPolling();
    }
  }, 1500);
}

function stopPolling() {
  if (pollHandle) {
    clearInterval(pollHandle);
    pollHandle = null;
  }
}

async function startUnseal() {
  if (busy) {
    return;
  }
  setBusy(true);
  try {
    const view = await invokeCommand("start_unseal", {
      server_url: serverUrl(),
    });
    render(view);
    appendLog(`会话已创建，阈值 ${view.threshold}`, "ok");
    startPolling();
  } catch (error) {
    appendLog(String(error), "error");
  } finally {
    setBusy(false);
  }
}

async function submitShare() {
  if (busy) {
    return;
  }

  const sessionId = byId("holder-session").value.trim();
  const holderId = byId("holder-id").value.trim();
  const secretFile = byId("holder-secret").files[0];
  const shareFile = byId("share-file").files[0];

  if (!sessionId || !holderId || !secretFile || !shareFile) {
    appendLog("请填写 Session ID、持有者标识，并选择私钥和加密份额文件", "error");
    return;
  }

  setBusy(true);
  try {
    const holderSecret = Array.from(
      new Uint8Array(await secretFile.arrayBuffer()),
    );
    const shareEnvelope = Array.from(
      new Uint8Array(await shareFile.arrayBuffer()),
    );
    const view = await invokeCommand("submit_share", {
      server_url: serverUrl(),
      session_id: sessionId,
      holder_id: holderId,
      share_envelope: shareEnvelope,
      holder_secret: holderSecret,
    });
    render(view);
    appendLog(`份额已提交：${holderId}`, "ok");
    if (view.state === "collecting") {
      startPolling();
    }
  } catch (error) {
    appendLog(String(error), "error");
  } finally {
    setBusy(false);
  }
}

async function sealService() {
  if (busy) {
    return;
  }
  setBusy(true);
  try {
    const sealed = await invokeCommand("seal", {
      server_url: serverUrl(),
    });
    if (sealed) {
      stopPolling();
      resetView();
      appendLog("服务已重新封存，KEK 和会话已清除", "ok");
    }
  } catch (error) {
    appendLog(String(error), "error");
  } finally {
    setBusy(false);
  }
}

byId("start-btn").addEventListener("click", startUnseal);
byId("submit-btn").addEventListener("click", submitShare);
byId("seal-btn").addEventListener("click", sealService);

byId("copy-session").addEventListener("click", async () => {
  if (!currentSessionId) {
    return;
  }
  try {
    await navigator.clipboard.writeText(currentSessionId);
    appendLog("Session ID 已复制", "ok");
  } catch (error) {
    appendLog(`复制失败：${error}`, "error");
  }
});

byId("clear-log").addEventListener("click", () => {
  byId("log").replaceChildren();
});

appendLog("客户端就绪，等待连接 signer");
