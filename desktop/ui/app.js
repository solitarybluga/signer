const invoke = window.__TAURI__.core.invoke;
const dialog = window.__TAURI__.dialog;

const byId = (id) => document.getElementById(id);
const terminalStates = new Set(["unsealed", "failed", "expired"]);
const holderFilters = [
  { name: "Signer files", extensions: ["key", "share", "vault", "json", "sig", "pub"] },
];

let currentSessionId = null;
let pollHandle = null;
let busy = false;

function serverUrl() {
  return byId("server").value.trim() || "http://127.0.0.1:50051";
}

function valueOf(id) {
  return byId(id).value.trim();
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

function setHolderStatus(state, collected, threshold) {
  const badge = byId("holder-unseal-state");
  if (badge) {
    badge.textContent = state;
    badge.dataset.state = state;
  }
  if (collected !== undefined) {
    byId("holder-unseal-collected").textContent = collected;
  }
  if (threshold !== undefined) {
    byId("holder-unseal-threshold").textContent = threshold;
  }
}

function setBusy(value) {
  busy = value;
  for (const id of [
    "start-btn",
    "seal-btn",
    "create-identity-btn",
    "export-public-btn",
    "import-share-btn",
    "submit-vault-btn",
  ]) {
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
  setHolderStatus(
    view.state || "sealed",
    view.shares_collected ?? 0,
    view.threshold ?? "–",
  );

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
  setHolderStatus("sealed", 0, "–");
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

function dialogReady() {
  if (!dialog) {
    appendLog("文件对话框插件不可用", "error");
    return false;
  }
  return true;
}

async function pickOpen(inputId, filters = holderFilters) {
  if (!dialogReady()) {
    return;
  }
  try {
    const selected = await dialog.open({ multiple: false, directory: false, filters });
    if (typeof selected === "string" && selected) {
      byId(inputId).value = selected;
    }
  } catch (error) {
    appendLog(`选择文件失败：${error}`, "error");
  }
}

async function pickSave(inputId, defaultPath, filters = holderFilters) {
  if (!dialogReady()) {
    return;
  }
  try {
    const selected = await dialog.save({ defaultPath, filters });
    if (typeof selected === "string" && selected) {
      byId(inputId).value = selected;
    }
  } catch (error) {
    appendLog(`选择保存位置失败：${error}`, "error");
  }
}

function clearPassphrases(ids) {
  for (const id of ids) {
    byId(id).value = "";
  }
}

async function createIdentity() {
  if (busy) {
    return;
  }

  const holderId = valueOf("identity-holder-id");
  const passphrase = byId("identity-passphrase").value;
  const confirm = byId("identity-passphrase-confirm").value;
  const identityPath = valueOf("identity-path");
  const publicPath = valueOf("identity-public-path");

  if (!holderId || !passphrase || !identityPath || !publicPath) {
    appendLog("请填写 Holder ID、口令，并选择两个保存路径", "error");
    return;
  }
  if (passphrase !== confirm) {
    appendLog("两次输入的口令不一致", "error");
    return;
  }
  if (passphrase.length < 8) {
    appendLog("口令至少需要 8 个字符；建议使用 12 个字符以上的高熵口令", "error");
    return;
  }
  if (passphrase.length < 12) {
    appendLog("提示：口令短于 12 个字符，离线爆破风险较高", "warning");
  }

  setBusy(true);
  try {
    const view = await invokeCommand("holder_create_identity", {
      holder_id: holderId,
      passphrase,
      identity_path: identityPath,
      public_path: publicPath,
    });

    byId("identity-result").textContent =
      `${view.holder_id} · 指纹 ${view.fingerprint}`;
    byId("import-identity-path").value = view.identity_path;
    byId("submit-identity-path").value = view.identity_path;
    appendLog(`身份已生成：${view.holder_id}，公钥指纹 ${view.fingerprint}`, "ok");
    appendLog("把公开信息文件交给 operator 注册；身份文件不要离开本机", "info");
  } catch (error) {
    appendLog(String(error), "error");
  } finally {
    clearPassphrases(["identity-passphrase", "identity-passphrase-confirm"]);
    setBusy(false);
  }
}

async function exportPublic() {
  if (busy) {
    return;
  }

  const identityPath = valueOf("identity-path") || valueOf("import-identity-path");
  const passphrase =
    byId("identity-passphrase").value || byId("import-passphrase").value;
  const publicPath = valueOf("identity-public-path");

  if (!identityPath || !passphrase || !publicPath) {
    appendLog("导出公开信息需要身份文件、口令和保存路径", "error");
    return;
  }

  setBusy(true);
  try {
    const view = await invokeCommand("holder_export_public", {
      identity_path: identityPath,
      passphrase,
      public_path: publicPath,
    });
    byId("identity-result").textContent =
      `${view.holder_id} · 指纹 ${view.fingerprint}`;
    appendLog(`公开信息已导出：${view.public_path}`, "ok");
  } catch (error) {
    appendLog(String(error), "error");
  } finally {
    clearPassphrases(["identity-passphrase", "import-passphrase"]);
    setBusy(false);
  }
}

async function importShare() {
  if (busy) {
    return;
  }

  const identityPath = valueOf("import-identity-path");
  const sharePath = valueOf("import-share-path");
  const vaultPath = valueOf("import-vault-path");
  const passphrase = byId("import-passphrase").value;
  const manifestPath = valueOf("import-manifest-path");
  const manifestSigPath = valueOf("import-manifest-sig-path");
  const operatorPubPath = valueOf("import-operator-pub-path");
  const expectedOperatorFingerprint = valueOf("import-operator-fingerprint");

  if (!identityPath || !sharePath || !vaultPath || !passphrase) {
    appendLog("请选择身份文件、份额文件和 vault 路径，并输入口令", "error");
    return;
  }

  const packageParts = [manifestPath, manifestSigPath, operatorPubPath].filter(Boolean);
  if (packageParts.length !== 0 && packageParts.length !== 3) {
    appendLog("manifest、manifest.sig、operator.pub 必须同时提供或同时留空", "error");
    return;
  }

  setBusy(true);
  try {
    const result = await invokeCommand("holder_import_share", {
      identity_path: identityPath,
      share_path: sharePath,
      vault_path: vaultPath,
      passphrase,
      manifest_path: manifestPath || null,
      manifest_sig_path: manifestSigPath || null,
      operator_pub_path: operatorPubPath || null,
      expected_operator_fingerprint: expectedOperatorFingerprint || null,
    });

    const info = result.vault;
    const verified =
      info.source === "manifest" ? "operator manifest 已验证" : "legacy 未验签";
    const vss = info.vss_verified ? "VSS 已验证" : "未 VSS 验证";
    const ceremony = info.ceremony_id ? ` · ceremony ${info.ceremony_id}` : "";
    const operator = result.operator_fingerprint
      ? ` · operator 指纹 ${result.operator_fingerprint}`
      : "";
    byId("import-result").textContent =
      `${info.holder_id} · index ${info.index} · ${verified} · ${vss}${ceremony}${operator}`;
    byId("submit-vault-path").value = vaultPath;

    if (info.source === "manifest") {
      appendLog(`份额已验证并写入 vault：${info.holder_id}（index ${info.index}）`, "ok");
      if (info.vss_verified) {
        appendLog("份额已通过 VSS 承诺校验", "ok");
      } else {
        appendLog("manifest 未包含 VSS 承诺，份额未通过 VSS 校验", "warning");
      }
      if (result.operator_fingerprint && !expectedOperatorFingerprint) {
        appendLog(
          `请带外核对 operator 指纹：${result.operator_fingerprint}`,
          "warning",
        );
      } else if (expectedOperatorFingerprint) {
        appendLog("operator 指纹已与输入值核对一致", "ok");
      }
    } else {
      appendLog("份额已写入 vault，但这是 legacy 导入：未验证 operator 签名和 VSS", "warning");
    }
  } catch (error) {
    appendLog(String(error), "error");
  } finally {
    clearPassphrases(["import-passphrase"]);
    setBusy(false);
  }
}

async function submitFromVault() {
  if (busy) {
    return;
  }

  const sessionId = valueOf("holder-session");
  const identityPath = valueOf("submit-identity-path");
  const vaultPath = valueOf("submit-vault-path");
  const passphrase = byId("submit-passphrase").value;

  if (!sessionId || !identityPath || !vaultPath || !passphrase) {
    appendLog("请填写 Session ID、选择身份文件和 vault，并输入口令", "error");
    return;
  }

  setBusy(true);
  try {
    const view = await invokeCommand("holder_submit_from_vault", {
      server_url: serverUrl(),
      session_id: sessionId,
      identity_path: identityPath,
      vault_path: vaultPath,
      passphrase,
    });
    render(view);
    appendLog(`份额已提交：${sessionId}`, "ok");
    if (view.state === "collecting") {
      startPolling();
    }
  } catch (error) {
    appendLog(String(error), "error");
  } finally {
    clearPassphrases(["submit-passphrase"]);
    setBusy(false);
  }
}

const tabButtons = Array.from(document.querySelectorAll(".tab"));
const tabPanels = {
  operator: byId("tab-operator"),
  holder: byId("tab-holder"),
};

function activateTab(name, focus = false) {
  if (!tabPanels[name]) {
    name = "operator";
  }

  for (const [key, panel] of Object.entries(tabPanels)) {
    const active = key === name;
    panel.hidden = !active;
    panel.classList.toggle("active", active);
  }

  for (const button of tabButtons) {
    const active = button.dataset.tab === name;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
    if (active && focus) {
      button.focus();
    }
  }

  try {
    localStorage.setItem("signer.activeTab", name);
  } catch {
    // localStorage is optional; the tab still works without persistence.
  }
}

for (const button of tabButtons) {
  button.addEventListener("click", () => activateTab(button.dataset.tab));
  button.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") {
      return;
    }
    event.preventDefault();
    const index = tabButtons.indexOf(button);
    const offset = event.key === "ArrowRight" ? 1 : -1;
    const next = tabButtons[(index + offset + tabButtons.length) % tabButtons.length];
    activateTab(next.dataset.tab, true);
  });
}

let initialTab = "operator";
try {
  initialTab = localStorage.getItem("signer.activeTab") || "operator";
} catch {
  // Ignore unavailable storage and use the default tab.
}
activateTab(initialTab);

const holderSubtabButtons = Array.from(document.querySelectorAll(".subtab"));
const holderSubtabPanels = {
  distribution: byId("holder-subtab-distribution"),
  unseal: byId("holder-subtab-unseal"),
};

function activateHolderSubtab(name, focus = false) {
  if (!holderSubtabPanels[name]) {
    name = "distribution";
  }

  for (const [key, panel] of Object.entries(holderSubtabPanels)) {
    const active = key === name;
    panel.hidden = !active;
    panel.classList.toggle("active", active);
  }

  for (const button of holderSubtabButtons) {
    const active = button.dataset.subtab === name;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
    if (active && focus) {
      button.focus();
    }
  }

  try {
    localStorage.setItem("signer.holderSubtab", name);
  } catch {
    // localStorage is optional; the subtab still works without persistence.
  }
}

for (const button of holderSubtabButtons) {
  button.addEventListener("click", () => activateHolderSubtab(button.dataset.subtab));
  button.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") {
      return;
    }
    event.preventDefault();
    const index = holderSubtabButtons.indexOf(button);
    const offset = event.key === "ArrowRight" ? 1 : -1;
    const next =
      holderSubtabButtons[
        (index + offset + holderSubtabButtons.length) % holderSubtabButtons.length
      ];
    activateHolderSubtab(next.dataset.subtab, true);
  });
}

let initialHolderSubtab = "distribution";
try {
  initialHolderSubtab = localStorage.getItem("signer.holderSubtab") || "distribution";
} catch {
  // Ignore unavailable storage and use the default subtab.
}
activateHolderSubtab(initialHolderSubtab);

byId("start-btn").addEventListener("click", startUnseal);
byId("seal-btn").addEventListener("click", sealService);
byId("create-identity-btn").addEventListener("click", createIdentity);
byId("export-public-btn").addEventListener("click", exportPublic);
byId("import-share-btn").addEventListener("click", importShare);
byId("submit-vault-btn").addEventListener("click", submitFromVault);

byId("pick-identity-save").addEventListener("click", () =>
  pickSave("identity-path", "holder.key", [{ name: "Holder key", extensions: ["key"] }]),
);
byId("pick-identity-public-save").addEventListener("click", () =>
  pickSave("identity-public-path", "holder.pub.json", [
    { name: "Public bundle", extensions: ["json"] },
  ]),
);
byId("pick-import-identity").addEventListener("click", () =>
  pickOpen("import-identity-path", [{ name: "Holder key", extensions: ["key"] }]),
);
byId("pick-import-share").addEventListener("click", () =>
  pickOpen("import-share-path", [{ name: "Share envelope", extensions: ["share"] }]),
);
byId("pick-import-vault").addEventListener("click", () =>
  pickSave("import-vault-path", "holder.share.vault", [
    { name: "Share vault", extensions: ["vault"] },
  ]),
);
byId("pick-import-manifest").addEventListener("click", () =>
  pickOpen("import-manifest-path", [{ name: "Manifest", extensions: ["json"] }]),
);
byId("pick-import-manifest-sig").addEventListener("click", () =>
  pickOpen("import-manifest-sig-path", [{ name: "Manifest signature", extensions: ["sig"] }]),
);
byId("pick-import-operator-pub").addEventListener("click", () =>
  pickOpen("import-operator-pub-path", [{ name: "Operator public key", extensions: ["pub"] }]),
);
byId("pick-submit-identity").addEventListener("click", () =>
  pickOpen("submit-identity-path", [{ name: "Holder key", extensions: ["key"] }]),
);
byId("pick-submit-vault").addEventListener("click", () =>
  pickOpen("submit-vault-path", [{ name: "Share vault", extensions: ["vault"] }]),
);

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
