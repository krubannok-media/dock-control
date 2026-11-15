/* ==========================================================================
   1. APPLICATION STATE & PRESETS
   ========================================================================== */
const STORAGE_KEY = 'obs_control_deck_state_v1';

const CANVAS_PRESETS = [
  { id: 'fhd', name: 'เต็มจอ Full HD', width: 1920, height: 1080 },
  { id: 'std', name: 'หน้าจอมาตรฐาน', width: 1400, height: 900 },
  { id: 'dock_v', name: 'OBS Dock แนวตั้ง', width: 420, height: 900 },
  { id: 'dock_h', name: 'OBS Dock แนวนอน', width: 960, height: 320 }
];

const TEXT_INPUT_KINDS = new Set([
  'text_gdiplus',
  'text_gdiplus_v2',
  'text_gdiplus_v3',
  'text_ft2_source',
  'text_ft2_source_v2',
  'text_pango_source'
]);

const appState = {
  mode: 'edit', // 'edit' | 'live'
  selectedId: null,
  wsUrl: 'ws://localhost:4455',
  wsPassword: '',
  canvas: {
    width: 1920,
    height: 1080,
    showGrid: true,
    snapGrid: true,
    showMinimap: true,
    bgColor: '#0e121b'
  },
  widgets: []
};

// Live OBS WebSocket v5 State (No mock data; populated exclusively from real OBS)
const obsData = {
  socket: null,
  connected: false,
  connecting: false,
  connectTimer: null,
  reqCounter: 1,
  pendingRequests: new Map(),
  currentScene: '',
  scenes: [],          // Array of sceneName strings
  groups: [],          // Array of groupName strings
  sceneItems: {},      // { [sceneName]: Array<{ sceneItemId, sceneItemIndex, sourceName, sourceType, inputKind, isGroup, sceneItemEnabled }> }
  groupItems: {},      // { [groupName]: Array<...> } sorted top-to-bottom by sceneItemIndex descending
  textInputs: [],      // Array of inputName strings (text sources)
  allInputs: [],       // Array of { inputName, inputKind, unversionedInputKind }
  textValues: {},      // { [inputName]: string }
  sourceFilters: {}    // { [sourceName]: Array<{ filterName, filterKind, filterEnabled }> }
};

/* ==========================================================================
   2. UTILITY FUNCTIONS (TOASTS, MODAL, SHA-256 AUTH)
   ========================================================================== */
function showToast(message, type = 'info', duration = 3600) {
  const stack = document.getElementById('toast-stack');
  const item = document.createElement('div');
  item.className = `toast-item ${type}`;
  const icons = { success: '✅', error: '❌', warn: '⚠️', info: 'ℹ️' };
  item.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><div style="flex:1;line-height:1.4;">${escapeHtml(message)}</div>`;
  stack.appendChild(item);
  setTimeout(() => {
    item.style.opacity = '0';
    item.style.transform = 'translateX(14px)';
    item.style.transition = 'opacity 0.2s ease, transform 0.2s ease';
    setTimeout(() => item.remove(), 220);
  }, duration);
}

function showConfirmModal(title, message) {
  return new Promise((resolve) => {
    const modal = document.getElementById('confirm-modal');
    document.getElementById('confirm-modal-title').textContent = title;
    document.getElementById('confirm-modal-message').textContent = message;
    modal.classList.add('open');

    const cleanup = (result) => {
      modal.classList.remove('open');
      btnOk.removeEventListener('click', onOk);
      btnCancel.removeEventListener('click', onCancel);
      resolve(result);
    };
    const btnOk = document.getElementById('confirm-modal-ok');
    const btnCancel = document.getElementById('confirm-modal-cancel');
    const onOk = () => cleanup(true);
    const onCancel = () => cleanup(false);

    btnOk.addEventListener('click', onOk);
    btnCancel.addEventListener('click', onCancel);
  });
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function generateId(prefix = 'w') {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
}

/**
 * Pure-JS SHA-256 returning Base64 (fallback when crypto.subtle is unavailable on non-HTTPS LAN IPs)
 */
function sha256Base64Fallback(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  let result = '';
  const words = [];
  const utf8 = unescape(encodeURIComponent(ascii));
  const asciiBitLength = utf8.length * 8;

  const hash = [];
  const k = [];
  let primeCounter = 0;
  const isComposite = {};
  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (let i = 0; i < 313; i += candidate) isComposite[i] = candidate;
      hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }

  let padded = utf8 + '\x80';
  while ((padded.length % 64) - 56) padded += '\x00';
  for (let i = 0; i < padded.length; i++) {
    const j = padded.charCodeAt(i);
    words[i >> 2] |= j << (((3 - i) % 4) * 8);
  }
  words[words.length] = (asciiBitLength / maxWord) | 0;
  words[words.length] = asciiBitLength;

  for (let j = 0; j < words.length; ) {
    const w = words.slice(j, (j += 16));
    const oldHash = hash.slice(0);
    for (let i = 0; i < 64; i++) {
      const w15 = w[i - 15];
      const w2 = w[i - 2];
      const a = hash[0];
      const e = hash[4];
      const temp1 =
        hash[7] +
        (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
        ((e & hash[5]) ^ (~e & hash[6])) +
        k[i] +
        (w[i] =
          i < 16
            ? w[i]
            : (w[i - 16] +
                (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
                w[i - 7] +
                (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) |
              0);
      const temp2 =
        (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
        ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
      hash.unshift((temp1 + temp2) | 0);
      hash[4] = (hash[4] + temp1) | 0;
      hash.pop();
    }
    for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
  }

  let binary = '';
  for (let i = 0; i < 8; i++) {
    for (let j = 3; j >= 0; j--) {
      binary += String.fromCharCode((hash[i] >> (j * 8)) & 255);
    }
  }
  return btoa(binary);
}

async function sha256Base64(text) {
  if (window.crypto && window.crypto.subtle) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    const bytes = new Uint8Array(hashBuffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  return sha256Base64Fallback(text);
}

async function computeObsAuth(password, salt, challenge) {
  const secret = await sha256Base64(password + salt);
  return await sha256Base64(secret + challenge);
}

/* ==========================================================================
   3. OBS WEBSOCKET v5 CLIENT & REAL-TIME SYNC
   ========================================================================== */
function updateConnectionUI(status, text) {
  const dot = document.getElementById('ws-status-dot');
  const label = document.getElementById('ws-status-text');
  const btnConnect = document.getElementById('btn-ws-connect');
  const btnSync = document.getElementById('btn-sync-obs');
  const sceneNameEl = document.getElementById('active-scene-name');

  dot.className = 'status-dot';
  if (status === 'connected') {
    dot.classList.add('connected');
    btnConnect.textContent = 'ตัดการเชื่อมต่อ';
    btnConnect.className = 'btn btn-danger';
    btnSync.disabled = false;
    sceneNameEl.textContent = obsData.currentScene || 'กำลังโหลด...';
  } else if (status === 'connecting') {
    dot.classList.add('connecting');
    btnConnect.textContent = 'กำลังเชื่อมต่อ...';
    btnConnect.className = 'btn';
    btnSync.disabled = true;
  } else {
    if (status === 'error') dot.classList.add('error');
    btnConnect.textContent = 'เชื่อมต่อ OBS';
    btnConnect.className = 'btn btn-primary';
    btnSync.disabled = true;
    sceneNameEl.textContent = 'ยังไม่ได้เชื่อมต่อ';
  }
  label.textContent = text;
}

function checkMixedContentWarning(url) {
  const banner = document.getElementById('mixed-content-banner');
  if (window.location.protocol === 'https:' && /^ws:\/\//i.test(url.trim())) {
    banner.classList.add('visible');
    return true;
  }
  banner.classList.remove('visible');
  return false;
}

function disconnectObs(reasonText = 'ไม่ได้เชื่อมต่อ', isError = false) {
  if (obsData.connectTimer) {
    clearTimeout(obsData.connectTimer);
    obsData.connectTimer = null;
  }
  obsData.pendingRequests.forEach((p) => p.reject(new Error('WebSocket disconnected')));
  obsData.pendingRequests.clear();

  if (obsData.socket) {
    try {
      obsData.socket.onopen = null;
      obsData.socket.onmessage = null;
      obsData.socket.onerror = null;
      obsData.socket.onclose = null;
      obsData.socket.close();
    } catch (_) {}
    obsData.socket = null;
  }

  obsData.connected = false;
  obsData.connecting = false;
  updateConnectionUI(isError ? 'error' : 'disconnected', reasonText);
  renderCanvas();
  renderInspector();
}

function connectObs() {
  if (obsData.connected || obsData.connecting) {
    disconnectObs('ตัดการเชื่อมต่อแล้ว');
    showToast('ตัดการเชื่อมต่อจาก OBS Studio แล้ว', 'info');
    return;
  }

  const url = document.getElementById('ws-url').value.trim() || 'ws://localhost:4455';
  const password = document.getElementById('ws-password').value;
  appState.wsUrl = url;
  appState.wsPassword = password;
  saveState();

  checkMixedContentWarning(url);

  let ws;
  try {
    ws = new WebSocket(url);
  } catch (err) {
    updateConnectionUI('error', 'URL ไม่ถูกต้อง');
    showToast(`ไม่สามารถสร้างการเชื่อมต่อ WebSocket ได้: ${err.message}`, 'error');
    return;
  }

  obsData.socket = ws;
  obsData.connecting = true;
  updateConnectionUI('connecting', 'กำลังเชื่อมต่อ...');

  // 5-Second Connection Timeout
  obsData.connectTimer = setTimeout(() => {
    if (obsData.connecting && !obsData.connected) {
      disconnectObs('หมดเวลาเชื่อมต่อ (5s)', true);
      showToast('หมดเวลาเชื่อมต่อ OBS WebSocket (เกิน 5 วินาที) กรุณาตรวจสอบว่าเปิด OBS และเปิดใช้งาน WebSocket Server แล้ว', 'error', 5000);
    }
  }, 5000);

  ws.onmessage = async (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch (_) {
      return;
    }

    const { op, d } = msg;

    // op: 0 Hello
    if (op === 0) {
      try {
        const identifyPayload = {
          rpcVersion: 1,
          eventSubscriptions: 2047 // Subscribe to all OBS v5 events
        };
        if (d && d.authentication) {
          if (!password) {
            disconnectObs('ต้องใส่รหัสผ่าน', true);
            showToast('OBS WebSocket ตั้งรหัสผ่านไว้ กรุณากรอกรหัสผ่านก่อนเชื่อมต่อ', 'warn', 4500);
            return;
          }
          identifyPayload.authentication = await computeObsAuth(
            password,
            d.authentication.salt,
            d.authentication.challenge
          );
        }
        ws.send(JSON.stringify({ op: 1, d: identifyPayload }));
      } catch (authErr) {
        disconnectObs('ยืนยันตัวตนล้มเหลว', true);
        showToast(`เกิดข้อผิดพลาดในการเข้ารหัสรหัสผ่าน: ${authErr.message}`, 'error');
      }
      return;
    }

    // op: 2 Identified
    if (op === 2) {
      if (obsData.connectTimer) {
        clearTimeout(obsData.connectTimer);
        obsData.connectTimer = null;
      }
      obsData.connecting = false;
      obsData.connected = true;
      updateConnectionUI('connected', 'เชื่อมต่อแล้ว');
      showToast('เชื่อมต่อ OBS WebSocket v5 สำเร็จ!', 'success');
      await syncAllObsData(true);
      return;
    }

    // op: 5 Event
    if (op === 5 && d) {
      handleObsEvent(d.eventType, d.eventData || {});
      return;
    }

    // op: 7 RequestResponse
    if (op === 7 && d && d.requestId) {
      const pending = obsData.pendingRequests.get(d.requestId);
      if (pending) {
        obsData.pendingRequests.delete(d.requestId);
        if (d.requestStatus && d.requestStatus.result) {
          pending.resolve(d.responseData || {});
        } else {
          const code = d.requestStatus ? d.requestStatus.code : 'ERR';
          const comment = (d.requestStatus && d.requestStatus.comment) || 'Request failed';
          pending.reject(new Error(`[${code}] ${comment}`));
        }
      }
    }
  };

  ws.onerror = () => {
    if (obsData.connecting || obsData.connected) {
      disconnectObs('เชื่อมต่อไม่สำเร็จ', true);
      showToast('ไม่สามารถเชื่อมต่อ OBS WebSocket ได้ กรุณาตรวจสอบ Port (4455) หรือ Mixed Content', 'error', 4500);
    }
  };

  ws.onclose = (ev) => {
    if (obsData.connecting || obsData.connected) {
      const authFailed = ev.code === 4009;
      disconnectObs(authFailed ? 'รหัสผ่านไม่ถูกต้อง' : 'ตัดการเชื่อมต่อ', authFailed);
      if (authFailed) {
        showToast('รหัสผ่าน OBS WebSocket ไม่ถูกต้อง (Authentication Failed)', 'error', 4500);
      }
    }
  };
}

function sendObsRequest(requestType, requestData = {}) {
  return new Promise((resolve, reject) => {
    if (!obsData.connected || !obsData.socket || obsData.socket.readyState !== WebSocket.OPEN) {
      reject(new Error('ยังไม่ได้เชื่อมต่อ OBS Studio'));
      return;
    }
    const requestId = `req_${obsData.reqCounter++}`;
    const timer = setTimeout(() => {
      if (obsData.pendingRequests.has(requestId)) {
        obsData.pendingRequests.delete(requestId);
        reject(new Error(`Request timeout: ${requestType}`));
      }
    }, 6000);

    obsData.pendingRequests.set(requestId, {
      resolve: (data) => {
        clearTimeout(timer);
        resolve(data);
      },
      reject: (err) => {
        clearTimeout(timer);
        reject(err);
      }
    });

    obsData.socket.send(
      JSON.stringify({
        op: 6,
        d: {
          requestType,
          requestId,
          requestData
        }
      })
    );
  });
}

/**
 * Fetches Scenes, Groups, Group Child Items (sorted top-to-bottom by sceneItemIndex descending so index 0 is the first source in the group),
 * Scene Items, Text Inputs, Input Settings, and Filters from OBS.
 */
async function syncAllObsData(silent = false) {
  if (!obsData.connected) {
    if (!silent) showToast('กรุณาเชื่อมต่อ OBS Studio ก่อนซิงค์ข้อมูล', 'warn');
    return;
  }

  try {
    // 1. Get Scene List & Current Program Scene
    const sceneListRes = await sendObsRequest('GetSceneList');
    obsData.currentScene = sceneListRes.currentProgramSceneName || '';
    obsData.scenes = (sceneListRes.scenes || []).map((s) => s.sceneName).reverse();
    document.getElementById('active-scene-name').textContent = obsData.currentScene || '-';

    // 2. Get Group List
    try {
      const groupListRes = await sendObsRequest('GetGroupList');
      obsData.groups = groupListRes.groups || [];
    } catch (_) {
      obsData.groups = [];
    }

    // 3. Get Scene Items for Active Scene + any Scenes referenced by widgets
    const scenesToFetch = new Set(obsData.scenes);
    if (obsData.currentScene) scenesToFetch.add(obsData.currentScene);
    for (const sName of scenesToFetch) {
      try {
        const itemsRes = await sendObsRequest('GetSceneItemList', { sceneName: sName });
        // Sort top-to-bottom by sceneItemIndex descending
        const sorted = (itemsRes.sceneItems || []).sort((a, b) => b.sceneItemIndex - a.sceneItemIndex);
        obsData.sceneItems[sName] = sorted;
      } catch (_) {
        obsData.sceneItems[sName] = [];
      }
    }

    // 4. Get Group Child Items for every OBS Group (sorted top-to-bottom by sceneItemIndex so index 0 is the first source in the group)
    for (const gName of obsData.groups) {
      await fetchGroupChildItems(gName);
    }

    // 5. Get Input List & Text Sources
    const inputListRes = await sendObsRequest('GetInputList');
    obsData.allInputs = inputListRes.inputs || [];
    obsData.textInputs = obsData.allInputs
      .filter((inp) => TEXT_INPUT_KINDS.has(inp.unversionedInputKind) || TEXT_INPUT_KINDS.has(inp.inputKind) || /text/i.test(inp.inputKind || ''))
      .map((inp) => inp.inputName);

    // Fetch current text value for all text inputs
    for (const inputName of obsData.textInputs) {
      try {
        const settingsRes = await sendObsRequest('GetInputSettings', { inputName });
        const val = settingsRes.inputSettings && typeof settingsRes.inputSettings.text === 'string'
          ? settingsRes.inputSettings.text
          : '';
        obsData.textValues[inputName] = val;
      } catch (_) {}
    }

    // 6. Fetch Filters for any Sources/Groups referenced by Move Transition widgets or selected widget
    const filterTargets = new Set();
    appState.widgets.forEach((w) => {
      if (w.type === 'move' && w.targetName) filterTargets.add(w.targetName);
    });
    const sel = getSelectedWidget();
    if (sel && sel.type === 'move' && sel.targetName) filterTargets.add(sel.targetName);

    for (const targetName of filterTargets) {
      await fetchSourceFilters(targetName);
    }

    renderCanvas();
    renderInspector();
    if (!silent) showToast('ซิงค์ข้อมูลจาก OBS Studio เรียบร้อยแล้ว', 'success');
  } catch (err) {
    showToast(`ซิงค์ข้อมูล OBS ไม่สำเร็จ: ${err.message}`, 'error');
  }
}

async function fetchGroupChildItems(groupName) {
  if (!obsData.connected || !groupName) return [];
  try {
    const res = await sendObsRequest('GetGroupSceneItemList', { sceneName: groupName });
    // Sort top-to-bottom by sceneItemIndex descending so index [0] is the top/first source in the group
    const sorted = (res.sceneItems || []).sort((a, b) => b.sceneItemIndex - a.sceneItemIndex);
    obsData.groupItems[groupName] = sorted;
    return sorted;
  } catch (_) {
    obsData.groupItems[groupName] = [];
    return [];
  }
}

async function fetchSourceFilters(sourceName) {
  if (!obsData.connected || !sourceName) return [];
  try {
    const res = await sendObsRequest('GetSourceFilterList', { sourceName });
    obsData.sourceFilters[sourceName] = res.filters || [];
    return obsData.sourceFilters[sourceName];
  } catch (_) {
    obsData.sourceFilters[sourceName] = [];
    return [];
  }
}

function handleObsEvent(eventType, data) {
  if (eventType === 'CurrentProgramSceneChanged') {
    obsData.currentScene = data.sceneName || '';
    document.getElementById('active-scene-name').textContent = obsData.currentScene || '-';
    if (obsData.currentScene && !obsData.sceneItems[obsData.currentScene]) {
      sendObsRequest('GetSceneItemList', { sceneName: obsData.currentScene })
        .then((res) => {
          obsData.sceneItems[obsData.currentScene] = (res.sceneItems || []).sort(
            (a, b) => b.sceneItemIndex - a.sceneItemIndex
          );
          renderCanvas();
        })
        .catch(() => {});
    } else {
      renderCanvas();
    }
    return;
  }

  if (eventType === 'SceneItemEnableStateChanged') {
    const { sceneName, sceneItemId, sceneItemEnabled } = data;
    // Update in sceneItems
    if (obsData.sceneItems[sceneName]) {
      const item = obsData.sceneItems[sceneName].find((i) => i.sceneItemId === sceneItemId);
      if (item) item.sceneItemEnabled = sceneItemEnabled;
    }
    // Update in groupItems (PlayGroup & Move Transition Group first-source tracking!)
    if (obsData.groupItems[sceneName]) {
      const gItem = obsData.groupItems[sceneName].find((i) => i.sceneItemId === sceneItemId);
      if (gItem) gItem.sceneItemEnabled = sceneItemEnabled;
    }
    renderCanvas();
    return;
  }

  if (eventType === 'SceneItemListReindexed' || eventType === 'SceneItemCreated' || eventType === 'SceneItemRemoved') {
    const { sceneName } = data;
    if (obsData.groups.includes(sceneName)) {
      fetchGroupChildItems(sceneName).then(() => {
        renderCanvas();
        renderInspector();
      });
    } else if (sceneName) {
      sendObsRequest('GetSceneItemList', { sceneName })
        .then((res) => {
          obsData.sceneItems[sceneName] = (res.sceneItems || []).sort(
            (a, b) => b.sceneItemIndex - a.sceneItemIndex
          );
          renderCanvas();
        })
        .catch(() => {});
    }
    return;
  }

  if (eventType === 'InputSettingsChanged') {
    const { inputName, inputSettings } = data;
    if (inputName && inputSettings && typeof inputSettings.text === 'string') {
      obsData.textValues[inputName] = inputSettings.text;
      renderCanvas();
    }
    return;
  }

  if (eventType === 'SceneListChanged' || eventType === 'InputCreated' || eventType === 'InputRemoved' || eventType === 'InputNameChanged' || eventType === 'SceneNameChanged') {
    syncAllObsData(true);
  }
}

/* ==========================================================================
   4. WIDGET FACTORY, LIVE STATE EVALUATION & EXECUTION
   ========================================================================== */
function createWidget(type) {
  const offset = (appState.widgets.length % 8) * 24;
  const baseX = Math.min(40 + offset, Math.max(10, appState.canvas.width - 240));
  const baseY = Math.min(40 + offset, Math.max(10, appState.canvas.height - 140));

  const defaults = {
    group: {
      id: generateId('grp'),
      type: 'group',
      label: 'Group Panel',
      customText: 'กลุ่มปุ่มควบคุม',
      textPosition: 'top-left',
      x: baseX,
      y: baseY,
      w: 380,
      h: 240,
      bgColor: '#161d2e',
      textColor: '#94a3b8',
      borderColor: '#334155',
      fontSize: 13
    },
    dashboard: {
      id: generateId('dash'),
      type: 'dashboard',
      label: 'Dashboard สถานะปุ่ม',
      x: baseX,
      y: baseY,
      w: 360,
      h: 220,
      bgColor: '#131926',
      textColor: '#f1f5f9',
      fontSize: 13,
      monitoredIds: [] // IDs of action / playgroup / move widgets to show
    },
    action: {
      id: generateId('act'),
      type: 'action',
      label: 'Action Button',
      x: baseX,
      y: baseY,
      w: 170,
      h: 84,
      bgColor: '#1e293b',
      textColor: '#f8fafc',
      fontSize: 14,
      actionMode: 'toggle', // 'show' | 'hide' | 'toggle'
      sceneName: '__ACTIVE__',
      targetType: 'source', // 'source' | 'group'
      targetName: ''
    },
    text_btn: {
      id: generateId('txtbtn'),
      type: 'text_btn',
      label: 'ส่งข้อความเข้า OBS',
      x: baseX,
      y: baseY,
      w: 270,
      h: 92,
      bgColor: '#1e293b',
      textColor: '#f8fafc',
      fontSize: 13,
      inputName: '',
      draftText: '',
      placeholder: 'พิมพ์ข้อความ...'
    },
    text_preview: {
      id: generateId('txtprv'),
      type: 'text_preview',
      label: 'ข้อความจาก OBS',
      x: baseX,
      y: baseY,
      w: 240,
      h: 82,
      bgColor: '#131b2b',
      textColor: '#38bdf8',
      fontSize: 16,
      inputName: '',
      prefix: '',
      suffix: ''
    },
    number_btn: {
      id: generateId('numbtn'),
      type: 'number_btn',
      label: 'ตัวนับคะแนน / ตัวเลข',
      x: baseX,
      y: baseY,
      w: 260,
      h: 94,
      bgColor: '#1e293b',
      textColor: '#f8fafc',
      fontSize: 14,
      inputName: '',
      currentValue: 0,
      step: 1,
      prefix: '',
      suffix: ''
    },
    playgroup: {
      id: generateId('pg'),
      type: 'playgroup',
      label: 'PlayGroup Action',
      x: baseX,
      y: baseY,
      w: 180,
      h: 84,
      bgColor: '#231b38',
      textColor: '#f3e8ff',
      fontSize: 14,
      actionMode: 'toggle', // 'show' | 'hide' | 'toggle'
      groupName: ''
    },
    move: {
      id: generateId('move'),
      type: 'move',
      label: 'Move Transition',
      x: baseX,
      y: baseY,
      w: 180,
      h: 84,
      bgColor: '#132a33',
      textColor: '#cffafe',
      fontSize: 14,
      actionMode: 'toggle', // 'show' | 'hide' | 'toggle'
      targetType: 'source', // 'source' | 'group'
      targetName: '',
      showFilter: '',
      hideFilter: '',
      fallbackState: false
    }
  };

  const widget = defaults[type];
  if (!widget) return;

  // Auto-select this new widget in Dashboard Panels if it's an eligible status button
  if (isDashboardEligible(widget)) {
    appState.widgets.forEach((w) => {
      if (w.type === 'dashboard' && Array.isArray(w.monitoredIds)) {
        w.monitoredIds.push(widget.id);
      }
    });
  }

  // If creating a Dashboard Panel, pre-populate with all currently existing eligible buttons
  if (type === 'dashboard') {
    widget.monitoredIds = appState.widgets.filter(isDashboardEligible).map((w) => w.id);
  }

  appState.widgets.push(widget);
  appState.selectedId = widget.id;
  saveState();
  renderCanvas();
  renderInspector();
}

function isDashboardEligible(w) {
  return w && (w.type === 'action' || w.type === 'playgroup' || w.type === 'move');
}

function getSelectedWidget() {
  return appState.widgets.find((w) => w.id === appState.selectedId) || null;
}

/**
 * Evaluates live SHOW (true) / HIDE (false) status from OBS state for:
 * - action: checks target source or group sceneItemEnabled in OBS scene
 * - playgroup: checks the FIRST source (index 0 when sorted top-to-bottom by sceneItemIndex) inside that OBS Group
 * - move: checks target source sceneItemEnabled, or FIRST source inside target group if targetType === 'group'
 */
function getWidgetLiveState(widget) {
  if (!widget) return false;

  if (widget.type === 'action') {
    if (!widget.targetName) return false;
    const targetScene =
      widget.sceneName && widget.sceneName !== '__ACTIVE__'
        ? widget.sceneName
        : obsData.currentScene;

    const items = obsData.sceneItems[targetScene] || [];
    const found = items.find((i) => i.sourceName === widget.targetName);
    if (found) return Boolean(found.sceneItemEnabled);

    // Fallback search across loaded scenes
    for (const sName of Object.keys(obsData.sceneItems)) {
      const item = (obsData.sceneItems[sName] || []).find((i) => i.sourceName === widget.targetName);
      if (item) return Boolean(item.sceneItemEnabled);
    }
    return false;
  }

  if (widget.type === 'playgroup') {
    if (!widget.groupName) return false;
    const gItems = obsData.groupItems[widget.groupName] || [];
    // First source in the group (index 0 after descending sceneItemIndex sort)
    if (gItems.length > 0) {
      return Boolean(gItems[0].sceneItemEnabled);
    }
    return false;
  }

  if (widget.type === 'move') {
    if (!widget.targetName) return Boolean(widget.fallbackState);
    if (widget.targetType === 'group') {
      const gItems = obsData.groupItems[widget.targetName] || [];
      // Check status of the FIRST source in the group
      if (gItems.length > 0) {
        return Boolean(gItems[0].sceneItemEnabled);
      }
      return Boolean(widget.fallbackState);
    } else {
      const activeItems = obsData.sceneItems[obsData.currentScene] || [];
      const found = activeItems.find((i) => i.sourceName === widget.targetName);
      if (found) return Boolean(found.sceneItemEnabled);

      for (const sName of Object.keys(obsData.sceneItems)) {
        const item = (obsData.sceneItems[sName] || []).find((i) => i.sourceName === widget.targetName);
        if (item) return Boolean(item.sceneItemEnabled);
      }
      return Boolean(widget.fallbackState);
    }
  }

  return false;
}

/**
 * Executes OBS WebSocket v5 command for a widget (verifying obsData.connected first)
 */
async function executeWidgetCommand(widget, payload = {}) {
  if (!obsData.connected) {
    showToast('ยังไม่ได้เชื่อมต่อ OBS Studio กรุณาเชื่อมต่อก่อนสั่งงานปุ่ม', 'warn');
    return;
  }

  try {
    // 1. General Action Button (Show / Hide / Toggle Source or Group)
    if (widget.type === 'action') {
      if (!widget.targetName) {
        showToast('กรุณาเลือก Source หรือ Group ในแถบตั้งค่าด้านขวา', 'warn');
        return;
      }
      const targetScene =
        widget.sceneName && widget.sceneName !== '__ACTIVE__'
          ? widget.sceneName
          : obsData.currentScene;

      const items = obsData.sceneItems[targetScene] || [];
      const found = items.find((i) => i.sourceName === widget.targetName);
      if (!found) {
        showToast(`ไม่พบ "${widget.targetName}" ใน Scene "${targetScene}"`, 'error');
        return;
      }

      let nextEnabled = true;
      if (widget.actionMode === 'show') nextEnabled = true;
      else if (widget.actionMode === 'hide') nextEnabled = false;
      else nextEnabled = !found.sceneItemEnabled;

      await sendObsRequest('SetSceneItemEnabled', {
        sceneName: targetScene,
        sceneItemId: found.sceneItemId,
        sceneItemEnabled: nextEnabled
      });
      found.sceneItemEnabled = nextEnabled;
      renderCanvas();
      return;
    }

    // 2. PlayGroup - JAMORNz Action Button (CallVendorRequest)
    if (widget.type === 'playgroup') {
      if (!widget.groupName) {
        showToast('กรุณาเลือก Group สำหรับ PlayGroup ในแถบตั้งค่าด้านขวา', 'warn');
        return;
      }
      await sendObsRequest('CallVendorRequest', {
        vendorName: 'PlayGroup',
        requestType: 'RunAction',
        requestData: {
          action: widget.actionMode || 'toggle',
          group: widget.groupName
        }
      });
      // Re-check group items shortly after PlayGroup runs to guarantee fresh first-source status
      setTimeout(async () => {
        await fetchGroupChildItems(widget.groupName);
        renderCanvas();
      }, 140);
      return;
    }

    // 3. Move Transition Plugin Action Button (Activate Filter on Source or Group)
    if (widget.type === 'move') {
      if (!widget.targetName) {
        showToast('กรุณาเลือก Source หรือ Group เป้าหมายในแถบตั้งค่าด้านขวา', 'warn');
        return;
      }

      const isCurrentlyShown = getWidgetLiveState(widget);
      let filterToActivate = '';

      if (widget.actionMode === 'show') {
        filterToActivate = widget.showFilter;
      } else if (widget.actionMode === 'hide') {
        filterToActivate = widget.hideFilter;
      } else {
        // Toggle mode: choose Hide Filter if currently SHOW, else Show Filter
        filterToActivate = isCurrentlyShown ? widget.hideFilter : widget.showFilter;
      }

      if (!filterToActivate) {
        showToast('กรุณาเลือก Filter ที่ต้องการสั่งทำงานในแถบตั้งค่าด้านขวา', 'warn');
        return;
      }

      await sendObsRequest('SetSourceFilterEnabled', {
        sourceName: widget.targetName,
        filterName: filterToActivate,
        filterEnabled: true
      });

      // Track fallback state for sources not currently inside a scene
      if (widget.actionMode === 'show') widget.fallbackState = true;
      else if (widget.actionMode === 'hide') widget.fallbackState = false;
      else widget.fallbackState = !isCurrentlyShown;

      if (widget.targetType === 'group') {
        setTimeout(async () => {
          await fetchGroupChildItems(widget.targetName);
          renderCanvas();
        }, 160);
      } else {
        renderCanvas();
      }
      return;
    }

    // 4. Text Button (Update OBS Text Source)
    if (widget.type === 'text_btn') {
      if (!widget.inputName) {
        showToast('กรุณาเลือก Text Source ในแถบตั้งค่าด้านขวา', 'warn');
        return;
      }
      const newText = payload.text !== undefined ? String(payload.text) : String(widget.draftText || '');
      await sendObsRequest('SetInputSettings', {
        inputName: widget.inputName,
        inputSettings: { text: newText },
        overlay: true
      });
      obsData.textValues[widget.inputName] = newText;
      renderCanvas();
      showToast(`อัปเดตข้อความ "${widget.inputName}" เรียบร้อย`, 'success', 2000);
      return;
    }

    // 5. Number Button (+ / - / Set updating OBS Text Source)
    if (widget.type === 'number_btn') {
      const val = Number(payload.value);
      if (Number.isNaN(val)) return;
      widget.currentValue = val;
      saveState();
      renderCanvas();

      if (!widget.inputName) {
        showToast('กรุณาเลือก Text Source สำหรับแสดงตัวเลขในแถบตั้งค่าด้านขวา', 'warn');
        return;
      }
      const formattedText = `${widget.prefix || ''}${val}${widget.suffix || ''}`;
      await sendObsRequest('SetInputSettings', {
        inputName: widget.inputName,
        inputSettings: { text: formattedText },
        overlay: true
      });
      obsData.textValues[widget.inputName] = formattedText;
      renderCanvas();
    }
  } catch (err) {
    showToast(`สั่งงาน OBS ไม่สำเร็จ: ${err.message}`, 'error', 4200);
  }
}

/* ==========================================================================
   5. CANVAS RENDERING & POINTER EVENTS (DRAG / RESIZE)
   ========================================================================== */
function getGroupPositionStyles(pos) {
  const map = {
    'top-left': 'align-items: flex-start; justify-content: flex-start; text-align: left;',
    'top-center': 'align-items: flex-start; justify-content: center; text-align: center;',
    'top-right': 'align-items: flex-start; justify-content: flex-end; text-align: right;',
    'center': 'align-items: center; justify-content: center; text-align: center;',
    'bottom-left': 'align-items: flex-end; justify-content: flex-start; text-align: left;',
    'bottom-center': 'align-items: flex-end; justify-content: center; text-align: center;',
    'bottom-right': 'align-items: flex-end; justify-content: flex-end; text-align: right;'
  };
  return map[pos] || map['top-left'];
}

function renderCanvas() {
  const board = document.getElementById('canvas-board');
  board.style.width = `${appState.canvas.width}px`;
  board.style.height = `${appState.canvas.height}px`;
  board.style.backgroundColor = appState.canvas.bgColor || '#0e121b';

  board.classList.toggle('show-grid', Boolean(appState.canvas.showGrid));
  board.classList.toggle('mode-edit', appState.mode === 'edit');
  board.classList.toggle('mode-live', appState.mode === 'live');

  document.getElementById('canvas-size-label').textContent = `${appState.canvas.width} × ${appState.canvas.height}`;

  const modeBtn = document.getElementById('btn-toggle-mode');
  if (appState.mode === 'edit') {
    modeBtn.textContent = '✏️ โหมดแก้ไข (Edit)';
    modeBtn.className = 'btn btn-mode-edit';
  } else {
    modeBtn.textContent = '🟢 โหมดใช้งานจริง (Live)';
    modeBtn.className = 'btn btn-mode-live';
  }

  // Preserve focus/cursor if user is actively typing inside a canvas input
  const activeEl = document.activeElement;
  const activeWidgetInputId = activeEl && activeEl.dataset ? activeEl.dataset.widgetInput : null;
  const activeCursorPos = activeEl && typeof activeEl.selectionStart === 'number' ? activeEl.selectionStart : null;

  board.innerHTML = '';

  appState.widgets.forEach((w) => {
    const el = document.createElement('div');
    el.className = `widget-item type-${w.type}`;
    el.dataset.id = w.id;
    if (w.id === appState.selectedId && appState.mode === 'edit') {
      el.classList.add('selected');
    }

    el.style.left = `${w.x}px`;
    el.style.top = `${w.y}px`;
    el.style.width = `${w.w}px`;
    el.style.height = `${w.h}px`;
    el.style.backgroundColor = w.bgColor;
    el.style.color = w.textColor;
    el.style.fontSize = `${w.fontSize || 14}px`;

    if (w.type === 'group') {
      el.style.borderColor = w.borderColor || '#334155';
      el.innerHTML = `
        <span class="widget-edit-badge">GROUP</span>
        <div class="group-panel-label" style="${getGroupPositionStyles(w.textPosition)}">
          ${escapeHtml(w.customText || '')}
        </div>
        <div class="resize-handle" data-resize-id="${w.id}">◢</div>
      `;
    } else if (w.type === 'action' || w.type === 'playgroup' || w.type === 'move') {
      const isShown = getWidgetLiveState(w);
      el.classList.add('is-clickable', isShown ? 'state-show' : 'state-hide');

      const typeBadgeMap = { action: 'ACT', playgroup: 'PLAYGROUP', move: 'MOVE' };
      const targetDesc =
        w.type === 'playgroup'
          ? w.groupName || 'ยังไม่เลือก Group'
          : w.targetName || 'ยังไม่เลือกเป้าหมาย';

      el.innerHTML = `
        <span class="widget-edit-badge">${typeBadgeMap[w.type]}</span>
        <div class="action-btn-body">
          <div class="status-led-bar">
            <span class="status-led-dot"></span>
            <span class="status-led-text">${isShown ? 'SHOW' : 'HIDE'}</span>
          </div>
          <div class="widget-main-label" style="margin-top: 10px;">${escapeHtml(w.label)}</div>
          <div class="widget-sub-target">${escapeHtml(targetDesc)}</div>
        </div>
        <div class="resize-handle" data-resize-id="${w.id}">◢</div>
      `;

      if (appState.mode === 'live') {
        el.addEventListener('click', (e) => {
          e.stopPropagation();
          executeWidgetCommand(w);
        });
      }
    } else if (w.type === 'text_btn') {
      el.innerHTML = `
        <span class="widget-edit-badge">TEXT BTN</span>
        <div class="text-btn-body">
          <div class="text-btn-header">
            <span>${escapeHtml(w.label)}</span>
            <span style="font-size:10px;opacity:0.65;">${escapeHtml(w.inputName || 'ยังไม่เลือก Source')}</span>
          </div>
          <div class="text-btn-row">
            <input
              type="text"
              data-widget-input="${w.id}"
              value="${escapeHtml(w.draftText || '')}"
              placeholder="${escapeHtml(w.placeholder || 'พิมพ์ข้อความ...')}"
            />
            <button type="button" class="text-btn-confirm" data-confirm-text="${w.id}">ยืนยัน</button>
          </div>
        </div>
        <div class="resize-handle" data-resize-id="${w.id}">◢</div>
      `;

      const inputEl = el.querySelector('input');
      const confirmBtn = el.querySelector('.text-btn-confirm');

      inputEl.addEventListener('pointerdown', (e) => e.stopPropagation());
      inputEl.addEventListener('input', (e) => {
        w.draftText = e.target.value;
        saveState();
      });
      inputEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          executeWidgetCommand(w, { text: w.draftText });
        }
      });

      confirmBtn.addEventListener('pointerdown', (e) => e.stopPropagation());
      confirmBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        executeWidgetCommand(w, { text: w.draftText });
      });
    } else if (w.type === 'text_preview') {
      const liveVal = w.inputName && obsData.textValues[w.inputName] !== undefined
        ? obsData.textValues[w.inputName]
        : obsData.connected
        ? '(ว่าง)'
        : '(รอเชื่อมต่อ OBS)';
      el.innerHTML = `
        <span class="widget-edit-badge">PREVIEW</span>
        <div class="text-preview-body">
          <div class="text-preview-caption">
            <span>${escapeHtml(w.label)}</span>
            <span>${escapeHtml(w.inputName || '')}</span>
          </div>
          <div class="text-preview-value">${escapeHtml(`${w.prefix || ''}${liveVal}${w.suffix || ''}`)}</div>
        </div>
        <div class="resize-handle" data-resize-id="${w.id}">◢</div>
      `;
    } else if (w.type === 'number_btn') {
      el.innerHTML = `
        <span class="widget-edit-badge">NUMBER</span>
        <div class="number-btn-body">
          <div class="text-btn-header">
            <span>${escapeHtml(w.label)}</span>
            <span style="font-size:10px;opacity:0.65;">±${w.step || 1}</span>
          </div>
          <div class="number-btn-controls">
            <button type="button" class="num-step-btn" data-num-dec="${w.id}">−</button>
            <input type="number" step="any" class="num-direct-input" data-widget-input="${w.id}" value="${Number(w.currentValue) || 0}" />
            <button type="button" class="num-set-btn" data-num-set="${w.id}">Set</button>
            <button type="button" class="num-step-btn" data-num-inc="${w.id}">+</button>
          </div>
        </div>
        <div class="resize-handle" data-resize-id="${w.id}">◢</div>
      `;

      const numInput = el.querySelector('.num-direct-input');
      const btnDec = el.querySelector(`[data-num-dec="${w.id}"]`);
      const btnInc = el.querySelector(`[data-num-inc="${w.id}"]`);
      const btnSet = el.querySelector(`[data-num-set="${w.id}"]`);

      [numInput, btnDec, btnInc, btnSet].forEach((ctrl) =>
        ctrl.addEventListener('pointerdown', (e) => e.stopPropagation())
      );

      btnDec.addEventListener('click', (e) => {
        e.stopPropagation();
        const step = Number(w.step) || 1;
        const next = Number(((Number(w.currentValue) || 0) - step).toFixed(4));
        executeWidgetCommand(w, { value: next });
      });

      btnInc.addEventListener('click', (e) => {
        e.stopPropagation();
        const step = Number(w.step) || 1;
        const next = Number(((Number(w.currentValue) || 0) + step).toFixed(4));
        executeWidgetCommand(w, { value: next });
      });

      btnSet.addEventListener('click', (e) => {
        e.stopPropagation();
        executeWidgetCommand(w, { value: Number(numInput.value) || 0 });
      });

      numInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          executeWidgetCommand(w, { value: Number(numInput.value) || 0 });
        }
      });
    } else if (w.type === 'dashboard') {
      const monitoredWidgets = (w.monitoredIds || [])
        .map((id) => appState.widgets.find((item) => item.id === id))
        .filter(isDashboardEligible);

      const shownCount = monitoredWidgets.filter((item) => getWidgetLiveState(item)).length;
      const rowsHtml =
        monitoredWidgets.length === 0
          ? `<div style="grid-column:1/-1;color:var(--text-secondary);font-size:12px;padding:8px;">ยังไม่ได้เลือกปุ่มสำหรับแสดงผล (ตั้งค่าได้ที่แถบด้านขวา)</div>`
          : monitoredWidgets
              .map((item) => {
                const shown = getWidgetLiveState(item);
                const tag = item.type === 'playgroup' ? 'PG' : item.type === 'move' ? 'MV' : 'ACT';
                return `
                  <div class="dash-item-row ${shown ? 'is-show' : ''}">
                    <div class="dash-item-name">
                      <span style="font-size:9px;opacity:0.65;font-weight:700;">[${tag}]</span>
                      <span class="truncate">${escapeHtml(item.label)}</span>
                    </div>
                    <span class="dash-state-pill ${shown ? 'show' : 'hide'}">${shown ? 'SHOW' : 'HIDE'}</span>
                  </div>
                `;
              })
              .join('');

      el.innerHTML = `
        <span class="widget-edit-badge">DASHBOARD</span>
        <div class="dashboard-body">
          <div class="dashboard-header">
            <div class="dashboard-title">📊 <span>${escapeHtml(w.label)}</span></div>
            <span class="dashboard-counter">SHOW ${shownCount}/${monitoredWidgets.length}</span>
          </div>
          <div class="dashboard-list">${rowsHtml}</div>
        </div>
        <div class="resize-handle" data-resize-id="${w.id}">◢</div>
      `;
    }

    // Attach Edit-Mode Pointer Drag & Resize
    setupWidgetPointerInteractions(el, w);
    board.appendChild(el);
  });

  // Restore active input focus if user was typing
  if (activeWidgetInputId) {
    const restored = board.querySelector(`[data-widget-input="${activeWidgetInputId}"]`);
    if (restored) {
      restored.focus();
      if (activeCursorPos !== null && restored.type === 'text') {
        restored.setSelectionRange(activeCursorPos, activeCursorPos);
      }
    }
  }

  renderMinimap();
}

/**
 * Smooth Pointer Events (setPointerCapture) for dragging and bottom-right resizing in Edit Mode
 */
function setupWidgetPointerInteractions(el, widget) {
  el.addEventListener('pointerdown', (e) => {
    if (appState.mode !== 'edit') return;
    if (e.button !== 0 && e.pointerType === 'mouse') return;

    e.stopPropagation();

    // Select widget & refresh inspector if selection changed
    if (appState.selectedId !== widget.id) {
      appState.selectedId = widget.id;
      document.querySelectorAll('.widget-item.selected').forEach((node) => node.classList.remove('selected'));
      el.classList.add('selected');
      renderInspector();
      renderMinimap();
    }

    const isResize = Boolean(e.target.closest('.resize-handle'));
    const startX = e.clientX;
    const startY = e.clientY;
    const origX = widget.x;
    const origY = widget.y;
    const origW = widget.w;
    const origH = widget.h;
    const snap = appState.canvas.snapGrid ? 10 : 1;

    el.setPointerCapture(e.pointerId);

    const onPointerMove = (moveEv) => {
      const dx = moveEv.clientX - startX;
      const dy = moveEv.clientY - startY;

      if (isResize) {
        const rawW = Math.max(80, origW + dx);
        const rawH = Math.max(44, origH + dy);
        widget.w = Math.min(appState.canvas.width - widget.x, Math.round(rawW / snap) * snap);
        widget.h = Math.min(appState.canvas.height - widget.y, Math.round(rawH / snap) * snap);
        el.style.width = `${widget.w}px`;
        el.style.height = `${widget.h}px`;
      } else {
        const rawX = origX + dx;
        const rawY = origY + dy;
        const snappedX = Math.round(rawX / snap) * snap;
        const snappedY = Math.round(rawY / snap) * snap;
        widget.x = Math.max(0, Math.min(appState.canvas.width - widget.w, snappedX));
        widget.y = Math.max(0, Math.min(appState.canvas.height - widget.h, snappedY));
        el.style.left = `${widget.x}px`;
        el.style.top = `${widget.y}px`;
      }

      syncInspectorGeometryInputs(widget);
      renderMinimap();
    };

    const onPointerUp = (upEv) => {
      try {
        el.releasePointerCapture(upEv.pointerId);
      } catch (_) {}
      el.removeEventListener('pointermove', onPointerMove);
      el.removeEventListener('pointerup', onPointerUp);
      el.removeEventListener('pointercancel', onPointerUp);
      saveState();
    };

    el.addEventListener('pointermove', onPointerMove);
    el.addEventListener('pointerup', onPointerUp);
    el.addEventListener('pointercancel', onPointerUp);
  });
}

function syncInspectorGeometryInputs(widget) {
  const inpX = document.getElementById('insp-x');
  const inpY = document.getElementById('insp-y');
  const inpW = document.getElementById('insp-w');
  const inpH = document.getElementById('insp-h');
  if (inpX) inpX.value = widget.x;
  if (inpY) inpY.value = widget.y;
  if (inpW) inpW.value = widget.w;
  if (inpH) inpH.value = widget.h;
}

/* ==========================================================================
   6. INTERACTIVE MINI-MAP (BOTTOM-RIGHT CORNER)
   ========================================================================== */
let minimapScale = 0.1;

function renderMinimap() {
  const container = document.getElementById('minimap-container');
  container.classList.toggle('hidden', !appState.canvas.showMinimap);
  if (!appState.canvas.showMinimap) return;

  const stage = document.getElementById('minimap-stage');
  document.getElementById('minimap-scale-info').textContent = `${appState.canvas.width}×${appState.canvas.height}`;

  const maxW = 196;
  const maxH = 132;
  minimapScale = Math.min(maxW / appState.canvas.width, maxH / appState.canvas.height);

  const stageW = Math.round(appState.canvas.width * minimapScale);
  const stageH = Math.round(appState.canvas.height * minimapScale);
  stage.style.width = `${stageW}px`;
  stage.style.height = `${stageH}px`;

  // Remove existing blocks but keep viewport indicator
  stage.querySelectorAll('.minimap-block').forEach((b) => b.remove());
  const viewportEl = document.getElementById('minimap-viewport');

  appState.widgets.forEach((w) => {
    const block = document.createElement('div');
    block.className = 'minimap-block';
    if (w.type === 'group') {
      block.classList.add('is-group');
    } else if (isDashboardEligible(w)) {
      block.classList.add('is-widget', getWidgetLiveState(w) ? 'is-show' : 'is-hide');
    } else {
      block.classList.add('is-widget');
    }
    if (w.id === appState.selectedId) block.classList.add('is-selected');

    block.style.left = `${w.x * minimapScale}px`;
    block.style.top = `${w.y * minimapScale}px`;
    block.style.width = `${Math.max(3, w.w * minimapScale)}px`;
    block.style.height = `${Math.max(3, w.h * minimapScale)}px`;
    stage.insertBefore(block, viewportEl);
  });

  updateMinimapViewport();
}

function updateMinimapViewport() {
  const scrollArea = document.getElementById('canvas-scroll-area');
  const viewportEl = document.getElementById('minimap-viewport');
  if (!scrollArea || !viewportEl) return;

  const padding = 28;
  const visibleLeft = Math.max(0, scrollArea.scrollLeft - padding);
  const visibleTop = Math.max(0, scrollArea.scrollTop - padding);
  const visibleW = Math.min(appState.canvas.width, scrollArea.clientWidth);
  const visibleH = Math.min(appState.canvas.height, scrollArea.clientHeight);

  viewportEl.style.left = `${visibleLeft * minimapScale}px`;
  viewportEl.style.top = `${visibleTop * minimapScale}px`;
  viewportEl.style.width = `${Math.max(12, visibleW * minimapScale)}px`;
  viewportEl.style.height = `${Math.max(10, visibleH * minimapScale)}px`;
}

function setupMinimapInteractions() {
  const stage = document.getElementById('minimap-stage');
  const scrollArea = document.getElementById('canvas-scroll-area');

  const panToPointer = (clientX, clientY) => {
    const rect = stage.getBoundingClientRect();
    const relX = (clientX - rect.left) / minimapScale;
    const relY = (clientY - rect.top) / minimapScale;
    const targetScrollLeft = relX - scrollArea.clientWidth / 2 + 28;
    const targetScrollTop = relY - scrollArea.clientHeight / 2 + 28;
    scrollArea.scrollTo({
      left: Math.max(0, targetScrollLeft),
      top: Math.max(0, targetScrollTop),
      behavior: 'auto'
    });
  };

  stage.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    stage.setPointerCapture(e.pointerId);
    panToPointer(e.clientX, e.clientY);

    const onMove = (ev) => panToPointer(ev.clientX, ev.clientY);
    const onUp = (ev) => {
      try {
        stage.releasePointerCapture(ev.pointerId);
      } catch (_) {}
      stage.removeEventListener('pointermove', onMove);
      stage.removeEventListener('pointerup', onUp);
    };
    stage.addEventListener('pointermove', onMove);
    stage.addEventListener('pointerup', onUp);
  });

  scrollArea.addEventListener('scroll', updateMinimapViewport, { passive: true });
  window.addEventListener('resize', updateMinimapViewport);
}

/* ==========================================================================
   7. RIGHT SIDEBAR INSPECTOR & CANVAS SETTINGS
   ========================================================================== */
function renderInspector() {
  const sidebar = document.getElementById('sidebar-right');
  const widget = getSelectedWidget();

  if (!widget) {
    renderInspectorEmptyState(sidebar);
    return;
  }

  const typeNames = {
    group: 'Group Panel (พื้นหลัง)',
    dashboard: 'Dashboard Panel (สถานะรวม)',
    action: 'Action Button',
    text_btn: 'Text Button',
    text_preview: 'Text Preview',
    number_btn: 'Number Button',
    playgroup: 'Action Button (PlayGroup)',
    move: 'Action Button (Move Filter)'
  };

  let specificHtml = '';

  // --- GROUP PANEL SETTINGS ---
  if (widget.type === 'group') {
    specificHtml = `
      <div class="inspector-card">
        <div class="section-title"><span>ตั้งค่า Group Panel</span></div>
        <div class="form-field">
          <label class="form-label">ข้อความหัวกลุ่ม (Custom Text)</label>
          <input type="text" id="insp-group-text" value="${escapeHtml(widget.customText || '')}" />
        </div>
        <div class="form-field">
          <label class="form-label">ตำแหน่งข้อความ</label>
          <select id="insp-group-pos">
            <option value="top-left" ${widget.textPosition === 'top-left' ? 'selected' : ''}>บนซ้าย (Top-Left)</option>
            <option value="top-center" ${widget.textPosition === 'top-center' ? 'selected' : ''}>บนกลาง (Top-Center)</option>
            <option value="top-right" ${widget.textPosition === 'top-right' ? 'selected' : ''}>บนขวา (Top-Right)</option>
            <option value="center" ${widget.textPosition === 'center' ? 'selected' : ''}>กึ่งกลาง (Center)</option>
            <option value="bottom-left" ${widget.textPosition === 'bottom-left' ? 'selected' : ''}>ล่างซ้าย (Bottom-Left)</option>
            <option value="bottom-center" ${widget.textPosition === 'bottom-center' ? 'selected' : ''}>ล่างกลาง (Bottom-Center)</option>
            <option value="bottom-right" ${widget.textPosition === 'bottom-right' ? 'selected' : ''}>ล่างขวา (Bottom-Right)</option>
          </select>
        </div>
        <div class="form-field">
          <label class="form-label">สีเส้นขอบ (Border Color)</label>
          <input type="color" id="insp-group-border" value="${widget.borderColor || '#334155'}" />
        </div>
      </div>
    `;
  }

  // --- DASHBOARD PANEL SETTINGS ---
  if (widget.type === 'dashboard') {
    const eligibleButtons = appState.widgets.filter(isDashboardEligible);
    const listHtml =
      eligibleButtons.length === 0
        ? `<div class="info-hint">ยังไม่มี Action Button, PlayGroup หรือ Move Transition บน Canvas</div>`
        : eligibleButtons
            .map((btn) => {
              const checked = (widget.monitoredIds || []).includes(btn.id);
              const typeTag =
                btn.type === 'playgroup' ? 'PlayGroup' : btn.type === 'move' ? 'Move' : 'Action';
              return `
                <label class="checkbox-row">
                  <span style="display:flex;align-items:center;gap:6px;min-width:0;">
                    <span style="font-size:10px;padding:1px 5px;border-radius:4px;background:rgba(59,130,246,0.2);color:#93c5fd;">${typeTag}</span>
                    <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(btn.label)}</span>
                  </span>
                  <input type="checkbox" data-dash-check="${btn.id}" ${checked ? 'checked' : ''} />
                </label>
              `;
            })
            .join('');

    specificHtml = `
      <div class="inspector-card">
        <div class="section-title">
          <span>เลือกปุ่มที่แสดงใน Dashboard</span>
        </div>
        <div style="display:flex;gap:6px;">
          <button type="button" class="btn" id="btn-dash-select-all" style="flex:1;">เลือกทั้งหมด</button>
          <button type="button" class="btn" id="btn-dash-clear-all" style="flex:1;">ล้างทั้งหมด</button>
        </div>
        <div class="dash-checklist">${listHtml}</div>
      </div>
    `;
  }

  // --- GENERAL ACTION BUTTON SETTINGS ---
  if (widget.type === 'action') {
    const sceneOptions = [
      `<option value="__ACTIVE__" ${widget.sceneName === '__ACTIVE__' ? 'selected' : ''}>🎬 Scene ปัจจุบัน (Active Scene)</option>`,
      ...obsData.scenes.map(
        (s) => `<option value="${escapeHtml(s)}" ${widget.sceneName === s ? 'selected' : ''}>${escapeHtml(s)}</option>`
      )
    ].join('');

    const effectiveScene =
      widget.sceneName && widget.sceneName !== '__ACTIVE__'
        ? widget.sceneName
        : obsData.currentScene;

    const itemsInScene = obsData.sceneItems[effectiveScene] || [];
    const filteredTargets = itemsInScene.filter((item) =>
      widget.targetType === 'group' ? item.isGroup : !item.isGroup
    );

    const targetOptions = [
      `<option value="">-- เลือก ${widget.targetType === 'group' ? 'Group' : 'Source'} --</option>`,
      ...filteredTargets.map(
        (it) =>
          `<option value="${escapeHtml(it.sourceName)}" ${widget.targetName === it.sourceName ? 'selected' : ''}>${escapeHtml(it.sourceName)} (${it.sceneItemEnabled ? 'SHOW' : 'HIDE'})</option>`
      )
    ];
    if (widget.targetName && !filteredTargets.some((it) => it.sourceName === widget.targetName)) {
      targetOptions.push(`<option value="${escapeHtml(widget.targetName)}" selected>${escapeHtml(widget.targetName)}</option>`);
    }

    specificHtml = `
      <div class="inspector-card">
        <div class="section-title"><span>ตั้งค่า Action Button</span></div>
        <div class="form-field">
          <label class="form-label">คำสั่ง (Action Mode)</label>
          <select id="insp-action-mode">
            <option value="toggle" ${widget.actionMode === 'toggle' ? 'selected' : ''}>Toggle (สลับ Show / Hide)</option>
            <option value="show" ${widget.actionMode === 'show' ? 'selected' : ''}>Show (แสดง)</option>
            <option value="hide" ${widget.actionMode === 'hide' ? 'selected' : ''}>Hide (ซ่อน)</option>
          </select>
        </div>
        <div class="form-field">
          <label class="form-label">Scene เป้าหมาย</label>
          <select id="insp-action-scene">${sceneOptions}</select>
        </div>
        <div class="form-field">
          <label class="form-label">ประเภทเป้าหมาย</label>
          <select id="insp-action-target-type">
            <option value="source" ${widget.targetType === 'source' ? 'selected' : ''}>Source (แหล่งที่มา)</option>
            <option value="group" ${widget.targetType === 'group' ? 'selected' : ''}>Group (กลุ่ม)</option>
          </select>
        </div>
        <div class="form-field">
          <label class="form-label">เลือก ${widget.targetType === 'group' ? 'Group' : 'Source'} จาก OBS</label>
          <select id="insp-action-target-name">${targetOptions.join('')}</select>
        </div>
      </div>
    `;
  }

  // --- TEXT BUTTON SETTINGS ---
  if (widget.type === 'text_btn') {
    const textOpts = [
      `<option value="">-- เลือก Text Source จาก OBS --</option>`,
      ...obsData.textInputs.map(
        (name) => `<option value="${escapeHtml(name)}" ${widget.inputName === name ? 'selected' : ''}>${escapeHtml(name)}</option>`
      )
    ];
    if (widget.inputName && !obsData.textInputs.includes(widget.inputName)) {
      textOpts.push(`<option value="${escapeHtml(widget.inputName)}" selected>${escapeHtml(widget.inputName)}</option>`);
    }

    specificHtml = `
      <div class="inspector-card">
        <div class="section-title"><span>ตั้งค่า Text Button</span></div>
        <div class="form-field">
          <label class="form-label">Text Source ใน OBS</label>
          <select id="insp-text-input-name">${textOpts.join('')}</select>
        </div>
        <div class="form-field">
          <label class="form-label">ข้อความเริ่มต้นในช่อง</label>
          <input type="text" id="insp-text-draft" value="${escapeHtml(widget.draftText || '')}" />
        </div>
        <div class="form-field">
          <label class="form-label">ข้อความแนะนำ (Placeholder)</label>
          <input type="text" id="insp-text-placeholder" value="${escapeHtml(widget.placeholder || '')}" />
        </div>
      </div>
    `;
  }

  // --- TEXT PREVIEW SETTINGS ---
  if (widget.type === 'text_preview') {
    const textOpts = [
      `<option value="">-- เลือก Text Source จาก OBS --</option>`,
      ...obsData.textInputs.map(
        (name) => `<option value="${escapeHtml(name)}" ${widget.inputName === name ? 'selected' : ''}>${escapeHtml(name)}</option>`
      )
    ];
    if (widget.inputName && !obsData.textInputs.includes(widget.inputName)) {
      textOpts.push(`<option value="${escapeHtml(widget.inputName)}" selected>${escapeHtml(widget.inputName)}</option>`);
    }

    specificHtml = `
      <div class="inspector-card">
        <div class="section-title"><span>ตั้งค่า Text Preview</span></div>
        <div class="form-field">
          <label class="form-label">ดึงข้อความจาก Text Source</label>
          <select id="insp-preview-input-name">${textOpts.join('')}</select>
        </div>
        <div class="form-grid-2">
          <div class="form-field">
            <label class="form-label">คำนำหน้า (Prefix)</label>
            <input type="text" id="insp-preview-prefix" value="${escapeHtml(widget.prefix || '')}" />
          </div>
          <div class="form-field">
            <label class="form-label">คำต่อท้าย (Suffix)</label>
            <input type="text" id="insp-preview-suffix" value="${escapeHtml(widget.suffix || '')}" />
          </div>
        </div>
      </div>
    `;
  }

  // --- NUMBER BUTTON SETTINGS ---
  if (widget.type === 'number_btn') {
    const textOpts = [
      `<option value="">-- เลือก Text Source จาก OBS --</option>`,
      ...obsData.textInputs.map(
        (name) => `<option value="${escapeHtml(name)}" ${widget.inputName === name ? 'selected' : ''}>${escapeHtml(name)}</option>`
      )
    ];
    if (widget.inputName && !obsData.textInputs.includes(widget.inputName)) {
      textOpts.push(`<option value="${escapeHtml(widget.inputName)}" selected>${escapeHtml(widget.inputName)}</option>`);
    }

    specificHtml = `
      <div class="inspector-card">
        <div class="section-title"><span>ตั้งค่า Number Button</span></div>
        <div class="form-field">
          <label class="form-label">Text Source ใน OBS</label>
          <select id="insp-num-input-name">${textOpts.join('')}</select>
        </div>
        <div class="form-grid-2">
          <div class="form-field">
            <label class="form-label">เพิ่ม/ลดต่อครั้ง (Step)</label>
            <input type="number" step="any" id="insp-num-step" value="${widget.step || 1}" />
          </div>
          <div class="form-field">
            <label class="form-label">ค่าตัวเลขปัจจุบัน</label>
            <input type="number" step="any" id="insp-num-current" value="${widget.currentValue || 0}" />
          </div>
        </div>
        <div class="form-grid-2">
          <div class="form-field">
            <label class="form-label">คำนำหน้า (Prefix)</label>
            <input type="text" id="insp-num-prefix" value="${escapeHtml(widget.prefix || '')}" />
          </div>
          <div class="form-field">
            <label class="form-label">คำต่อท้าย (Suffix)</label>
            <input type="text" id="insp-num-suffix" value="${escapeHtml(widget.suffix || '')}" />
          </div>
        </div>
      </div>
    `;
  }

  // --- PLAYGROUP - JAMORNz SETTINGS ---
  if (widget.type === 'playgroup') {
    const groupOpts = [
      `<option value="">-- เลือก OBS Group --</option>`,
      ...obsData.groups.map(
        (g) => `<option value="${escapeHtml(g)}" ${widget.groupName === g ? 'selected' : ''}>${escapeHtml(g)}</option>`
      )
    ];
    if (widget.groupName && !obsData.groups.includes(widget.groupName)) {
      groupOpts.push(`<option value="${escapeHtml(widget.groupName)}" selected>${escapeHtml(widget.groupName)}</option>`);
    }

    const gItems = obsData.groupItems[widget.groupName] || [];
    const firstSourceHint =
      widget.groupName && gItems.length > 0
        ? `เช็คสถานะจาก Source ตัวแรกใน Group: <strong>${escapeHtml(gItems[0].sourceName)}</strong> (${gItems[0].sceneItemEnabled ? 'SHOW' : 'HIDE'})`
        : 'ระบบจะเช็คสถานะ SHOW/HIDE จาก Source ตัวแรกใน Group อัตโนมัติ';

    specificHtml = `
      <div class="inspector-card">
        <div class="section-title"><span>ตั้งค่า PlayGroup (JAMORNz)</span></div>
        <div class="form-field">
          <label class="form-label">คำสั่ง (Action)</label>
          <select id="insp-pg-action">
            <option value="toggle" ${widget.actionMode === 'toggle' ? 'selected' : ''}>toggle (สลับ Show/Hide)</option>
            <option value="show" ${widget.actionMode === 'show' ? 'selected' : ''}>show (แสดง)</option>
            <option value="hide" ${widget.actionMode === 'hide' ? 'selected' : ''}>hide (ซ่อน)</option>
          </select>
        </div>
        <div class="form-field">
          <label class="form-label">เลือก Group เป้าหมาย</label>
          <select id="insp-pg-group">${groupOpts.join('')}</select>
        </div>
        <div class="info-hint">${firstSourceHint}</div>
      </div>
    `;
  }

  // --- MOVE TRANSITION PLUGIN SETTINGS ---
  if (widget.type === 'move') {
    // Build list of available Sources or Groups from OBS
    const targetNamesSet = new Set();
    if (widget.targetType === 'group') {
      obsData.groups.forEach((g) => targetNamesSet.add(g));
    } else {
      Object.values(obsData.sceneItems).forEach((list) => {
        list.forEach((item) => {
          if (!item.isGroup) targetNamesSet.add(item.sourceName);
        });
      });
      obsData.allInputs.forEach((inp) => targetNamesSet.add(inp.inputName));
    }

    const targetOpts = [
      `<option value="">-- เลือก ${widget.targetType === 'group' ? 'Group' : 'Source'} --</option>`,
      ...Array.from(targetNamesSet).map(
        (name) => `<option value="${escapeHtml(name)}" ${widget.targetName === name ? 'selected' : ''}>${escapeHtml(name)}</option>`
      )
    ];
    if (widget.targetName && !targetNamesSet.has(widget.targetName)) {
      targetOpts.push(`<option value="${escapeHtml(widget.targetName)}" selected>${escapeHtml(widget.targetName)}</option>`);
    }

    const filters = obsData.sourceFilters[widget.targetName] || [];
    const buildFilterOpts = (selectedVal) => {
      const opts = [
        `<option value="">-- เลือก Filter จาก OBS --</option>`,
        ...filters.map(
          (f) => `<option value="${escapeHtml(f.filterName)}" ${selectedVal === f.filterName ? 'selected' : ''}>${escapeHtml(f.filterName)}</option>`
        )
      ];
      if (selectedVal && !filters.some((f) => f.filterName === selectedVal)) {
        opts.push(`<option value="${escapeHtml(selectedVal)}" selected>${escapeHtml(selectedVal)}</option>`);
      }
      return opts.join('');
    };

    let filterSelectorsHtml = '';
    if (widget.actionMode === 'toggle') {
      filterSelectorsHtml = `
        <div class="form-field">
          <label class="form-label">Filter สำหรับ SHOW (เมื่อสถานะเป็น Hide)</label>
          <select id="insp-move-show-filter">${buildFilterOpts(widget.showFilter)}</select>
        </div>
        <div class="form-field">
          <label class="form-label">Filter สำหรับ HIDE (เมื่อสถานะเป็น Show)</label>
          <select id="insp-move-hide-filter">${buildFilterOpts(widget.hideFilter)}</select>
        </div>
      `;
    } else if (widget.actionMode === 'show') {
      filterSelectorsHtml = `
        <div class="form-field">
          <label class="form-label">Filter ที่ต้องการ Activate (Show)</label>
          <select id="insp-move-show-filter">${buildFilterOpts(widget.showFilter)}</select>
        </div>
      `;
    } else {
      filterSelectorsHtml = `
        <div class="form-field">
          <label class="form-label">Filter ที่ต้องการ Activate (Hide)</label>
          <select id="insp-move-hide-filter">${buildFilterOpts(widget.hideFilter)}</select>
        </div>
      `;
    }

    let groupHint = '';
    if (widget.targetType === 'group' && widget.targetName) {
      const gItems = obsData.groupItems[widget.targetName] || [];
      groupHint =
        gItems.length > 0
          ? `<div class="info-hint">เช็คสถานะจาก Source ตัวแรกใน Group: <strong>${escapeHtml(gItems[0].sourceName)}</strong> (${gItems[0].sceneItemEnabled ? 'SHOW' : 'HIDE'})</div>`
          : `<div class="info-hint">ระบบจะเช็คสถานะ SHOW/HIDE จาก Source ตัวแรกใน Group</div>`;
    }

    specificHtml = `
      <div class="inspector-card">
        <div class="section-title"><span>ตั้งค่า Move Transition Filter</span></div>
        <div class="form-field">
          <label class="form-label">คำสั่ง (Action Mode)</label>
          <select id="insp-move-action">
            <option value="toggle" ${widget.actionMode === 'toggle' ? 'selected' : ''}>Toggle (เลือก Filter Show/Hide แยกกัน)</option>
            <option value="show" ${widget.actionMode === 'show' ? 'selected' : ''}>Show (Activate Filter)</option>
            <option value="hide" ${widget.actionMode === 'hide' ? 'selected' : ''}>Hide (Activate Filter)</option>
          </select>
        </div>
        <div class="form-field">
          <label class="form-label">ประเภทเป้าหมาย</label>
          <select id="insp-move-target-type">
            <option value="source" ${widget.targetType === 'source' ? 'selected' : ''}>Source (แหล่งที่มา)</option>
            <option value="group" ${widget.targetType === 'group' ? 'selected' : ''}>Group (กลุ่ม)</option>
          </select>
        </div>
        <div class="form-field">
          <label class="form-label">เลือก ${widget.targetType === 'group' ? 'Group' : 'Source'} เป้าหมาย</label>
          <select id="insp-move-target-name">${targetOpts.join('')}</select>
        </div>
        ${filterSelectorsHtml}
        ${groupHint}
      </div>
    `;
  }

  sidebar.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:6px;">
      <strong style="font-size:13px;color:#fff;">🎛️ ${typeNames[widget.type] || 'ตั้งค่าปุ่ม'}</strong>
      <button type="button" class="btn" id="btn-deselect-widget" style="padding:4px 8px;font-size:11px;">ยกเลิกเลือก</button>
    </div>

    ${specificHtml}

    <!-- Appearance & Typography -->
    <div class="inspector-card">
      <div class="section-title"><span>รูปลักษณ์และข้อความ</span></div>
      <div class="form-field">
        <label class="form-label">ชื่อปุ่ม / หัวข้อ</label>
        <input type="text" id="insp-label" value="${escapeHtml(widget.label || '')}" />
      </div>
      <div class="form-grid-2">
        <div class="form-field">
          <label class="form-label">สีพื้นหลัง</label>
          <input type="color" id="insp-bg-color" value="${widget.bgColor || '#1e293b'}" />
        </div>
        <div class="form-field">
          <label class="form-label">สีข้อความ</label>
          <input type="color" id="insp-text-color" value="${widget.textColor || '#f8fafc'}" />
        </div>
      </div>
      <div class="form-field">
        <label class="form-label">ขนาดตัวอักษร (px)</label>
        <input type="number" min="9" max="64" id="insp-font-size" value="${widget.fontSize || 14}" />
      </div>
    </div>

    <!-- Position & Dimensions -->
    <div class="inspector-card">
      <div class="section-title"><span>ตำแหน่งและขนาด (px)</span></div>
      <div class="form-grid-4">
        <div class="form-field">
          <label class="form-label">X</label>
          <input type="number" id="insp-x" value="${widget.x}" />
        </div>
        <div class="form-field">
          <label class="form-label">Y</label>
          <input type="number" id="insp-y" value="${widget.y}" />
        </div>
        <div class="form-field">
          <label class="form-label">กว้าง</label>
          <input type="number" min="40" id="insp-w" value="${widget.w}" />
        </div>
        <div class="form-field">
          <label class="form-label">สูง</label>
          <input type="number" min="30" id="insp-h" value="${widget.h}" />
        </div>
      </div>
    </div>

    <!-- Duplicate & Delete Actions -->
    <div style="display:flex;gap:8px;margin-top:auto;">
      <button type="button" class="btn" id="btn-duplicate-widget" style="flex:1;">📋 ทำซ้ำปุ่ม</button>
      <button type="button" class="btn btn-danger" id="btn-delete-widget" style="flex:1;">🗑️ ลบปุ่ม</button>
    </div>
  `;

  bindInspectorEvents(widget);
}

/**
 * Deletes a widget cleanly from appState.widgets, removes its ID from any dashboard monitoredIds,
 * clears selectedId, persists to localStorage, and refreshes canvas, mini-map, and inspector.
 */
function deleteWidget(widgetId) {
  if (!widgetId) return;
  const idx = appState.widgets.findIndex((item) => item.id === widgetId);
  if (idx === -1) return;

  const removedWidget = appState.widgets[idx];
  appState.widgets.splice(idx, 1);

  // Clean up reference from all Dashboard Panels
  appState.widgets.forEach((w) => {
    if (w.type === 'dashboard' && Array.isArray(w.monitoredIds)) {
      w.monitoredIds = w.monitoredIds.filter((id) => id !== widgetId);
    }
  });

  if (appState.selectedId === widgetId) {
    appState.selectedId = null;
  }

  saveState();
  renderCanvas();
  renderInspector();
  showToast(`ลบ "${removedWidget.label || 'ปุ่ม'}" เรียบร้อยแล้ว`, 'info', 2200);
}

/**
 * Duplicates an existing widget with a new ID and slight offset.
 */
function duplicateWidget(widgetId) {
  const orig = appState.widgets.find((item) => item.id === widgetId);
  if (!orig) return;

  const copy = JSON.parse(JSON.stringify(orig));
  copy.id = generateId(orig.type === 'group' ? 'grp' : 'w');
  copy.label = `${orig.label || 'Widget'} (สำเนา)`;
  copy.x = Math.min(Math.max(0, appState.canvas.width - copy.w), orig.x + 20);
  copy.y = Math.min(Math.max(0, appState.canvas.height - copy.h), orig.y + 20);

  if (isDashboardEligible(copy)) {
    appState.widgets.forEach((w) => {
      if (w.type === 'dashboard' && Array.isArray(w.monitoredIds)) {
        w.monitoredIds.push(copy.id);
      }
    });
  }

  appState.widgets.push(copy);
  appState.selectedId = copy.id;
  saveState();
  renderCanvas();
  renderInspector();
  showToast(`ทำซ้ำ "${orig.label}" เรียบร้อยแล้ว`, 'success', 2000);
}

/**
 * Binds all form controls and action buttons inside the Right Inspector for the selected widget.
 */
function bindInspectorEvents(widget) {
  if (!widget) return;

  const onUpdate = (shouldRerenderInspector = false) => {
    saveState();
    renderCanvas();
    if (shouldRerenderInspector) {
      renderInspector();
    }
  };

  // Deselect button
  const btnDeselect = document.getElementById('btn-deselect-widget');
  if (btnDeselect) {
    btnDeselect.addEventListener('click', () => {
      appState.selectedId = null;
      renderCanvas();
      renderInspector();
    });
  }

  // Duplicate & Delete buttons
  const btnDup = document.getElementById('btn-duplicate-widget');
  if (btnDup) {
    btnDup.addEventListener('click', () => duplicateWidget(widget.id));
  }

  const btnDel = document.getElementById('btn-delete-widget');
  if (btnDel) {
    btnDel.addEventListener('click', () => deleteWidget(widget.id));
  }

  // Common Appearance & Typography
  const inpLabel = document.getElementById('insp-label');
  if (inpLabel) {
    inpLabel.addEventListener('input', (e) => {
      widget.label = e.target.value;
      onUpdate(false);
    });
  }

  const inpBg = document.getElementById('insp-bg-color');
  if (inpBg) {
    inpBg.addEventListener('input', (e) => {
      widget.bgColor = e.target.value;
      onUpdate(false);
    });
  }

  const inpTextCol = document.getElementById('insp-text-color');
  if (inpTextCol) {
    inpTextCol.addEventListener('input', (e) => {
      widget.textColor = e.target.value;
      onUpdate(false);
    });
  }

  const inpFontSize = document.getElementById('insp-font-size');
  if (inpFontSize) {
    inpFontSize.addEventListener('input', (e) => {
      widget.fontSize = Math.max(8, Math.min(96, Number(e.target.value) || 14));
      onUpdate(false);
    });
  }

  // Geometry (X, Y, W, H)
  const inpX = document.getElementById('insp-x');
  if (inpX) {
    inpX.addEventListener('input', (e) => {
      widget.x = Math.max(0, Math.min(appState.canvas.width - widget.w, Number(e.target.value) || 0));
      onUpdate(false);
    });
  }

  const inpY = document.getElementById('insp-y');
  if (inpY) {
    inpY.addEventListener('input', (e) => {
      widget.y = Math.max(0, Math.min(appState.canvas.height - widget.h, Number(e.target.value) || 0));
      onUpdate(false);
    });
  }

  const inpW = document.getElementById('insp-w');
  if (inpW) {
    inpW.addEventListener('input', (e) => {
      widget.w = Math.max(40, Math.min(appState.canvas.width - widget.x, Number(e.target.value) || 80));
      onUpdate(false);
    });
  }

  const inpH = document.getElementById('insp-h');
  if (inpH) {
    inpH.addEventListener('input', (e) => {
      widget.h = Math.max(30, Math.min(appState.canvas.height - widget.y, Number(e.target.value) || 44));
      onUpdate(false);
    });
  }

  // Type-specific bindings
  if (widget.type === 'group') {
    document.getElementById('insp-group-text')?.addEventListener('input', (e) => {
      widget.customText = e.target.value;
      onUpdate(false);
    });
    document.getElementById('insp-group-pos')?.addEventListener('change', (e) => {
      widget.textPosition = e.target.value;
      onUpdate(false);
    });
    document.getElementById('insp-group-border')?.addEventListener('input', (e) => {
      widget.borderColor = e.target.value;
      onUpdate(false);
    });
  }

  if (widget.type === 'dashboard') {
    document.querySelectorAll('[data-dash-check]').forEach((chk) => {
      chk.addEventListener('change', (e) => {
        const targetId = chk.dataset.dashCheck;
        if (!Array.isArray(widget.monitoredIds)) widget.monitoredIds = [];
        if (e.target.checked) {
          if (!widget.monitoredIds.includes(targetId)) widget.monitoredIds.push(targetId);
        } else {
          widget.monitoredIds = widget.monitoredIds.filter((id) => id !== targetId);
        }
        onUpdate(false);
      });
    });

    document.getElementById('btn-dash-select-all')?.addEventListener('click', () => {
      widget.monitoredIds = appState.widgets.filter(isDashboardEligible).map((b) => b.id);
      onUpdate(true);
    });

    document.getElementById('btn-dash-clear-all')?.addEventListener('click', () => {
      widget.monitoredIds = [];
      onUpdate(true);
    });
  }

  if (widget.type === 'action') {
    document.getElementById('insp-action-mode')?.addEventListener('change', (e) => {
      widget.actionMode = e.target.value;
      onUpdate(false);
    });
    document.getElementById('insp-action-scene')?.addEventListener('change', (e) => {
      widget.sceneName = e.target.value;
      widget.targetName = '';
      onUpdate(true);
    });
    document.getElementById('insp-action-target-type')?.addEventListener('change', (e) => {
      widget.targetType = e.target.value;
      widget.targetName = '';
      onUpdate(true);
    });
    document.getElementById('insp-action-target-name')?.addEventListener('change', (e) => {
      widget.targetName = e.target.value;
      onUpdate(false);
    });
  }

  if (widget.type === 'text_btn') {
    document.getElementById('insp-text-input-name')?.addEventListener('change', (e) => {
      widget.inputName = e.target.value;
      onUpdate(false);
    });
    document.getElementById('insp-text-draft')?.addEventListener('input', (e) => {
      widget.draftText = e.target.value;
      onUpdate(false);
    });
    document.getElementById('insp-text-placeholder')?.addEventListener('input', (e) => {
      widget.placeholder = e.target.value;
      onUpdate(false);
    });
  }

  if (widget.type === 'text_preview') {
    document.getElementById('insp-preview-input-name')?.addEventListener('change', (e) => {
      widget.inputName = e.target.value;
      onUpdate(false);
    });
    document.getElementById('insp-preview-prefix')?.addEventListener('input', (e) => {
      widget.prefix = e.target.value;
      onUpdate(false);
    });
    document.getElementById('insp-preview-suffix')?.addEventListener('input', (e) => {
      widget.suffix = e.target.value;
      onUpdate(false);
    });
  }

  if (widget.type === 'number_btn') {
    document.getElementById('insp-num-input-name')?.addEventListener('change', (e) => {
      widget.inputName = e.target.value;
      onUpdate(false);
    });
    document.getElementById('insp-num-step')?.addEventListener('input', (e) => {
      widget.step = Number(e.target.value) || 1;
      onUpdate(false);
    });
    document.getElementById('insp-num-current')?.addEventListener('input', (e) => {
      widget.currentValue = Number(e.target.value) || 0;
      onUpdate(false);
    });
    document.getElementById('insp-num-prefix')?.addEventListener('input', (e) => {
      widget.prefix = e.target.value;
      onUpdate(false);
    });
    document.getElementById('insp-num-suffix')?.addEventListener('input', (e) => {
      widget.suffix = e.target.value;
      onUpdate(false);
    });
  }

  if (widget.type === 'playgroup') {
    document.getElementById('insp-pg-action')?.addEventListener('change', (e) => {
      widget.actionMode = e.target.value;
      onUpdate(false);
    });
    document.getElementById('insp-pg-group')?.addEventListener('change', async (e) => {
      widget.groupName = e.target.value;
      if (widget.groupName && obsData.connected) {
        await fetchGroupChildItems(widget.groupName);
      }
      onUpdate(true);
    });
  }

  if (widget.type === 'move') {
    document.getElementById('insp-move-action')?.addEventListener('change', (e) => {
      widget.actionMode = e.target.value;
      onUpdate(true);
    });
    document.getElementById('insp-move-target-type')?.addEventListener('change', (e) => {
      widget.targetType = e.target.value;
      widget.targetName = '';
      widget.showFilter = '';
      widget.hideFilter = '';
      onUpdate(true);
    });
    document.getElementById('insp-move-target-name')?.addEventListener('change', async (e) => {
      widget.targetName = e.target.value;
      widget.showFilter = '';
      widget.hideFilter = '';
      if (widget.targetName && obsData.connected) {
        await fetchSourceFilters(widget.targetName);
        if (widget.targetType === 'group') {
          await fetchGroupChildItems(widget.targetName);
        }
      }
      onUpdate(true);
    });
    document.getElementById('insp-move-show-filter')?.addEventListener('change', (e) => {
      widget.showFilter = e.target.value;
      onUpdate(false);
    });
    document.getElementById('insp-move-hide-filter')?.addEventListener('change', (e) => {
      widget.hideFilter = e.target.value;
      onUpdate(false);
    });
  }
}

function renderInspectorEmptyState(sidebar) {
  sidebar.innerHTML = `
    <div class="section-title">
      <span>🎛️ ตัวตั้งค่าปุ่ม (Button Inspector)</span>
    </div>
    <div class="inspector-empty-state">
      <div class="inspector-empty-icon">👆</div>
      <strong style="font-size:13px;color:var(--text-primary);">ยังไม่ได้เลือกปุ่มบน Canvas</strong>
      <p style="font-size:12px;line-height:1.5;color:var(--text-secondary);">
        คลิกเลือกปุ่มหรือแผงควบคุมบนพื้นที่ตรงกลาง เพื่อปรับแต่งชื่อปุ่ม สี ขนาด และเชื่อมต่อกับ OBS Source / Group
      </p>
      <button type="button" class="btn" id="btn-inspector-open-settings" style="margin-top:6px;">
        ⚙️ เปิดหน้าตั้งค่าหลัก (Canvas)
      </button>
    </div>
  `;

  const openSettingsBtn = document.getElementById('btn-inspector-open-settings');
  if (openSettingsBtn) {
    openSettingsBtn.addEventListener('click', openMainSettingsModal);
  }
}

function openMainSettingsModal() {
  const modal = document.getElementById('main-settings-modal');
  renderMainSettingsModal();
  modal.classList.add('open');
}

function closeMainSettingsModal() {
  const modal = document.getElementById('main-settings-modal');
  modal.classList.remove('open');
}

function renderMainSettingsModal() {
  const container = document.getElementById('main-settings-modal-body');
  if (!container) return;

  const presetsHtml = CANVAS_PRESETS.map((p) => {
    const isActive = appState.canvas.width === p.width && appState.canvas.height === p.height;
    return `
      <button type="button" class="preset-btn ${isActive ? 'active' : ''}" data-preset-w="${p.width}" data-preset-h="${p.height}">
        <span class="preset-name">${p.name}</span>
        <span class="preset-dim">${p.width} × ${p.height}</span>
      </button>
    `;
  }).join('');

  container.innerHTML = `
    <div class="inspector-card">
      <div class="section-title"><span>📐 ตั้งค่าขนาดพื้นที่วางปุ่ม (Canvas Presets)</span></div>
      <div class="preset-grid">${presetsHtml}</div>
    </div>

    <div class="inspector-card">
      <div class="section-title"><span>กำหนดขนาดเอง (Custom Size)</span></div>
      <div class="form-grid-2">
        <div class="form-field">
          <label class="form-label">ความกว้าง (Width px)</label>
          <input type="number" min="240" max="3840" id="canvas-custom-w" value="${appState.canvas.width}" />
        </div>
        <div class="form-field">
          <label class="form-label">ความสูง (Height px)</label>
          <input type="number" min="200" max="2160" id="canvas-custom-h" value="${appState.canvas.height}" />
        </div>
      </div>
      <button type="button" class="btn btn-primary" id="btn-apply-canvas-size">ปรับขนาด Canvas</button>
    </div>

    <div class="inspector-card">
      <div class="section-title"><span>การแสดงผลและจัดการพื้นที่ทำงาน</span></div>
      <label class="checkbox-row">
        <span>แสดงเส้นตาราง (Grid Lines)</span>
        <input type="checkbox" id="chk-show-grid" ${appState.canvas.showGrid ? 'checked' : ''} />
      </label>
      <label class="checkbox-row">
        <span>ดูดติดเส้นตารางอัตโนมัติ (Snap 10px)</span>
        <input type="checkbox" id="chk-snap-grid" ${appState.canvas.snapGrid ? 'checked' : ''} />
      </label>
      <label class="checkbox-row">
        <span>แสดงแผนที่ย่อมุมขวาล่าง (Mini-map)</span>
        <input type="checkbox" id="chk-show-minimap" ${appState.canvas.showMinimap ? 'checked' : ''} />
      </label>
      <div class="form-field">
        <label class="form-label">สีพื้นหลัง Canvas</label>
        <input type="color" id="inp-canvas-bg" value="${appState.canvas.bgColor || '#0e121b'}" />
      </div>
    </div>

    <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;padding-top:4px;">
      <button type="button" class="btn btn-danger" id="btn-clear-canvas">
        🧹 ล้างปุ่มทั้งหมดบน Canvas
      </button>
      <button type="button" class="btn btn-primary" id="btn-done-main-settings">
        เสร็จสิ้น
      </button>
    </div>
  `;

  // Preset Buttons
  container.querySelectorAll('[data-preset-w]').forEach((btn) => {
    btn.addEventListener('click', () => {
      appState.canvas.width = Number(btn.dataset.presetW);
      appState.canvas.height = Number(btn.dataset.presetH);
      saveState();
      renderCanvas();
      renderMainSettingsModal();
      showToast(`ปรับขนาด Canvas เป็น ${appState.canvas.width} × ${appState.canvas.height}`, 'info', 2200);
    });
  });

  // Custom Width/Height
  document.getElementById('btn-apply-canvas-size').addEventListener('click', () => {
    const w = Math.max(240, Math.min(3840, Number(document.getElementById('canvas-custom-w').value) || 1920));
    const h = Math.max(200, Math.min(2160, Number(document.getElementById('canvas-custom-h').value) || 1080));
    appState.canvas.width = w;
    appState.canvas.height = h;
    saveState();
    renderCanvas();
    renderMainSettingsModal();
    showToast(`ปรับขนาด Canvas เป็น ${w} × ${h}`, 'info', 2200);
  });

  document.getElementById('chk-show-grid').addEventListener('change', (e) => {
    appState.canvas.showGrid = e.target.checked;
    saveState();
    renderCanvas();
  });

  document.getElementById('chk-snap-grid').addEventListener('change', (e) => {
    appState.canvas.snapGrid = e.target.checked;
    saveState();
  });

  document.getElementById('chk-show-minimap').addEventListener('change', (e) => {
    appState.canvas.showMinimap = e.target.checked;
    saveState();
    renderMinimap();
  });

  document.getElementById('inp-canvas-bg').addEventListener('input', (e) => {
    appState.canvas.bgColor = e.target.value;
    saveState();
    renderCanvas();
  });

  document.getElementById('btn-clear-canvas').addEventListener('click', async () => {
    if (appState.widgets.length === 0) {
      showToast('ไม่มีปุ่มบน Canvas ให้ล้าง', 'info', 2000);
      return;
    }
    const ok = await showConfirmModal(
      'ยืนยันการล้างหน้าจอ Canvas',
      'คุณต้องการลบปุ่มและแผงควบคุมทั้งหมดบน Canvas ใช่หรือไม่? การกระทำนี้ไม่สามารถย้อนกลับได้'
    );
    if (ok) {
      appState.widgets = [];
      appState.selectedId = null;
      saveState();
      renderCanvas();
      renderInspector();
      closeMainSettingsModal();
      showToast('ล้างปุ่มทั้งหมดบน Canvas เรียบร้อยแล้ว', 'info');
    }
  });

  document.getElementById('btn-done-main-settings').addEventListener('click', closeMainSettingsModal);
}

/* ==========================================================================
   8. PERSISTENCE (LOCALSTORAGE, JSON EXPORT / IMPORT)
   ========================================================================== */
function saveState() {
  try {
    const toSave = {
      wsUrl: appState.wsUrl,
      canvas: appState.canvas,
      widgets: appState.widgets
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave));
  } catch (_) {}
}

function loadSavedState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (parsed.wsUrl) {
      appState.wsUrl = parsed.wsUrl;
      document.getElementById('ws-url').value = parsed.wsUrl;
    }
    if (parsed.canvas) {
      Object.assign(appState.canvas, parsed.canvas);
    }
    if (Array.isArray(parsed.widgets)) {
      appState.widgets = parsed.widgets;
    }
  } catch (_) {}
}

function exportLayoutJson() {
  const exportData = {
    app: 'OBS Control Deck',
    version: 1,
    exportedAt: new Date().toISOString(),
    wsUrl: appState.wsUrl,
    canvas: appState.canvas,
    widgets: appState.widgets
  };
  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `obs-control-deck-${appState.canvas.width}x${appState.canvas.height}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  showToast('ส่งออกไฟล์ตั้งค่า JSON เรียบร้อยแล้ว', 'success');
}

function importLayoutJson(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const parsed = JSON.parse(e.target.result);
      if (!parsed || !Array.isArray(parsed.widgets)) {
        throw new Error('รูปแบบไฟล์ JSON ไม่ถูกต้อง');
      }
      if (parsed.wsUrl) {
        appState.wsUrl = parsed.wsUrl;
        document.getElementById('ws-url').value = parsed.wsUrl;
      }
      if (parsed.canvas) {
        Object.assign(appState.canvas, parsed.canvas);
      }
      appState.widgets = parsed.widgets;
      appState.selectedId = null;
      saveState();
      renderCanvas();
      renderInspector();
      if (obsData.connected) syncAllObsData(true);
      showToast('นำเข้าการตั้งค่าจากไฟล์ JSON สำเร็จ!', 'success');
    } catch (err) {
      showToast(`นำเข้าไฟล์ไม่สำเร็จ: ${err.message}`, 'error');
    }
  };
  reader.readAsText(file);
}

/* ==========================================================================
   9. INITIALIZATION & GLOBAL EVENT WIRING
   ========================================================================== */
window.addEventListener('DOMContentLoaded', () => {
  loadSavedState();
  checkMixedContentWarning(appState.wsUrl);

  // Header Buttons
  document.getElementById('btn-ws-connect').addEventListener('click', connectObs);
  document.getElementById('btn-sync-obs').addEventListener('click', () => syncAllObsData(false));

  document.getElementById('btn-toggle-pass').addEventListener('click', () => {
    const inp = document.getElementById('ws-password');
    inp.type = inp.type === 'password' ? 'text' : 'password';
  });

  document.getElementById('btn-dismiss-mixed').addEventListener('click', () => {
    document.getElementById('mixed-content-banner').classList.remove('visible');
  });

  document.getElementById('btn-open-main-settings').addEventListener('click', openMainSettingsModal);
  document.getElementById('btn-canvas-size-badge').addEventListener('click', openMainSettingsModal);
  document.getElementById('btn-close-main-settings').addEventListener('click', closeMainSettingsModal);

  // Close Main Settings Popup when clicking outside backdrop or pressing Escape
  const mainSettingsModal = document.getElementById('main-settings-modal');
  mainSettingsModal.addEventListener('pointerdown', (e) => {
    if (e.target === mainSettingsModal) {
      closeMainSettingsModal();
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && mainSettingsModal.classList.contains('open')) {
      closeMainSettingsModal();
      return;
    }
    // Allow Delete/Backspace to remove selected widget when in Edit Mode and not typing in an input
    const tag = document.activeElement ? document.activeElement.tagName : '';
    const isTyping = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
    if ((e.key === 'Delete' || e.key === 'Backspace') && !isTyping && appState.mode === 'edit' && appState.selectedId) {
      e.preventDefault();
      deleteWidget(appState.selectedId);
    }
  });

  document.getElementById('btn-toggle-mode').addEventListener('click', () => {
    appState.mode = appState.mode === 'edit' ? 'live' : 'edit';
    if (appState.mode === 'live') {
      appState.selectedId = null;
    }
    renderCanvas();
    renderInspector();
  });

  document.getElementById('btn-export-json').addEventListener('click', exportLayoutJson);

  const fileInput = document.getElementById('file-import-input');
  document.getElementById('btn-import-json').addEventListener('click', () => {
    fileInput.value = '';
    fileInput.click();
  });
  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      importLayoutJson(e.target.files[0]);
    }
  });

  // Sidebar Collapse Toggles
  document.getElementById('btn-toggle-left').addEventListener('click', () => {
    document.getElementById('sidebar-left').classList.toggle('collapsed');
    updateMinimapViewport();
  });
  document.getElementById('btn-toggle-right').addEventListener('click', () => {
    document.getElementById('sidebar-right').classList.toggle('collapsed');
    updateMinimapViewport();
  });

  // Left Palette Add Widget Buttons
  document.querySelectorAll('[data-add-type]').forEach((btn) => {
    btn.addEventListener('click', () => {
      if (appState.mode === 'live') {
        appState.mode = 'edit';
      }
      createWidget(btn.dataset.addType);
    });
  });

  // Click empty canvas to deselect
  document.getElementById('canvas-board').addEventListener('pointerdown', (e) => {
    if (e.target === e.currentTarget && appState.selectedId !== null) {
      appState.selectedId = null;
      renderCanvas();
      renderInspector();
    }
  });

  setupMinimapInteractions();
  renderCanvas();
  renderInspector();
});