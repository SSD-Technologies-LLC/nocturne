// Nocturne Dashboard — app.js
// No dependencies, no frameworks.

(function () {
  'use strict';

  // ── State ──────────────────────────────────────────────────
  let files = [];
  let selectedFile = null;   // file pending upload
  let linkModalFileId = null;
  let expandedLinks = {};    // fileId -> boolean

  // ── Auth ──────────────────────────────────────────────────
  function getToken() {
    return sessionStorage.getItem('nocturne_token') || '';
  }

  function setToken(token) {
    sessionStorage.setItem('nocturne_token', token);
  }

  function clearToken() {
    sessionStorage.removeItem('nocturne_token');
  }

  function showLogin() {
    document.getElementById('loginOverlay').classList.add('active');
    document.getElementById('mainContent').classList.add('hidden');
  }

  function hideLogin() {
    document.getElementById('loginOverlay').classList.remove('active');
    document.getElementById('mainContent').classList.remove('hidden');
  }

  function handleLogin() {
    var token = document.getElementById('loginToken').value.trim();
    if (!token) {
      showToast('API key is required');
      return;
    }
    setToken(token);
    hideLogin();
    fetchFiles();
    checkRecoveryBanner();
  }
  window.handleLogin = handleLogin;

  function logout() {
    clearToken();
    showLogin();
  }
  window.logout = logout;

  // ── Init ───────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    initDragDrop();
    initCipherSelector();
    initModeSelector();
    if (!getToken()) {
      showLogin();
    } else {
      fetchFiles();
      checkRecoveryBanner();
    }
  });

  // ── API helpers ────────────────────────────────────────────
  async function api(method, path, body, isFormData) {
    var opts = { method: method, headers: {} };
    var token = getToken();
    if (token && path.indexOf('/api/') === 0) {
      opts.headers['Authorization'] = 'Bearer ' + token;
    }
    if (body) {
      if (isFormData) {
        opts.body = body;
      } else {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
      }
    }
    var res = await fetch(path, opts);
    if (res.status === 401) {
      clearToken();
      showLogin();
      throw new Error('Authentication required');
    }
    return res;
  }

  async function apiJSON(method, path, body) {
    const res = await api(method, path, body);
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Request failed');
    }
    return data;
  }

  // ── Utility ────────────────────────────────────────────────
  function humanSize(bytes) {
    if (bytes === 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.floor(Math.log(bytes) / Math.log(1024));
    if (i >= units.length) i = units.length - 1;
    var size = bytes / Math.pow(1024, i);
    return size.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
  }

  function relativeTime(unixSeconds) {
    var now = Math.floor(Date.now() / 1000);
    var diff = now - unixSeconds;
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff / 60) + ' min ago';
    if (diff < 86400) return Math.floor(diff / 3600) + ' hours ago';
    if (diff < 2592000) return Math.floor(diff / 86400) + ' days ago';
    var d = new Date(unixSeconds * 1000);
    return d.toLocaleDateString();
  }

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  function setLoading(btn, loading) {
    if (!btn) return;
    if (loading) {
      btn.classList.add('btn-loading');
      btn.disabled = true;
    } else {
      btn.classList.remove('btn-loading');
      btn.disabled = false;
    }
  }

  // ── Safe DOM builder helpers ───────────────────────────────
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      for (var key in attrs) {
        if (key === 'className') node.className = attrs[key];
        else if (key === 'onclick') node.addEventListener('click', attrs[key]);
        else if (key === 'textContent') node.textContent = attrs[key];
        else if (key === 'title') node.title = attrs[key];
        else if (key.indexOf('data-') === 0) node.setAttribute(key, attrs[key]);
        else if (key === 'style') node.style.cssText = attrs[key];
        else if (key === 'id') node.id = attrs[key];
        else node.setAttribute(key, attrs[key]);
      }
    }
    if (children) {
      if (!Array.isArray(children)) children = [children];
      for (var i = 0; i < children.length; i++) {
        if (typeof children[i] === 'string') {
          node.appendChild(document.createTextNode(children[i]));
        } else if (children[i]) {
          node.appendChild(children[i]);
        }
      }
    }
    return node;
  }

  // ── Files ──────────────────────────────────────────────────
  async function fetchFiles() {
    try {
      const data = await apiJSON('GET', '/api/files');
      files = data || [];
      renderFiles();
    } catch (err) {
      showToast(err.message);
    }
  }
  window.fetchFiles = fetchFiles;

  function buildFileCard(f) {
    var cipherClass = f.cipher === 'noctis' ? 'noctis' : 'aes';
    var cipherLabel = f.cipher === 'noctis' ? 'NOCTIS' : 'AES';
    var expanded = expandedLinks[f.id];

    var card = el('div', { className: 'file-card', 'data-file-id': f.id });

    // Top row
    var top = el('div', { className: 'file-card-top' });
    top.appendChild(el('div', { className: 'file-card-name', textContent: f.name, title: f.name }));
    top.appendChild(el('span', { className: 'cipher-badge ' + cipherClass, textContent: cipherLabel }));
    card.appendChild(top);

    // Meta row
    var meta = el('div', { className: 'file-card-meta' });
    meta.appendChild(el('span', { className: 'file-card-size', textContent: humanSize(f.size) }));
    meta.appendChild(el('span', { className: 'file-card-date', textContent: relativeTime(f.created_at) }));
    card.appendChild(meta);

    // Actions row
    var actions = el('div', { className: 'file-card-actions' });

    var createLinkBtn = el('button', {
      className: 'btn btn-ghost btn-sm',
      textContent: 'Create Link',
      onclick: function () { openLinkModal(f.id); }
    });
    actions.appendChild(createLinkBtn);

    var toggleLinksBtn = el('button', {
      className: 'btn btn-ghost btn-sm',
      textContent: expanded ? 'Hide Links' : 'Show Links',
      onclick: function () { toggleLinks(f.id); }
    });
    actions.appendChild(toggleLinksBtn);

    var deleteBtn = el('button', {
      className: 'btn btn-danger btn-sm',
      textContent: 'Delete',
      onclick: function () { deleteFile(f.id); }
    });
    actions.appendChild(deleteBtn);

    card.appendChild(actions);

    // Links section
    var linksSection = el('div', { className: 'file-links' + (expanded ? '' : ' hidden') });
    linksSection.id = 'links-' + f.id;
    linksSection.appendChild(el('div', { className: 'file-links-header', textContent: 'Active Links' }));
    var linksList = el('div', { textContent: 'Loading...' });
    linksList.id = 'links-list-' + f.id;
    linksSection.appendChild(linksList);
    card.appendChild(linksSection);

    return card;
  }

  function renderFiles() {
    var list = document.getElementById('fileList');
    var count = document.getElementById('fileCount');

    count.textContent = files.length + ' file' + (files.length !== 1 ? 's' : '');

    // Clear existing content
    while (list.firstChild) list.removeChild(list.firstChild);

    if (files.length === 0) {
      var empty = el('div', { className: 'empty-state' });
      empty.appendChild(el('div', { className: 'empty-state-icon', textContent: '\u25E6' }));
      empty.appendChild(el('div', { textContent: 'No files yet. Drop a file to begin.' }));
      list.appendChild(empty);
      return;
    }

    for (var i = 0; i < files.length; i++) {
      list.appendChild(buildFileCard(files[i]));
    }

    // Load links for expanded sections
    for (var id in expandedLinks) {
      if (expandedLinks[id]) {
        fetchLinks(id);
      }
    }
  }

  async function uploadFile(file, password, cipher) {
    var fd = new FormData();
    fd.append('file', file);
    fd.append('password', password);
    fd.append('cipher', cipher);

    var btn = document.getElementById('uploadBtn');
    setLoading(btn, true);

    try {
      var res = await api('POST', '/api/files', fd, true);
      var data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Upload failed');
      showToast('File encrypted and uploaded', 'success');
      cancelUpload();
      fetchFiles();
      checkRecoveryBanner();
    } catch (err) {
      showToast(err.message);
    } finally {
      setLoading(btn, false);
    }
  }
  window.uploadFile = uploadFile;

  async function deleteFile(id) {
    if (!confirm('Delete this file and all its links? This cannot be undone.')) return;
    try {
      await apiJSON('DELETE', '/api/files/' + id);
      showToast('File deleted', 'success');
      delete expandedLinks[id];
      fetchFiles();
    } catch (err) {
      showToast(err.message);
    }
  }
  window.deleteFile = deleteFile;

  // ── Links ──────────────────────────────────────────────────
  async function createLink(fileId, password, mode, expiresIn) {
    var body = {
      password: password,
      mode: mode,
    };
    if (mode === 'timed' && expiresIn > 0) {
      body.expires_in = parseInt(expiresIn, 10);
    }

    var btn = document.getElementById('createLinkBtn');
    setLoading(btn, true);

    try {
      var data = await apiJSON('POST', '/api/files/' + fileId + '/link', body);
      var fullUrl = window.location.origin + data.url;
      document.getElementById('linkResultUrl').textContent = fullUrl;
      document.getElementById('linkResult').classList.remove('hidden');
      document.getElementById('linkModalFooter').classList.add('hidden');
      showToast('Link created', 'success');
      // Refresh links if expanded
      if (expandedLinks[fileId]) {
        fetchLinks(fileId);
      }
    } catch (err) {
      showToast(err.message);
    } finally {
      setLoading(btn, false);
    }
  }
  window.createLink = createLink;

  function buildLinkItem(l, fileId) {
    var modeClass = l.mode;
    var modeLabel = l.mode === 'onetime' ? 'ONE-TIME' : l.mode.toUpperCase();
    var fullUrl = window.location.origin + l.url;

    var item = el('div', { className: 'link-item' });

    item.appendChild(el('span', { className: 'link-slug', textContent: fullUrl, title: fullUrl }));
    item.appendChild(el('span', { className: 'link-mode-badge ' + modeClass, textContent: modeLabel }));

    if (l.burned) {
      item.appendChild(el('span', { className: 'link-burned', textContent: 'burned' }));
    } else if (l.expires_at && l.expires_at < Math.floor(Date.now() / 1000)) {
      item.appendChild(el('span', { className: 'link-expired', textContent: 'expired' }));
    } else {
      item.appendChild(el('span', { className: 'link-downloads', textContent: l.downloads + ' dl' }));
    }

    var copyBtn = el('button', {
      className: 'btn btn-ghost btn-sm btn-icon',
      title: 'Copy link',
      textContent: '\u23B8',
      onclick: function () { copyText(fullUrl); }
    });
    item.appendChild(copyBtn);

    var revokeBtn = el('button', {
      className: 'btn btn-danger btn-sm btn-icon',
      title: 'Revoke link',
      textContent: '\u00D7',
      onclick: function () { deleteLink(l.id, fileId); }
    });
    item.appendChild(revokeBtn);

    return item;
  }

  async function fetchLinks(fileId) {
    var container = document.getElementById('links-list-' + fileId);
    if (!container) return;

    try {
      var links = await apiJSON('GET', '/api/files/' + fileId + '/links');

      while (container.firstChild) container.removeChild(container.firstChild);

      if (!links || links.length === 0) {
        container.appendChild(el('div', {
          className: 'text-muted',
          style: 'font-size:12px;padding:4px 0;',
          textContent: 'No links yet'
        }));
        return;
      }

      for (var i = 0; i < links.length; i++) {
        container.appendChild(buildLinkItem(links[i], fileId));
      }
    } catch (err) {
      while (container.firstChild) container.removeChild(container.firstChild);
      container.appendChild(el('div', {
        className: 'text-muted',
        style: 'font-size:12px;',
        textContent: 'Failed to load links'
      }));
    }
  }
  window.fetchLinks = fetchLinks;

  async function deleteLink(linkId, fileId) {
    try {
      await apiJSON('DELETE', '/api/links/' + linkId);
      showToast('Link revoked', 'success');
      fetchLinks(fileId);
    } catch (err) {
      showToast(err.message);
    }
  }
  window.deleteLink = deleteLink;

  function toggleLinks(fileId) {
    expandedLinks[fileId] = !expandedLinks[fileId];
    renderFiles();
  }
  window.toggleLinks = toggleLinks;

  // ── Recovery ───────────────────────────────────────────────
  async function checkRecoveryBanner() {
    // Check if recovery keys exist by checking the file list for recovery_id
    // If any files exist they already have a recovery_id, so banner not needed
    try {
      var data = await apiJSON('GET', '/api/files');
      if (data && data.length > 0) {
        document.getElementById('recoveryBanner').classList.add('hidden');
      } else {
        document.getElementById('recoveryBanner').classList.remove('hidden');
      }
    } catch (err) {
      // Show banner by default if we can't check
      document.getElementById('recoveryBanner').classList.remove('hidden');
    }
  }

  async function setupRecovery(password) {
    var btn = document.getElementById('setupRecoveryBtn');
    setLoading(btn, true);

    try {
      var data = await apiJSON('POST', '/api/recovery/setup', { password: password });
      document.getElementById('recoveryHexDisplay').textContent = data.hex_key;
      document.getElementById('recoveryMnemonicDisplay').textContent = data.mnemonic;
      document.getElementById('recoveryDisplay').classList.remove('hidden');
      document.getElementById('recoveryBanner').classList.add('hidden');
      showToast('Recovery key generated. Save it now!', 'success');
    } catch (err) {
      showToast(err.message);
    } finally {
      setLoading(btn, false);
    }
  }
  window.setupRecovery = setupRecovery;

  async function recoverPassword(hexKey) {
    var btn = document.getElementById('recoverBtn');
    setLoading(btn, true);

    try {
      var data = await apiJSON('POST', '/api/recovery/recover', { hex_key: hexKey });
      document.getElementById('recoveredPasswordValue').textContent = data.password;
      document.getElementById('recoveredPassword').classList.remove('hidden');
      showToast('Password recovered', 'success');
    } catch (err) {
      showToast(err.message);
    } finally {
      setLoading(btn, false);
    }
  }
  window.recoverPassword = recoverPassword;

  // ── Event handlers ─────────────────────────────────────────
  function handleFileSelect(file) {
    if (!file) return;
    selectedFile = file;
    document.getElementById('uploadFilename').textContent = file.name + ' (' + humanSize(file.size) + ')';
    document.getElementById('uploadForm').classList.remove('hidden');
    document.getElementById('uploadZone').classList.add('hidden');
    document.getElementById('uploadPassword').value = '';
    document.getElementById('uploadPassword').focus();
  }
  window.handleFileSelect = handleFileSelect;

  function cancelUpload() {
    selectedFile = null;
    document.getElementById('uploadForm').classList.add('hidden');
    document.getElementById('uploadZone').classList.remove('hidden');
    document.getElementById('fileInput').value = '';
  }
  window.cancelUpload = cancelUpload;

  function handleUpload() {
    var password = document.getElementById('uploadPassword').value.trim();
    if (!password) {
      showToast('Password is required');
      document.getElementById('uploadPassword').focus();
      return;
    }
    if (!selectedFile) {
      showToast('No file selected');
      return;
    }
    var cipher = document.querySelector('#cipherSelector input[name="cipher"]:checked').value;
    uploadFile(selectedFile, password, cipher);
  }
  window.handleUpload = handleUpload;

  function handleSetupRecovery() {
    var password = document.getElementById('recoveryPassword').value.trim();
    if (!password) {
      showToast('Password is required');
      document.getElementById('recoveryPassword').focus();
      return;
    }
    setupRecovery(password);
  }
  window.handleSetupRecovery = handleSetupRecovery;

  function dismissRecoveryDisplay() {
    document.getElementById('recoveryDisplay').classList.add('hidden');
  }
  window.dismissRecoveryDisplay = dismissRecoveryDisplay;

  // ── Link Modal ─────────────────────────────────────────────
  function openLinkModal(fileId) {
    linkModalFileId = fileId;
    document.getElementById('linkPassword').value = '';
    document.getElementById('linkExpiry').value = '';
    document.getElementById('linkResult').classList.add('hidden');
    document.getElementById('linkModalFooter').classList.remove('hidden');
    document.getElementById('expiryGroup').classList.add('hidden');

    // Reset mode selector
    var cards = document.querySelectorAll('#modeSelector .mode-card');
    cards.forEach(function (c) { c.classList.remove('selected'); });
    cards[0].classList.add('selected');
    cards[0].querySelector('input').checked = true;

    document.getElementById('linkModal').classList.add('active');
    setTimeout(function () {
      document.getElementById('linkPassword').focus();
    }, 100);
  }
  window.openLinkModal = openLinkModal;

  function closeLinkModal() {
    document.getElementById('linkModal').classList.remove('active');
    linkModalFileId = null;
  }
  window.closeLinkModal = closeLinkModal;

  function handleCreateLink() {
    var password = document.getElementById('linkPassword').value.trim();
    if (!password) {
      showToast('Link password is required');
      document.getElementById('linkPassword').focus();
      return;
    }
    var mode = document.querySelector('#modeSelector input[name="linkMode"]:checked').value;
    var expiresIn = document.getElementById('linkExpiry').value;
    if (mode === 'timed' && (!expiresIn || parseInt(expiresIn) < 60)) {
      showToast('Expiry must be at least 60 seconds');
      document.getElementById('linkExpiry').focus();
      return;
    }
    createLink(linkModalFileId, password, mode, expiresIn);
  }
  window.handleCreateLink = handleCreateLink;

  function copyLinkResult() {
    var url = document.getElementById('linkResultUrl').textContent;
    copyText(url);
  }
  window.copyLinkResult = copyLinkResult;

  // ── Recovery Modal ─────────────────────────────────────────
  function openRecoveryModal() {
    document.getElementById('recoverHexInput').value = '';
    document.getElementById('recoveredPassword').classList.add('hidden');
    document.getElementById('recoveryModal').classList.add('active');
    setTimeout(function () {
      document.getElementById('recoverHexInput').focus();
    }, 100);
  }
  window.openRecoveryModal = openRecoveryModal;

  function closeRecoveryModal() {
    document.getElementById('recoveryModal').classList.remove('active');
  }
  window.closeRecoveryModal = closeRecoveryModal;

  function handleRecover() {
    var hexKey = document.getElementById('recoverHexInput').value.trim();
    if (!hexKey) {
      showToast('Recovery key is required');
      document.getElementById('recoverHexInput').focus();
      return;
    }
    recoverPassword(hexKey);
  }
  window.handleRecover = handleRecover;

  // ── Drag & Drop ────────────────────────────────────────────
  function initDragDrop() {
    var zone = document.getElementById('uploadZone');
    var dragCounter = 0;

    zone.addEventListener('dragenter', function (e) {
      e.preventDefault();
      dragCounter++;
      zone.classList.add('dragover');
    });

    zone.addEventListener('dragleave', function (e) {
      e.preventDefault();
      dragCounter--;
      if (dragCounter <= 0) {
        dragCounter = 0;
        zone.classList.remove('dragover');
      }
    });

    zone.addEventListener('dragover', function (e) {
      e.preventDefault();
    });

    zone.addEventListener('drop', function (e) {
      e.preventDefault();
      dragCounter = 0;
      zone.classList.remove('dragover');
      var dt = e.dataTransfer;
      if (dt && dt.files && dt.files.length > 0) {
        handleFileSelect(dt.files[0]);
      }
    });
  }

  // ── Cipher Selector ────────────────────────────────────────
  function initCipherSelector() {
    var options = document.querySelectorAll('#cipherSelector .cipher-option');
    options.forEach(function (opt) {
      opt.addEventListener('click', function () {
        options.forEach(function (o) { o.classList.remove('selected'); });
        opt.classList.add('selected');
        opt.querySelector('input').checked = true;
      });
    });
  }

  // ── Mode Selector ──────────────────────────────────────────
  function initModeSelector() {
    var cards = document.querySelectorAll('#modeSelector .mode-card');
    cards.forEach(function (card) {
      card.addEventListener('click', function () {
        cards.forEach(function (c) { c.classList.remove('selected'); });
        card.classList.add('selected');
        card.querySelector('input').checked = true;

        var mode = card.dataset.mode;
        var expiryGroup = document.getElementById('expiryGroup');
        if (mode === 'timed') {
          expiryGroup.classList.remove('hidden');
        } else {
          expiryGroup.classList.add('hidden');
        }
      });
    });
  }

  // ── Toast Notifications ────────────────────────────────────
  function showToast(message, type) {
    var container = document.getElementById('toastContainer');
    var toast = document.createElement('div');
    toast.className = 'toast' + (type === 'success' ? ' success' : '');

    var msg = document.createElement('span');
    msg.className = 'toast-msg';
    msg.textContent = message;
    toast.appendChild(msg);

    var closeBtn = document.createElement('button');
    closeBtn.className = 'toast-close';
    closeBtn.textContent = '\u00D7';
    closeBtn.addEventListener('click', function () { toast.remove(); });
    toast.appendChild(closeBtn);

    container.appendChild(toast);

    setTimeout(function () {
      toast.style.animation = 'slideOut 300ms ease forwards';
      setTimeout(function () {
        if (toast.parentElement) toast.remove();
      }, 300);
    }, 4000);
  }
  window.showToast = showToast;

  // ── Clipboard ──────────────────────────────────────────────
  function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(function () {
      showToast('Copied to clipboard', 'success');
      if (btn) {
        var original = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(function () { btn.textContent = original; }, 1500);
      }
    }).catch(function () {
      // Fallback
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast('Copied to clipboard', 'success');
    });
  }
  window.copyText = copyText;

  // Keyboard shortcut: Escape closes modals
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      closeLinkModal();
      closeRecoveryModal();
    }
  });

})();
