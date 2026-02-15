// Nocturne Public Download — download.js
// No dependencies, no frameworks.

(function () {
  'use strict';

  // Extract slug from URL: /s/{slug}
  var slug = extractSlug();
  var verifiedLinkPassword = '';

  function extractSlug() {
    var path = window.location.pathname;
    var parts = path.split('/s/');
    if (parts.length > 1) {
      // Remove trailing slash if any
      return parts[1].replace(/\/$/, '');
    }
    return '';
  }

  // ── Init ───────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    if (!slug) {
      showGone('Invalid link', 'This URL does not contain a valid file link.');
      return;
    }

    // Allow Enter key to submit
    document.getElementById('linkPassword').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') handleVerify();
    });
    document.getElementById('filePassword').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') handleDownload();
    });

    // Focus the first input
    document.getElementById('linkPassword').focus();
  });

  // ── Verify (Step 1) ────────────────────────────────────────
  async function handleVerify() {
    var password = document.getElementById('linkPassword').value.trim();
    if (!password) {
      showError('step1Error', 'Please enter the link password');
      shakeInput('linkPassword');
      return;
    }

    var btn = document.getElementById('verifyBtn');
    setLoading(btn, true);
    hideError('step1Error');

    try {
      var res = await fetch('/s/' + slug + '/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ link_password: password })
      });

      var data = await res.json();

      if (!res.ok) {
        if (res.status === 410) {
          // Link burned or expired
          var msg = data.error || 'Link unavailable';
          if (msg.indexOf('expired') !== -1) {
            showGone('Link expired', 'This link has passed its expiration time.');
          } else if (msg.indexOf('used') !== -1) {
            showGone('Link burned', 'This one-time link has already been used.');
          } else {
            showGone('Link unavailable', msg);
          }
          return;
        }
        if (res.status === 401) {
          showError('step1Error', 'Wrong link password');
          shakeInput('linkPassword');
          return;
        }
        throw new Error(data.error || 'Verification failed');
      }

      // Success — show file info and step 2
      verifiedLinkPassword = password;
      showFileInfo(data);

    } catch (err) {
      showError('step1Error', err.message);
    } finally {
      setLoading(btn, false);
    }
  }
  window.handleVerify = handleVerify;

  function showFileInfo(data) {
    document.getElementById('fileName').textContent = data.name;
    document.getElementById('fileSize').textContent = humanSize(data.size);

    var cipherEl = document.getElementById('fileCipher');
    if (data.cipher === 'noctis') {
      cipherEl.textContent = 'NOCTIS';
      cipherEl.className = 'file-info-cipher noctis';
    } else {
      cipherEl.textContent = 'AES';
      cipherEl.className = 'file-info-cipher aes';
    }

    document.getElementById('step1').classList.add('hidden');
    document.getElementById('step2').classList.add('active');
    document.getElementById('filePassword').focus();
  }

  // ── Download (Step 2) ──────────────────────────────────────
  async function handleDownload() {
    var filePassword = document.getElementById('filePassword').value.trim();
    if (!filePassword) {
      showError('step2Error', 'Please enter the file password');
      shakeInput('filePassword');
      return;
    }

    var btn = document.getElementById('downloadBtn');
    setLoading(btn, true);
    hideError('step2Error');

    try {
      var res = await fetch('/s/' + slug + '/download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          link_password: verifiedLinkPassword,
          file_password: filePassword
        })
      });

      if (!res.ok) {
        var errData;
        try {
          errData = await res.json();
        } catch (_) {
          errData = { error: 'Download failed' };
        }

        if (res.status === 401) {
          showError('step2Error', 'Wrong file password');
          shakeInput('filePassword');
          return;
        }
        if (res.status === 410) {
          showGone('Link unavailable', errData.error || 'Link is no longer accessible.');
          return;
        }
        throw new Error(errData.error || 'Download failed');
      }

      // Success — download the file
      var blob = await res.blob();
      var filename = extractFilename(res) || 'download';

      // Brief green flash
      document.getElementById('mainCard').classList.add('success-flash');

      // Trigger download
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      // Update button to show success
      btn.textContent = 'Downloaded';
      btn.disabled = true;
      btn.style.background = '#166534';

    } catch (err) {
      showError('step2Error', err.message);
    } finally {
      setLoading(btn, false);
    }
  }
  window.handleDownload = handleDownload;

  function extractFilename(response) {
    var cd = response.headers.get('Content-Disposition');
    if (cd) {
      var match = cd.match(/filename="?([^";\n]+)"?/);
      if (match) return match[1];
    }
    return null;
  }

  // ── Gone state ─────────────────────────────────────────────
  function showGone(title, msg) {
    document.getElementById('step1').classList.add('hidden');
    document.getElementById('step2').classList.remove('active');
    document.getElementById('goneTitle').textContent = title;
    document.getElementById('goneMsg').textContent = msg;
    document.getElementById('goneState').classList.remove('hidden');
  }

  // ── Error handling ─────────────────────────────────────────
  function showError(elId, msg) {
    var el = document.getElementById(elId);
    el.textContent = msg;
    el.classList.remove('hidden');
  }

  function hideError(elId) {
    var el = document.getElementById(elId);
    el.textContent = '';
    el.classList.add('hidden');
  }

  function shakeInput(inputId) {
    var input = document.getElementById(inputId);
    input.classList.add('shake');
    setTimeout(function () {
      input.classList.remove('shake');
    }, 500);
    input.focus();
    input.select();
  }

  // ── Loading state ──────────────────────────────────────────
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

  // ── Utility ────────────────────────────────────────────────
  function humanSize(bytes) {
    if (bytes === 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.floor(Math.log(bytes) / Math.log(1024));
    if (i >= units.length) i = units.length - 1;
    var size = bytes / Math.pow(1024, i);
    return size.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
  }

})();
