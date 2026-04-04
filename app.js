/* ═══════════════════════════════════════════
   HADES 2.1 — app.js
   Cifrado: AES-GCM-256 + PBKDF2-SHA256
   Sin contraseñas en memoria plana.
   ═══════════════════════════════════════════ */
'use strict';
// ── CRYPTO ENGINE ────────────────────────────────────
const Crypto = {
  SALT_KEY: 'hades_salt',
  VAULT_KEY: 'hades_vault',
  META_KEY: 'hades_meta',
  RECOVERY_KEY: 'hades_recovery',
  USER_KEY: 'hades_user',
  BIOMETRIC_KEY: 'hades_biometric_id',
  getSalt() {
    let salt = localStorage.getItem(this.SALT_KEY);
    if (!salt) {
      const raw = crypto.getRandomValues(new Uint8Array(16));
      salt = btoa(String.fromCharCode(...raw));
      localStorage.setItem(this.SALT_KEY, salt);
    }
    return Uint8Array.from(atob(salt), c => c.charCodeAt(0));
  },
  async deriveKey(password, salt) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },
  async encrypt(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const buf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(data)));
    const combined = new Uint8Array(12 + buf.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(buf), 12);
    return btoa(String.fromCharCode(...combined));
  },
  async decrypt(key, b64) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const iv = raw.slice(0, 12);
    const data = raw.slice(12);
    const buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return JSON.parse(new TextDecoder().decode(buf));
  },
  async saveVault(key, entries) {
    const enc = await this.encrypt(key, entries);
    localStorage.setItem(this.VAULT_KEY, enc);
  },
  async loadVault(key) {
    const enc = localStorage.getItem(this.VAULT_KEY);
    if (!enc) return [];
    return await this.decrypt(key, enc);
  },
  hasVault() {
    return !!localStorage.getItem(this.VAULT_KEY);
  },
  saveUser(name, email) {
    localStorage.setItem(this.USER_KEY, JSON.stringify({ name, email }));
  },
  getUser() {
    try { return JSON.parse(localStorage.getItem(this.USER_KEY)) || null; } catch { return null; }
  },
  saveRecovery(phrase) {
    // Guardamos el hash de la frase para verificación
    const hashed = btoa(phrase.join('|'));
    localStorage.setItem(this.RECOVERY_KEY, hashed);
  },
  verifyRecovery(words) {
    const stored = localStorage.getItem(this.RECOVERY_KEY);
    if (!stored) return false;
    return btoa(words.join('|')) === stored;
  },
  deleteVault() {
    localStorage.removeItem(this.VAULT_KEY);
    localStorage.removeItem(this.SALT_KEY);
    localStorage.removeItem(this.META_KEY);
  },
  async initVault(password) {
    const salt = this.getSalt();
    const key = await this.deriveKey(password, salt);
    await this.saveVault(key, []);
    const verifier = await this.encrypt(key, { ok: true });
    localStorage.setItem(this.META_KEY, verifier);
    return key;
  },
  async verifyPassword(password) {
    try {
      const salt = this.getSalt();
      const key = await this.deriveKey(password, salt);
      const meta = localStorage.getItem(this.META_KEY);
      if (!meta) return null;
      const result = await this.decrypt(key, meta);
      if (result && result.ok) return key;
      return null;
    } catch {
      return null;
    }
  }
};

// ── BIOMETRIC ENGINE ──────────────────────────────────
const Biometric = {
  // ── Helpers ──
  isSupported() {
    return window.PublicKeyCredential !== undefined &&
           typeof navigator.credentials?.create === 'function';
  },
  getMode() { return localStorage.getItem('hades_biometric_mode') || 'off'; },
  setMode(mode) { localStorage.setItem('hades_biometric_mode', mode); },
  getCredentialId() { return localStorage.getItem(Crypto.BIOMETRIC_KEY); },
  saveCredentialId(id) { localStorage.setItem(Crypto.BIOMETRIC_KEY, id); },
  clearAll() {
    localStorage.removeItem(Crypto.BIOMETRIC_KEY);
    localStorage.removeItem('hades_biometric_pw');
    localStorage.removeItem('hades_biometric_mode');
  },
  bufToB64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); },
  b64ToBuf(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); },

  // ── Cifra la contraseña maestra con AES usando el credentialId como semilla ──
  async encryptPassword(password, credentialId) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(credentialId), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: enc.encode('hades-bio-salt'), iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const buf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(password));
    const combined = new Uint8Array(12 + buf.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(buf), 12);
    return btoa(String.fromCharCode(...combined));
  },

  // ── Descifra la contraseña maestra ──
  async decryptPassword(encrypted, credentialId) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(credentialId), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: enc.encode('hades-bio-salt'), iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const raw = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const iv = raw.slice(0, 12);
    const data = raw.slice(12);
    const buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(buf);
  },

  // ── Guardar contraseña maestra cifrada para acceso biométrico ──
  async savePassword(password) {
    const credId = this.getCredentialId();
    if (!credId) throw new Error('No hay credencial registrada');
    const encrypted = await this.encryptPassword(password, credId);
    localStorage.setItem('hades_biometric_pw', encrypted);
  },

  // ── Registrar huella y guardar contraseña cifrada ──
  async register(password) {
    if (!this.isSupported()) throw new Error('WebAuthn no soportado');
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: 'Hades', id: location.hostname },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: 'hades-user',
          displayName: 'Hades User'
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 }
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'preferred'
        },
        timeout: 60000
      }
    });
    const credId = this.bufToB64(credential.rawId);
    this.saveCredentialId(credId);
    // Cifrar y guardar la contraseña maestra
    const encrypted = await this.encryptPassword(password, credId);
    localStorage.setItem('hades_biometric_pw', encrypted);
    return true;
  },

  // ── Verificar huella y obtener la contraseña maestra descifrada ──
  async verifyAndGetPassword() {
    if (!this.isSupported()) throw new Error('WebAuthn no soportado');
    const credId = this.getCredentialId();
    if (!credId) throw new Error('No hay credencial registrada');
    const encrypted = localStorage.getItem('hades_biometric_pw');
    if (!encrypted) throw new Error('No hay contraseña guardada');
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const options = {
      publicKey: {
        challenge,
        userVerification: 'required',
        timeout: 60000,
        allowCredentials: [{
          type: 'public-key',
          id: this.b64ToBuf(credId),
          transports: ['internal']
        }]
      }
    };
    const assertion = await navigator.credentials.get(options);
    if (!assertion) throw new Error('Verificación fallida');
    // Descifrar la contraseña con el credentialId
    const password = await this.decryptPassword(encrypted, credId);
    return password;
  }
};
// ── RECOVERY PHRASE ENGINE ───────────────────────────
const RECOVERY_WORDS = [
  'árbol','banco','brazo','campo','carta','cielo','clase','clave','corte','cueva',
  'datos','deber','delta','denso','dicha','dulce','earth','enero','fábri','fácil',
  'falda','fecha','finca','firma','flota','flujo','forma','fruta','fuego','fuerza',
  'ganas','globo','golpe','grano','grupo','gusto','habla','había','hielo','hierba',
  'hijos','honor','hotel','hueso','huevo','ideas','igual','imagen','inicio','joven',
  'juego','junto','largo','leche','letra','libro','línea','llave','lluvia','local',
  'logro','lucha','lugar','madre','manga','manos','marca','marea','media','mejor',
  'menos','mente','mesón','metas','miedo','monte','mundo','músic','nieve','nivel',
  'noble','noche','norma','norte','novia','nueva','nunca','obras','orden','orgen',
  'otros','padre','papel','parce','parqu','pasos','patri','peace','perro','pesos',
  'piedra','pista','plano','plaza','pluma','poder','pompa','preci','prima','publi',
  'punto','queda','quien','razón','rebos','reino','reloj','resto','river','robot',
  'rocas','ruido','rumbo','salud','salvo','sangr','sauce','selva','señal','seria',
  'siete','siglo','signo','silba','silla','sitio','sobre','solar','solid','sombr',
  'suelo','sueño','surco','tabla','tarea','tarde','techo','tejid','temas','tener',
  'texto','tiempo','timón','tinta','título','todas','tomar','topes','torre','total',
  'tramo','trato','trigo','tropa','tunel','turno','única','unión','unity','vacío',
  'valor','vapor','verde','vibra','viaje','video','villa','viola','vista','voces',
  'vuelo','world','yerba','zones'
];

const Recovery = {
  generate() {
    const words = [];
    const arr = new Uint32Array(12);
    crypto.getRandomValues(arr);
    arr.forEach(n => words.push(RECOVERY_WORDS[n % RECOVERY_WORDS.length]));
    return words;
  },
  renderPhrase(words, containerId) {
    const container = $(containerId);
    if (!container) return;
    container.innerHTML = words.map((w, i) => `
      <div class="recovery-word">
        <span class="recovery-word-num">${i+1}.</span>
        <span class="recovery-word-text">${w}</span>
      </div>`).join('');
  },
  renderInputs(containerId) {
    const container = $(containerId);
    if (!container) return;
    container.innerHTML = Array.from({length: 12}, (_, i) =>
      `<input type="text" placeholder="Palabra ${i+1}" data-idx="${i}" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" />`
    ).join('');
  },
  getInputWords(containerId) {
    const inputs = $(containerId)?.querySelectorAll('input');
    return Array.from(inputs || []).map(i => i.value.trim().toLowerCase());
  }
};

// ── APP STATE ─────────────────────────────────────────
const State = {
  cryptoKey: null,
  entries: [],
  editingId: null,
  currentView: 'vault',
  currentCat: 'all',
  autoLockTimer: null,
  autoLockSeconds: 300,
  theme: 'dark',
};
// ── DOM HELPERS ───────────────────────────────────────
const $ = id => document.getElementById(id);
const on = (el, ev, fn) => el && el.addEventListener(ev, fn);
function showToast(msg, duration = 2200) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  void t.offsetWidth;
  t.classList.add('show');
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => {
    t.classList.remove('show');
    setTimeout(() => t.classList.add('hidden'), 300);
  }, duration);
}
function showConfirm(title, msg) {
  return new Promise(resolve => {
    $('confirm-title').textContent = title;
    $('confirm-msg').textContent = msg;
    $('modal-confirm').classList.remove('hidden');
    const ok = $('confirm-ok');
    const cancel = $('confirm-cancel');
    const cleanup = (val) => {
      $('modal-confirm').classList.add('hidden');
      ok.replaceWith(ok.cloneNode(true));
      cancel.replaceWith(cancel.cloneNode(true));
      resolve(val);
    };
    on($('confirm-ok'), 'click', () => cleanup(true));
    on($('confirm-cancel'), 'click', () => cleanup(false));
  });
}
// ── THEME ─────────────────────────────────────────────
function applyTheme(theme) {
  State.theme = theme;
  document.body.classList.toggle('theme-dark', theme === 'dark');
  document.body.classList.toggle('theme-light', theme === 'light');
  localStorage.setItem('hades_theme', theme);
  $('theme-light-btn')?.classList.toggle('active', theme === 'light');
  $('theme-dark-btn')?.classList.toggle('active', theme === 'dark');
}
function toggleTheme() {
  applyTheme(State.theme === 'dark' ? 'light' : 'dark');
}
// ── AUTO LOCK ─────────────────────────────────────────
function resetAutoLock() {
  if (!State.autoLockSeconds) return;
  clearTimeout(State.autoLockTimer);
  State.autoLockTimer = setTimeout(lockApp, State.autoLockSeconds * 1000);
}
function lockApp() {
  State.cryptoKey = null;
  State.entries = [];
  clearTimeout(State.autoLockTimer);
  $('page-app').classList.add('hidden');
  $('page-home').classList.add('hidden');
  $('page-unlock').classList.remove('hidden');
  document.body.dataset.page = 'unlock';
  $('mp-enter')?.focus();
}
// ── UNLOCK SCREEN ─────────────────────────────────────
async function initUnlockScreen() {
  const hasVault = Crypto.hasVault();
  $('unlock-first-time').classList.toggle('hidden', hasVault);
  $('unlock-existing').classList.toggle('hidden', !hasVault);
  $('unlock-recovery').classList.add('hidden');
  $('unlock-new-password').classList.add('hidden');

  // Mostrar nombre del usuario en unlock y home
  const user = Crypto.getUser();
  if (user) {
    const name = user.name || 'Usuario';
    if ($('unlock-username')) $('unlock-username').textContent = name;
    if ($('home-username')) $('home-username').textContent = name;
  }

  if (!hasVault) {
    // ── PASO 1: Datos personales ──
    on($('mp-new'), 'input', () => {
      const pw = $('mp-new').value;
      const s = passwordStrength(pw);
      $('strength-wrap').classList.toggle('hidden', pw.length === 0);
      updateStrengthUI('strength-fill', 'strength-label', s);
    });

    on($('btn-setup-next'), 'click', () => {
      const name = $('reg-name').value.trim();
      const pw = $('mp-new').value.trim();
      const confirm = $('mp-confirm').value;
      const err = $('setup-error-1');
      if (!name) { err.textContent = 'Ingresa tu nombre'; err.classList.remove('hidden'); return; }
      if (pw.length < 8) { err.textContent = 'Mínimo 8 caracteres'; err.classList.remove('hidden'); return; }
      if (pw !== confirm) { err.textContent = 'Las contraseñas no coinciden'; err.classList.remove('hidden'); return; }
      err.classList.add('hidden');
      $('setup-step-1').classList.add('hidden');
      $('setup-step-2').classList.remove('hidden');
    });

    on($('btn-setup-back'), 'click', () => {
      $('setup-step-2').classList.add('hidden');
      $('setup-step-1').classList.remove('hidden');
    });
    on($('btn-setup'), 'click', async () => {
      const name = $('reg-name').value.trim();
      const pw = $('mp-new').value.trim();
      const mode = document.querySelector('input[name="access-mode"]:checked')?.value || 'password';
      const err = $('setup-error-2');
      try {
        $('btn-setup').disabled = true;
        $('btn-setup').textContent = 'Creando…';
        // Crear bóveda
        State.cryptoKey = await Crypto.initVault(pw);
        State.entries = [];
        // Guardar usuario
        Crypto.saveUser(name, '');
        // Configurar modo biométrico
        if (mode === 'biometric' || mode === 'both') {
          Biometric.setMode(mode);
          if (Biometric.isSupported()) {
            try { await Biometric.register(pw); } catch(e) { /* continúa sin huella */ }
          }
        }
        // Generar frase de recuperación
        const phrase = Recovery.generate();
        Crypto.saveRecovery(phrase);
        // Mostrar frase
        $('setup-step-2').classList.add('hidden');
        $('setup-step-3').classList.remove('hidden');
        Recovery.renderPhrase(phrase, 'recovery-phrase-display');
      } catch (e) {
        err.textContent = 'Error al crear bóveda';
        err.classList.remove('hidden');
        $('btn-setup').disabled = false;
        $('btn-setup').textContent = 'Finalizar';
      }
    });

    on($('btn-setup-finish'), 'click', () => {
      enterApp();
    });
  } else {
    // Configurar pantalla según modo biométrico
    const bioMode = Biometric.getMode();
    const hasCredential = !!Biometric.getCredentialId();
    if ((bioMode === 'biometric' || bioMode === 'both') && hasCredential && Biometric.isSupported()) {
      $('btn-biometric').classList.remove('hidden');
      $('biometric-hint').classList.remove('hidden');
      if (bioMode === 'biometric') {
        // Solo huella: ocultar formulario de contraseña
        $('mp-enter').closest('.field-group').classList.add('hidden');
        $('btn-unlock').classList.add('hidden');
        $('biometric-hint').classList.add('hidden');
      }
      // Auto-trigger huella si modo es solo biométrico
      if (bioMode === 'biometric') {
        setTimeout(() => $('btn-biometric').click(), 400);
      }
    }
    on($('btn-biometric'), 'click', async () => {
      const btn = $('btn-biometric');
      btn.classList.add('scanning');
      btn.disabled = true;
      try {
        // Obtiene la contraseña maestra directamente desde la huella
        const password = await Biometric.verifyAndGetPassword();
        const bioMode = Biometric.getMode();
        if (bioMode === 'both') {
          // Modo ambos: huella OK, ahora pedir contraseña maestra
          btn.classList.remove('scanning');
          btn.disabled = false;
          showToast('Huella verificada ✓ — ingresa tu contraseña');
          $('mp-enter').closest('.field-group').classList.remove('hidden');
          $('btn-unlock').classList.remove('hidden');
          $('btn-biometric').classList.add('hidden');
          $('biometric-hint').classList.add('hidden');
          $('mp-enter').focus();
          State._bioVerified = true;
        } else {
          // Modo solo huella: usar contraseña descifrada directamente
          const key = await Crypto.verifyPassword(password);
          if (key) {
            State.cryptoKey = key;
            State.entries = await Crypto.loadVault(key);
            enterApp();
          } else {
            throw new Error('Clave inválida');
          }
        }
      } catch (e) {
        btn.classList.remove('scanning');
        btn.disabled = false;
        if (e.name === 'NotAllowedError') {
          showToast('Verificación cancelada');
        } else {
          showToast('Error biométrico — usa tu contraseña');
          $('mp-enter').closest('.field-group').classList.remove('hidden');
          $('btn-unlock').classList.remove('hidden');
        }
      }
    });
    // Contador de intentos fallidos
    let failCount = parseInt(localStorage.getItem('hades_fail_count') || '0');
    function updateAttemptsUI() {
      if (failCount >= 1) {
        $('unlock-attempts-wrap').classList.remove('hidden');
        const remaining = 3 - failCount;
        if (remaining > 0) {
          $('attempts-warning').textContent = `Intento fallido. Te quedan ${remaining} intento${remaining === 1 ? '' : 's'}.`;
          $('btn-forgot').classList.add('hidden');
        } else {
          $('attempts-warning').textContent = '3 intentos fallidos.';
          $('btn-forgot').classList.remove('hidden');
        }
      } else {
        $('unlock-attempts-wrap').classList.add('hidden');
      }
    }
    updateAttemptsUI();

    on($('btn-unlock'), 'click', async () => {
      const pw = $('mp-enter').value;
      if (!pw) return;
      $('btn-unlock').disabled = true;
      $('btn-unlock').textContent = 'Verificando…';
      $('unlock-error').classList.add('hidden');
      const key = await Crypto.verifyPassword(pw);
      if (!key) {
        failCount = Math.min(failCount + 1, 3);
        localStorage.setItem('hades_fail_count', failCount);
        $('unlock-error').classList.remove('hidden');
        $('btn-unlock').disabled = false;
        $('btn-unlock').textContent = 'Entrar';
        $('mp-enter').focus();
        State._bioVerified = false;
        updateAttemptsUI();
        return;
      }
      localStorage.setItem('hades_fail_count', '0');
      State._bioVerified = false;
      State.cryptoKey = key;
      State.entries = await Crypto.loadVault(key);
      enterApp();
    });
    on($('mp-enter'), 'keydown', e => { if (e.key === 'Enter') $('btn-unlock').click(); });

    // Recuperación por frase de 12 palabras
    on($('btn-forgot'), 'click', () => {
      $('unlock-existing').classList.add('hidden');
      $('unlock-recovery').classList.remove('hidden');
      Recovery.renderInputs('recovery-input-grid');
    });
    on($('btn-recovery-back'), 'click', () => {
      $('unlock-recovery').classList.add('hidden');
      $('unlock-existing').classList.remove('hidden');
    });
    on($('btn-recovery-verify'), 'click', () => {
      const words = Recovery.getInputWords('recovery-input-grid');
      if (words.some(w => !w)) { showToast('Completa todas las palabras'); return; }
      if (!Crypto.verifyRecovery(words)) {
        $('recovery-error').classList.remove('hidden');
        return;
      }
      $('recovery-error').classList.add('hidden');
      $('unlock-recovery').classList.add('hidden');
      $('unlock-new-password').classList.remove('hidden');
    });
    on($('btn-recovery-save'), 'click', async () => {
      const newPw = $('recovery-pw-new').value.trim();
      const confirm = $('recovery-pw-confirm').value;
      const err = $('recovery-pw-error');
      if (newPw.length < 8) { err.textContent = 'Mínimo 8 caracteres'; err.classList.remove('hidden'); return; }
      if (newPw !== confirm) { err.textContent = 'Las contraseñas no coinciden'; err.classList.remove('hidden'); return; }
      err.classList.add('hidden');
      const ok = await showConfirm(
        'Restablecer contraseña',
        'La bóveda se reiniciará vacía al cambiar la contraseña. ¿Continuar?'
      );
      if (!ok) return;
      try {
        Crypto.deleteVault();
        State.cryptoKey = await Crypto.initVault(newPw);
        State.entries = [];
        localStorage.setItem('hades_fail_count', '0');
        const phrase = Recovery.generate();
        Crypto.saveRecovery(phrase);
        showToast('Contraseña restablecida');
        enterApp();
      } catch(e) {
        err.textContent = 'Error al guardar'; err.classList.remove('hidden');
      }
    });
  }
}
function enterApp() {
  $('page-unlock').classList.add('hidden');
  $('page-home').classList.remove('hidden');
  $('page-app').classList.add('hidden');
  document.body.dataset.page = 'home';
  loadAutoLockSetting();
  loadBiometricSetting();
  resetAutoLock();
  history.replaceState({ page: 'home' }, '', '');
  document.addEventListener('mousemove', resetAutoLock, { passive: true });
  document.addEventListener('keydown', resetAutoLock, { passive: true });
  document.addEventListener('touchstart', resetAutoLock, { passive: true });
}

function goToApp(view) {
  $('page-home').classList.add('hidden');
  $('page-app').classList.remove('hidden');
  document.body.dataset.page = 'app';
  renderVault();
  switchView(view);
  history.pushState({ page: 'app', view }, '', '');
}

function goHome() {
  $('page-app').classList.add('hidden');
  $('page-home').classList.remove('hidden');
  document.body.dataset.page = 'home';
  history.pushState({ page: 'home' }, '', '');
}
// ── VIEWS ─────────────────────────────────────────────
const ALL_VIEWS = ['vault', 'generator', 'settings', 'help', 'about'];
const VIEW_TITLES = {
  vault: 'Bóveda',
  generator: 'Generador',
  settings: 'Ajustes',
  help: 'Ayuda',
  about: 'Acerca de'
};

function switchView(view, pushHistory = true) {
  State.currentView = view;
  ALL_VIEWS.forEach(v => {
    $(`view-${v}`)?.classList.toggle('hidden', v !== view);
    document.querySelector(`.nav-item[data-view="${v}"]`)?.classList.toggle('active', v === view);
  });
  $('view-title').textContent = VIEW_TITLES[view] || '';
  // Agregar al historial del navegador para que el botón de retroceso funcione
  if (pushHistory) {
    history.pushState({ view }, '', '');
  }
  if (window.innerWidth <= 768) {
    $('sidebar').classList.remove('open');
    document.querySelector('.sidebar-overlay')?.classList.remove('show');
  }
}

// Escuchar el botón de retroceso del navegador/smartphone
window.addEventListener('popstate', (e) => {
  const page = e.state?.page || 'home';
  const view = e.state?.view || 'vault';
  // Si hay modales abiertos, cerrarlos primero
  const modals = ['modal-entry', 'modal-view', 'modal-confirm', 'modal-change-master'];
  const openModal = modals.find(m => !$(m)?.classList.contains('hidden'));
  if (openModal) {
    $(openModal).classList.add('hidden');
    history.pushState({ page: 'app', view: State.currentView }, '', '');
    return;
  }
  // Si estamos en la app y el historial dice home, volver al home
  if (page === 'home' && document.body.dataset.page === 'app') {
    goHome();
    return;
  }
  // Si estamos en home y presionan retroceso, dejar que minimice
  if (page === 'home' && document.body.dataset.page === 'home') return;
  // Navegar entre vistas dentro de la app
  switchView(view, false);
});

// ── VAULT RENDER ──────────────────────────────────────
function renderVault() {
  const search = $('search-input')?.value.toLowerCase() || '';
  const cat = State.currentCat;
  let filtered = State.entries.filter(e => {
    const matchCat = cat === 'all' || e.type === cat;
    const term = search;
    const name = (e.name || e.cardName || e.noteTitle || e.firstName || '').toLowerCase();
    const user = (e.username || '').toLowerCase();
    const url = (e.url || '').toLowerCase();
    const matchSearch = !term || name.includes(term) || user.includes(term) || url.includes(term);
    return matchCat && matchSearch;
  });
  const grid = $('entries-grid');
  const empty = $('empty-state');
  if (filtered.length === 0) {
    grid.innerHTML = '';
    empty.classList.remove('hidden');
  } else {
    empty.classList.add('hidden');
    grid.innerHTML = filtered.map(e => renderEntryCard(e)).join('');
    grid.querySelectorAll('.entry-card').forEach(card => {
      on(card, 'click', () => openViewModal(card.dataset.id));
    });
  }
}
function entryIcon(e) {
  const icons = { login: (e.name || '?')[0].toUpperCase(), card: '💳', note: '📝', identity: '👤' };
  return icons[e.type] || '?';
}
function tagLabel(type) {
  const map = { login: ['login-tag', 'Login'], card: ['card-tag', 'Tarjeta'], note: ['note-tag', 'Nota'], identity: ['identity-tag', 'Identidad'] };
  const [cls, label] = map[type] || ['login-tag', type];
  return `<span class="entry-tag ${cls}">${label}</span>`;
}
function renderEntryCard(e) {
  const name = e.name || e.cardName || e.noteTitle || (e.firstName ? `${e.firstName} ${e.lastName}` : 'Sin nombre');
  const sub = e.username || (e.type === 'card' ? `•••• ${(e.cardNumber || '').slice(-4) || '••••'}` : e.noteTitle ? 'Nota segura' : e.email || '');
  return `
    <div class="entry-card" data-id="${e.id}">
      <div class="entry-card-header">
        <div class="entry-favicon">${entryIcon(e)}</div>
        <div class="entry-card-info">
          <div class="entry-card-name">${escHtml(name)}</div>
          <div class="entry-card-user">${escHtml(sub)}</div>
        </div>
        ${tagLabel(e.type)}
      </div>
      ${e.url ? `<div class="entry-card-url">${escHtml(e.url)}</div>` : ''}
    </div>`;
}
function escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
// ── ADD / EDIT ENTRY ──────────────────────────────────
function openAddModal(prefill = null) {
  State.editingId = prefill ? prefill.id : null;
  const isEdit = !!prefill;
  $('modal-entry-title').textContent = isEdit ? 'Editar entrada' : 'Nueva entrada';
  clearEntryForm();
  $('modal-entry').classList.remove('hidden');
  history.pushState({ view: State.currentView, modal: 'entry' }, '', '');
  if (isEdit) {
    $('entry-type').value = prefill.type || 'login';
    switchEntryType(prefill.type || 'login');
    fillEntryForm(prefill);
  } else {
    switchEntryType('login');
  }
}
function clearEntryForm() {
  ['f-name','f-url','f-username','f-password','f-notes',
   'c-name','c-number','c-expiry','c-cvv','c-notes',
   'n-title','n-content',
   'i-first','i-last','i-email','i-phone','i-address'
  ].forEach(id => { if ($(id)) $(id).value = ''; });
}
function fillEntryForm(e) {
  if (e.type === 'login') {
    if ($('f-name')) $('f-name').value = e.name || '';
    if ($('f-url')) $('f-url').value = e.url || '';
    if ($('f-username')) $('f-username').value = e.username || '';
    if ($('f-password')) $('f-password').value = e.password || '';
    if ($('f-notes')) $('f-notes').value = e.notes || '';
  } else if (e.type === 'card') {
    if ($('c-name')) $('c-name').value = e.cardName || '';
    if ($('c-number')) $('c-number').value = e.cardNumber || '';
    if ($('c-expiry')) $('c-expiry').value = e.expiry || '';
    if ($('c-cvv')) $('c-cvv').value = e.cvv || '';
    if ($('c-notes')) $('c-notes').value = e.notes || '';
  } else if (e.type === 'note') {
    if ($('n-title')) $('n-title').value = e.noteTitle || '';
    if ($('n-content')) $('n-content').value = e.noteContent || '';
  } else if (e.type === 'identity') {
    if ($('i-first')) $('i-first').value = e.firstName || '';
    if ($('i-last')) $('i-last').value = e.lastName || '';
    if ($('i-email')) $('i-email').value = e.email || '';
    if ($('i-phone')) $('i-phone').value = e.phone || '';
    if ($('i-address')) $('i-address').value = e.address || '';
  }
}
function switchEntryType(type) {
  ['login','card','note','identity'].forEach(t => {
    $(`fields-${t}`).classList.toggle('hidden', t !== type);
  });
}
function collectEntry() {
  const type = $('entry-type').value;
  const base = { id: State.editingId || crypto.randomUUID(), type, createdAt: Date.now() };
  if (type === 'login') {
    return { ...base, name: $('f-name').value.trim(), url: $('f-url').value.trim(), username: $('f-username').value.trim(), password: $('f-password').value, notes: $('f-notes').value.trim() };
  } else if (type === 'card') {
    return { ...base, cardName: $('c-name').value.trim(), cardNumber: $('c-number').value.trim(), expiry: $('c-expiry').value.trim(), cvv: $('c-cvv').value.trim(), notes: $('c-notes').value.trim() };
  } else if (type === 'note') {
    return { ...base, noteTitle: $('n-title').value.trim(), noteContent: $('n-content').value.trim() };
  } else {
    return { ...base, firstName: $('i-first').value.trim(), lastName: $('i-last').value.trim(), email: $('i-email').value.trim(), phone: $('i-phone').value.trim(), address: $('i-address').value.trim() };
  }
}
async function saveEntry() {
  const entry = collectEntry();
  const name = entry.name || entry.cardName || entry.noteTitle || entry.firstName;
  if (!name) return showToast('Ingresa un nombre para la entrada');
  if (State.editingId) {
    const idx = State.entries.findIndex(e => e.id === State.editingId);
    if (idx !== -1) State.entries[idx] = entry;
  } else {
    State.entries.unshift(entry);
  }
  await Crypto.saveVault(State.cryptoKey, State.entries);
  $('modal-entry').classList.add('hidden');
  renderVault();
  showToast(State.editingId ? 'Entrada actualizada' : 'Entrada guardada');
  State.editingId = null;
}
// ── VIEW ENTRY MODAL ──────────────────────────────────
function openViewModal(id) {
  const e = State.entries.find(en => en.id === id);
  if (!e) return;
  State.editingId = id;
  const name = e.name || e.cardName || e.noteTitle || (e.firstName ? `${e.firstName} ${e.lastName}` : '—');
  $('view-entry-name').textContent = name;
  const body = $('view-entry-body');
  body.innerHTML = '';
  const field = (label, value, secret = false) => {
    const wrap = document.createElement('div');
    wrap.className = 'view-field';
    const display = secret ? `<span class="password-dots" data-plain="${escHtml(value)}" data-shown="false">${'•'.repeat(Math.min(value.length, 12))}</span>` : `<span>${escHtml(value)}</span>`;
    wrap.innerHTML = `
      <div class="view-field-label">${label}</div>
      <div class="view-field-value">
        ${display}
        ${secret ? `<button class="copy-btn eye-inline" title="Mostrar/ocultar">
          <svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>` : ''}
        <button class="copy-btn" data-copy="${escHtml(value)}" title="Copiar">
          <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        </button>
      </div>`;
    return wrap;
  };
  const text = (label, value) => {
    if (!value) return;
    const wrap = document.createElement('div');
    wrap.className = 'view-field';
    wrap.innerHTML = `<div class="view-field-label">${label}</div><div class="view-field-value"><span>${escHtml(value)}</span></div>`;
    body.appendChild(wrap);
  };
  if (e.type === 'login') {
    if (e.name) body.appendChild(field('Sitio', e.name));
    if (e.url) body.appendChild(field('URL', e.url));
    if (e.username) body.appendChild(field('Usuario', e.username));
    if (e.password) body.appendChild(field('Contraseña', e.password, true));
    if (e.notes) text('Notas', e.notes);
  } else if (e.type === 'card') {
    if (e.cardName) body.appendChild(field('Nombre', e.cardName));
    if (e.cardNumber) body.appendChild(field('Número', e.cardNumber, true));
    if (e.expiry) body.appendChild(field('Vencimiento', e.expiry));
    if (e.cvv) body.appendChild(field('CVV', e.cvv, true));
    if (e.notes) text('Notas', e.notes);
  } else if (e.type === 'note') {
    if (e.noteTitle) body.appendChild(field('Título', e.noteTitle));
    if (e.noteContent) body.appendChild(field('Contenido', e.noteContent, false));
  } else if (e.type === 'identity') {
    text('Nombre', `${e.firstName} ${e.lastName}`);
    text('Email', e.email);
    text('Teléfono', e.phone);
    text('Dirección', e.address);
  }
  $('modal-view').classList.remove('hidden');
  history.pushState({ view: State.currentView, modal: 'view' }, '', '');
  body.querySelectorAll('.copy-btn[data-copy]').forEach(btn => {
    on(btn, 'click', e2 => {
      e2.stopPropagation();
      navigator.clipboard.writeText(btn.dataset.copy).then(() => showToast('Copiado al portapapeles'));
    });
  });
  body.querySelectorAll('.eye-inline').forEach(btn => {
    on(btn, 'click', e2 => {
      e2.stopPropagation();
      const span = btn.previousElementSibling;
      const shown = span.dataset.shown === 'true';
      span.dataset.shown = !shown;
      span.textContent = shown ? '•'.repeat(Math.min(span.dataset.plain.length, 12)) : span.dataset.plain;
      span.classList.toggle('password-dots', shown);
    });
  });
}
// ── DELETE ENTRY ──────────────────────────────────────
async function deleteEntry(id) {
  const ok = await showConfirm('Eliminar entrada', '¿Eliminar esta entrada permanentemente?');
  if (!ok) return;
  State.entries = State.entries.filter(e => e.id !== id);
  await Crypto.saveVault(State.cryptoKey, State.entries);
  $('modal-view').classList.add('hidden');
  renderVault();
  showToast('Entrada eliminada');
}
// ── PASSWORD GENERATOR ────────────────────────────────
function generatePassword(length = 16, opts = {}) {
  const upper = opts.upper !== false ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : '';
  const lower = opts.lower !== false ? 'abcdefghijklmnopqrstuvwxyz' : '';
  const numbers = opts.numbers !== false ? '0123456789' : '';
  const symbols = opts.symbols !== false ? '!@#$%^&*()-_=+[]{}|;:,.<>?' : '';
  const charset = upper + lower + numbers + symbols;
  if (!charset) return '';
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr, n => charset[n % charset.length]).join('');
}
function passwordStrength(pw) {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(score, 5);
}
function updateStrengthUI(fillId, labelId, score) {
  const fill = $(fillId);
  const label = $(labelId);
  if (!fill || !label) return;
  const pct = (score / 5) * 100;
  fill.style.width = pct + '%';
  const colors = ['#f43f5e','#f97316','#eab308','#22c55e','#10b981'];
  const labels = ['Muy débil','Débil','Regular','Fuerte','Muy fuerte'];
  fill.style.background = colors[score - 1] || '#f43f5e';
  label.textContent = labels[score - 1] || '—';
}
function renderGenerator() {
  const len = parseInt($('gen-length').value) || 16;
  const opts = {
    upper: $('use-upper').checked,
    lower: $('use-lower').checked,
    numbers: $('use-numbers').checked,
    symbols: $('use-symbols').checked,
  };
  const pw = generatePassword(len, opts);
  $('gen-output').textContent = pw || '— selecciona al menos un tipo —';
  const s = passwordStrength(pw);
  updateStrengthUI('gen-strength-fill', 'gen-strength-label', s);
  return pw;
}
// ── SETTINGS ──────────────────────────────────────────
function loadBiometricSetting() {
  const mode = Biometric.getMode();
  if ($('biometric-mode-select')) $('biometric-mode-select').value = mode;
  const hasCredential = !!Biometric.getCredentialId();
  const showRegister = (mode !== 'off') && !hasCredential;
  $('biometric-register-row')?.classList.toggle('hidden', !showRegister);
}

function loadAutoLockSetting() {
  const saved = localStorage.getItem('hades_autolock');
  const val = saved !== null ? parseInt(saved) : 300;
  State.autoLockSeconds = val;
  if ($('auto-lock-select')) $('auto-lock-select').value = String(val);
}
// ── EXPORT / IMPORT ───────────────────────────────────
async function exportVault() {
  const data = JSON.stringify({ version: '2.1', vault: localStorage.getItem(Crypto.VAULT_KEY), salt: localStorage.getItem(Crypto.SALT_KEY), meta: localStorage.getItem(Crypto.META_KEY) });
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `hades-backup-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Backup exportado (cifrado)');
}
async function importVault(file) {
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    if (!data.vault || !data.salt || !data.meta) throw new Error('Formato inválido');
    const ok = await showConfirm('Importar bóveda', 'Esto reemplazará tu bóveda actual. ¿Continuar?');
    if (!ok) return;
    localStorage.setItem(Crypto.VAULT_KEY, data.vault);
    localStorage.setItem(Crypto.SALT_KEY, data.salt);
    localStorage.setItem(Crypto.META_KEY, data.meta);
    showToast('Bóveda importada. Deberás desbloquear de nuevo.');
    lockApp();
  } catch {
    showToast('Error al importar: archivo inválido');
  }
}
// ── CHANGE MASTER PASSWORD ────────────────────────────
async function changeMasterPassword() {
  const current = $('cm-current').value;
  const newPw = $('cm-new').value;
  const confirm = $('cm-confirm').value;
  const err = $('cm-error');
  err.classList.add('hidden');
  if (!current || !newPw || !confirm) { err.textContent = 'Completa todos los campos'; err.classList.remove('hidden'); return; }
  if (newPw.length < 8) { err.textContent = 'Mínimo 8 caracteres'; err.classList.remove('hidden'); return; }
  if (newPw !== confirm) { err.textContent = 'Las contraseñas no coinciden'; err.classList.remove('hidden'); return; }
  const testKey = await Crypto.verifyPassword(current);
  if (!testKey) { err.textContent = 'Contraseña actual incorrecta'; err.classList.remove('hidden'); return; }
  const salt = Crypto.getSalt();
  const newKey = await Crypto.deriveKey(newPw, salt);
  await Crypto.saveVault(newKey, State.entries);
  const verifier = await Crypto.encrypt(newKey, { ok: true });
  localStorage.setItem(Crypto.META_KEY, verifier);
  State.cryptoKey = newKey;
  $('modal-change-master').classList.add('hidden');
  showToast('Contraseña maestra actualizada');
}
// ── BIND EVENTS ───────────────────────────────────────
function bindEvents() {
  on($('theme-toggle-unlock'), 'click', toggleTheme);
  on($('theme-toggle-home'), 'click', toggleTheme);
  on($('btn-lock-home'), 'click', lockApp);
  on($('theme-toggle-app'), 'click', toggleTheme);
  on($('theme-light-btn'), 'click', () => applyTheme('light'));
  on($('theme-dark-btn'), 'click', () => applyTheme('dark'));
  document.querySelectorAll('.nav-item[data-view]').forEach(btn => {
    on(btn, 'click', () => switchView(btn.dataset.view));
  });
  const overlay = document.createElement('div');
  overlay.className = 'sidebar-overlay';
  document.body.appendChild(overlay);
  on($('sidebar-toggle'), 'click', () => {
    $('sidebar').classList.toggle('open');
    overlay.classList.toggle('show');
  });
  on(overlay, 'click', () => { $('sidebar').classList.remove('open'); overlay.classList.remove('show'); });
  on($('btn-lock'), 'click', lockApp);
  // Home menu cards
  on($('home-btn-vault'),     'click', () => goToApp('vault'));
  on($('home-btn-generator'), 'click', () => goToApp('generator'));
  on($('home-btn-settings'),  'click', () => goToApp('settings'));
  on($('home-btn-help'),      'click', () => goToApp('help'));
  on($('search-input'), 'input', renderVault);
  $('category-tabs')?.querySelectorAll('.tab').forEach(tab => {
    on(tab, 'click', () => {
      $('category-tabs').querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      State.currentCat = tab.dataset.cat;
      renderVault();
    });
  });
  on($('btn-add-entry'), 'click', () => openAddModal());
  on($('btn-add-first'), 'click', () => openAddModal());
  on($('entry-type'), 'change', () => switchEntryType($('entry-type').value));
  on($('btn-gen-quick'), 'click', () => {
    const pw = generatePassword(16, { upper: true, lower: true, numbers: true, symbols: true });
    $('f-password').value = pw;
    $('f-password').type = 'text';
    setTimeout(() => $('f-password').type = 'password', 1500);
    showToast('Contraseña generada');
  });
  on($('modal-entry-save'), 'click', saveEntry);
  on($('modal-entry-close'), 'click', () => { $('modal-entry').classList.add('hidden'); history.back(); });
  on($('modal-entry-cancel'), 'click', () => { $('modal-entry').classList.add('hidden'); history.back(); });
  on($('modal-view-close'), 'click', () => { $('modal-view').classList.add('hidden'); history.back(); });
  on($('btn-delete-entry'), 'click', () => deleteEntry(State.editingId));
  on($('btn-edit-entry'), 'click', () => {
    $('modal-view').classList.add('hidden');
    const entry = State.entries.find(e => e.id === State.editingId);
    if (entry) openAddModal(entry);
  });
  document.querySelectorAll('.eye-btn').forEach(btn => {
    on(btn, 'click', () => {
      const input = $(btn.dataset.target);
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
    });
  });
  on($('btn-generate'), 'click', renderGenerator);
  on($('gen-length'), 'input', () => { $('len-val').textContent = $('gen-length').value; renderGenerator(); });
  ['use-upper','use-lower','use-numbers','use-symbols'].forEach(id => on($(id), 'change', renderGenerator));
  on($('btn-copy-gen'), 'click', () => {
    const pw = $('gen-output').textContent;
    if (pw && pw !== 'haz clic en generar') navigator.clipboard.writeText(pw).then(() => showToast('Contraseña copiada'));
  });
  on($('auto-lock-select'), 'change', () => {
    State.autoLockSeconds = parseInt($('auto-lock-select').value);
    localStorage.setItem('hades_autolock', State.autoLockSeconds);
    showToast('Auto-bloqueo actualizado');
    resetAutoLock();
  });
  on($('btn-export'), 'click', exportVault);
  on($('btn-import'), 'click', () => $('import-file').click());
  on($('import-file'), 'change', () => { const f = $('import-file').files[0]; if (f) importVault(f); });
  on($('btn-delete-vault'), 'click', async () => {
    const ok = await showConfirm('Eliminar bóveda', 'Esto elimina TODOS tus datos permanentemente y no se puede deshacer.');
    if (ok) { Crypto.deleteVault(); location.reload(); }
  });
  on($('btn-change-master'), 'click', () => $('modal-change-master').classList.remove('hidden'));
  on($('modal-cm-close'), 'click', () => $('modal-change-master').classList.add('hidden'));
  on($('modal-cm-cancel'), 'click', () => $('modal-change-master').classList.add('hidden'));
  on($('btn-cm-save'), 'click', changeMasterPassword);
  on($('c-number'), 'input', () => {
    let v = $('c-number').value.replace(/\D/g,'').slice(0,16);
    $('c-number').value = v.match(/.{1,4}/g)?.join(' ') || v;
  });
  on($('c-expiry'), 'input', () => {
    let v = $('c-expiry').value.replace(/\D/g,'').slice(0,4);
    if (v.length > 2) v = v.slice(0,2) + '/' + v.slice(2);
    $('c-expiry').value = v;
  });
  on($('mp-new'), 'keydown', e => { if (e.key === 'Enter') $('mp-confirm').focus(); });
  on($('mp-confirm'), 'keydown', e => { if (e.key === 'Enter') $('btn-setup')?.click(); });
  // Biometric settings
  on($('biometric-mode-select'), 'change', async () => {
    const mode = $('biometric-mode-select').value;
    const hasCredential = !!Biometric.getCredentialId();
    if (mode !== 'off' && !hasCredential) {
      // Necesita registrar primero
      $('biometric-register-row').classList.remove('hidden');
    } else {
      $('biometric-register-row').classList.add('hidden');
      Biometric.setMode(mode);
      showToast(mode === 'off' ? 'Acceso biométrico desactivado' : 'Modo biométrico actualizado');
    }
  });
  on($('btn-register-biometric'), 'click', async () => {
    if (!Biometric.isSupported()) {
      showToast('Tu dispositivo no soporta biometría');
      return;
    }
    // Necesitamos la contraseña maestra para cifrarla junto a la huella
    const pw = await new Promise(resolve => {
      const modal = document.createElement('div');
      modal.className = 'modal-overlay';
      modal.innerHTML = `
        <div class="glass-card modal-card small">
          <div class="modal-header"><h2>Confirmar contraseña</h2></div>
          <div class="modal-body">
            <p style="font-size:13px;color:var(--text2);margin-bottom:12px">Ingresa tu contraseña maestra para vincularla con tu huella.</p>
            <div class="field-group">
              <div class="glass-input-wrap">
                <input type="password" id="bio-pw-input" placeholder="Contraseña maestra" autocomplete="current-password" />
              </div>
            </div>
            <p id="bio-pw-error" class="error-msg hidden">Contraseña incorrecta</p>
          </div>
          <div class="modal-footer">
            <button class="btn-ghost" id="bio-pw-cancel">Cancelar</button>
            <button class="btn-primary" id="bio-pw-confirm">Confirmar</button>
          </div>
        </div>`;
      document.body.appendChild(modal);
      setTimeout(() => modal.querySelector('#bio-pw-input').focus(), 100);
      modal.querySelector('#bio-pw-cancel').onclick = () => { modal.remove(); resolve(null); };
      modal.querySelector('#bio-pw-confirm').onclick = async () => {
        const val = modal.querySelector('#bio-pw-input').value;
        const testKey = await Crypto.verifyPassword(val);
        if (!testKey) {
          modal.querySelector('#bio-pw-error').classList.remove('hidden');
          return;
        }
        modal.remove();
        resolve(val);
      };
      modal.querySelector('#bio-pw-input').addEventListener('keydown', async e => {
        if (e.key === 'Enter') modal.querySelector('#bio-pw-confirm').click();
      });
    });
    if (!pw) return;
    try {
      $('btn-register-biometric').textContent = 'Registrando…';
      $('btn-register-biometric').disabled = true;
      await Biometric.register(pw);
      const mode = $('biometric-mode-select').value;
      Biometric.setMode(mode);
      $('biometric-register-row').classList.add('hidden');
      showToast('¡Huella registrada exitosamente! 🔐');
    } catch(e) {
      showToast(e.name === 'NotAllowedError' ? 'Registro cancelado' : 'Error al registrar huella');
    } finally {
      $('btn-register-biometric').textContent = 'Registrar';
      $('btn-register-biometric').disabled = false;
    }
  });
}
// ── REGISTER SERVICE WORKER ───────────────────────────
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  });
}
// ── BOOT ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const savedTheme = localStorage.getItem('hades_theme') || 'dark';
  applyTheme(savedTheme);
  bindEvents();
  initUnlockScreen();
  on(document.querySelector('.nav-item[data-view="generator"]'), 'click', renderGenerator);
});
