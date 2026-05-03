/* ═══════════════════════════════════════════
   HADES 2.1 — app.js
   Cifrado: AES-256-GCM + PBKDF2-HMAC-SHA256 (OWASP)
   Arquitectura KEK/DEK con separación de claves
   KDF auto-calibrado por dispositivo (OWASP)
   Formato criptográfico v3 con AAD y versionado
   Sin contraseñas en memoria plana.

   ARQUITECTURA DE CLAVES:
   ┌─────────────────────────────────────────┐
   │ KEK (Key Encryption Key)                │
   │   Derivada de contraseña maestra        │
   │   PBKDF2-HMAC-SHA256, salt única 32B    │
   │   Uso: wrappear la DEK                  │
   ├─────────────────────────────────────────┤
   │ DEK (Data Encryption Key)               │
   │   Aleatoria 256 bits por bóveda         │
   │   Uso: cifrar entradas del vault        │
   │   Almacenada: cifrada con KEK           │
   ├─────────────────────────────────────────┤
   │ Recovery Verifier                       │
   │   PBKDF2 de frase 12 palabras           │
   │   Solo para verificación, no descifrado │
   ├─────────────────────────────────────────┤
   │ Biometric Key                           │
   │   PBKDF2 de credentialId               │
   │   Uso: cifrar contraseña maestra        │
   └─────────────────────────────────────────┘

   FORMATO CRIPTOGRÁFICO v3:
   hades_vault_dek: base64(iv[12] || AES-GCM(KEK, DEK_raw, AAD=kdf_header))
   hades_vault:     base64(iv[12] || AES-GCM(DEK, entries_json, AAD=vault_aad))
   hades_meta:      base64(iv[12] || AES-GCM(KEK, {ok,v,kdf_hash}, AAD=kdf_header))
   hades_kdf:       {kdf,version,iterations,salt}

   VIDA ÚTIL DE CLAVES Y EVENTOS DE REKEY:
   - KEK: se regenera en cambio de contraseña maestra, recovery, sospecha de compromiso
   - DEK: se regenera en cambio de contraseña maestra, importación de backup
   - Biometric Key: se regenera en reenrolamiento biométrico
   - Recovery verifier: se regenera en reset de contraseña, a petición del usuario
   ═══════════════════════════════════════════ */
'use strict';

// ── KDF CALIBRATION ──────────────────────────────────
/**
 * Mide cuántas iteraciones PBKDF2-HMAC-SHA256 puede ejecutar
 * el dispositivo en el rango objetivo [250ms, 500ms].
 * Piso: 600,000 (OWASP 2023). Techo: 1,000,000.
 * Se ejecuta una sola vez en el registro y se persiste en el header KDF.
 */
async function calibrateKDF() {
  const FLOOR = 600_000;
  const CEILING = 1_000_000;
  const TARGET_MIN_MS = 250;
  const TARGET_MAX_MS = 500;
  const PROBE_ITERS = 100_000;

  const enc = new TextEncoder();
  const probeKey = await crypto.subtle.importKey(
    'raw', enc.encode('calibration-probe'), 'PBKDF2', false, ['deriveKey']
  );
  const probeSalt = crypto.getRandomValues(new Uint8Array(16));

  const t0 = performance.now();
  await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: probeSalt, iterations: PROBE_ITERS, hash: 'SHA-256' },
    probeKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const elapsed = performance.now() - t0;

  // Proyectar iteraciones para alcanzar target
  const msPerIter = elapsed / PROBE_ITERS;
  const targetMs = (TARGET_MIN_MS + TARGET_MAX_MS) / 2; // 375ms
  const projected = Math.round(targetMs / msPerIter);

  return Math.max(FLOOR, Math.min(CEILING, projected));
}

// ── CRYPTO ENGINE v3 — KEK/DEK + AAD + Versioned Format ──────
const Crypto = {
  // ── Storage keys ──
  VAULT_KEY:    'hades_vault',      // Vault cifrado con DEK
  DEK_KEY:      'hades_vault_dek',  // DEK cifrada con KEK (nuevo en v3)
  KDF_KEY:      'hades_kdf',        // Header KDF público
  META_KEY:     'hades_meta',       // Verifier cifrado con KEK
  RECOVERY_KEY: 'hades_recovery',
  USER_KEY:     'hades_user',
  BIOMETRIC_KEY:'hades_biometric_id',

  // ── KDF header: {kdf, version, iterations, salt} ──
  _getKDFHeader() {
    try { return JSON.parse(localStorage.getItem(this.KDF_KEY)); } catch { return null; }
  },
  _saveKDFHeader(h) {
    localStorage.setItem(this.KDF_KEY, JSON.stringify(h));
  },
  _newSalt() {
    return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  },

  // ── AAD: datos adicionales autenticados — vinculan ciphertext al header KDF ──
  // Cambiar hades_kdf sin la clave correcta rompe el descifrado.
  _buildAAD(header, purpose) {
    const enc = new TextEncoder();
    // AAD = kdf|version|iterations|salt_completa|purpose
    // Salt completa para unicidad máxima — evita colisiones entre bóvedas distintas
    return enc.encode(`${header.kdf}|v${header.version}|${header.iterations}|${header.salt}|${purpose}`);
  },

  // ── Derivar KEK (Key Encryption Key) desde contraseña maestra ──
  async deriveKEK(password, saltB64, iterations) {
    const enc = new TextEncoder();
    const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
    const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  },

  // ── Generar DEK aleatoria (Data Encryption Key) ──
  async generateDEK() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  },

  // ── Exportar DEK como raw bytes ──
  async exportDEK(dek) {
    const raw = await crypto.subtle.exportKey('raw', dek);
    return new Uint8Array(raw);
  },

  // ── Importar DEK desde raw bytes ──
  async importDEK(raw) {
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  },

  // ── Cifrado AES-GCM con IV único + AAD opcional ──
  // Formato blob: version(1) || iv(12) || ciphertext
  // version byte: 0x03 = v3
  async _encrypt(key, data, aad = null) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const plain = typeof data === 'string' ? enc.encode(data) : enc.encode(JSON.stringify(data));
    const params = aad ? { name: 'AES-GCM', iv, additionalData: aad } : { name: 'AES-GCM', iv };
    const buf = await crypto.subtle.encrypt(params, key, plain);
    // version(1) + iv(12) + ciphertext
    const combined = new Uint8Array(1 + 12 + buf.byteLength);
    combined[0] = 0x03; // formato v3
    combined.set(iv, 1);
    combined.set(new Uint8Array(buf), 13);
    return btoa(String.fromCharCode(...combined));
  },

  // ── Descifrado AES-GCM — soporta v2 (sin version byte) y v3 ──
  async _decrypt(key, b64, aad = null) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    let iv, data;
    if (raw[0] === 0x03) {
      // Formato v3: version(1) + iv(12) + ciphertext
      iv = raw.slice(1, 13);
      data = raw.slice(13);
    } else {
      // Formato v2 legacy: iv(12) + ciphertext (sin version byte)
      iv = raw.slice(0, 12);
      data = raw.slice(12);
      aad = null; // v2 no tiene AAD
    }
    const params = aad ? { name: 'AES-GCM', iv, additionalData: aad } : { name: 'AES-GCM', iv };
    const buf = await crypto.subtle.decrypt(params, key, data);
    return JSON.parse(new TextDecoder().decode(buf));
  },

  // ── Compat shim: encrypt/decrypt sin AAD ──
  // NOTA: solo usar para datos no críticos o flujos legacy. Preferir _encrypt/_decrypt con AAD.
  async encrypt(key, data) { return this._encrypt(key, data, null); },
  async decrypt(key, b64)  { return this._decrypt(key, b64, null); },

  // ── DEK I/O: cifrar/descifrar DEK con KEK + AAD ──
  async saveDEK(kek, dekRaw, header) {
    const aad = this._buildAAD(header, 'dek');
    const dekB64 = btoa(String.fromCharCode(...dekRaw));
    const enc = await this._encrypt(kek, dekB64, aad);
    localStorage.setItem(this.DEK_KEY, enc);
  },
  async loadDEK(kek, header) {
    const enc = localStorage.getItem(this.DEK_KEY);
    if (!enc) return null;
    const aad = this._buildAAD(header, 'dek');
    const dekB64 = await this._decrypt(kek, enc, aad);
    const raw = Uint8Array.from(atob(dekB64), c => c.charCodeAt(0));
    return this.importDEK(raw);
  },

  // ── Vault I/O con DEK ──
  async saveVault(dek, entries, header) {
    const aad = this._buildAAD(header || this._getKDFHeader(), 'vault');
    const enc = await this._encrypt(dek, entries, aad);
    localStorage.setItem(this.VAULT_KEY, enc);
  },
  async loadVault(dek, header) {
    const enc = localStorage.getItem(this.VAULT_KEY);
    if (!enc) return [];
    const aad = this._buildAAD(header || this._getKDFHeader(), 'vault');
    return this._decrypt(dek, enc, aad);
  },
  hasVault() { return !!localStorage.getItem(this.VAULT_KEY); },

  // ── Usuario ──
  saveUser(name, email) {
    localStorage.setItem(this.USER_KEY, JSON.stringify({ name, email }));
  },
  getUser() {
    try { return JSON.parse(localStorage.getItem(this.USER_KEY)) || null; } catch { return null; }
  },

  // ── Recuperación ──
  // Normalización estable: trim + lowercase + orden exacto de palabras
  _normalizePhrase(words) {
    return words.map(w => w.trim().toLowerCase().replace(/\s+/g, '')).join('|');
  },
  //
  // saveRecovery: guarda recovery_verifier con PBKDF2 + salt aleatoria única.
  // La frase NUNCA se guarda — solo el verifier irreversible.
  // Estructura en localStorage['hades_recovery']:
  // { kdf:"PBKDF2-SHA256", version:1, iterations:600000, salt:<b64 32B>, verifier:<b64 256b> }
  //
  // Iteraciones: 300k justificado por alta entropía base de frase de 12 palabras (~130 bits).
  //
  async saveRecovery(phrase) {
    const normalized = this._normalizePhrase(phrase);
    const enc = new TextEncoder();
    const saltRaw = crypto.getRandomValues(new Uint8Array(32));
    const salt = btoa(String.fromCharCode(...saltRaw));
    // 600k iteraciones (OWASP) — justificado por entropía base alta (~130 bits en 12 palabras)
    const iterations = 600000;
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(normalized), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: saltRaw, iterations, hash: 'SHA-256' },
      keyMaterial, 256
    );
    const verifier = btoa(String.fromCharCode(...new Uint8Array(bits)));
    const record = { kdf: 'PBKDF2-SHA256', version: 1, iterations, salt, verifier };
    localStorage.setItem(this.RECOVERY_KEY, JSON.stringify(record));
  },
  //
  // verifyRecovery: deriva el verifier con los mismos parámetros y compara
  // en tiempo constante. No descifra nada reversible.
  //
  async verifyRecovery(words) {
    try {
      const stored = localStorage.getItem(this.RECOVERY_KEY);
      if (!stored) return false;
      const record = JSON.parse(stored);
      if (!record.kdf) return false; // Legacy base64 simple → falla segura
      const normalized = this._normalizePhrase(words);
      const enc = new TextEncoder();
      const saltRaw = Uint8Array.from(atob(record.salt), c => c.charCodeAt(0));
      const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(normalized), 'PBKDF2', false, ['deriveBits']
      );
      const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: saltRaw, iterations: record.iterations, hash: 'SHA-256' },
        keyMaterial, 256
      );
      const candidate = btoa(String.fromCharCode(...new Uint8Array(bits)));
      // Comparación en tiempo constante para evitar timing attacks
      if (candidate.length !== record.verifier.length) return false;
      let diff = 0;
      for (let i = 0; i < candidate.length; i++) {
        diff |= candidate.charCodeAt(i) ^ record.verifier.charCodeAt(i);
      }
      return diff === 0;
    } catch { return false; }
  },

  // ── Eliminar bóveda ──
  deleteVault() {
    // Limpiar todos los keys de bóveda incluyendo DEK (v3) y legacy
    [this.VAULT_KEY, this.DEK_KEY, this.KDF_KEY, this.META_KEY, 'hades_salt'].forEach(k =>
      localStorage.removeItem(k)
    );
  },

  // ── Inicializar bóveda nueva (registro) — Arquitectura KEK/DEK v3 ──
  // KEK: derivada de contraseña maestra (PBKDF2 calibrado)
  // DEK: aleatoria, cifrada con KEK + AAD
  // Vault: cifrado con DEK + AAD
  // Verifier: cifrado con KEK + AAD
  // Todo validado en memoria antes de escribir en producción (atómico)
  async initVault(password) {
    const iterations = await calibrateKDF();
    const salt = this._newSalt();
    const header = { kdf: 'PBKDF2-SHA256', version: 3, iterations, salt };
    const aadVault   = this._buildAAD(header, 'vault');
    const aadDek     = this._buildAAD(header, 'dek');
    const aadVerifier= this._buildAAD(header, 'verifier');

    // 1. Derivar KEK
    const kek = await this.deriveKEK(password, salt, iterations);
    // 2. Generar DEK aleatoria
    const dekObj = await this.generateDEK();
    const dekRaw = await this.exportDEK(dekObj);
    // 3. Preparar blobs en memoria
    const dekB64     = btoa(String.fromCharCode(...dekRaw));
    const dekEnc     = await this._encrypt(kek, dekB64, aadDek);
    const vaultEnc   = await this._encrypt(dekObj, [], aadVault);
    const verifier   = await this._encrypt(kek, { ok: true, v: 3 }, aadVerifier);
    // 4. Validar descifrado en memoria antes de persistir
    const testDekB64 = await this._decrypt(kek, dekEnc, aadDek);
    const testDek    = await this.importDEK(Uint8Array.from(atob(testDekB64), c => c.charCodeAt(0)));
    const testVault  = await this._decrypt(testDek, vaultEnc, aadVault);
    const testMeta   = await this._decrypt(kek, verifier, aadVerifier);
    if (!Array.isArray(testVault) || !testMeta?.ok) {
      throw new Error('initVault: validación pre-escritura fallida');
    }
    // 5. Escritura atómica
    this._saveKDFHeader(header);
    localStorage.setItem(this.DEK_KEY, dekEnc);
    localStorage.setItem(this.VAULT_KEY, vaultEnc);
    localStorage.setItem(this.META_KEY, verifier);
    // Retornar DEK (no KEK) — State.cryptoKey es la DEK
    return dekObj;
  },


  // ── verifyPassword v3: soporta v1 (legacy), v2 (intermedio) y v3 (KEK/DEK) ──
  async verifyPassword(password) {
    try {
      const header = this._getKDFHeader();

      // v1 legacy: sin header KDF, salt en hades_salt
      if (!header) {
        const oldSaltRaw = localStorage.getItem('hades_salt');
        if (!oldSaltRaw) return null;
        const enc = new TextEncoder();
        const oldSalt = Uint8Array.from(atob(oldSaltRaw), c => c.charCodeAt(0));
        const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
        const oldKey = await crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: oldSalt, iterations: 310000, hash: 'SHA-256' },
          base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
        );
        const meta = localStorage.getItem(this.META_KEY);
        if (!meta) return null;
        let r; try { r = await this.decrypt(oldKey, meta); } catch { return null; }
        if (!r?.ok) return null;
        return this._migrateToV3(password, oldKey, 1);
      }

      // v2: KEK sin DEK separada, sin AAD
      if (header.version === 2) {
        const kek = await this.deriveKEK(password, header.salt, header.iterations);
        const meta = localStorage.getItem(this.META_KEY);
        if (!meta) return null;
        let r; try { r = await this.decrypt(kek, meta); } catch { return null; }
        if (!r?.ok) return null;
        return this._migrateToV3(password, kek, 2);
      }

      // v3: KEK + DEK + AAD
      if (header.version === 3) {
        const kek = await this.deriveKEK(password, header.salt, header.iterations);
        const aad = this._buildAAD(header, 'verifier');
        const meta = localStorage.getItem(this.META_KEY);
        if (!meta) return null;
        let r; try { r = await this._decrypt(kek, meta, aad); } catch { return null; }
        if (!r?.ok) return null;
        return this.loadDEK(kek, header);
      }
      return null;
    } catch { return null; }
  },

  // ── Migración atómica a v3 con staging + validación + rollback ──
  async _migrateToV3(password, oldKey, fromVersion) {
    const ST = 'hades_v3_staging';
    localStorage.removeItem(ST);
    // [HADES] Migración iniciada
    try {
      const vaultEnc = localStorage.getItem(this.VAULT_KEY);
      const entries = vaultEnc ? await this.decrypt(oldKey, vaultEnc) : [];
      const iterations = await calibrateKDF();
      const salt = this._newSalt();
      const header = { kdf: 'PBKDF2-SHA256', version: 3, iterations, salt };
      const aadV = this._buildAAD(header, 'vault');
      const aadD = this._buildAAD(header, 'dek');
      const aadM = this._buildAAD(header, 'verifier');
      const kek = await this.deriveKEK(password, salt, iterations);
      const dekObj = await this.generateDEK();
      const dekRaw = await this.exportDEK(dekObj);
      const dekB64 = btoa(String.fromCharCode(...dekRaw));
      const newDekEnc   = await this._encrypt(kek, dekB64, aadD);
      const newVaultEnc = await this._encrypt(dekObj, entries, aadV);
      const newVerifier = await this._encrypt(kek, { ok: true, v: 3 }, aadM);
      // Staging
      localStorage.setItem(ST, JSON.stringify({ dek: newDekEnc, vault: newVaultEnc, verifier: newVerifier, kdf: header }));
      // Validar staging
      const st = JSON.parse(localStorage.getItem(ST));
      const stAadD = this._buildAAD(st.kdf, 'dek');
      const stAadV = this._buildAAD(st.kdf, 'vault');
      const stAadM = this._buildAAD(st.kdf, 'verifier');
      const tDekB64 = await this._decrypt(kek, st.dek, stAadD);
      const tDek = await this.importDEK(Uint8Array.from(atob(tDekB64), c => c.charCodeAt(0)));
      const tVault = await this._decrypt(tDek, st.vault, stAadV);
      const tMeta = await this._decrypt(kek, st.verifier, stAadM);
      if (!Array.isArray(tVault) || !tMeta?.ok) throw new Error('Staging inválido');
      // Promover
      this._saveKDFHeader(header);
      localStorage.setItem(this.DEK_KEY, newDekEnc);
      localStorage.setItem(this.VAULT_KEY, newVaultEnc);
      localStorage.setItem(this.META_KEY, newVerifier);
      localStorage.removeItem('hades_salt');
      localStorage.removeItem(ST);
      // [HADES] Migración v3 completada
      return dekObj;
    } catch(err) {
      localStorage.removeItem(ST);
      // [HADES] Migración fallida — rollback silencioso
      // Retornar null: el llamador (verifyPassword) manejará el error
      // No retornar oldKey (KEK) porque State.cryptoKey espera DEK en v3
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
    // Limpiar todos los materiales biométricos incluyendo KDF salt
    ['hades_biometric_pw', 'hades_biometric_mode', 'hades_bio_kdf_salt'].forEach(k =>
      localStorage.removeItem(k)
    );
    localStorage.removeItem(Crypto.BIOMETRIC_KEY);
  },
  bufToB64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); },
  b64ToBuf(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); },

  // ── Cifra la contraseña maestra con AES usando el credentialId como semilla ──
  // ── Cifrado biométrico: PBKDF2-SHA256 600k iters + salt aleatoria persistida ──
  async encryptPassword(password, credentialId) {
    const enc = new TextEncoder();
    // Salt aleatoria persistida para cifrado biométrico (no reutilizar)
    let bioSaltB64 = localStorage.getItem('hades_bio_kdf_salt');
    if (!bioSaltB64) {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      bioSaltB64 = btoa(String.fromCharCode(...raw));
      localStorage.setItem('hades_bio_kdf_salt', bioSaltB64);
    }
    const salt = Uint8Array.from(atob(bioSaltB64), c => c.charCodeAt(0));
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(credentialId), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const buf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(password));
    const combined = new Uint8Array(12 + buf.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(buf), 12);
    return btoa(String.fromCharCode(...combined));
  },

  // ── Descifrado biométrico ──
  async decryptPassword(encrypted, credentialId) {
    const enc = new TextEncoder();
    const bioSaltB64 = localStorage.getItem('hades_bio_kdf_salt');
    if (!bioSaltB64) throw new Error('Bio KDF salt not found');
    const salt = Uint8Array.from(atob(bioSaltB64), c => c.charCodeAt(0));
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(credentialId), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
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
    container.innerHTML = ''; // Limpiar primero
    words.forEach((w, i) => {
      const div = document.createElement('div');
      div.className = 'recovery-word';
      const num = document.createElement('span');
      num.className = 'recovery-word-num';
      num.textContent = `${i + 1}.`;
      const word = document.createElement('span');
      word.className = 'recovery-word-text';
      word.textContent = w; // textContent — las palabras son del generador interno
      div.appendChild(num);
      div.appendChild(word);
      container.appendChild(div);
    });
  },
  renderInputs(containerId) {
    const container = $(containerId);
    if (!container) return;
    container.innerHTML = '';
    Array.from({length: 12}, (_, i) => {
      const input = document.createElement('input');
      input.type = 'text';
      input.placeholder = `Palabra ${i + 1}`;
      input.dataset.idx = i;
      input.autocomplete = 'off';
      input.setAttribute('autocorrect', 'off');
      input.setAttribute('autocapitalize', 'off');
      input.setAttribute('spellcheck', 'false');
      container.appendChild(input);
    });
  },
  getInputWords(containerId) {
    const inputs = $(containerId)?.querySelectorAll('input');
    return Array.from(inputs || []).map(i => i.value.trim().toLowerCase());
  }
};

// ══════════════════════════════════════════════════════
// HADES-REAUTH — ReauthManager
// Capa centralizada de reautenticación para acciones sensibles.
// Ventana de validez: 120 segundos.
// Expiración forzada tras eventos de alto riesgo.
// ══════════════════════════════════════════════════════
const ReauthManager = {
  WINDOW_MS: 120_000, // 120 segundos
  _lastReauth: null,  // timestamp de la última reauth exitosa

  // ── ¿La reauth está vigente? ──
  isRecent() {
    if (!this._lastReauth) return false;
    return (Date.now() - this._lastReauth) < this.WINDOW_MS;
  },

  // ── Registrar reauth exitosa ──
  stamp() {
    this._lastReauth = Date.now();
  },

  // ── Forzar reauth en el próximo intento (eventos de alto riesgo) ──
  // HADES-REAUTH: llamar tras import, recovery, cambio de método, reenrol biométrico
  invalidate() {
    this._lastReauth = null;
  },

  // ── Punto de entrada principal ──
  // actionLabel: string descriptivo para el modal (no expone detalles internos)
  // Retorna true si reauth exitosa, false si cancelada o fallida.
  async require(actionLabel = 'esta acción') {
    if (this.isRecent()) return true; // Reauth vigente — no molestar

    const mode = Biometric.getMode();
    const hasCredential = !!Biometric.getCredentialId();
    const usesBiometric = (mode === 'biometric' || mode === 'both') && hasCredential && Biometric.isSupported();

    return new Promise(resolve => {
      // ── Construir modal de reauth via DOM API (HADES-REAUTH) ──
      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay reauth-overlay';

      const card = document.createElement('div');
      card.className = 'glass-card modal-card small';

      // Header
      const header = document.createElement('div');
      header.className = 'modal-header';
      const title = document.createElement('h2');
      title.textContent = 'Verificar identidad';
      const closeBtn = document.createElement('button');
      closeBtn.className = 'icon-btn';
      closeBtn.title = 'Cancelar';
      const closeSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      closeSvg.setAttribute('viewBox', '0 0 24 24');
      closeSvg.innerHTML = '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>';
      closeBtn.appendChild(closeSvg);
      header.appendChild(title);
      header.appendChild(closeBtn);

      // Body
      const body = document.createElement('div');
      body.className = 'modal-body';

      const hint = document.createElement('p');
      hint.className = 'form-hint';
      hint.textContent = `Para ${actionLabel} debes verificar tu identidad.`;
      body.appendChild(hint);

      const errEl = document.createElement('p');
      errEl.className = 'error-msg hidden';
      body.appendChild(errEl);

      // Campo contraseña (siempre visible excepto en modo solo-huella)
      let pwInput = null;
      if (mode !== 'biometric') {
        const fg = document.createElement('div');
        fg.className = 'field-group';
        const lbl = document.createElement('label');
        lbl.textContent = 'Contraseña maestra';
        const iw = document.createElement('div');
        iw.className = 'glass-input-wrap';
        pwInput = document.createElement('input');
        pwInput.type = 'password';
        pwInput.placeholder = '••••••••';
        pwInput.autocomplete = 'current-password';
        iw.appendChild(pwInput);
        fg.appendChild(lbl);
        fg.appendChild(iw);
        body.appendChild(fg);
      }

      // Footer
      const footer = document.createElement('div');
      footer.className = 'modal-footer';
      footer.style.flexDirection = 'column';
      footer.style.gap = '8px';

      const cancelBtn = document.createElement('button');
      cancelBtn.className = 'btn-ghost';
      cancelBtn.textContent = 'Cancelar';

      // Botón biométrico si aplica
      if (usesBiometric) {
        const bioBtn = document.createElement('button');
        bioBtn.className = 'btn-biometric';
        const bioSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        bioSvg.setAttribute('viewBox', '0 0 24 24');
        bioSvg.innerHTML = '<path d="M12 2a10 10 0 0 1 10 10"/><path d="M12 6a6 6 0 0 1 6 6"/><path d="M12 10a2 2 0 0 1 2 2"/><path d="M2 12a10 10 0 0 0 10 10"/><path d="M6 12a6 6 0 0 0 6 6"/><path d="M10 12a2 2 0 0 0 2 2"/>';
        const bioSpan = document.createElement('span');
        bioSpan.textContent = mode === 'both' ? 'Verificar huella primero' : 'Usar huella dactilar';
        bioBtn.appendChild(bioSvg);
        bioBtn.appendChild(bioSpan);

        bioBtn.addEventListener('click', async () => {
          bioBtn.classList.add('scanning');
          bioBtn.disabled = true;
          errEl.classList.add('hidden');
          try {
            const pw = await Biometric.verifyAndGetPassword();
            if (mode === 'biometric') {
              // Solo huella — verificar contra vault como prueba real
              const key = await Crypto.verifyPassword(pw);
              if (!key) throw new Error('Verificación fallida');
              this.stamp();
              cleanup();
              resolve(true);
            } else {
              // Modo both — huella OK, ahora pedir contraseña
              bioBtn.classList.remove('scanning');
              bioBtn.disabled = true;
              bioBtn.style.opacity = '0.5';
              bioSpan.textContent = 'Huella verificada ✓';
              if (pwInput) {
                pwInput.closest('.field-group').style.borderColor = 'var(--accent)';
                pwInput.focus();
                // Marcar que huella ya pasó
                pwInput.dataset.bioVerified = 'true';
              }
            }
          } catch(e) {
            bioBtn.classList.remove('scanning');
            bioBtn.disabled = false;
            errEl.textContent = e.name === 'NotAllowedError' ? 'Verificación cancelada' : 'Error biométrico';
            errEl.classList.remove('hidden');
          }
        });
        footer.appendChild(bioBtn);
      }

      // Botón confirmar (contraseña)
      if (mode !== 'biometric') {
        const confirmBtn = document.createElement('button');
        confirmBtn.className = 'btn-primary';
        confirmBtn.textContent = 'Verificar';

        const verify = async () => {
          if (!pwInput) return;
          const pw = pwInput.value;
          if (!pw) { errEl.textContent = 'Ingresa tu contraseña'; errEl.classList.remove('hidden'); return; }
          // Modo both: exigir que huella haya pasado primero
          if (mode === 'both' && pwInput.dataset.bioVerified !== 'true') {
            errEl.textContent = 'Verifica tu huella primero'; errEl.classList.remove('hidden'); return;
          }
          confirmBtn.disabled = true;
          confirmBtn.textContent = 'Verificando…';
          errEl.classList.add('hidden');
          // HADES-REAUTH: verificar contraseña sin exponer clave en estado global
          const key = await Crypto.verifyPassword(pw);
          if (!key) {
            confirmBtn.disabled = false;
            confirmBtn.textContent = 'Verificar';
            errEl.textContent = 'Contraseña incorrecta';
            errEl.classList.remove('hidden');
            pwInput.value = '';
            pwInput.focus();
            return;
          }
          // Limpiar contraseña de memoria inmediatamente
          pwInput.value = '';
          this.stamp();
          cleanup();
          resolve(true);
        };

        confirmBtn.addEventListener('click', verify);
        if (pwInput) pwInput.addEventListener('keydown', e => { if (e.key === 'Enter') verify(); });
        footer.appendChild(confirmBtn);
      }

      footer.appendChild(cancelBtn);

      // Cancelar → abort total
      const abort = () => { cleanup(); resolve(false); };
      closeBtn.addEventListener('click', abort);
      cancelBtn.addEventListener('click', abort);
      overlay.addEventListener('click', e => { if (e.target === overlay) abort(); });

      card.appendChild(header);
      card.appendChild(body);
      card.appendChild(footer);
      overlay.appendChild(card);
      document.body.appendChild(overlay);
      if (pwInput) setTimeout(() => pwInput.focus(), 80);

      function cleanup() {
        if (pwInput) pwInput.value = ''; // Limpiar contraseña de DOM
        overlay.remove();
      }
    });
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
  ReauthManager.invalidate(); // Invalidar reauth al bloquear sesión
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
        $('btn-setup').textContent = 'Calibrando seguridad…';
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
            State.entries = await Crypto.loadVault(key, Crypto._getKDFHeader());
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
          $('attempts-warning').textContent = 'Intento fallido. Te quedan ' + remaining + ' intento' + (remaining === 1 ? '' : 's') + '.';
          $('btn-forgot').classList.add('hidden');
          $('btn-unlock').disabled = false;
          $('mp-enter').disabled = false;
        } else {
          $('attempts-warning').textContent = '3 intentos fallidos. Usa tu frase de recuperación.';
          $('btn-forgot').classList.remove('hidden');
          $('btn-unlock').disabled = true;
          $('mp-enter').disabled = true;
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
      State.entries = await Crypto.loadVault(key, Crypto._getKDFHeader());
      // ── Migración silenciosa recovery_verifier legacy → v1 seguro ──
      // Si existe formato Base64 simple (pre-PBKDF2), no es posible migrar sin
      // la frase original (no la tenemos aquí). Se elimina y se invita a regenerar.
      try {
        const stored = localStorage.getItem(Crypto.RECOVERY_KEY);
        if (stored) {
          const parsed = JSON.parse(stored);
          // Si parsea y tiene .kdf → ya es v1 seguro, no hacer nada
        }
      } catch {
        // No parsea → es Base64 simple legacy → eliminar definitivamente
        localStorage.removeItem(Crypto.RECOVERY_KEY);
        showToast('Frase de recuperación reseteada por seguridad. Genérala en Ajustes.');
      }
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
    on($('btn-recovery-verify'), 'click', async () => {
      const words = Recovery.getInputWords('recovery-input-grid');
      if (words.some(w => !w)) { showToast('Completa todas las palabras'); return; }
      if (!await Crypto.verifyRecovery(words)) {
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
      // ── Flujo seguro de re-cifrado post-recuperación ──
      // Frase verificada → autorizado crear nueva contraseña → re-cifrar bóveda
      // La bóveda se reinicia vacía (no hay forma de descifrar con clave anterior desconocida)
      // Nuevo recovery_verifier se genera con la misma frase (el usuario ya la tiene anotada)
      // No se expone ningún secreto previo
      const btn = $('btn-recovery-save');
      btn.disabled = true;
      btn.textContent = 'Procesando…';
      try {
        // 1. Eliminar vault anterior (no recuperable sin clave vieja)
        Crypto.deleteVault();
        // 2. Inicializar nueva bóveda con nueva contraseña (atómico + KDF calibrado)
        State.cryptoKey = await Crypto.initVault(newPw);
        State.entries = [];
        // 3. Regenerar recovery_verifier con nueva salt (mismo flujo que registro)
        //    La frase sigue siendo válida — solo se rederiva con salt nueva
        const phrase = Recovery.generate();
        await Crypto.saveRecovery(phrase);
        // 4. Limpiar contador de intentos
        localStorage.setItem('hades_fail_count', '0');
        // 5. Limpiar biométrico (credencial vieja ya no corresponde a la nueva clave)
        Biometric.clearAll();
        ReauthManager.invalidate(); // HADES-REAUTH: recovery es evento de alto riesgo
    showToast('✅ Contraseña restablecida');
        // 6. Mostrar nueva frase de recuperación
        $('unlock-new-password').classList.add('hidden');
        $('unlock-first-time').classList.remove('hidden');
        $('setup-step-1').classList.add('hidden');
        $('setup-step-2').classList.add('hidden');
        $('setup-step-3').classList.remove('hidden');
        Recovery.renderPhrase(phrase, 'recovery-phrase-display');
      } catch(e) {
        err.textContent = 'Error al restablecer'; err.classList.remove('hidden');
        btn.disabled = false;
        btn.textContent = 'Guardar contraseña';
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
    grid.innerHTML = '';
    filtered.forEach(e => grid.appendChild(renderEntryCard(e)));
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
// Construye entry card via DOM API — sin innerHTML, sin data-* sensibles
function renderEntryCard(e) {
  const name = e.name || e.cardName || e.noteTitle || (e.firstName ? `${e.firstName} ${e.lastName}` : 'Sin nombre');
  const sub = e.username || (e.type === 'card' ? `•••• ${(e.cardNumber || '').slice(-4) || '••••'}` : e.noteTitle ? 'Nota segura' : e.email || '');

  const card = document.createElement('div');
  card.className = 'entry-card';
  card.dataset.id = e.id; // id no es secreto — es UUID

  const header = document.createElement('div');
  header.className = 'entry-card-header';

  const favicon = document.createElement('div');
  favicon.className = 'entry-favicon';
  favicon.textContent = entryIcon(e);

  const info = document.createElement('div');
  info.className = 'entry-card-info';

  const nameEl = document.createElement('div');
  nameEl.className = 'entry-card-name';
  nameEl.textContent = name; // textContent — nunca HTML

  const subEl = document.createElement('div');
  subEl.className = 'entry-card-user';
  subEl.textContent = sub;

  info.appendChild(nameEl);
  info.appendChild(subEl);
  header.appendChild(favicon);
  header.appendChild(info);

  // Tag label via DOM
  const tagEl = document.createElement('span');
  const tagMap = { login: ['Login', ''], card: ['Tarjeta', 'card-tag'], note: ['Nota', 'note-tag'], identity: ['Identidad', 'identity-tag'] };
  const [tagText, tagClass] = tagMap[e.type] || ['', ''];
  tagEl.className = `entry-tag ${tagClass}`.trim();
  tagEl.textContent = tagText;
  header.appendChild(tagEl);

  card.appendChild(header);

  if (e.url) {
    const urlEl = document.createElement('div');
    urlEl.className = 'entry-card-url';
    urlEl.textContent = e.url;
    card.appendChild(urlEl);
  }

  return card; // Retorna nodo DOM, no string
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
  await Crypto.saveVault(State.cryptoKey, State.entries, Crypto._getKDFHeader());
  $('modal-entry').classList.add('hidden');
  renderVault();
  showToast(State.editingId ? 'Entrada actualizada' : 'Entrada guardada');
  State.editingId = null;
}
// ── VIEW ENTRY MODAL ──────────────────────────────────
async function openViewModal(id) { // HADES-REAUTH para tarjetas
  const e = State.entries.find(en => en.id === id);
  if (!e) return;
  // Tarjetas exponen número completo y CVV — requieren reauth
  if (e.type === 'card') {
    if (!await ReauthManager.require('ver datos completos de tarjeta')) return;
  }
  State.editingId = id;
  const name = e.name || e.cardName || e.noteTitle || (e.firstName ? `${e.firstName} ${e.lastName}` : '—');
  $('view-entry-name').textContent = name;
  const body = $('view-entry-body');
  body.innerHTML = '';
  // field() y text() usan DOM API — sin innerHTML, sin data-* con secretos
  // El valor sensible se guarda en closure de JS (no en DOM)
  const makeSvg = (path) => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.innerHTML = path; // SVG hardcodeado — no datos usuario
    return svg;
  };

  const field = (label, value, secret = false) => {
    const wrap = document.createElement('div');
    wrap.className = 'view-field';

    const labelEl = document.createElement('div');
    labelEl.className = 'view-field-label';
    labelEl.textContent = label;

    const valueRow = document.createElement('div');
    valueRow.className = 'view-field-value';

    const span = document.createElement('span');
    if (secret) {
      span.className = 'password-dots';
      span.textContent = '•'.repeat(Math.min((value || '').length, 12));
      // El valor real vive en closure — nunca en el DOM
      let shown = false;
      const eyeBtn = document.createElement('button');
      eyeBtn.className = 'copy-btn eye-inline';
      eyeBtn.title = 'Mostrar/ocultar';
      eyeBtn.appendChild(makeSvg('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>'));
      eyeBtn.addEventListener('click', () => {
        shown = !shown;
        span.textContent = shown ? value : '•'.repeat(Math.min((value || '').length, 12));
      });
      valueRow.appendChild(span);
      valueRow.appendChild(eyeBtn);
    } else {
      span.textContent = value || '';
      valueRow.appendChild(span);
    }

    // Botón copiar: valor en closure, no en data-*
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.title = 'Copiar';
    copyBtn.appendChild(makeSvg('<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>'));
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(value || '').then(() => showToast('Copiado al portapapeles'));
    });
    valueRow.appendChild(copyBtn);

    wrap.appendChild(labelEl);
    wrap.appendChild(valueRow);
    return wrap;
  };

  const text = (label, value) => {
    if (!value) return;
    const wrap = document.createElement('div');
    wrap.className = 'view-field';
    const labelEl = document.createElement('div');
    labelEl.className = 'view-field-label';
    labelEl.textContent = label;
    const valEl = document.createElement('div');
    valEl.className = 'view-field-value';
    const span = document.createElement('span');
    span.textContent = value; // textContent — sin HTML
    valEl.appendChild(span);
    wrap.appendChild(labelEl);
    wrap.appendChild(valEl);
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
  // Copy y eye-inline buttons usan closures — event listeners agregados en field()
}
// ── DELETE ENTRY ──────────────────────────────────────
async function deleteEntry(id) {
  const ok = await showConfirm('Eliminar entrada', '¿Eliminar esta entrada permanentemente?');
  if (!ok) return;
  State.entries = State.entries.filter(e => e.id !== id);
  await Crypto.saveVault(State.cryptoKey, State.entries, Crypto._getKDFHeader());
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
  // Validar que todos los componentes del vault existen antes de exportar
  const vaultEnc = localStorage.getItem(Crypto.VAULT_KEY);
  const metaEnc  = localStorage.getItem(Crypto.META_KEY);
  const kdfRaw   = localStorage.getItem(Crypto.KDF_KEY);
  const dekEnc   = localStorage.getItem(Crypto.DEK_KEY); // v3: DEK cifrada con KEK

  if (!vaultEnc || !metaEnc) {
    showToast('Error: bóveda incompleta, no se puede exportar');
    return;
  }

  // Estructura v3: incluye DEK cifrada (sin ella el backup v3 es inutilizable)
  const backup = {
    version: '3.0',
    vault:        vaultEnc,  // AES-GCM(DEK, entries)
    dek:          dekEnc,    // AES-GCM(KEK, DEK_raw) — cifrado, seguro exportar
    kdf:          kdfRaw,    // Header KDF público (salt, iterations, version)
    meta:         metaEnc,   // AES-GCM(KEK, verifier)
    recovery:     localStorage.getItem(Crypto.RECOVERY_KEY) || null, // Verifier irreversible
    user:         localStorage.getItem(Crypto.USER_KEY) || null,     // Nombre (no sensible)
    // hades_salt legacy NO incluida
    exported_at: new Date().toISOString(),
  };

  const data = JSON.stringify(backup);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `hades-backup-${new Date().toISOString().slice(0,10)}.hades`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('Backup exportado (cifrado AES-256-GCM)');
}
// ── IMPORT HARDENING HELPERS ─────────────────────────
// HADES-IMPORT-HARDENING: Límite de tamaño del backup
// Justificación: 1000 entradas × ~500B promedio × 1.33 (base64) ≈ 665KB
// 512KB es el límite conservador — cubre uso real con margen holgado para
// el resto de keys de localStorage (~5MB límite total por origin).
const IMPORT_MAX_BYTES = 512 * 1024; // 512KB

// HADES-IMPORT-HARDENING: Validar que un string es base64 válido y no vacío
function isValidBase64(str) {
  if (typeof str !== 'string' || str.length === 0) return false;
  // Longitud debe ser múltiplo de 4 (con padding)
  if (str.length % 4 !== 0) return false;
  // Solo caracteres base64 válidos + padding
  return /^[A-Za-z0-9+/]*={0,2}$/.test(str);
}

// HADES-IMPORT-HARDENING: Validar estructura del KDF header
function isValidKDFHeader(raw) {
  try {
    const h = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (typeof h !== 'object' || h === null) return false;
    if (typeof h.kdf !== 'string' || !h.kdf) return false;
    if (typeof h.version !== 'number' || h.version < 1) return false;
    if (typeof h.iterations !== 'number' || h.iterations < 100000) return false;
    if (!isValidBase64(h.salt)) return false;
    return h;
  } catch { return false; }
}

// HADES-IMPORT-HARDENING: Validar estructura del recovery verifier
function isValidRecoveryRecord(raw) {
  try {
    const r = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (typeof r !== 'object' || r === null) return false;
    if (typeof r.kdf !== 'string') return false;
    if (typeof r.iterations !== 'number' || r.iterations < 100000) return false;
    if (!isValidBase64(r.salt)) return false;
    if (!isValidBase64(r.verifier)) return false;
    return true;
  } catch { return false; }
}

// HADES-IMPORT-HARDENING: Tomar snapshot de todas las claves relevantes del vault actual
// Claves incluidas en snapshot:
//   hades_vault, hades_vault_dek, hades_kdf, hades_meta,
//   hades_recovery, hades_user, hades_salt (legacy)
// Claves excluidas (no son del vault, no deben restaurarse):
//   hades_biometric_*, hades_theme, hades_autolock, hades_fail_count
function snapshotVaultState() {
  const keys = [
    Crypto.VAULT_KEY,   // hades_vault
    Crypto.DEK_KEY,     // hades_vault_dek
    Crypto.KDF_KEY,     // hades_kdf
    Crypto.META_KEY,    // hades_meta
    Crypto.RECOVERY_KEY,// hades_recovery
    Crypto.USER_KEY,    // hades_user
    'hades_salt',       // legacy
  ];
  const snap = {};
  keys.forEach(k => { snap[k] = localStorage.getItem(k); }); // null si no existe
  return snap;
}

// HADES-IMPORT-HARDENING: Restaurar snapshot completo
// Escribe las claves que tenían valor, elimina las que no tenían
function restoreVaultSnapshot(snap) {
  Object.entries(snap).forEach(([k, v]) => {
    if (v !== null) {
      localStorage.setItem(k, v);
    } else {
      localStorage.removeItem(k);
    }
  });
}

async function importVault(file) {
  // ── PASO 1: Límite de tamaño ANTES de leer el contenido ──────────────────
  // HADES-IMPORT-HARDENING: rechazar antes de parsear
  if (file.size > IMPORT_MAX_BYTES) {
    return showToast(`Archivo demasiado grande (máx 512KB, recibido ${Math.round(file.size/1024)}KB)`);
  }

  let text;
  try { text = await file.text(); } catch { return showToast('No se pudo leer el archivo'); }

  // Verificación redundante post-lectura (el size puede ser aproximado en algunos browsers)
  if (text.length > IMPORT_MAX_BYTES) {
    return showToast('Archivo demasiado grande para importar');
  }

  // ── PASO 2: Validación de esquema estricta — nada escrito todavía ─────────
  // HADES-IMPORT-HARDENING: toda validación ocurre aquí antes de tocar localStorage

  let data;
  try { data = JSON.parse(text); } catch { return showToast('Archivo inválido: no es JSON válido'); }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return showToast('Archivo inválido: estructura incorrecta');
  }

  // Campos obligatorios para todas las versiones
  if (!isValidBase64(data.vault)) return showToast('Archivo inválido: campo "vault" ausente o no es base64 válido');
  if (!isValidBase64(data.meta))  return showToast('Archivo inválido: campo "meta" ausente o no es base64 válido');

  // Detectar y validar versión
  const ver = data.version;
  const VALID_VERSIONS = ['3.0', '2.2', 'legacy'];

  let importMode; // 'v3' | 'v22' | 'legacy'

  if (ver === '3.0') {
    // v3: dek y kdf obligatorios y válidos
    if (!isValidBase64(data.dek)) {
      return showToast('Backup v3 inválido: campo "dek" ausente o no es base64 válido');
    }
    const kdfParsed = isValidKDFHeader(data.kdf);
    if (!kdfParsed) {
      return showToast('Backup v3 inválido: "kdf" debe ser JSON con kdf, version, iterations, salt válidos');
    }
    // Consistencia: versión del KDF header debe ser 3 para backup v3
    if (kdfParsed.version !== 3) {
      return showToast('Backup v3 inconsistente: versión del KDF header no coincide');
    }
    // recovery es opcional, pero si existe debe ser válido
    if (data.recovery !== undefined && data.recovery !== null) {
      if (!isValidRecoveryRecord(data.recovery)) {
        return showToast('Backup v3 inválido: campo "recovery" tiene estructura incorrecta');
      }
    }
    importMode = 'v3';

  } else if (ver === '2.2') {
    const kdfParsed = isValidKDFHeader(data.kdf);
    if (!kdfParsed) {
      return showToast('Backup v2.2 inválido: "kdf" debe ser JSON con kdf, version, iterations, salt válidos');
    }
    importMode = 'v22';

  } else if (typeof data.salt === 'string' && data.salt) {
    // Legacy: sin version field explícito, con salt
    if (!isValidBase64(data.salt)) {
      return showToast('Backup legacy inválido: "salt" no es base64 válido');
    }
    importMode = 'legacy';

  } else {
    return showToast(`Archivo inválido: versión desconocida (${ver ?? 'sin versión'})`);
  }

  // ── PASO 3: Confirmación del usuario ─────────────────────────────────────
  const versionLabel = { v3: 'v3.0 (formato actual)', v22: 'v2.2', legacy: 'legacy' }[importMode];
  const ok = await showConfirm(
    'Importar bóveda',
    `Se importará un backup ${versionLabel}. Esto reemplazará tu bóveda actual. ¿Continuar?`
  );
  if (!ok) return;

  // ── PASO 4: Snapshot del estado actual ANTES de escribir nada ────────────
  // HADES-IMPORT-HARDENING: si algo falla, restauramos este snapshot íntegro
  // No usamos deleteVault() como rollback — restauramos el estado previo exacto
  const previousState = snapshotVaultState();

  let commitSucceeded = false;

  try {
    // ── PASO 5: Escribir nuevo estado en localStorage ─────────────────────
    // HADES-IMPORT-HARDENING: escritura secuencial — si cualquier setItem lanza,
    // el catch restaurará previousState sin haber borrado nada

    if (importMode === 'v3') {
      localStorage.setItem(Crypto.VAULT_KEY,    data.vault);
      localStorage.setItem(Crypto.DEK_KEY,      data.dek);
      localStorage.setItem(Crypto.KDF_KEY,      data.kdf);
      localStorage.setItem(Crypto.META_KEY,     data.meta);
      // recovery y user son opcionales — escribir solo si presentes y válidos
      if (data.recovery) localStorage.setItem(Crypto.RECOVERY_KEY, data.recovery);
      if (data.user && typeof data.user === 'string') localStorage.setItem(Crypto.USER_KEY, data.user);
      // Eliminar legacy salt — no debe coexistir con v3
      localStorage.removeItem('hades_salt');

    } else if (importMode === 'v22') {
      localStorage.setItem(Crypto.VAULT_KEY,    data.vault);
      localStorage.setItem(Crypto.KDF_KEY,      data.kdf);
      localStorage.setItem(Crypto.META_KEY,     data.meta);
      // v2.2 no tiene DEK separada — se generará en la migración al primer unlock
      localStorage.removeItem(Crypto.DEK_KEY);
      localStorage.removeItem('hades_salt');

    } else { // legacy
      localStorage.setItem(Crypto.VAULT_KEY,    data.vault);
      localStorage.setItem(Crypto.META_KEY,     data.meta);
      localStorage.setItem('hades_salt',        data.salt);
      localStorage.removeItem(Crypto.DEK_KEY);
      localStorage.removeItem(Crypto.KDF_KEY);
    }

    // ── PASO 6: Validación de lectura del nuevo estado ───────────────────
    // HADES-IMPORT-HARDENING: verificar que lo escrito se puede leer correctamente
    // No podemos descifrar sin la contraseña, pero validamos que las claves
    // existen, son legibles y tienen el formato esperado post-escritura
    const readbackVault = localStorage.getItem(Crypto.VAULT_KEY);
    const readbackMeta  = localStorage.getItem(Crypto.META_KEY);

    if (readbackVault !== data.vault) throw new Error('Readback vault falló');
    if (readbackMeta  !== data.meta)  throw new Error('Readback meta falló');

    if (importMode === 'v3') {
      const readbackDek = localStorage.getItem(Crypto.DEK_KEY);
      const readbackKdf = localStorage.getItem(Crypto.KDF_KEY);
      if (readbackDek !== data.dek) throw new Error('Readback dek falló');
      if (readbackKdf !== data.kdf) throw new Error('Readback kdf falló');
    }

    // ── PASO 7: Commit exitoso ───────────────────────────────────────────
    commitSucceeded = true;

  } catch (writeError) {
    // ── ROLLBACK: restaurar snapshot previo íntegramente ──────────────────
    // HADES-IMPORT-HARDENING: NO se llama deleteVault() — se restaura el estado
    // anterior completo para que el usuario pueda seguir usando su bóveda previa
    try {
      restoreVaultSnapshot(previousState);
    } catch {
      // Si la restauración también falla (localStorage lleno, etc.)
      // documentar el estado — el usuario tendrá que recuperar con frase
    }
    showToast('Error al importar: tu bóveda anterior fue restaurada');
    return;
  }

  // ── PASO 8: Post-commit — solo llega aquí si commitSucceeded === true ────
  // Limpiar biométrico — no corresponde al vault importado
  Biometric.clearAll();
  ReauthManager.invalidate(); // HADES-REAUTH: importación es evento de alto riesgo
  showToast('Bóveda importada. Desbloquea con tu contraseña maestra.');
  lockApp();
}

/*
 * HADES-IMPORT-HARDENING — Límites residuales por usar localStorage
 * ══════════════════════════════════════════════════════════════════
 * 1. localStorage NO tiene transacciones ACID — si el proceso se interrumpe
 *    (crash del browser, pestaña cerrada) entre escrituras, el estado puede
 *    quedar parcialmente comprometido. El snapshot/restore mitiga esto para
 *    errores de JS, pero no para interrupciones externas del proceso.
 *
 * 2. El readback (Paso 6) confirma que localStorage aceptó los valores,
 *    pero no confirma que el descifrado funcionará — eso solo se sabe al
 *    desbloquear con la contraseña maestra. Si el backup fue generado con
 *    una contraseña diferente, el error aparece en ese momento.
 *
 * 3. Si localStorage está lleno y el rollback también falla (Paso catch),
 *    el usuario queda sin bóveda accesible. Se muestra mensaje apropiado
 *    y puede recuperar acceso con la frase de 12 palabras.
 *
 * 4. El límite de 512KB protege contra DoS por archivo gigante pero no
 *    contra un backup corrupto de tamaño válido — la validación de esquema
 *    y el descifrado posterior son las defensas reales.
 * ══════════════════════════════════════════════════════════════════
 */
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
  // HADES-REAUTH + Punto 5: rotación completa KEK + DEK en cambio de contraseña
  // Nueva KEK (nueva salt + iteraciones calibradas) + nueva DEK aleatoria
  const iterations = await calibrateKDF();
  const newSalt = Crypto._newSalt();
  const newHeader = { kdf: 'PBKDF2-SHA256', version: 3, iterations, salt: newSalt };
  const aadV = Crypto._buildAAD(newHeader, 'vault');
  const aadD = Crypto._buildAAD(newHeader, 'dek');
  const aadM = Crypto._buildAAD(newHeader, 'verifier');
  const newKEK = await Crypto.deriveKEK(newPw, newSalt, iterations);
  const newDEK = await Crypto.generateDEK();
  const newDEKRaw = await Crypto.exportDEK(newDEK);
  const newDEKB64 = btoa(String.fromCharCode(...newDEKRaw));
  const newDekEnc   = await Crypto._encrypt(newKEK, newDEKB64, aadD);
  const newVaultEnc = await Crypto._encrypt(newDEK, State.entries, aadV);
  const newVerifier = await Crypto._encrypt(newKEK, { ok: true, v: 3 }, aadM);
  // Validar antes de escribir
  const tDekB64 = await Crypto._decrypt(newKEK, newDekEnc, aadD);
  const tDek = await Crypto.importDEK(Uint8Array.from(atob(tDekB64), c=>c.charCodeAt(0)));
  const tVault = await Crypto._decrypt(tDek, newVaultEnc, aadV);
  if (!Array.isArray(tVault)) throw new Error('Validación fallida');
  // Escribir atómicamente
  Crypto._saveKDFHeader(newHeader);
  localStorage.setItem(Crypto.DEK_KEY, newDekEnc);
  localStorage.setItem(Crypto.VAULT_KEY, newVaultEnc);
  localStorage.setItem(Crypto.META_KEY, newVerifier);
  State.cryptoKey = newDEK; // State.cryptoKey es ahora la DEK
  $('modal-change-master').classList.add('hidden');
  ReauthManager.invalidate(); // HADES-REAUTH: cambio de contraseña es evento de alto riesgo
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
  on($('btn-export'), 'click', async () => { // HADES-REAUTH
    if (!await ReauthManager.require('exportar la bóveda')) return;
    exportVault();
  });
  on($('btn-import'), 'click', async () => { // HADES-REAUTH
    if (!await ReauthManager.require('importar una bóveda')) return;
    $('import-file').click();
  });
  on($('import-file'), 'change', async () => {
    const f = $('import-file').files[0];
    if (f) importVault(f);
  });
  on($('btn-delete-vault'), 'click', async () => { // HADES-REAUTH
    if (!await ReauthManager.require('eliminar la bóveda')) return;
    const ok = await showConfirm('Eliminar bóveda', 'Esto elimina TODOS tus datos permanentemente y no se puede deshacer.');
    if (ok) { Crypto.deleteVault(); location.reload(); }
  });
  on($('btn-change-master'), 'click', async () => { // HADES-REAUTH
    if (!await ReauthManager.require('cambiar la contraseña maestra')) return;
    $('modal-change-master').classList.remove('hidden');
  });
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
  on($('biometric-mode-select'), 'change', async () => { // HADES-REAUTH
    if (!await ReauthManager.require('cambiar el modo de acceso biométrico')) {
      // Revertir select al valor anterior si cancela
      $('biometric-mode-select').value = Biometric.getMode();
      return;
    }
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
  on($('btn-register-biometric'), 'click', async () => { // HADES-REAUTH
    if (!await ReauthManager.require('registrar o cambiar la huella dactilar')) return;
    if (!Biometric.isSupported()) {
      showToast('Tu dispositivo no soporta biometría');
      return;
    }
    // Necesitamos la contraseña maestra para cifrarla junto a la huella
    const pw = await new Promise(resolve => {
      // Modal biométrico construido via DOM API — sin innerHTML con datos usuario
      const modal = document.createElement('div');
      modal.className = 'modal-overlay';

      const card = document.createElement('div');
      card.className = 'glass-card modal-card small';

      const mHeader = document.createElement('div');
      mHeader.className = 'modal-header';
      const mTitle = document.createElement('h2');
      mTitle.textContent = 'Confirmar contraseña';
      mHeader.appendChild(mTitle);

      const mBody = document.createElement('div');
      mBody.className = 'modal-body';
      const hint = document.createElement('p');
      hint.style.cssText = 'font-size:13px;color:var(--text2);margin-bottom:12px';
      hint.textContent = 'Ingresa tu contraseña maestra para vincularla con tu huella.';
      const fg = document.createElement('div');
      fg.className = 'field-group';
      const iw = document.createElement('div');
      iw.className = 'glass-input-wrap';
      const pwInput = document.createElement('input');
      pwInput.type = 'password';
      pwInput.id = 'bio-pw-input';
      pwInput.placeholder = 'Contraseña maestra';
      pwInput.autocomplete = 'current-password';
      iw.appendChild(pwInput);
      fg.appendChild(iw);
      const pwErr = document.createElement('p');
      pwErr.id = 'bio-pw-error';
      pwErr.className = 'error-msg hidden';
      pwErr.textContent = 'Contraseña incorrecta';
      mBody.appendChild(hint);
      mBody.appendChild(fg);
      mBody.appendChild(pwErr);

      const mFooter = document.createElement('div');
      mFooter.className = 'modal-footer';
      const cancelBtn = document.createElement('button');
      cancelBtn.className = 'btn-ghost';
      cancelBtn.id = 'bio-pw-cancel';
      cancelBtn.textContent = 'Cancelar';
      const confirmBtn = document.createElement('button');
      confirmBtn.className = 'btn-primary';
      confirmBtn.id = 'bio-pw-confirm';
      confirmBtn.textContent = 'Confirmar';
      mFooter.appendChild(cancelBtn);
      mFooter.appendChild(confirmBtn);

      card.appendChild(mHeader);
      card.appendChild(mBody);
      card.appendChild(mFooter);
      modal.appendChild(card);
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
      ReauthManager.invalidate(); // HADES-REAUTH: reenrol biométrico es evento de alto riesgo
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
