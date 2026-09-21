/* Hades · Rescate — solo lectura. Nunca escribe ni borra. */
'use strict';

const $ = id => document.getElementById(id);
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

// Se abre SIN version para no disparar nunca un upgrade sobre la base real.
function openDB() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('hades_v2');
    r.onsuccess = e => res(e.target.result);
    r.onerror   = e => rej(e.target.error);
  });
}

function get(db, store, key) {
  return new Promise(res => {
    if (!db.objectStoreNames.contains(store)) return res(undefined);
    const r = db.transaction(store, 'readonly').objectStore(store).get(key);
    r.onsuccess = e => res(e.target.result);
    r.onerror   = () => res(undefined);
  });
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

let DB_, HEADER_, BLOBS_, VAULT_;

async function cargar() {
  const out = [];
  try {
    DB_ = await openDB();
    out.push('base hades_v2: ABIERTA (version ' + DB_.version + ')');
    out.push('stores: ' + Array.from(DB_.objectStoreNames).join(', '));
    HEADER_ = await get(DB_, 'kdf_header', 'header');
    BLOBS_  = await get(DB_, 'crypto_blobs', 'blobs');
    VAULT_  = await get(DB_, 'vault', 'data');
    out.push('');
    out.push('kdf_header : ' + (HEADER_ ? 'SI' : 'NO'));
    out.push('vault      : ' + (VAULT_ ? 'SI' : 'NO'));
    out.push('crypto_blobs: ' + (BLOBS_ ? 'SI' : 'NO'));
    if (BLOBS_) {
      out.push('');
      out.push('campos guardados (solo presencia y tamano, nunca el contenido):');
      ['dekEnc','verifierEnc','recoverySalt','recoveryWrap','bioCredentialId','bioWrap','bioOnlyKeyB64','bioOnlyWrap','user']
        .forEach(k => {
          const v = BLOBS_[k];
          const n = v === undefined ? 'FALTA' : (typeof v === 'string' ? v.length + ' car.' : 'presente');
          out.push('  ' + k.padEnd(16) + n);
        });
    }
  } catch (e) {
    out.push('ERROR al leer: ' + e.name + ' — ' + e.message);
  }
  out.push('');
  out.push('localStorage hades_bio_mode: ' + (localStorage.getItem('hades_bio_mode') || '(vacio)'));
  out.push('WebAuthn disponible: ' + !!(window.PublicKeyCredential && navigator.credentials));
  try {
    const uvpaa = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    out.push('lector del dispositivo: ' + (uvpaa ? 'SI' : 'NO'));
  } catch { out.push('lector del dispositivo: no se pudo consultar'); }
  out.push('origen: ' + location.origin);
  $('estado').textContent = out.join('\n');
}

$('btn-rescate').addEventListener('click', async () => {
  const msg = $('rescate-msg');
  msg.className = 'msg';
  try {
    if (!HEADER_ || !BLOBS_ || !VAULT_) {
      msg.className = 'msg bad';
      msg.textContent = 'Faltan piezas de la boveda, no se puede armar el respaldo.';
      return;
    }
    const backup = {
      format: 'hades-backup', version: 2,
      created_at: new Date().toISOString(),
      kdf_header: HEADER_, crypto_blobs: BLOBS_, vault_enc: VAULT_,
      checksum: await sha256Hex(JSON.stringify(VAULT_))
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(backup)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url; a.download = 'hades-rescate-' + Date.now() + '.hades';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    msg.className = 'msg ok';
    msg.textContent = 'Listo. Guarda ese archivo en dos lugares distintos.';
  } catch (e) {
    msg.className = 'msg bad';
    msg.textContent = 'Error: ' + e.name + ' — ' + e.message;
  }
});

$('btn-huella').addEventListener('click', async () => {
  const box = $('btn-huella'), out = $('huella-msg');
  box.disabled = true; out.textContent = 'Pidiendo la huella…';
  const t0 = Date.now();
  try {
    if (!BLOBS_?.bioCredentialId) throw new Error('No hay bioCredentialId guardado');
    const p = navigator.credentials.get({
      publicKey: {
        rpId: location.hostname,
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ id: unb64(BLOBS_.bioCredentialId), type: 'public-key' }],
        userVerification: 'required', timeout: 60000
      }
    });
    const colgada = new Promise((_, rej) =>
      setTimeout(() => rej(new Error('COLGADA: 25 s sin respuesta ni error')), 25000));
    await Promise.race([p, colgada]);
    out.textContent = 'La huella respondio OK en ' + ((Date.now() - t0) / 1000).toFixed(1) + ' s.';
  } catch (e) {
    out.textContent = 'Tras ' + ((Date.now() - t0) / 1000).toFixed(1) + ' s:\n'
      + 'nombre : ' + (e.name || '(sin nombre)') + '\n'
      + 'mensaje: ' + (e.message || '(sin mensaje)');
  } finally { box.disabled = false; }
});

let WORDS = [];
(function construirCampos() {
  const c = $('palabras');
  for (let i = 1; i <= 12; i++) {
    const l = document.createElement('label');
    l.textContent = i + '.';
    const inp = document.createElement('input');
    inp.type = 'text'; inp.autocapitalize = 'off'; inp.autocomplete = 'off';
    inp.spellcheck = false; inp.setAttribute('autocorrect', 'off');
    l.appendChild(inp); c.appendChild(l);
  }
})();

$('btn-palabras').addEventListener('click', async () => {
  const out = $('palabras-msg');
  if (!WORDS.length) {
    try {
      const txt = await (await fetch('/app.js')).text();
      const m = txt.match(/const W = '([a-z ]+)'\.split/);
      WORDS = m ? m[1].split(' ') : [];
    } catch { /* sigue vacio */ }
  }
  if (!WORDS.length) { out.textContent = 'No se pudo cargar la lista de palabras.'; return; }
  const inputs = Array.from(document.querySelectorAll('#palabras input'));
  const malas = [];
  inputs.forEach((inp, i) => {
    const w = inp.value.trim().toLowerCase();
    inp.classList.remove('ok', 'bad');
    if (!w) return;
    if (WORDS.includes(w)) inp.classList.add('ok');
    else { inp.classList.add('bad'); malas.push((i + 1) + ': ' + w); }
  });
  out.textContent = malas.length
    ? 'No existen en la lista BIP39:\n' + malas.join('\n')
    : 'Las palabras escritas existen todas en la lista. Si aun asi no abre, el problema es el orden o no es la frase de esta boveda.';
});

cargar();
