/* ═══════════════════════════════════════════════════════════════
   HADES V2 — app.js
   Arquitectura: DB → Crypto → Recovery → Biometric → Reauth →
                 Backup → State → UI → App → Init
   ═══════════════════════════════════════════════════════════════ */

'use strict';

// ─────────────────────────────────────────────
// HADES-V2-STORAGE: IndexedDB Module
// ─────────────────────────────────────────────
const DB = (() => {
  let _db = null;
  const NAME = 'hades_v2';
  const VER  = 1;
  const STORES = ['kdf_header','crypto_blobs','vault','staging','import_staging'];

  async function open() {
    if (_db) return _db;
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(NAME, VER);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        STORES.forEach(s => { if (!db.objectStoreNames.contains(s)) db.createObjectStore(s); });
      };
      req.onsuccess = e => { _db = e.target.result; resolve(_db); };
      req.onerror   = e => reject(e.target.error);
    });
  }

  async function tx(stores, mode, fn) {
    const db = await open();
    return new Promise((resolve, reject) => {
      const t = db.transaction(stores, mode);
      t.oncomplete = () => resolve();
      t.onerror = t.onabort = e => reject(e.target.error);
      fn(t);
    });
  }

  async function get(store, key) {
    const db = await open();
    return new Promise((resolve, reject) => {
      const req = db.transaction(store, 'readonly').objectStore(store).get(key);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = e => reject(e.target.error);
    });
  }

  async function put(store, key, value) {
    return tx(store, 'readwrite', t => t.objectStore(store).put(value, key));
  }

  async function del(store, key) {
    return tx(store, 'readwrite', t => t.objectStore(store).delete(key));
  }

  async function clear(store) {
    return tx(store, 'readwrite', t => t.objectStore(store).clear());
  }

  async function atomicWrite(ops) {
    const stores = [...new Set(ops.map(o => o.store))];
    return tx(stores, 'readwrite', t => {
      ops.forEach(op => {
        const s = t.objectStore(op.store);
        if (op.type === 'put')    s.put(op.value, op.key);
        if (op.type === 'delete') s.delete(op.key);
        if (op.type === 'clear')  s.clear();
      });
    });
  }

  async function hasVault() {
    const h = await get('kdf_header', 'header');
    return !!h;
  }

  async function snapshot() {
    const header = await get('kdf_header', 'header');
    const blobs  = await get('crypto_blobs', 'blobs');
    const vault  = await get('vault', 'data');
    if (!header || !blobs) return null;
    const snap = { ts: Date.now(), header, blobs, vault };
    await put('staging', 'snap', snap);
    return snap;
  }

  async function rollback() {
    const snap = await get('staging', 'snap');
    if (!snap) return false;
    const ops = [
      { store: 'kdf_header',   type: 'put', key: 'header', value: snap.header },
      { store: 'crypto_blobs', type: 'put', key: 'blobs',  value: snap.blobs  },
    ];
    if (snap.vault) ops.push({ store: 'vault', type: 'put', key: 'data', value: snap.vault });
    else            ops.push({ store: 'vault', type: 'clear' });
    await atomicWrite(ops);
    await del('staging', 'snap');
    return true;
  }

  return { open, get, put, del, clear, atomicWrite, hasVault, snapshot, rollback };
})();

// ─────────────────────────────────────────────
// HADES-V2-CRYPTO: Cryptographic Module
// ─────────────────────────────────────────────
const Crypto = (() => {
  const ITERATIONS = 600_000;
  const HASH = 'SHA-256';

  function rand(n)    { return crypto.getRandomValues(new Uint8Array(n)); }
  function b64(buf)   { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
  function unb64(s)   { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
  function newSalt()  { return b64(rand(32)); }

  function buildAAD(header, context) {
    const s = JSON.stringify({ kdf: header.kdf, version: header.version, salt: header.salt, context });
    return new TextEncoder().encode(s);
  }

  async function deriveKEK(password, saltB64) {
    const base = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: unb64(saltB64), iterations: ITERATIONS, hash: HASH },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  async function generateDEK() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  async function exportDEK(dek) {
    return b64(await crypto.subtle.exportKey('raw', dek));
  }

  async function importDEK(dekB64) {
    return crypto.subtle.importKey('raw', unb64(dekB64), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  async function encrypt(key, data, aad) {
    const iv      = rand(12);
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const params  = { name: 'AES-GCM', iv };
    if (aad) params.additionalData = aad;
    const ct = await crypto.subtle.encrypt(params, key, encoded);
    return { v: 2, iv: b64(iv), ct: b64(ct) };
  }

  async function decrypt(key, blob, aad) {
    const iv     = unb64(blob.iv);
    const ct     = unb64(blob.ct);
    const params = { name: 'AES-GCM', iv };
    if (aad) params.additionalData = aad;
    const buf = await crypto.subtle.decrypt(params, key, ct);
    return JSON.parse(new TextDecoder().decode(buf));
  }

  async function initVault(password, userName) {
    const salt   = newSalt();
    const header = { kdf: 'PBKDF2-SHA256', version: 2, iterations: ITERATIONS, salt };
    const aadDek = buildAAD(header, 'dek');
    const aadVlt = buildAAD(header, 'vault');
    const aadVer = buildAAD(header, 'verifier');

    const kek    = await deriveKEK(password, salt);
    const dek    = await generateDEK();
    const dekB64 = await exportDEK(dek);

    const dekEnc  = await encrypt(kek, dekB64, aadDek);
    const vaultEnc = await encrypt(dek, [], aadVlt);
    const verifierEnc = await encrypt(kek, { ok: true, v: 2, user: userName }, aadVer);

    // Validate in memory before writing
    const testDekB64 = await decrypt(kek, dekEnc, aadDek);
    const testDek    = await importDEK(testDekB64);
    const testVault  = await decrypt(testDek, vaultEnc, aadVlt);
    const testVer    = await decrypt(kek, verifierEnc, aadVer);
    if (!Array.isArray(testVault) || !testVer?.ok) throw new Error('initVault: pre-write validation failed');

    await DB.atomicWrite([
      { store: 'kdf_header',   type: 'put', key: 'header', value: header },
      { store: 'crypto_blobs', type: 'put', key: 'blobs',  value: { dekEnc, verifierEnc } },
      { store: 'vault',        type: 'put', key: 'data',   value: vaultEnc },
    ]);

    return { dek, dekB64 };
  }

  async function verifyPassword(password) {
    const header = await DB.get('kdf_header', 'header');
    const blobs  = await DB.get('crypto_blobs', 'blobs');
    if (!header || !blobs) return null;
    try {
      const kek    = await deriveKEK(password, header.salt);
      const aadVer = buildAAD(header, 'verifier');
      const ver    = await decrypt(kek, blobs.verifierEnc, aadVer);
      if (!ver?.ok) return null;
      const aadDek = buildAAD(header, 'dek');
      const dekB64 = await decrypt(kek, blobs.dekEnc, aadDek);
      const dek    = await importDEK(dekB64);
      return { kek, dek, dekB64, user: ver.user };
    } catch { return null; }
  }

  async function loadVault(dek) {
    const header   = await DB.get('kdf_header', 'header');
    const vaultEnc = await DB.get('vault', 'data');
    if (!vaultEnc) return [];
    return decrypt(dek, vaultEnc, buildAAD(header, 'vault'));
  }

  async function saveVault(dek, entries) {
    const header   = await DB.get('kdf_header', 'header');
    const vaultEnc = await encrypt(dek, entries, buildAAD(header, 'vault'));
    await DB.put('vault', 'data', vaultEnc);
  }

  async function changeMasterPassword(oldPwd, newPwd) {
    const result = await verifyPassword(oldPwd);
    if (!result) throw new Error('Contraseña actual incorrecta');
    const header = await DB.get('kdf_header', 'header');
    const blobs  = await DB.get('crypto_blobs', 'blobs');
    const newSaltVal = newSalt();
    const newHeader  = { ...header, salt: newSaltVal };
    const newKek     = await deriveKEK(newPwd, newSaltVal);
    const newAadDek  = buildAAD(newHeader, 'dek');
    const newAadVer  = buildAAD(newHeader, 'verifier');
    const newDekEnc  = await encrypt(newKek, result.dekB64, newAadDek);
    const newVerEnc  = await encrypt(newKek, { ok: true, v: 2, user: result.user }, newAadVer);
    const testB64    = await decrypt(newKek, newDekEnc, newAadDek);
    if (testB64 !== result.dekB64) throw new Error('changeMasterPassword: validation failed');
    const newBlobs   = { ...blobs, dekEnc: newDekEnc, verifierEnc: newVerEnc };
    await DB.atomicWrite([
      { store: 'kdf_header',   type: 'put', key: 'header', value: newHeader },
      { store: 'crypto_blobs', type: 'put', key: 'blobs',  value: newBlobs  },
    ]);
    return { newKek, newHeader };
  }

  return {
    newSalt, buildAAD, deriveKEK, generateDEK, exportDEK, importDEK,
    encrypt, decrypt, initVault, verifyPassword, loadVault, saveVault, changeMasterPassword
  };
})();

// ─────────────────────────────────────────────
// HADES-V2-RECOVERY: Recovery Phrase Module
// ─────────────────────────────────────────────
const Recovery = (() => {
  // BIP39 English wordlist (2048 words)
  const W = 'abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic afford afraid again age agent agree ahead aim air airport aisle alarm album alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone book boost border boring borrow boss bottom bounce box boy bracket brain brand brave breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canvas canyon capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle cause caution cave ceiling celery cement census chair chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact endless endorse enemy engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude exercise exhaust exhibit exile exist exit exotic expand expire explain expose express extend extra eye fable face faculty fade faint faith fall false fame family famous fan fancy fantasy far fashion fat fatal father fatigue fault favorite feature february federal fee feed feel feet fellow felt fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garbage garden garlic garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grasp grass gravity great green grid grief grit grocery group grow grunt guard guide guilt guitar gun guy habit hair half hamster hand happy harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn hospital host hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon ignore ill illegal image imitate immense immune impact impose improve impulse inbox income increase index indicate indoor industry infant inflict inform inhale inherit initial inject inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jelly jewel job join journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label lamp language laptop large later laugh laundry lava law lawn lawsuit layer lazy leader learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid main major make mammal mango mansion manual maple marble march margin marine market marriage mask master match material math matrix maximum maze meadow mean medal media melody melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor miracle miss mixed mixture mobile model modify mom monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery naive name napkin narrow nasty natural nature near neck need negative neglect neither nephew nerve nest network news next nice night noble noise nominee noodle normal notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure obtain ocean october odor off offer office often oil okay old omit once onion open opera oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outside oval over own oyster ozone packet page pair palace palm panda panel panic panther paper parade parent park parrot party pass patch path patrol pause pave payment peace peanut peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play plaza pledge pluck plug plunge poem poet point polar pole police pond pony popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rage rail rain raise rally ramp ranch random range rapid rare rate rather raven reach ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm ribbon rice rich ride rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling siege sight sign silent silk silly silver similar simple since sing siren sister situate six size ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar solution solve someone song soon sorry sort soul sound soup source south space spare spatial spawn speak special speed sphere spice spider spike spin spirit split spoil sponsor spoon spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stop store storm story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise sustain swallow swamp swap swear sweet swift swim swing switch sword symbol symptom syrup table tackle tag tail talent tamper tank tape target task tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme theory there they thing this thought three thrive throw thumb thunder ticket tilt timber time tiny tip tired title toast tobacco today together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck truly trumpet trust truth tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique universe unknown unlock until unusual unwrap update upgrade uphold upon upper upset urban usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel wedding weekend weird welcome well west wet whale wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo'.split(' ');

  function generate() {
    const arr = crypto.getRandomValues(new Uint16Array(12));
    return Array.from(arr).map(i => W[i % 2048]);
  }

  async function save(phrase, dekB64) {
    const salt   = Crypto.newSalt();
    const header = { kdf: 'PBKDF2-SHA256', version: 2, iterations: 600000, salt };
    const rKek   = await Crypto.deriveKEK(phrase.join(' '), salt);
    const aad    = Crypto.buildAAD(header, 'recovery');
    const wrap   = await Crypto.encrypt(rKek, dekB64, aad);
    const blobs  = await DB.get('crypto_blobs', 'blobs');
    await DB.put('crypto_blobs', 'blobs', { ...blobs, recoverySalt: salt, recoveryWrap: wrap });
  }

  async function resetPassword(phrase, newPassword) {
    const blobs = await DB.get('crypto_blobs', 'blobs');
    if (!blobs?.recoveryWrap) throw new Error('No hay datos de recuperación');
    const header = { kdf: 'PBKDF2-SHA256', version: 2, iterations: 600000, salt: blobs.recoverySalt };
    const rKek   = await Crypto.deriveKEK(phrase.join(' '), blobs.recoverySalt);
    let dekB64;
    try {
      dekB64 = await Crypto.decrypt(rKek, blobs.recoveryWrap, Crypto.buildAAD(header, 'recovery'));
    } catch { throw new Error('Frase de recuperación incorrecta'); }
    const dek       = await Crypto.importDEK(dekB64);
    const kdfHeader = await DB.get('kdf_header', 'header');
    const newSalt   = Crypto.newSalt();
    const newHeader = { ...kdfHeader, salt: newSalt };
    const newKek    = await Crypto.deriveKEK(newPassword, newSalt);
    const newAadDek = Crypto.buildAAD(newHeader, 'dek');
    const newAadVer = Crypto.buildAAD(newHeader, 'verifier');
    const newDekEnc = await Crypto.encrypt(newKek, dekB64, newAadDek);
    const newVerEnc = await Crypto.encrypt(newKek, { ok: true, v: 2, user: blobs.user || 'Usuario' }, newAadVer);
    const newBlobs  = { ...blobs, dekEnc: newDekEnc, verifierEnc: newVerEnc };
    await DB.atomicWrite([
      { store: 'kdf_header',   type: 'put', key: 'header', value: newHeader },
      { store: 'crypto_blobs', type: 'put', key: 'blobs',  value: newBlobs  },
    ]);
    return dek;
  }

  function renderPhrase(words, containerId) {
    const c = document.getElementById(containerId);
    if (!c) return;
    c.innerHTML = '';
    words.forEach((word, i) => {
      const el = document.createElement('div');
      el.className = 'phrase-word';
      el.innerHTML = `<span class="phrase-num">${i + 1}</span><span class="phrase-text">${word}</span>`;
      c.appendChild(el);
    });
  }

  function buildRecoveryInputs(containerId) {
    const c = document.getElementById(containerId);
    if (!c) return;
    c.innerHTML = '';
    for (let i = 0; i < 12; i++) {
      const wrap = document.createElement('div');
      wrap.className = 'recovery-word-wrap';
      wrap.innerHTML = `<span>${i + 1}</span><input type="text" data-idx="${i}" autocomplete="off" autocorrect="off" spellcheck="false" />`;
      c.appendChild(wrap);
    }
  }

  function getRecoveryWords(containerId) {
    return Array.from(document.querySelectorAll(`#${containerId} input`)).map(i => i.value.trim().toLowerCase());
  }

  return { generate, save, resetPassword, renderPhrase, buildRecoveryInputs, getRecoveryWords };
})();

// ─────────────────────────────────────────────
// HADES-V2-BIOMETRIC: WebAuthn Module
// ─────────────────────────────────────────────
const Biometric = (() => {
  const RP_ID   = location.hostname;
  const RP_NAME = 'Hades V2';

  function isSupported() { return !!(window.PublicKeyCredential && navigator.credentials); }
  function getMode() { return localStorage.getItem('hades_bio_mode') || 'off'; }
  function setMode(m) { localStorage.setItem('hades_bio_mode', m); }

  async function hasCredential() {
    const blobs = await DB.get('crypto_blobs', 'blobs');
    return !!(blobs?.bioCredentialId);
  }

  async function register(dek, kek) {
    if (!isSupported()) throw new Error('WebAuthn no disponible en este dispositivo');
    const userId    = crypto.getRandomValues(new Uint8Array(16));
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const credential = await navigator.credentials.create({
      publicKey: {
        rp: { id: RP_ID, name: RP_NAME },
        user: { id: userId, name: 'hades-user', displayName: 'Hades User' },
        challenge,
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        timeout: 60000,
        authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
        attestation: 'none'
      }
    });
    const credId  = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
    const header  = await DB.get('kdf_header', 'header');
    const dekB64  = await Crypto.exportDEK(dek);
    const aadBio  = Crypto.buildAAD(header, 'bio');
    const bioWrap = await Crypto.encrypt(kek, dekB64, aadBio);
    const blobs   = await DB.get('crypto_blobs', 'blobs');
    await DB.put('crypto_blobs', 'blobs', { ...blobs, bioCredentialId: credId, bioWrap });
    setMode('both');
  }

  async function authenticate(kek) {
    if (!isSupported()) throw new Error('WebAuthn no disponible');
    const blobs = await DB.get('crypto_blobs', 'blobs');
    if (!blobs?.bioCredentialId) throw new Error('Sin credencial biométrica registrada');
    const credId    = Uint8Array.from(atob(blobs.bioCredentialId), c => c.charCodeAt(0));
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    await navigator.credentials.get({
      publicKey: {
        rpId: RP_ID, challenge,
        allowCredentials: [{ id: credId, type: 'public-key' }],
        userVerification: 'required', timeout: 60000
      }
    });
    const header = await DB.get('kdf_header', 'header');
    const aadBio = Crypto.buildAAD(header, 'bio');
    const dekB64 = await Crypto.decrypt(kek, blobs.bioWrap, aadBio);
    return Crypto.importDEK(dekB64);
  }

  async function registerBioOnly(dek) {
    const b64    = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
    const bioKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const bioKeyB64 = b64(await crypto.subtle.exportKey('raw', bioKey));
    const dekB64    = await Crypto.exportDEK(dek);
    const bioOnlyWrap = await Crypto.encrypt(bioKey, dekB64, null);
    const blobs = await DB.get('crypto_blobs', 'blobs');
    await DB.put('crypto_blobs', 'blobs', { ...blobs, bioOnlyKeyB64: bioKeyB64, bioOnlyWrap });
  }

  async function authenticateBioOnly() {
    if (!isSupported()) throw new Error('WebAuthn no disponible');
    const blobs = await DB.get('crypto_blobs', 'blobs');
    if (!blobs?.bioCredentialId || !blobs?.bioOnlyKeyB64 || !blobs?.bioOnlyWrap) {
      throw new Error('Huella de solo acceso no configurada. Desactiva y vuelve a activar la opción en Ajustes.');
    }
    const unb64  = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
    const credId = unb64(blobs.bioCredentialId);
    await navigator.credentials.get({
      publicKey: {
        rpId: RP_ID, challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ id: credId, type: 'public-key' }],
        userVerification: 'required', timeout: 60000
      }
    });
    const bioKey = await crypto.subtle.importKey(
      'raw', unb64(blobs.bioOnlyKeyB64), { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const dekB64 = await Crypto.decrypt(bioKey, blobs.bioOnlyWrap, null);
    return Crypto.importDEK(dekB64);
  }

  async function unregisterBioOnly() {
    const blobs = await DB.get('crypto_blobs', 'blobs');
    if (!blobs) return;
    const { bioOnlyKeyB64, bioOnlyWrap, ...rest } = blobs;
    await DB.put('crypto_blobs', 'blobs', rest);
    setMode('both');
  }

  async function unregister() {
    const blobs = await DB.get('crypto_blobs', 'blobs');
    if (!blobs) return;
    const { bioCredentialId, bioWrap, bioOnlyKeyB64, bioOnlyWrap, ...rest } = blobs;
    await DB.put('crypto_blobs', 'blobs', rest);
    setMode('off');
  }

  return { isSupported, getMode, setMode, hasCredential, register, authenticate, registerBioOnly, authenticateBioOnly, unregisterBioOnly, unregister };
})();

// ─────────────────────────────────────────────
// HADES-V2-REAUTH: Re-authentication Module
// ─────────────────────────────────────────────
const Reauth = (() => {
  const WINDOW = 120_000;
  let _ts = null;

  function isValid() { return _ts !== null && (Date.now() - _ts) < WINDOW; }
  function confirm() { _ts = Date.now(); }
  function invalidate() { _ts = null; }

  async function require(actionLabel) {
    if (isValid()) return true;
    return new Promise(resolve => {
      State.reauthResolve = resolve;
      UI.showReauth(actionLabel);
    });
  }

  return { isValid, confirm, invalidate, require };
})();

// ─────────────────────────────────────────────
// HADES-V2-BACKUP: Import / Export Module
// ─────────────────────────────────────────────
const Backup = (() => {
  async function checksum(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function exportVault() {
    const ok = await Reauth.require('exportar backup');
    if (!ok) return;
    const header   = await DB.get('kdf_header', 'header');
    const blobs    = await DB.get('crypto_blobs', 'blobs');
    const vaultEnc = await DB.get('vault', 'data');
    if (!header || !blobs || !vaultEnc) { UI.toast('No hay bóveda para exportar', 'error'); return; }
    const cs = await checksum(JSON.stringify(vaultEnc));
    const backup = { format: 'hades-backup', version: 2, created_at: new Date().toISOString(), kdf_header: header, crypto_blobs: blobs, vault_enc: vaultEnc, checksum: cs };
    const blob = new Blob([JSON.stringify(backup)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `hades-backup-${Date.now()}.hades`; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    UI.toast('Backup exportado correctamente', 'success');
  }

  async function loadFile(file) {
    if (file.size > 512 * 1024) throw new Error('Archivo demasiado grande (máximo 512KB)');
    let data;
    try { data = JSON.parse(await file.text()); } catch { throw new Error('JSON inválido'); }
    if (data.format !== 'hades-backup') throw new Error('Formato no reconocido');
    if (data.version !== 2) throw new Error('Versión de backup incompatible');
    if (!data.kdf_header || !data.crypto_blobs || !data.vault_enc) throw new Error('Backup incompleto');
    const cs = await checksum(JSON.stringify(data.vault_enc));
    if (cs !== data.checksum) throw new Error('Checksum inválido — backup corrupto o modificado');
    await DB.put('import_staging', 'data', data);
    return data;
  }

  async function promoteImport(password) {
    const data = await DB.get('import_staging', 'data');
    if (!data) throw new Error('No hay backup en staging');
    const kek = await Crypto.deriveKEK(password, data.kdf_header.salt);
    const aadVer = Crypto.buildAAD(data.kdf_header, 'verifier');
    try {
      const ver = await Crypto.decrypt(kek, data.crypto_blobs.verifierEnc, aadVer);
      if (!ver?.ok) throw new Error('Verificación fallida');
    } catch { throw new Error('Contraseña incorrecta para este backup'); }
    await DB.snapshot();
    try {
      await DB.atomicWrite([
        { store: 'kdf_header',   type: 'put', key: 'header', value: data.kdf_header   },
        { store: 'crypto_blobs', type: 'put', key: 'blobs',  value: data.crypto_blobs },
        { store: 'vault',        type: 'put', key: 'data',   value: data.vault_enc    },
      ]);
    } catch (e) {
      await DB.rollback();
      throw new Error('Error al importar — estado anterior restaurado');
    }
    await DB.clear('import_staging');
    await DB.del('staging', 'snap');
  }

  return { exportVault, loadFile, promoteImport };
})();

// ─────────────────────────────────────────────
// HADES-V2-STATE: Application State
// ─────────────────────────────────────────────
const State = {
  dek: null,
  kek: null,
  dekB64: null,
  user: '',
  entries: [],
  failedAttempts: 0,
  MAX_ATTEMPTS: 3,
  _lockTimer: null,
  _pendingPhrase: null,
  _pendingDekB64: null,
  reauthResolve: null,
  _importData: null,
  currentEditId: null,
  currentCat: 'all',
};

// ─────────────────────────────────────────────
// HADES-V2-UI: UI Utilities
// ─────────────────────────────────────────────
const UI = (() => {
  function $(id) { return document.getElementById(id); }
  function show(id)  { const e = $(id); if (e) e.classList.remove('hidden'); }
  function hide(id)  { const e = $(id); if (e) e.classList.add('hidden'); }

  function setPage(page) {
    document.querySelectorAll('.page').forEach(p => p.classList.toggle('hidden', p.id !== `page-${page}`));
    document.body.dataset.page = page;
  }

  function setState(stateId) {
    ['state-loading','state-setup-1','state-setup-2','state-setup-3','state-login','state-recovery','state-new-password']
      .forEach(s => { const e = $(s); if (e) e.classList.toggle('hidden', s !== stateId); });
  }

  function setView(view) {
    document.querySelectorAll('.view').forEach(v => {
      const isActive = v.id === `view-${view}`;
      v.classList.toggle('active', isActive);
      v.classList.toggle('hidden', !isActive);
    });
    document.querySelectorAll('[data-view]').forEach(n => n.classList.toggle('active', n.dataset.view === view));
    const titles = { vault: 'Bóveda', generator: 'Generador', settings: 'Ajustes', help: 'Ayuda' };
    const el = $('view-title'); if (el) el.textContent = titles[view] || view;
  }

  function showModal(id)  { const m = $(id); if (m) { m.classList.remove('hidden'); } }
  function hideModal(id)  { const m = $(id); if (m) { m.classList.add('hidden'); } }

  function showReauth(label) {
    const el = $('reauth-action-msg');
    if (el) el.textContent = `Verificación requerida para: ${label}`;
    hide('reauth-error');
    const inp = $('reauth-password'); if (inp) inp.value = '';
    showModal('modal-reauth');
    setTimeout(() => { if (inp) inp.focus(); }, 100);
  }

  let _toastTimer = null;
  function toast(msg, type = '') {
    const t = $('toast');
    if (!t) return;
    t.textContent = msg;
    t.className = `toast${type ? ' ' + type : ''}`;
    t.classList.remove('hidden');
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => t.classList.add('hidden'), 3000);
  }

  function err(id, msg) {
    const el = $(id);
    if (!el) return;
    if (msg) { el.textContent = msg; el.classList.remove('hidden'); }
    else el.classList.add('hidden');
  }

  function eyeToggle(targetId) {
    const inp = $(targetId);
    if (!inp) return;
    inp.type = inp.type === 'password' ? 'text' : 'password';
  }

  function passwordStrength(pwd) {
    if (!pwd) return { pct: 0, label: '', color: '' };
    let score = 0;
    if (pwd.length >= 8)  score++;
    if (pwd.length >= 12) score++;
    if (pwd.length >= 16) score++;
    if (/[A-Z]/.test(pwd)) score++;
    if (/[a-z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    const levels = [
      { pct: 0,   label: '',           color: '' },
      { pct: 15,  label: 'Muy débil',  color: '#f87171' },
      { pct: 30,  label: 'Débil',      color: '#fb923c' },
      { pct: 50,  label: 'Regular',    color: '#fbbf24' },
      { pct: 70,  label: 'Buena',      color: '#34d399' },
      { pct: 85,  label: 'Fuerte',     color: '#34d399' },
      { pct: 100, label: 'Muy fuerte', color: '#6ee7b7' },
    ];
    return levels[Math.min(score, 6)];
  }

  function updateStrength(pwdId, fillId, labelId, wrapId) {
    const pwd  = $(pwdId)?.value || '';
    const s    = passwordStrength(pwd);
    const fill = $(fillId);
    const lbl  = $(labelId);
    const wrap = $(wrapId);
    if (!fill || !lbl) return;
    if (pwd.length === 0) { if (wrap) wrap.classList.add('hidden'); return; }
    if (wrap) wrap.classList.remove('hidden');
    fill.style.width = s.pct + '%';
    fill.style.background = s.color;
    lbl.textContent = s.label;
  }

  function clearClipboardAfter(ms = 30000) {
    setTimeout(() => {
      try { navigator.clipboard.writeText(''); } catch {}
    }, ms);
  }

  async function copyToClipboard(text, label = 'Copiado') {
    try {
      await navigator.clipboard.writeText(text);
      toast(`${label} copiado`, 'success');
      clearClipboardAfter(30000);
    } catch { toast('No se pudo copiar', 'error'); }
  }

  return { $, show, hide, setPage, setState, setView, showModal, hideModal, showReauth, toast, err, eyeToggle, passwordStrength, updateStrength, copyToClipboard };
})();

// ─────────────────────────────────────────────
// HADES-V2-APP: Application Controller
// ─────────────────────────────────────────────
const App = (() => {
  const $ = UI.$;

  // ── Utils ──
  function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2); }
  function on(id, ev, fn) { const e = $(id); if (e) e.addEventListener(ev, fn); }

  // ── Shader Background (dual WebGL programs: aurora dark / stripe light) ──
  function initShaderBackground() {
    const container = document.getElementById('parallax-bg');
    if (!container) return;

    const canvas = document.createElement('canvas');
    canvas.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;display:block;';
    container.insertBefore(canvas, container.querySelector('.grid-overlay'));

    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return;

    const VS = `attribute vec2 a_pos; void main(){ gl_Position=vec4(a_pos,0,1); }`;

    // ── Dark: aurora ──
    const DARK_FS = `
      precision mediump float;
      uniform float iTime; uniform vec2 iResolution;
      #define NO 3
      float rand(vec2 n){ return fract(sin(dot(n,vec2(12.9898,4.1414)))*43758.5453); }
      float noise(vec2 p){
        vec2 ip=floor(p),u=fract(p); u=u*u*(3.0-2.0*u);
        return mix(mix(rand(ip),rand(ip+vec2(1,0)),u.x),mix(rand(ip+vec2(0,1)),rand(ip+vec2(1,1)),u.x),u.y);
      }
      float fbm(vec2 x){
        float v=0.0,a=0.3; vec2 sh=vec2(100.0);
        mat2 r=mat2(cos(0.5),sin(0.5),-sin(0.5),cos(0.5));
        for(int i=0;i<NO;++i){ v+=a*noise(x); x=r*x*2.0+sh; a*=0.4; } return v;
      }
      vec3 tnh(vec3 x){ vec3 e=exp(2.0*clamp(x,-8.0,8.0)); return (e-1.0)/(e+1.0); }
      void main(){
        vec2 shake=vec2(sin(iTime*1.2)*0.005,cos(iTime*2.1)*0.005);
        vec2 p=((gl_FragCoord.xy+shake*iResolution)-iResolution*0.5)/iResolution.y*mat2(6,-4,4,6);
        vec2 v; vec4 o=vec4(0);
        float f=2.0+fbm(p+vec2(iTime*5.0,0.0))*0.5;
        for(float i=0.0;i<20.0;i++){
          v=p+cos(i*i+(iTime+p.x*0.08)*0.025+i*vec2(13,11))*3.5
            +vec2(sin(iTime*3.0+i)*0.003,cos(iTime*3.5-i)*0.003);
          float tn=fbm(v+vec2(iTime*0.5,i))*0.3*(1.0-i/20.0);
          vec4 ac=vec4(0.1+0.3*sin(i*0.2+iTime*0.4),0.3+0.5*cos(i*0.3+iTime*0.5),0.7+0.3*sin(i*0.4+iTime*0.3),1);
          vec4 c=ac*exp(sin(i*i+iTime*0.8))/length(max(v,vec2(v.x*f*0.015,v.y*1.5)));
          o+=c*(1.0+tn*0.8)*smoothstep(0.0,1.0,i/20.0)*0.6;
        }
        vec3 col=pow(clamp(o.rgb/100.0,0.0001,10.0),vec3(1.6));
        gl_FragColor=vec4(tnh(col)*1.5,1.0);
      }
    `;

    // ── Light: stripe gradient (white / cyan #42FFE9 / purple #8106BE) ──
    const LIGHT_FS = `
      precision mediump float;
      uniform float iTime; uniform vec2 iResolution;
      float hash(vec2 p){ return fract(sin(dot(p,vec2(127.1,311.7)))*43758.5453); }
      float snoise(vec2 p){
        vec2 i=floor(p),f=fract(p); f=f*f*(3.0-2.0*f);
        return mix(mix(hash(i),hash(i+vec2(1,0)),f.x),mix(hash(i+vec2(0,1)),hash(i+vec2(1,1)),f.x),f.y);
      }
      void main(){
        vec2 uv=gl_FragCoord.xy/iResolution;
        float n=snoise(uv*3.0+vec2(iTime*0.08,iTime*0.05))*0.08;
        float t=(uv.x-uv.y+n)*2.2+iTime*0.1;
        const float PI=3.14159265;
        float w1=sin(t*PI)*0.5+0.5;
        float w2=sin(t*PI+2.094)*0.5+0.5;
        float w3=sin(t*PI+4.189)*0.5+0.5;
        float ws=w1+w2+w3;
        vec3 c1=vec3(1.000,1.000,1.000);
        vec3 c2=vec3(0.259,1.000,0.914);
        vec3 c3=vec3(0.506,0.024,0.745);
        vec3 col=(c1*w1+c2*w2+c3*w3)/ws;
        col=mix(col,vec3(1.0),0.30);
        gl_FragColor=vec4(col,1.0);
      }
    `;

    function mkProg(fs) {
      function sh(type, src) {
        const s = gl.createShader(type);
        gl.shaderSource(s, src); gl.compileShader(s); return s;
      }
      const p = gl.createProgram();
      gl.attachShader(p, sh(gl.VERTEX_SHADER, VS));
      gl.attachShader(p, sh(gl.FRAGMENT_SHADER, fs));
      gl.linkProgram(p);
      return p;
    }

    // Lazy compilation: compile only initial theme at startup
    let darkProg = null, lightProg = null;

    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1,1,-1,-1,1,1,1]), gl.STATIC_DRAW);

    function activateProg(prog) {
      gl.useProgram(prog);
      const loc = gl.getAttribLocation(prog, 'a_pos');
      gl.enableVertexAttribArray(loc);
      gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
      return {
        uTime: gl.getUniformLocation(prog, 'iTime'),
        uRes:  gl.getUniformLocation(prog, 'iResolution')
      };
    }

    let isLight = document.body.classList.contains('theme-light');
    // Compile only the active theme's shader at startup
    if (isLight) {
      if (!lightProg) lightProg = mkProg(LIGHT_FS);
    } else {
      if (!darkProg) darkProg = mkProg(DARK_FS);
    }
    let uni = activateProg(isLight ? lightProg : darkProg);

    // Called by applyTheme
    window._bgSetTheme = (light) => {
      if (isLight === light) return;
      isLight = light;
      // Lazy compile the target theme if not already compiled
      if (isLight) {
        if (!lightProg) lightProg = mkProg(LIGHT_FS);
      } else {
        if (!darkProg) darkProg = mkProg(DARK_FS);
      }
      uni = activateProg(isLight ? lightProg : darkProg);
      gl.uniform2f(uni.uRes, canvas.width, canvas.height);
    };

    function resize() {
      const pr = Math.min(window.devicePixelRatio, 1.5);
      canvas.width  = window.innerWidth  * pr;
      canvas.height = window.innerHeight * pr;
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.uniform2f(uni.uRes, canvas.width, canvas.height);
    }
    resize();
    window.addEventListener('resize', resize);

    const t0 = performance.now();
    let _raf;
    function draw(now) {
      gl.uniform1f(uni.uTime, (now - t0) * 0.001);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      _raf = requestAnimationFrame(draw);
    }
    _raf = requestAnimationFrame(draw);

    document.addEventListener('visibilitychange', () => {
      if (document.hidden) { cancelAnimationFrame(_raf); _raf = null; }
      else if (!_raf) _raf = requestAnimationFrame(draw);
    });
  }

  // ── Parallax (replaced by shader) ──
  function initParallax() {
    initShaderBackground();
  }

  function initTilt() {
    document.querySelectorAll('.tilt-card').forEach(card => {
      card.addEventListener('mousemove', e => {
        const r = card.getBoundingClientRect();
        const x = (e.clientX - r.left) / r.width  - 0.5;
        const y = (e.clientY - r.top)  / r.height - 0.5;
        card.style.transform = `perspective(900px) rotateY(${x * 7}deg) rotateX(${-y * 7}deg) translateZ(6px)`;
      });
      card.addEventListener('mouseleave', () => {
        card.style.transform = 'perspective(900px) rotateY(0) rotateX(0) translateZ(0)';
      });
    });
  }

  // ── Theme ──
  function applyTheme(t) {
    document.body.classList.toggle('theme-light', t === 'light');
    document.body.classList.toggle('theme-dark',  t !== 'light');
    localStorage.setItem('hades_theme', t);
    if (window._bgSetTheme) window._bgSetTheme(t === 'light');
    const lb = $('theme-light-btn'); const db = $('theme-dark-btn');
    if (lb) lb.classList.toggle('active', t === 'light');
    if (db) db.classList.toggle('active', t !== 'light');
  }
  function initTheme() {
    applyTheme(localStorage.getItem('hades_theme') || 'dark');
    on('theme-toggle-unlock', 'click', () => applyTheme(document.body.classList.contains('theme-light') ? 'dark' : 'light'));
    on('theme-toggle-app',    'click', () => applyTheme(document.body.classList.contains('theme-light') ? 'dark' : 'light'));
    on('theme-light-btn', 'click', () => applyTheme('light'));
    on('theme-dark-btn',  'click', () => applyTheme('dark'));
  }

  // ── Eye buttons ──
  function initEyeButtons() {
    document.querySelectorAll('.eye-btn').forEach(btn => {
      btn.addEventListener('click', () => UI.eyeToggle(btn.dataset.target));
    });
  }

  // ── Sidebar ──
  function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');

    function closeSidebar() {
      if (sidebar) sidebar.classList.remove('open');
      if (backdrop) backdrop.classList.remove('active');
    }

    on('sidebar-toggle', 'click', () => {
      if (!sidebar) return;
      const isOpen = sidebar.classList.toggle('open');
      if (backdrop) backdrop.classList.toggle('active', isOpen);
    });

    if (backdrop) backdrop.addEventListener('click', closeSidebar);

    document.querySelectorAll('.nav-item[data-view]').forEach(btn => {
      btn.addEventListener('click', () => {
        UI.setView(btn.dataset.view);
        closeSidebar();
      });
    });

    document.querySelectorAll('.bottom-nav-item[data-view]').forEach(btn => {
      btn.addEventListener('click', () => UI.setView(btn.dataset.view));
    });

    on('btn-lock', 'click', lock);
    on('btn-lock-bottom', 'click', lock);
  }

  // ── Auto-lock ──
  function startLockTimer() {
    clearTimeout(State._lockTimer);
    const secs = parseInt(localStorage.getItem('hades_autolock') || '300');
    if (secs <= 0) return;
    State._lockTimer = setTimeout(lock, secs * 1000);
    ['click','keydown','touchstart','mousemove'].forEach(ev =>
      document.addEventListener(ev, resetLockTimer, { passive: true })
    );
  }
  function resetLockTimer() {
    clearTimeout(State._lockTimer);
    const secs = parseInt(localStorage.getItem('hades_autolock') || '300');
    if (secs > 0) State._lockTimer = setTimeout(lock, secs * 1000);
  }
  function lock() {
    clearTimeout(State._lockTimer);
    State.dek = null; State.kek = null; State.dekB64 = null; State.entries = [];
    State.failedAttempts = 0;
    Reauth.invalidate();
    UI.setPage('unlock');
    UI.setState('state-login');
    const lp = $('login-password'); if (lp) lp.value = '';
    UI.hide('login-error'); UI.hide('login-attempts-wrap');
  }

  // ── Enter App ──
  async function enterApp(dek, kek, user) {
    State.dek = dek; State.kek = kek; State.user = user || 'Usuario';
    State.failedAttempts = 0;
    State.entries = await Crypto.loadVault(dek);
    const el = document.getElementById('home-username');
    UI.setPage('app');
    UI.setView('vault');
    renderEntries();
    updateBioSettings();
    const al = $('autolock-select');
    if (al) al.value = localStorage.getItem('hades_autolock') || '300';
    on('autolock-select', 'change', () => localStorage.setItem('hades_autolock', $('autolock-select').value));
    startLockTimer();
  }

  // ── SETUP ──
  function initSetup() {
    // Strength meter on step 1
    on('reg-password', 'input', () => UI.updateStrength('reg-password','reg-strength-fill','reg-strength-label','reg-strength-wrap'));

    on('btn-setup-next-1', 'click', () => {
      const name = $('reg-name')?.value.trim();
      const pwd  = $('reg-password')?.value;
      const conf = $('reg-confirm')?.value;
      if (!name) { UI.err('setup-err-1', 'Ingresa tu nombre'); return; }
      if (!pwd || pwd.length < 10) { UI.err('setup-err-1', 'La contraseña debe tener al menos 10 caracteres'); return; }
      if (pwd !== conf) { UI.err('setup-err-1', 'Las contraseñas no coinciden'); return; }
      UI.err('setup-err-1', '');
      State._setupName = name;
      State._setupPwd  = pwd;
      UI.setState('state-setup-2');
    });

    on('btn-setup-back-2', 'click', () => UI.setState('state-setup-1'));

    on('btn-setup-next-2', 'click', async () => {
      const mode = document.querySelector('input[name="access-mode"]:checked')?.value || 'password';
      State._setupMode = mode;
      const btn = $('btn-setup-next-2');
      btn.disabled = true; btn.textContent = 'Creando bóveda…';
      try {
        const { dek, dekB64 } = await Crypto.initVault(State._setupPwd, State._setupName);
        const phrase = Recovery.generate();
        State._pendingPhrase  = phrase;
        State._pendingDekB64  = dekB64;
        State._pendingDek     = dek;
        await Recovery.save(phrase, dekB64);
        Recovery.renderPhrase(phrase, 'phrase-display');
        UI.setState('state-setup-3');
      } catch (e) {
        console.error('Setup error:', e);
        UI.err('setup-err-2', 'Error al crear la bóveda. Intenta de nuevo.');
      } finally {
        btn.disabled = false; btn.textContent = 'Siguiente →';
      }
    });

    on('btn-setup-finish', 'click', async () => {
      if (State._setupMode === 'both' && Biometric.isSupported()) {
        try {
          const result = await Crypto.verifyPassword(State._setupPwd);
          if (result) await Biometric.register(result.dek, result.kek);
        } catch (e) {
          console.warn('Biometric registration skipped:', e);
        }
      }
      await enterApp(State._pendingDek, null, State._setupName);
      State._setupPwd = null; State._pendingDekB64 = null;
    });
  }

  // ── LOGIN ──
  function initLogin() {
    on('btn-login', 'click', async () => {
      const pwd = $('login-password')?.value;
      if (!pwd) return;
      const btn = $('btn-login');
      btn.disabled = true; btn.textContent = 'Verificando…';
      try {
        const result = await Crypto.verifyPassword(pwd);
        if (!result) {
          State.failedAttempts++;
          const left = State.MAX_ATTEMPTS - State.failedAttempts;
          if (left <= 0) {
            UI.err('login-error', 'Sin intentos restantes.');
            UI.show('login-attempts-wrap');
            $('login-attempts-msg').textContent = 'Usa tu frase de recuperación para restablecer el acceso.';
            btn.disabled = true;
          } else {
            UI.err('login-error', `Contraseña incorrecta. ${left} intento${left > 1 ? 's' : ''} restante${left > 1 ? 's' : ''}.`);
            if (State.failedAttempts >= 2) {
              UI.show('login-attempts-wrap');
              $('login-attempts-msg').textContent = `Quedan ${left} intento${left > 1 ? 's' : ''}.`;
            }
          }
          return;
        }
        const blobs = await DB.get('crypto_blobs', 'blobs');
        await enterApp(result.dek, result.kek, result.user || blobs?.user || 'Usuario');
      } finally {
        if ($('btn-login')) { btn.disabled = false; btn.textContent = 'Entrar'; }
      }
    });

    on('login-password', 'keydown', e => { if (e.key === 'Enter') $('btn-login')?.click(); });

    on('btn-forgot', 'click', () => {
      Recovery.buildRecoveryInputs('recovery-input-grid');
      UI.setState('state-recovery');
      UI.hide('recovery-error');
    });

    on('btn-biometric-login', 'click', async () => {
      UI.toast('Ingresa tu contraseña primero. La huella es un segundo factor desde Ajustes.', '');
    });

    on('btn-bio-only-login', 'click', async () => {
      const btn = $('btn-bio-only-login');
      if (btn) btn.classList.add('loading');
      try {
        const dek = await Biometric.authenticateBioOnly();
        const blobs = await DB.get('crypto_blobs', 'blobs');
        await enterApp(dek, null, blobs?.user || 'Usuario');
      } catch (e) {
        UI.toast(e.message || 'Error de autenticación biométrica', 'error');
      } finally {
        if (btn) btn.classList.remove('loading');
      }
    });

    on('btn-use-password', 'click', () => {
      UI.hide('login-bio-only-wrap');
      UI.show('login-pw-wrap');
      setTimeout(() => { $('login-password')?.focus(); }, 100);
    });
  }

  // ── RECOVERY ──
  function initRecovery() {
    on('btn-recovery-back', 'click', () => UI.setState('state-login'));
    on('btn-recovery-verify', 'click', async () => {
      const words = Recovery.getRecoveryWords('recovery-input-grid');
      if (words.some(w => !w)) { UI.err('recovery-error', 'Completa las 12 palabras.'); return; }
      const btn = $('btn-recovery-verify');
      btn.disabled = true; btn.textContent = 'Verificando…';
      try {
        // Try to validate phrase by attempting decrypt
        const blobs = await DB.get('crypto_blobs', 'blobs');
        if (!blobs?.recoveryWrap) { UI.err('recovery-error', 'No hay datos de recuperación guardados.'); return; }
        const header = { kdf: 'PBKDF2-SHA256', version: 2, iterations: 600000, salt: blobs.recoverySalt };
        const rKek   = await Crypto.deriveKEK(words.join(' '), blobs.recoverySalt);
        try {
          await Crypto.decrypt(rKek, blobs.recoveryWrap, Crypto.buildAAD(header, 'recovery'));
        } catch { UI.err('recovery-error', 'Frase incorrecta. Verifica las palabras.'); return; }
        State._pendingRecoveryWords = words;
        UI.err('recovery-error', '');
        UI.setState('state-new-password');
        const npi = $('new-pw-input'); if (npi) { npi.value = ''; npi.focus(); }
        const npc = $('new-pw-confirm'); if (npc) npc.value = '';
      } finally {
        btn.disabled = false; btn.textContent = 'Verificar';
      }
    });

    on('btn-new-pw-save', 'click', async () => {
      const pwd  = $('new-pw-input')?.value;
      const conf = $('new-pw-confirm')?.value;
      if (!pwd || pwd.length < 10) { UI.err('new-pw-error', 'Mínimo 10 caracteres.'); return; }
      if (pwd !== conf)            { UI.err('new-pw-error', 'Las contraseñas no coinciden.'); return; }
      const btn = $('btn-new-pw-save');
      btn.disabled = true; btn.textContent = 'Guardando…';
      try {
        const dek = await Recovery.resetPassword(State._pendingRecoveryWords, pwd);
        State._pendingRecoveryWords = null;
        const result = await Crypto.verifyPassword(pwd);
        if (result) await enterApp(result.dek, result.kek, result.user);
        else        UI.err('new-pw-error', 'Error inesperado. Intenta de nuevo.');
      } catch (e) {
        UI.err('new-pw-error', e.message);
      } finally {
        btn.disabled = false; btn.textContent = 'Guardar contraseña';
      }
    });
  }

  // ── VAULT — Entry rendering ──
  const ICONS = {
    login: `<svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
    card:  `<svg viewBox="0 0 24 24"><rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>`,
    note:  `<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`,
    identity: `<svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
  };
  const TYPE_CLASS = { login: '', card: 'card-type', note: 'note-type', identity: 'id-type' };

  function entryTitle(e) {
    if (e.type === 'login')    return e.name || e.username || 'Login';
    if (e.type === 'card')     return e.name || 'Tarjeta';
    if (e.type === 'note')     return e.title || 'Nota';
    if (e.type === 'identity') return `${e.firstName || ''} ${e.lastName || ''}`.trim() || 'Identidad';
    return 'Entrada';
  }
  function entrySub(e) {
    if (e.type === 'login')    return e.username || e.url || '';
    if (e.type === 'card')     return e.number ? '•••• ' + e.number.slice(-4) : '';
    if (e.type === 'note')     return '';
    if (e.type === 'identity') return e.email || '';
    return '';
  }

  function renderEntries() {
    const grid = $('entries-grid'); const empty = $('empty-state');
    if (!grid) return;
    const q    = $('search-input')?.value?.toLowerCase() || '';
    const cat  = State.currentCat;
    const list = State.entries.filter(e => {
      if (cat !== 'all' && e.type !== cat) return false;
      if (!q) return true;
      return (entryTitle(e) + entrySub(e)).toLowerCase().includes(q);
    });
    if (!list.length) {
      grid.innerHTML = ''; grid.classList.add('hidden'); empty?.classList.remove('hidden');
      return;
    }
    grid.classList.remove('hidden'); empty?.classList.add('hidden');
    grid.innerHTML = list.map(e => `
      <div class="entry-card" data-id="${e.id}">
        <div class="entry-card-header">
          <div class="entry-icon ${TYPE_CLASS[e.type] || ''}">${ICONS[e.type] || ''}</div>
          <div>
            <div class="entry-name">${escHtml(entryTitle(e))}</div>
            <div class="entry-sub">${escHtml(entrySub(e))}</div>
          </div>
        </div>
      </div>`).join('');
    grid.querySelectorAll('.entry-card').forEach(card => {
      card.addEventListener('click', () => openViewModal(card.dataset.id));
    });
  }

  function escHtml(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function initVaultView() {
    on('search-input', 'input', renderEntries);
    $('category-tabs')?.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => {
        $('category-tabs').querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        State.currentCat = tab.dataset.cat;
        renderEntries();
      });
    });
    on('btn-add-entry',  'click', () => openEntryModal(null));
    on('btn-add-first',  'click', () => openEntryModal(null));
  }

  // ── Entry Modal ──
  function openEntryModal(id) {
    State.currentEditId = id || null;
    const entry = id ? State.entries.find(e => e.id === id) : null;
    const $$ = UI.$;
    $$('modal-entry-title').textContent = entry ? 'Editar entrada' : 'Nueva entrada';
    const type = entry?.type || 'login';
    $$('entry-type').value = type;
    showFieldsForType(type);
    if (entry) populateEntryForm(entry);
    else clearEntryForm();
    UI.showModal('modal-entry');
  }

  function showFieldsForType(type) {
    ['fields-login','fields-card','fields-note','fields-identity'].forEach(id => UI.hide(id));
    UI.show(`fields-${type}`);
  }

  function clearEntryForm() {
    ['f-name','f-url','f-username','f-password','f-notes',
     'c-name','c-number','c-expiry','c-cvv','c-notes',
     'n-title','n-content','i-first','i-last','i-email','i-phone','i-address'
    ].forEach(id => { const e = UI.$(id); if (e) e.value = ''; });
  }

  function populateEntryForm(e) {
    const set = (id, v) => { const el = UI.$(id); if (el) el.value = v || ''; };
    if (e.type === 'login') {
      set('f-name', e.name); set('f-url', e.url); set('f-username', e.username); set('f-password', e.password); set('f-notes', e.notes);
    } else if (e.type === 'card') {
      set('c-name', e.name); set('c-number', e.number); set('c-expiry', e.expiry); set('c-cvv', e.cvv); set('c-notes', e.notes);
    } else if (e.type === 'note') {
      set('n-title', e.title); set('n-content', e.content);
    } else if (e.type === 'identity') {
      set('i-first', e.firstName); set('i-last', e.lastName); set('i-email', e.email); set('i-phone', e.phone); set('i-address', e.address);
    }
  }

  function collectEntryForm(type) {
    const v = id => UI.$(id)?.value?.trim() || '';
    if (type === 'login')    return { type, name: v('f-name'), url: v('f-url'), username: v('f-username'), password: v('f-password'), notes: v('f-notes') };
    if (type === 'card')     return { type, name: v('c-name'), number: v('c-number'), expiry: v('c-expiry'), cvv: v('c-cvv'), notes: v('c-notes') };
    if (type === 'note')     return { type, title: v('n-title'), content: v('n-content') };
    if (type === 'identity') return { type, firstName: v('i-first'), lastName: v('i-last'), email: v('i-email'), phone: v('i-phone'), address: v('i-address') };
  }

  function initEntryModal() {
    on('entry-type', 'change', () => showFieldsForType(UI.$('entry-type').value));
    on('modal-entry-close',  'click', () => UI.hideModal('modal-entry'));
    on('modal-entry-cancel', 'click', () => UI.hideModal('modal-entry'));
    on('btn-gen-quick', 'click', () => {
      const pwd = generatePassword(16, true, true, true, true);
      const el  = UI.$('f-password'); if (el) el.value = pwd;
    });
    on('modal-entry-save', 'click', async () => {
      const type  = UI.$('entry-type').value;
      const data  = collectEntryForm(type);
      if (State.currentEditId) {
        const idx = State.entries.findIndex(e => e.id === State.currentEditId);
        if (idx >= 0) State.entries[idx] = { ...State.entries[idx], ...data };
      } else {
        State.entries.push({ id: uid(), createdAt: Date.now(), ...data });
      }
      await Crypto.saveVault(State.dek, State.entries);
      UI.hideModal('modal-entry');
      renderEntries();
      UI.toast(State.currentEditId ? 'Entrada actualizada' : 'Entrada guardada', 'success');
    });
  }

  // ── View Modal ──
  function openViewModal(id) {
    const entry = State.entries.find(e => e.id === id);
    if (!entry) return;
    State.currentEditId = id;
    const title = UI.$('view-entry-title');
    const body  = UI.$('view-entry-body');
    if (title) title.textContent = entryTitle(entry);
    if (body)  body.innerHTML = buildViewBody(entry);
    body?.querySelectorAll('[data-copy]').forEach(btn => {
      btn.addEventListener('click', () => {
        const field = btn.dataset.copy;
        if (field === 'cvv' || field === 'number') {
          Reauth.require('ver datos sensibles de tarjeta').then(ok => {
            if (ok) UI.copyToClipboard(entry[field] || '', field.toUpperCase());
          });
        } else {
          UI.copyToClipboard(entry[field] || '', btn.dataset.label || field);
        }
      });
    });
    const SVG_EYE    = `<svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    const SVG_EYEOFF = `<svg viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
    body?.querySelectorAll('[data-reveal]').forEach(btn => {
      btn.addEventListener('click', () => {
        const field   = btn.dataset.reveal;
        const visible = btn.dataset.visible === 'true';
        const span    = body.querySelector(`[data-field="${field}"]`);
        if (!span) return;
        if (!visible) {
          span.textContent     = span.dataset.actual;
          btn.innerHTML        = SVG_EYEOFF;
          btn.dataset.visible  = 'true';
        } else {
          span.textContent     = '••••';
          btn.innerHTML        = SVG_EYE;
          btn.dataset.visible  = 'false';
        }
      });
    });
    UI.showModal('modal-view');
  }

  function buildViewBody(e) {
    const SVG_COPY = `<svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
    const SVG_EYE  = `<svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    const SVG_EYEOFF = `<svg viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
    const row = (label, val, field, sensitive = false) => {
      if (!val) return '';
      const escaped = escHtml(val);
      const display = sensitive ? '••••' : escaped;
      const eyeBtn  = sensitive
        ? `<button class="icon-btn" data-reveal="${field}" data-visible="false" title="Mostrar/ocultar">${SVG_EYE}</button>`
        : '';
      return `<div class="view-row"><span class="view-label">${label}</span><div class="view-val-wrap"><span class="view-val" data-field="${field}" data-actual="${escaped}">${display}</span>${eyeBtn}<button class="icon-btn" data-copy="${field}" data-label="${label}">${SVG_COPY}</button></div></div>`;
    };
    if (e.type === 'login')    return row('Sitio', e.name, 'name') + row('URL', e.url, 'url') + row('Usuario', e.username, 'username') + row('Contraseña', e.password, 'password', true) + row('Notas', e.notes, 'notes');
    if (e.type === 'card')     return row('Nombre', e.name, 'name') + row('Número', e.number, 'number', true) + row('Vencimiento', e.expiry, 'expiry') + row('CVV', e.cvv, 'cvv', true) + row('Notas', e.notes, 'notes');
    if (e.type === 'note')     return row('Título', e.title, 'title') + row('Contenido', e.content, 'content');
    if (e.type === 'identity') return row('Nombre', e.firstName, 'firstName') + row('Apellido', e.lastName, 'lastName') + row('Email', e.email, 'email') + row('Teléfono', e.phone, 'phone') + row('Dirección', e.address, 'address');
    return '';
  }

  function initViewModal() {
    on('modal-view-close', 'click', () => UI.hideModal('modal-view'));
    on('btn-edit-entry', 'click', () => { UI.hideModal('modal-view'); openEntryModal(State.currentEditId); });
    on('btn-delete-entry', 'click', () => {
      UI.hideModal('modal-view');
      const entry = State.entries.find(e => e.id === State.currentEditId);
      if (!entry) return;
      UI.$('confirm-title').textContent = 'Eliminar entrada';
      UI.$('confirm-msg').textContent   = `¿Eliminar "${escHtml(entryTitle(entry))}"? Esta acción no se puede deshacer.`;
      UI.showModal('modal-confirm');
      UI.$('confirm-ok').onclick = async () => {
        State.entries = State.entries.filter(e => e.id !== State.currentEditId);
        await Crypto.saveVault(State.dek, State.entries);
        UI.hideModal('modal-confirm');
        renderEntries();
        UI.toast('Entrada eliminada', 'success');
      };
      UI.$('confirm-cancel').onclick = () => UI.hideModal('modal-confirm');
    });
  }

  // ── Generator ──
  function generatePassword(len, upper, lower, numbers, symbols) {
    let chars = '';
    if (upper)   chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (lower)   chars += 'abcdefghijklmnopqrstuvwxyz';
    if (numbers) chars += '0123456789';
    if (symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';
    const arr = crypto.getRandomValues(new Uint32Array(len));
    return Array.from(arr).map(n => chars[n % chars.length]).join('');
  }

  function initGenerator() {
    const gen = () => {
      const len = parseInt(UI.$('gen-length')?.value || '16');
      const pwd = generatePassword(
        len,
        UI.$('use-upper')?.checked,
        UI.$('use-lower')?.checked,
        UI.$('use-numbers')?.checked,
        UI.$('use-symbols')?.checked
      );
      const out = UI.$('gen-output'); if (out) out.textContent = pwd;
      const s   = UI.passwordStrength(pwd);
      const sf  = UI.$('gen-strength-fill'); if (sf) { sf.style.width = s.pct + '%'; sf.style.background = s.color; }
      const sl  = UI.$('gen-strength-label'); if (sl) sl.textContent = s.label;
    };
    on('btn-generate', 'click', gen);
    on('gen-length', 'input', () => { const lv = UI.$('len-val'); if (lv) lv.textContent = UI.$('gen-length').value; });
    on('btn-copy-gen', 'click', () => {
      const txt = UI.$('gen-output')?.textContent;
      if (txt && txt !== 'Haz clic en generar') UI.copyToClipboard(txt, 'Contraseña');
    });
  }

  // ── Settings ──
  function updateBioSettings() {
    Biometric.hasCredential().then(has => {
      const lbl    = UI.$('bio-status-label');
      const reg    = UI.$('btn-bio-register');
      const rem    = UI.$('btn-bio-remove');
      const row    = UI.$('bio-only-row');
      const toggle = UI.$('bio-only-toggle');
      if (lbl) { lbl.textContent = has ? 'Configurado' : 'No configurado'; lbl.classList.toggle('active', has); }
      if (reg) reg.classList.toggle('hidden', has);
      if (rem) rem.classList.toggle('hidden', !has);
      if (row) row.classList.toggle('hidden', !has);
      if (toggle) toggle.checked = Biometric.getMode() === 'solo';
    });
  }

  function initSettings() {
    on('btn-change-master', 'click', () => {
      ['cm-current','cm-new','cm-confirm'].forEach(id => { const e = UI.$(id); if (e) e.value = ''; });
      UI.hide('cm-error');
      UI.showModal('modal-change-master');
    });
    on('modal-cm-close',  'click', () => UI.hideModal('modal-change-master'));
    on('modal-cm-cancel', 'click', () => UI.hideModal('modal-change-master'));
    on('btn-cm-save', 'click', async () => {
      const cur  = UI.$('cm-current')?.value;
      const nw   = UI.$('cm-new')?.value;
      const conf = UI.$('cm-confirm')?.value;
      if (!nw || nw.length < 10) { UI.err('cm-error', 'Mínimo 10 caracteres.'); return; }
      if (nw !== conf)           { UI.err('cm-error', 'Las contraseñas no coinciden.'); return; }
      const btn = UI.$('btn-cm-save');
      btn.disabled = true; btn.textContent = 'Actualizando…';
      try {
        const { newKek } = await Crypto.changeMasterPassword(cur, nw);
        State.kek = newKek;
        Reauth.invalidate();
        UI.hideModal('modal-change-master');
        UI.toast('Contraseña actualizada', 'success');
      } catch (e) {
        UI.err('cm-error', e.message);
      } finally {
        btn.disabled = false; btn.textContent = 'Cambiar';
      }
    });

    on('btn-bio-register', 'click', async () => {
      if (!Biometric.isSupported()) { UI.toast('WebAuthn no disponible en este dispositivo', 'error'); return; }
      const ok = await Reauth.require('registrar huella dactilar');
      if (!ok) return;
      try {
        if (!State.kek) { UI.toast('Necesitas iniciar sesión con contraseña para registrar la huella.', ''); return; }
        await Biometric.register(State.dek, State.kek);
        UI.toast('Huella registrada correctamente', 'success');
        updateBioSettings();
      } catch (e) { UI.toast(e.message, 'error'); }
    });

    on('btn-bio-remove', 'click', async () => {
      const ok = await Reauth.require('eliminar huella dactilar');
      if (!ok) return;
      await Biometric.unregister();
      UI.toast('Huella eliminada', 'success');
      updateBioSettings();
    });

    on('bio-only-toggle', 'change', async () => {
      const toggle  = UI.$('bio-only-toggle');
      const wantOn  = toggle?.checked;
      if (wantOn) {
        if (!State.dek) { UI.toast('Sesión expirada, reinicia la app.', 'error'); toggle.checked = false; return; }
        try {
          await Biometric.registerBioOnly(State.dek);
          Biometric.setMode('solo');
          UI.toast('Solo huella activado', 'success');
        } catch (e) {
          toggle.checked = false;
          UI.toast(e.message || 'Error al activar', 'error');
        }
      } else {
        const ok = await Reauth.require('desactivar acceso solo huella');
        if (!ok) { toggle.checked = true; return; }
        await Biometric.unregisterBioOnly();
        UI.toast('Solo huella desactivado', 'success');
      }
    });

    on('btn-export', 'click', () => Backup.exportVault().catch(e => UI.toast(e.message, 'error')));

    on('btn-import', 'click', () => UI.$('import-file')?.click());
    on('import-file', 'change', async e => {
      const file = e.target.files?.[0]; if (!file) return;
      const ok = await Reauth.require('importar backup');
      if (!ok) { e.target.value = ''; return; }
      try {
        State._importData = await Backup.loadFile(file);
        UI.hide('import-pw-error');
        UI.$('import-pw-input').value = '';
        UI.showModal('modal-import-pw');
      } catch (err) { UI.toast(err.message, 'error'); }
      e.target.value = '';
    });
    on('import-pw-cancel', 'click', () => { UI.hideModal('modal-import-pw'); State._importData = null; });
    on('import-pw-ok', 'click', async () => {
      const pwd = UI.$('import-pw-input')?.value;
      if (!pwd) { UI.err('import-pw-error', 'Ingresa la contraseña del backup.'); return; }
      const btn = UI.$('import-pw-ok'); btn.disabled = true; btn.textContent = 'Importando…';
      try {
        await Backup.promoteImport(pwd);
        UI.hideModal('modal-import-pw');
        lock();
        UI.toast('Backup importado. Inicia sesión con tu contraseña.', 'success');
      } catch (e) {
        UI.err('import-pw-error', e.message);
      } finally {
        btn.disabled = false; btn.textContent = 'Importar';
      }
    });

    on('btn-delete-vault', 'click', async () => {
      const ok = await Reauth.require('eliminar bóveda permanentemente');
      if (!ok) return;
      UI.$('confirm-title').textContent = 'Eliminar bóveda';
      UI.$('confirm-msg').textContent   = 'Esta acción eliminará TODOS tus datos permanentemente. No hay vuelta atrás.';
      UI.showModal('modal-confirm');
      UI.$('confirm-ok').onclick = async () => {
        await DB.clear('kdf_header'); await DB.clear('crypto_blobs'); await DB.clear('vault');
        await DB.clear('staging'); await DB.clear('import_staging');
        localStorage.removeItem('hades_bio_mode');
        UI.hideModal('modal-confirm');
        lock();
        UI.toast('Bóveda eliminada.', 'success');
        UI.setState('state-loading');
        await init();
      };
      UI.$('confirm-cancel').onclick = () => UI.hideModal('modal-confirm');
    });
  }

  // ── Reauth Modal ──
  function initReauth() {
    on('reauth-cancel', 'click', () => {
      UI.hideModal('modal-reauth');
      if (State.reauthResolve) { State.reauthResolve(false); State.reauthResolve = null; }
    });
    on('reauth-ok', 'click', async () => {
      const pwd = UI.$('reauth-password')?.value;
      const btn = UI.$('reauth-ok'); btn.disabled = true; btn.textContent = 'Verificando…';
      try {
        const result = await Crypto.verifyPassword(pwd);
        if (!result) { UI.show('reauth-error'); return; }
        Reauth.confirm();
        UI.hideModal('modal-reauth');
        if (State.reauthResolve) { State.reauthResolve(true); State.reauthResolve = null; }
      } finally {
        btn.disabled = false; btn.textContent = 'Verificar';
      }
    });
    on('reauth-password', 'keydown', e => { if (e.key === 'Enter') UI.$('reauth-ok')?.click(); });
  }

  // ── CSS for view rows (injected) ──
  function injectViewRowStyles() {
    const style = document.createElement('style');
    style.textContent = `
      .view-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);}
      .view-row:last-child{border-bottom:none;}
      .view-label{font-size:.8125rem;color:var(--text-2);min-width:90px;}
      .view-val-wrap{display:flex;align-items:center;gap:8px;flex:1;justify-content:flex-end;}
      .view-val{font-size:.875rem;color:var(--text);word-break:break-all;text-align:right;}
    `;
    document.head.appendChild(style);
  }

  // ── Init ──
  async function init() {
    initParallax();
    initTheme();
    initEyeButtons();
    injectViewRowStyles();
    const hasVault = await DB.hasVault();
    if (hasVault) {
      const blobs = await DB.get('crypto_blobs', 'blobs');
      const header = await DB.get('kdf_header', 'header');
      const loginUsernameEl = UI.$('login-username');
      if (loginUsernameEl) loginUsernameEl.textContent = blobs?.user || 'Usuario';
      const bioMode = Biometric.getMode();
      const hasBioCredential = !!(blobs?.bioCredentialId) && Biometric.isSupported();
      if (hasBioCredential && bioMode === 'solo') {
        UI.hide('login-pw-wrap');
        UI.show('login-bio-only-wrap');
        UI.setState('state-login');
        // Auto-trigger fingerprint reader on launch
        setTimeout(() => { $('btn-bio-only-login')?.click(); }, 400);
      } else {
        UI.show('login-pw-wrap');
        UI.hide('login-bio-only-wrap');
        if (hasBioCredential && bioMode === 'both') UI.show('btn-biometric-login');
        UI.setState('state-login');
        setTimeout(() => { UI.$('login-password')?.focus(); }, 100);
      }
    } else {
      UI.setState('state-setup-1');
      setTimeout(() => { UI.$('reg-name')?.focus(); }, 100);
    }
    initSetup();
    initLogin();
    initRecovery();
    initVaultView();
    initEntryModal();
    initViewModal();
    initGenerator();
    initSettings();
    initReauth();
    initSidebar();
    setTimeout(initTilt, 200);

    // SW message listener
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('sw.js').catch(() => {});
      navigator.serviceWorker.addEventListener('message', e => {
        if (e.data?.type === 'SW_UPDATED' && document.body.dataset.page === 'unlock') location.reload();
      });
    }
  }

  return { init };
})();

// ─────────────────────────────────────────────
// HADES-V2-INIT
// ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => App.init());
