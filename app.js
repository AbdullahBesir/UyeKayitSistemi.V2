(function() {
  try {
    window.localStorage.removeItem('uye_logged_in');
  } catch (error) {
  }

  const API_PREFIX = '/api';
  const AUTH_HASH_ITERATIONS = 120000;
  const DATA_KEY_ITERATIONS = 180000;
  const CURRENT_SCHEMA_VERSION = 3;
  const LOCAL_PROFILE_CACHE_PREFIX = 'uye_profile_cache_v1:';
  const CELL_NOTIFICATION_DURATION_MS = 2400;
  const BASE_VALUE_COUNT = 26;
  const DISTRICT_COLUMN_INDEX = 9;
  const VOTE_SEQUENCE = ['SEÇ', 'HAYIR', 'ORTA', 'EVET'];
  const SIVAS_DISTRICTS = [
    'Merkez', 'Akıncılar', 'Altınyayla', 'Divriği', 'Doğanşar', 'Gemerek', 'Gölova', 'Gürün',
    'Hafik', 'İmranlı', 'Kangal', 'Koyulhisar', 'Suşehri', 'Şarkışla', 'Ulaş', 'Yıldızeli', 'Zara'
  ];
  const LEGACY_STORAGE_KEYS = {
    history: 'uye_history',
    draft: 'uye_draft',
    hiddenColumns: 'uye_hidden_columns',
    imageDirName: 'uye_image_dir_name',
    isimListesi: 'ozelIsimListesi'
  };
  const DEFAULT_NAME_RECORDS = [
    { id: 1, isim: '1. Komite Üyesi Adayı' },
    { id: 2, isim: '2. Komite Üyesi Adayı' },
    { id: 3, isim: '3. Komite Üyesi Adayı' },
    { id: 4, isim: '4. Komite Üyesi Adayı' },
    { id: 5, isim: '5. Komite Üyesi Adayı' },
    { id: 6, isim: '6. Komite Üyesi Adayı' },
    { id: 7, isim: '7. Komite Üyesi Adayı' },
    { id: 8, isim: '8. Komite Üyesi Adayı' },
    { id: 9, isim: '9. Komite Üyesi Adayı' },
    { id: 10, isim: '10. Komite Üyesi Adayı' },
    { id: 11, isim: '11. Komite Üyesi Adayı' },
    { id: 12, isim: '12. Komite Üyesi Adayı' }
  ];
  const COLUMN_TITLES = [
    'Resim', 'Üye Sicil', 'Ticaret Sicil', 'Mersis No', 'Nace Kodu', 'Vergi No', 'Meslek Grubu', 'Ünvan', 'Adres', 'İlçe',
    'Yetkili Adı-1', 'Yetkili Adı-2', 'Yetkili Adı-3', 'Firma Sabit Tel', 'Yetkili GSM.1', 'Yetkili GSM.2', 'Yetkili GSM.3',
    'E-mail', 'Instagram', 'Facebook', 'X', 'Linkedin', 'Referans.1', 'Referans.2', 'Referans.3', 'Not',
    'Ulusal Olma Durumu', 'Ziyaret 1', 'Ziyaret 1 Notu', 'Ziyaret 1 Tarihi', 'Ziyaret 2', 'Ziyaret 2 Notu',
    'Ziyaret 2 Tarihi', 'Telefon Görüşmesi', 'Telefon Görüşmesi Notu', 'Telefon Görüşmesi Tarihi',
    'Askı Olma Durumu', '2 Yıl Olma Durumu', 'Oy', 'Tarih'
  ];
  const HEADER_TITLES = ['Resim (Üye Resmi)', ...COLUMN_TITLES.slice(1)];
  const TABLE_INDEX = {
    ULUSAL: 26,
    ZIYARET1: 27,
    ZIYARET1_NOT: 28,
    ZIYARET1_TARIH: 29,
    ZIYARET2: 30,
    ZIYARET2_NOT: 31,
    ZIYARET2_TARIH: 32,
    TELEFON: 33,
    TELEFON_NOT: 34,
    TELEFON_TARIH: 35,
    ASKI: 36,
    IKI_YIL: 37,
    OY: 38,
    TARIH: 39
  };
  const LEGACY_HIDDEN_COLUMN_MAP_V1_TO_V2 = {
    0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9,
    10: 10, 11: 11, 12: 12, 13: 13, 14: 14, 15: 15, 16: 16, 17: 17, 18: 18, 19: 19,
    20: 20, 21: 21, 22: 22, 23: 23, 24: 24, 25: 35, 26: 36, 27: 26, 28: 27, 29: 28,
    30: 29, 31: 30, 32: 31, 33: 32, 34: 33, 35: 34, 36: 37, 37: 38
  };
  const BASE_IMPORT_FIELDS = [
    'image', 'uyeSicil', 'ticaretSicil', 'mersisNo', 'naceKodu', 'vergiNo', 'meslekGrubu', 'unvan', 'adres', 'ilce',
    'yetkiliAdi1', 'yetkiliAdi2', 'yetkiliAdi3', 'firmaSabitTel', 'yetkiliGsm1', 'yetkiliGsm2', 'yetkiliGsm3',
    'email', 'instagram', 'facebook', 'x', 'linkedin', 'referans1', 'referans2', 'referans3', 'not'
  ];
  const IMPORT_FIELD_ALIASES = {
    image: [{ name: 'resim' }, { name: 'resim uye resmi' }, { name: 'uye resmi' }],
    uyeSicil: [{ name: 'uye sicil' }],
    ticaretSicil: [{ name: 'ticaret sicil' }],
    mersisNo: [{ name: 'mersis no' }],
    naceKodu: [{ name: 'nace kodu' }],
    vergiNo: [{ name: 'vergi no' }],
    meslekGrubu: [{ name: 'meslek grubu' }],
    unvan: [{ name: 'unvan' }],
    adres: [{ name: 'adres' }],
    ilce: [{ name: 'ilce' }, { name: 'ilçe' }],
    yetkiliAdi1: [{ name: 'yetkili adi 1' }],
    yetkiliAdi2: [{ name: 'yetkili adi 2' }],
    yetkiliAdi3: [{ name: 'yetkili adi 3' }],
    firmaSabitTel: [{ name: 'firma sabit tel' }],
    yetkiliGsm1: [{ name: 'yetkili gsm 1' }],
    yetkiliGsm2: [{ name: 'yetkili gsm 2' }],
    yetkiliGsm3: [{ name: 'yetkili gsm 3' }],
    email: [{ name: 'e mail' }, { name: 'email' }],
    instagram: [{ name: 'instagram' }],
    facebook: [{ name: 'facebook' }],
    x: [{ name: 'x' }],
    linkedin: [{ name: 'linkedin' }],
    referans1: [{ name: 'referans 1' }],
    referans2: [{ name: 'referans 2' }],
    referans3: [{ name: 'referans 3' }],
    not: [{ name: 'not' }, { name: 'not zengin metin' }],
    ulusal: [{ name: 'ulusal olma durumu' }],
    ziyaret1: [{ name: 'ziyaret 1' }],
    ziyaret1Not: [{ name: 'ziyaret 1 notu' }],
    ziyaret1Tarih: [{ name: 'ziyaret 1 tarihi' }],
    ziyaret2: [{ name: 'ziyaret 2' }],
    ziyaret2Not: [{ name: 'ziyaret 2 notu' }],
    ziyaret2Tarih: [{ name: 'ziyaret 2 tarihi' }],
    telefonGorusmesi: [{ name: 'telefon gorusmesi' }, { name: 'ziyaret 3' }],
    telefonGorusmesiNot: [{ name: 'telefon gorusmesi notu' }, { name: 'ziyaret 3 notu' }],
    telefonGorusmesiTarih: [{ name: 'telefon gorusmesi tarihi' }, { name: 'ziyaret 3 tarihi' }],
    aski: [
      { name: 'aski olma durumu' },
      { name: 'aski olmama durumu', legacyInverted: true },
      { name: 'aski durumu', legacyInverted: true }
    ],
    ikiYil: [
      { name: '2 yil olma durumu' },
      { name: '2 yil olmama durumu', legacyInverted: true },
      { name: '2 yil durumu', legacyInverted: true }
    ],
    oy: [{ name: 'oy' }],
    tarih: [{ name: 'tarih' }]
  };

  let chartInstance = null;
  let activeColumnFilter = null;
  let imageDirectoryHandle = null;
  let aktifDuzenlemeId = null;
  let kayitlar = cloneDefaultNameRecords();
  let loginLockInterval = null;
  let activeNotificationRow = null;
  let notificationTimer = null;
  const state = {
    currentUser: null,
    authToken: '',
    userData: buildDefaultUserData(),
    profileUpdatedAt: 0,
    persistTimer: null
  };

  async function apiRequest(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (state.authToken) headers.Authorization = `Bearer ${state.authToken}`;
    if (options.body !== undefined && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    const response = await fetch(API_PREFIX + path, {
      ...options,
      headers,
      body: options.body !== undefined && typeof options.body !== 'string'
        ? JSON.stringify(options.body)
        : options.body
    });
    let payload = null;
    try {
      payload = await response.json();
    } catch (error) {
      payload = null;
    }
    if (!response.ok) {
      const err = new Error(payload.error || `API hatasi (${response.status})`);
      err.status = response.status;
      err.payload = payload || {};
      throw err;
    }
    return payload;
  }

  function qs(id) {
    return document.getElementById(id);
  }

  function escapeHtml(text) {
    return String(text || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function nv(value, fallback) {
    return value === null || value === undefined ? fallback : value;
  }

  function cloneDefaultNameRecords() {
    return DEFAULT_NAME_RECORDS.map(item => ({ ...item }));
  }

  function buildDefaultUserData() {
    return {
      schemaVersion: CURRENT_SCHEMA_VERSION,
      history: [],
      draft: [],
      hiddenColumns: [],
      imageDirName: '',
      isimListesi: cloneDefaultNameRecords()
    };
  }

  function tarih() {
    return new Date().toLocaleString('tr-TR');
  }

  function normalizeYesNo(value, fallback = 'HAYIR') {
    const normalized = String(nv(value, '')).trim().toUpperCase();
    if (normalized === 'EVET' || normalized === 'HAYIR') return normalized;
    return fallback;
  }

  function normalizeTextKey(value) {
    return String(nv(value, ''))
      .trim()
      .toLocaleLowerCase('tr-TR')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '');
  }

  function normalizeDistrict(value) {
    const normalized = normalizeTextKey(value);
    if (!normalized) return '';
    const match = SIVAS_DISTRICTS.find(item => normalizeTextKey(item) === normalized);
    return match || '';
  }

  function normalizeVote(value) {
    const normalized = String(nv(value, '')).trim().toUpperCase();
    return VOTE_SEQUENCE.includes(normalized) ? normalized : 'SEÇ';
  }

  function normalizeRestrictedStatus(value, legacyInverted = false) {
    const normalized = normalizeYesNo(value, legacyInverted ? 'EVET' : 'HAYIR');
    return legacyInverted ? (normalized === 'EVET' ? 'HAYIR' : 'EVET') : normalized;
  }

  function normalizeNameRecords(value) {
    if (!Array.isArray(value) || !value.length) return cloneDefaultNameRecords();
    return value.map((item, index) => ({
      id: Number(item && item.id) || index + 1,
      isim: String((item && item.isim) || `Komite Üyesi ${index + 1}`)
    }));
  }

  function migrateHiddenColumnIndex(index, sourceSchemaVersion = CURRENT_SCHEMA_VERSION) {
    let nextIndex = Number(index);
    if (!Number.isInteger(nextIndex)) return null;
    if (sourceSchemaVersion < 2) nextIndex = LEGACY_HIDDEN_COLUMN_MAP_V1_TO_V2[nextIndex];
    if (!Number.isInteger(nextIndex)) return null;
    if (sourceSchemaVersion < 3 && nextIndex >= DISTRICT_COLUMN_INDEX) nextIndex += 1;
    return nextIndex;
  }

  function normalizeHiddenColumns(value, sourceSchemaVersion = CURRENT_SCHEMA_VERSION) {
    if (!Array.isArray(value)) return [];
    return [...new Set(
      value
        .map(item => Number(item))
        .filter(item => Number.isInteger(item))
        .map(item => migrateHiddenColumnIndex(item, sourceSchemaVersion))
        .filter(item => Number.isInteger(item) && item >= 0 && item < COLUMN_TITLES.length)
    )].sort((a, b) => a - b);
  }

  function migrateBaseValues(values, sourceSchemaVersion = CURRENT_SCHEMA_VERSION, row = {}) {
    const nextValues = Array.isArray(values) ? values.map(item => String(nv(item, ''))) : [];
    if (sourceSchemaVersion < 3) nextValues.splice(DISTRICT_COLUMN_INDEX, 0, String(nv(row.ilce, '')));
    nextValues[DISTRICT_COLUMN_INDEX] = normalizeDistrict(nextValues[DISTRICT_COLUMN_INDEX]);
    return Array.from({ length: BASE_VALUE_COUNT }, (_, index) => String(nv(nextValues[index], '')));
  }

  function normalizeRowRecord(row = {}, options = {}) {
    const sourceSchemaVersion = Number(options.sourceSchemaVersion) || CURRENT_SCHEMA_VERSION;
    const legacySchema = sourceSchemaVersion < 2;
    const values = Array.isArray(row.veri) ? row.veri : [];
    return {
      veri: migrateBaseValues(values, sourceSchemaVersion, row),
      ulusal: normalizeYesNo(row.ulusal, 'HAYIR'),
      ziyaret1: normalizeYesNo(row.ziyaret1, 'HAYIR'),
      ziyaret1Not: String(nv(row.ziyaret1Not, '')),
      ziyaret1Tarih: String(nv(row.ziyaret1Tarih, '')),
      ziyaret2: normalizeYesNo(row.ziyaret2, 'HAYIR'),
      ziyaret2Not: String(nv(row.ziyaret2Not, '')),
      ziyaret2Tarih: String(nv(row.ziyaret2Tarih, '')),
      telefonGorusmesi: normalizeYesNo(nv(row.telefonGorusmesi, row.ziyaret3), 'HAYIR'),
      telefonGorusmesiNot: String(nv(nv(row.telefonGorusmesiNot, row.ziyaret3Not), '')),
      telefonGorusmesiTarih: String(nv(nv(row.telefonGorusmesiTarih, row.ziyaret3Tarih), '')),
      aski: normalizeRestrictedStatus(row.aski, legacySchema),
      ikiYil: normalizeRestrictedStatus(row.ikiYil, legacySchema),
      oy: normalizeVote(row.oy),
      tarih: String(nv(row.tarih, tarih()))
    };
  }

  function normalizeHistoryEntry(entry = {}, sourceSchemaVersion = CURRENT_SCHEMA_VERSION) {
    return {
      id: Number(entry.id) || Date.now(),
      tarih: String(nv(entry.tarih, tarih())),
      satir: Number(entry.satir) || (Array.isArray(entry.data) ? entry.data.length : 0),
      img: String(nv(entry.img, '')),
      data: Array.isArray(entry.data) ? entry.data.map(item => normalizeRowRecord(item, { sourceSchemaVersion })) : []
    };
  }

  function normalizeUserData(rawData) {
    const source = rawData && typeof rawData === 'object' ? rawData : {};
    const sourceSchemaVersion = Number(source.schemaVersion) || 1;
    return {
      schemaVersion: CURRENT_SCHEMA_VERSION,
      history: Array.isArray(source.history) ? source.history.map(item => normalizeHistoryEntry(item, sourceSchemaVersion)) : [],
      draft: Array.isArray(source.draft) ? source.draft.map(item => normalizeRowRecord(item, { sourceSchemaVersion })) : [],
      hiddenColumns: normalizeHiddenColumns(source.hiddenColumns, sourceSchemaVersion),
      imageDirName: String(nv(source.imageDirName, '')),
      isimListesi: normalizeNameRecords(source.isimListesi)
    };
  }

  function readLegacyJson(key, fallback) {
    try {
      const raw = window.localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (error) {
      return fallback;
    }
  }

  function readLegacyUserData() {
    const history = readLegacyJson(LEGACY_STORAGE_KEYS.history, []);
    const draft = readLegacyJson(LEGACY_STORAGE_KEYS.draft, []);
    const hiddenColumns = readLegacyJson(LEGACY_STORAGE_KEYS.hiddenColumns, []);
    const isimListesi = readLegacyJson(LEGACY_STORAGE_KEYS.isimListesi, null);
    const imageDirName = window.localStorage.getItem(LEGACY_STORAGE_KEYS.imageDirName) || '';
    const hasLegacyData = Boolean(
      (Array.isArray(history) && history.length) ||
      (Array.isArray(draft) && draft.length) ||
      (Array.isArray(hiddenColumns) && hiddenColumns.length) ||
      imageDirName ||
      Array.isArray(isimListesi)
    );
    if (!hasLegacyData) return null;
    return {
      schemaVersion: 1,
      history,
      draft,
      hiddenColumns,
      imageDirName,
      isimListesi: Array.isArray(isimListesi) ? isimListesi : cloneDefaultNameRecords()
    };
  }

  function clearLegacyStorage() {
    Object.values(LEGACY_STORAGE_KEYS).forEach(key => {
      try {
        window.localStorage.removeItem(key);
      } catch (error) {
      }
    });
    try {
      window.localStorage.removeItem('uye_logged_in');
    } catch (error) {
    }
  }

  function getLocalProfileCacheKey(username) {
    const normalizedUsername = String(nv(username, '')).trim().toLocaleLowerCase('tr-TR');
    return normalizedUsername ? `${LOCAL_PROFILE_CACHE_PREFIX}${normalizedUsername}` : '';
  }

  function readLocalProfileCache(username) {
    const key = getLocalProfileCacheKey(username);
    if (!key) return null;
    try {
      const raw = window.localStorage.getItem(key);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') return null;
      return {
        savedAt: Number(parsed.savedAt) || 0,
        userData: normalizeUserData(parsed.userData)
      };
    } catch (error) {
      return null;
    }
  }

  function writeLocalProfileCache(username, userData, savedAt = Date.now()) {
    const key = getLocalProfileCacheKey(username);
    if (!key) return;
    try {
      window.localStorage.setItem(key, JSON.stringify({
        savedAt: Number(savedAt) || Date.now(),
        userData: normalizeUserData(userData)
      }));
    } catch (error) {
    }
  }

  function resolveUserData(username, remoteUserData, remoteUpdatedAt = 0) {
    const normalizedRemoteData = normalizeUserData(remoteUserData || buildDefaultUserData());
    const normalizedRemoteUpdatedAt = Number(remoteUpdatedAt) || 0;
    const localCache = readLocalProfileCache(username);
    if (localCache && (!normalizedRemoteUpdatedAt || localCache.savedAt > normalizedRemoteUpdatedAt)) {
      return {
        userData: localCache.userData,
        updatedAt: localCache.savedAt
      };
    }
    return {
      userData: normalizedRemoteData,
      updatedAt: normalizedRemoteUpdatedAt
    };
  }

  function bytesToBase64(bytes) {
    let binary = '';
    bytes.forEach(byte => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary);
  }

  function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function randomBase64(length) {
    return bytesToBase64(window.crypto.getRandomValues(new Uint8Array(length)));
  }

  async function derivePasswordBits(password, saltBase64, iterations) {
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    );
    const bits = await window.crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt: base64ToBytes(saltBase64),
      iterations,
      hash: 'SHA-256'
    }, keyMaterial, 256);
    return new Uint8Array(bits);
  }

  async function hashPassword(password, saltBase64) {
    return bytesToBase64(await derivePasswordBits(password, saltBase64, AUTH_HASH_ITERATIONS));
  }

  async function deriveEncryptionKey(password, saltBase64) {
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return window.crypto.subtle.deriveKey({
      name: 'PBKDF2',
      salt: base64ToBytes(saltBase64),
      iterations: DATA_KEY_ITERATIONS,
      hash: 'SHA-256'
    }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  async function encryptData(data, password, saltBase64) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveEncryptionKey(password, saltBase64);
    const cipherBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(JSON.stringify(data))
    );
    return {
      iv: bytesToBase64(iv),
      cipherText: bytesToBase64(new Uint8Array(cipherBuffer))
    };
  }

  async function decryptData(record, password, saltBase64) {
    const key = await deriveEncryptionKey(password, saltBase64);
    const plainBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(record.iv) },
      key,
      base64ToBytes(record.cipherText)
    );
    return JSON.parse(new TextDecoder().decode(plainBuffer));
  }

  async function seedDefaultUsers() {
    return;
  }

  async function saveUserData(data) {
    return apiRequest('/profile', {
      method: 'PUT',
      body: { userData: normalizeUserData(data) }
    });
  }

  async function persistCurrentUserData() {
    if (!state.currentUser || !state.authToken) return;
    const response = await saveUserData(state.userData);
    state.profileUpdatedAt = Number(response && response.updatedAt) || Date.now();
    writeLocalProfileCache(state.currentUser, state.userData, state.profileUpdatedAt);
  }

  async function loadUserData() {
    const response = await apiRequest('/profile');
    return resolveUserData(state.currentUser, response.userData, response.updatedAt);
  }

  async function saveDirectoryHandleForCurrentUser(handle) {
    if (!state.currentUser || !handle) return;
  }

  async function loadDirectoryHandleForUser(username) {
    if (!username) return null;
    return null;
  }

  function clearLoginStatus() {
    qs('loginError').textContent = '';
    qs('loginMeta').textContent = '';
  }

  function setLoginControlsDisabled(disabled) {
    ['user', 'pass', 'loginButton'].forEach(id => {
      const element = qs(id);
      if (element) element.disabled = disabled;
    });
  }

  function clearLoginLockInterval() {
    if (loginLockInterval) {
      clearInterval(loginLockInterval);
      loginLockInterval = null;
    }
  }

  function startLoginLockCountdown(username, lockUntil) {
    clearLoginLockInterval();
    const tick = () => {
      const remaining = lockUntil - Date.now();
      if (remaining <= 0) {
        clearLoginLockInterval();
        clearLoginStatus();
        setLoginControlsDisabled(false);
        return;
      }
      if (qs('user').value.trim() === username) {
        qs('loginError').textContent = '3 hatali deneme sonrasi giris gecici olarak kilitlendi.';
        qs('loginMeta').textContent = `${Math.ceil(remaining / 1000)} saniye sonra tekrar deneyebilirsin.`;
        setLoginControlsDisabled(true);
      }
    };
    tick();
    loginLockInterval = window.setInterval(tick, 1000);
  }

  async function refreshLoginStateForUser(username) {
    if (!username) {
      clearLoginLockInterval();
      clearLoginStatus();
      setLoginControlsDisabled(false);
      return;
    }
    try {
      const response = await apiRequest(`/login-statususername=${encodeURIComponent(username)}`);
      if (!response.locked || !response.lockUntil || response.lockUntil <= Date.now()) {
        clearLoginLockInterval();
        clearLoginStatus();
        setLoginControlsDisabled(false);
        return;
      }
      startLoginLockCountdown(username, response.lockUntil);
    } catch (error) {
      clearLoginLockInterval();
      clearLoginStatus();
      setLoginControlsDisabled(false);
    }
  }

  async function login() {
    const username = qs('user').value.trim();
    const password = qs('pass').value;
    clearLoginStatus();
    if (!username || !password) {
      qs('loginError').textContent = 'Kullanici adi ve sifre zorunlu.';
      return;
    }
    setLoginControlsDisabled(true);
    try {
      const response = await apiRequest('/login', {
        method: 'POST',
        body: { username, password }
      });
      const resolvedProfile = resolveUserData(username, response.userData, response.updatedAt);
      state.currentUser = username;
      state.authToken = response.token || '';
      state.userData = resolvedProfile.userData;
      state.profileUpdatedAt = resolvedProfile.updatedAt;
      writeLocalProfileCache(username, state.userData, state.profileUpdatedAt || Date.now());
      kayitlar = normalizeNameRecords(state.userData.isimListesi);
      aktifDuzenlemeId = null;
      imageDirectoryHandle = await loadDirectoryHandleForUser(username);
      qs('loginPage').classList.add('hidden');
      qs('app').classList.remove('hidden');
      await initializeApp();
    } catch (error) {
      if (error.status === 423 && error.payload.lockUntil) {
        startLoginLockCountdown(username, error.payload.lockUntil);
        return;
      }
      if (error.status === 401) {
        qs('loginError').textContent = 'Kullanici adi veya sifre hatali.';
        if (Number.isInteger(error.payload.remainingAttempts)) {
          qs('loginMeta').textContent = `Kalan deneme hakki: ${error.payload.remainingAttempts}`;
        }
        setLoginControlsDisabled(false);
        return;
      }
      console.error(error);
      qs('loginError').textContent = 'Giris sirasinda beklenmeyen bir hata olustu.';
      setLoginControlsDisabled(false);
    }
  }

  function renderTableHeader() {
    const headerRow = qs('tableHeaderRow');
    if (!headerRow) return;
    headerRow.innerHTML = HEADER_TITLES.map((title, index) => `
      <th data-col="${index}" oncontextmenu="kolonMenuAc(event, ${index})">
        ${escapeHtml(title)}
        <span class="col-resizer" onmousedown="sutunBoyutlandirBaslat(event, ${index})"></span>
      </th>
    `).join('') + `<th data-col="${COLUMN_TITLES.length}">Sil</th>`;
  }

  function voteClass(value) {
    return ({ 'SEÇ': 'none', 'HAYIR': 'hayir', 'ORTA': 'orta', 'EVET': 'evet' })[value] || 'none';
  }

  function setVoteElementValue(el, value) {
    el.dataset.val = value;
    el.textContent = value;
    el.className = 'vote ' + voteClass(value) + (el.dataset.locked === '1' ? ' disabled' : '');
  }

  function hucre(value = '', type = 'text') {
    const safe = escapeHtml(value);
    if (type === 'note') return `<textarea class="cell" oninput="autoSaveDraft(); filtre()">${safe}</textarea>`;
    return `<input class="cell" value="${safe}" oninput="autoSaveDraft(); filtre()">`;
  }

  function oyDiv(value = 'SEÇ') {
    const normalized = normalizeVote(value);
    return `<div class="vote ${voteClass(normalized)}" onclick="oyDegistir(this)" data-val="${escapeHtml(normalized)}" data-locked="0">${escapeHtml(normalized)}</div>`;
  }

  function evetHayirSelect(value = 'HAYIR', cls = '') {
    const normalized = normalizeYesNo(value, 'HAYIR');
    return `<select class="cell ${cls}" onchange="durumDegisti(this)"><option value="EVET" ${normalized === 'EVET' ? 'selected' : ''}>Evet</option><option value="HAYIR" ${normalized === 'HAYIR' ? 'selected' : ''}>Hayır</option></select>`;
  }

  function selectCell(options, value = '', cls = '', placeholder = 'Seçiniz') {
    const normalizedValue = String(nv(value, ''));
    const optionValues = options.includes(normalizedValue) ? options : [...options, normalizedValue].filter(Boolean);
    return `<select class="cell ${cls}" onchange="autoSaveDraft(); filtre()">
      <option value="">${escapeHtml(placeholder)}</option>
      ${optionValues.map(option => `<option value="${escapeHtml(option)}" ${option === normalizedValue ? 'selected' : ''}>${escapeHtml(option)}</option>`).join('')}
    </select>`;
  }

  function ilceSelect(value = '') {
    return selectCell(SIVAS_DISTRICTS, normalizeDistrict(value), 'ilce-select', 'İlçe Seç');
  }

  function makeLink(url, type) {
    const value = (url || '').trim();
    if (!value) return '';
    let href = value;
    if (type === 'phone') href = 'tel:' + value.replace(/\s+/g, '');
    if (type === 'email') href = value.startsWith('mailto:') ? value : 'mailto:' + value;
    if (type === 'social' && !/^https:\/\//i.test(value)) href = 'https://' + value;
    return `<a class="link-preview" href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">Bağlantıyı Aç</a>`;
  }

  function imageCell(value = '') {
    const safe = escapeHtml(value);
    return `
      <div class="image-cell" style="display:flex; flex-direction:row; gap:10px; align-items:flex-start; min-width:260px;">
        <img class="thumb" src="${safe}" onerror="this.style.visibility='hidden'" onload="this.style.visibility='visible'">
        <div style="display:flex; flex-direction:column; gap:8px; min-width:150px; flex:1;">
          <input class="cell" placeholder="Resim yolu / veri / URL" value="${safe}" oninput="resimInputDegisti(this)">
          <div class="inline-actions">
            <input type="file" accept="image/*" onchange="resimSec(this)">
          </div>
        </div>
      </div>
    `;
  }

  function actionCell(value = '', type = 'text', linkType = '') {
    const safe = escapeHtml(value);
    const link = linkType ? makeLink(value, linkType) : '';
    return `
      <div class="link-cell">
        ${type === 'note' ? `<textarea class="cell" oninput="autoSaveDraft(); filtre()">${safe}</textarea>` : `<input class="cell" value="${safe}" oninput="autoSaveDraft(); filtre()">`}
        ${link}
      </div>
    `;
  }

  function getCellValue(td) {
    const input = td.querySelector('input.cell, textarea.cell, select.cell');
    if (input) return input.value || '';
    const vote = td.querySelector('.vote');
    if (vote) return vote.dataset.val || vote.textContent || '';
    return td.textContent || '';
  }

  function clearCellNotification() {
    if (notificationTimer) {
      clearTimeout(notificationTimer);
      notificationTimer = null;
    }
    if (activeNotificationRow) {
      activeNotificationRow.classList.remove('row-notification');
      activeNotificationRow = null;
    }
  }

  function getTableCellTarget(target) {
    if (!target || !target.closest) return null;
    const cell = target.closest('#tablo tbody td');
    if (!cell) return null;
    if (target.closest('button')) return null;
    return cell;
  }

  function notifyTableCell(target) {
    const cell = getTableCellTarget(target);
    if (!cell) return;
    const row = cell.closest('tr');
    if (!row) return;
    clearCellNotification();
    activeNotificationRow = row;
    activeNotificationRow.classList.add('row-notification');
    notificationTimer = window.setTimeout(clearCellNotification, CELL_NOTIFICATION_DURATION_MS);
  }

  function handleTableNotificationEvent(event) {
    notifyTableCell(event.target);
  }

  function getTableData() {
    const rows = [...qs('tablo').querySelectorAll('tbody tr')];
    return rows.map(row => {
      const cells = [...row.querySelectorAll('td')];
      return normalizeRowRecord({
        veri: cells.slice(0, BASE_VALUE_COUNT).map(td => getCellValue(td)),
        ulusal: getCellValue(cells[TABLE_INDEX.ULUSAL]),
        ziyaret1: getCellValue(cells[TABLE_INDEX.ZIYARET1]),
        ziyaret1Not: getCellValue(cells[TABLE_INDEX.ZIYARET1_NOT]),
        ziyaret1Tarih: getCellValue(cells[TABLE_INDEX.ZIYARET1_TARIH]),
        ziyaret2: getCellValue(cells[TABLE_INDEX.ZIYARET2]),
        ziyaret2Not: getCellValue(cells[TABLE_INDEX.ZIYARET2_NOT]),
        ziyaret2Tarih: getCellValue(cells[TABLE_INDEX.ZIYARET2_TARIH]),
        telefonGorusmesi: getCellValue(cells[TABLE_INDEX.TELEFON]),
        telefonGorusmesiNot: getCellValue(cells[TABLE_INDEX.TELEFON_NOT]),
        telefonGorusmesiTarih: getCellValue(cells[TABLE_INDEX.TELEFON_TARIH]),
        aski: getCellValue(cells[TABLE_INDEX.ASKI]),
        ikiYil: getCellValue(cells[TABLE_INDEX.IKI_YIL]),
        oy: getCellValue(cells[TABLE_INDEX.OY]),
        tarih: cells[TABLE_INDEX.TARIH].textContent.trim() || tarih()
      });
    });
  }

  function getDraft() {
    return Array.isArray(state.userData.draft) ? state.userData.draft.map(item => normalizeRowRecord(item)) : [];
  }

  function getHistory() {
    return Array.isArray(state.userData.history) ? state.userData.history.map(item => normalizeHistoryEntry(item)) : [];
  }

  function queuePersistUserData(immediate = false) {
    if (!state.currentUser) return;
    writeLocalProfileCache(state.currentUser, state.userData, Date.now());
    if (state.persistTimer) {
      clearTimeout(state.persistTimer);
      state.persistTimer = null;
    }
    if (immediate) {
      persistCurrentUserData().catch(console.error);
      return;
    }
    state.persistTimer = window.setTimeout(() => {
      persistCurrentUserData().catch(console.error);
    }, 250);
  }

  function autoSaveDraft() {
    if (!state.currentUser) return;
    state.userData.draft = getTableData();
    queuePersistUserData();
    loadChart();
  }

  function rowVotingLocked(row) {
    return (row.querySelector('.aski-select').value || 'HAYIR') === 'EVET' ||
      (row.querySelector('.ikiyil-select').value || 'HAYIR') === 'EVET';
  }

  function updateVoteAvailability(row) {
    const vote = row.querySelector('.vote');
    if (!vote) return;
    const locked = rowVotingLocked(row);
    vote.dataset.locked = locked ? '1' : '0';
    setVoteElementValue(vote, locked ? 'SEÇ' : (vote.dataset.val || 'SEÇ'));
    vote.title = locked
      ? 'Askı Olma Durumu veya 2 Yıl Olma Durumu = Evet olduğu için oy verilemez.'
      : 'Oy durumunu değiştirmek için tıkla.';
  }

  function satirRenkGuncelle(row) {
    if (!row) return;
    updateVoteAvailability(row);
    row.classList.remove('row-none', 'row-hayir', 'row-orta', 'row-evet', 'row-excluded');
    row.classList.add(({ 'SEÇ': 'row-none', 'HAYIR': 'row-hayir', 'ORTA': 'row-orta', 'EVET': 'row-evet' })[row.querySelector('.vote').dataset.val || 'SEÇ'] || 'row-none');
    if (rowVotingLocked(row)) row.classList.add('row-excluded');
  }

  function satirEkle(data = null, options = {}) {
    const item = normalizeRowRecord(data || {});
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${imageCell(item.veri[0] || '')}</td>
      <td>${hucre(item.veri[1] || '')}</td>
      <td>${hucre(item.veri[2] || '')}</td>
      <td>${hucre(item.veri[3] || '')}</td>
      <td>${hucre(item.veri[4] || '')}</td>
      <td>${hucre(item.veri[5] || '')}</td>
      <td>${hucre(item.veri[6] || '')}</td>
      <td>${hucre(item.veri[7] || '')}</td>
      <td>${hucre(item.veri[8] || '')}</td>
      <td>${ilceSelect(item.veri[9] || '')}</td>
      <td>${hucre(item.veri[10] || '')}</td>
      <td>${hucre(item.veri[11] || '')}</td>
      <td>${hucre(item.veri[12] || '')}</td>
      <td>${actionCell(item.veri[13] || '', 'text', 'phone')}</td>
      <td>${actionCell(item.veri[14] || '', 'text', 'phone')}</td>
      <td>${actionCell(item.veri[15] || '', 'text', 'phone')}</td>
      <td>${actionCell(item.veri[16] || '', 'text', 'phone')}</td>
      <td>${actionCell(item.veri[17] || '', 'text', 'email')}</td>
      <td>${actionCell(item.veri[18] || '', 'text', 'social')}</td>
      <td>${actionCell(item.veri[19] || '', 'text', 'social')}</td>
      <td>${actionCell(item.veri[20] || '', 'text', 'social')}</td>
      <td>${actionCell(item.veri[21] || '', 'text', 'social')}</td>
      <td>${hucre(item.veri[22] || '')}</td>
      <td>${hucre(item.veri[23] || '')}</td>
      <td>${hucre(item.veri[24] || '')}</td>
      <td>${actionCell(item.veri[25] || '', 'note')}</td>
      <td>${evetHayirSelect(item.ulusal, 'ulusal-select')}</td>
      <td>${evetHayirSelect(item.ziyaret1, 'ziyaret1-select')}</td>
      <td>${actionCell(item.ziyaret1Not, 'note')}</td>
      <td>${hucre(item.ziyaret1Tarih)}</td>
      <td>${evetHayirSelect(item.ziyaret2, 'ziyaret2-select')}</td>
      <td>${actionCell(item.ziyaret2Not, 'note')}</td>
      <td>${hucre(item.ziyaret2Tarih)}</td>
      <td>${evetHayirSelect(item.telefonGorusmesi, 'telefon-select')}</td>
      <td>${actionCell(item.telefonGorusmesiNot, 'note')}</td>
      <td>${hucre(item.telefonGorusmesiTarih)}</td>
      <td>${evetHayirSelect(item.aski, 'aski-select')}</td>
      <td>${evetHayirSelect(item.ikiYil, 'ikiyil-select')}</td>
      <td>${oyDiv(item.oy)}</td>
      <td class="meta">${escapeHtml(item.tarih)}</td>
      <td><button type="button" class="btn-danger" onclick="sil(this)">Sil</button></td>
    `;
    qs('tablo').querySelector('tbody').appendChild(tr);
    satirRenkGuncelle(tr);
    applyHiddenColumns();
    if (!options.skipSave) autoSaveDraft();
    filtre();
  }

  function renderRows(data = []) {
    const tbody = qs('tablo').querySelector('tbody');
    clearCellNotification();
    tbody.innerHTML = '';
    if (Array.isArray(data) && data.length) data.forEach(item => satirEkle(item, { skipSave: true }));
    else satirEkle(null, { skipSave: true });
    autoSaveDraft();
  }

  function renderHiddenColumns() {
    const hidden = Array.isArray(state.userData.hiddenColumns) ? state.userData.hiddenColumns : [];
    const box = qs('hiddenColumnsBox');
    if (!hidden.length) {
      box.innerHTML = '<span class="mini-note">Gizlenmiş sütun yok.</span>';
      return;
    }
    box.innerHTML = '<span class="mini-note">Gizlenmiş sütunlar:</span>' + hidden.map(index => `
      <button type="button" class="hidden-chip" onclick="sutunGoster(${index})">${escapeHtml(COLUMN_TITLES[index] || ('Sütun ' + index))} ekle</button>
    `).join('');
  }

  function applyHiddenColumns() {
    const hidden = Array.isArray(state.userData.hiddenColumns) ? state.userData.hiddenColumns : [];
    qs('tablo').querySelectorAll('tr').forEach(row => {
      [...row.children].forEach((cell, index) => {
        cell.style.display = hidden.includes(index) ? 'none' : '';
      });
    });
  }

  function sutunGizle(index) {
    const hidden = normalizeHiddenColumns([...(state.userData.hiddenColumns || []), index]);
    state.userData.hiddenColumns = hidden;
    queuePersistUserData();
    applyHiddenColumns();
    renderHiddenColumns();
  }

  function sutunGoster(index) {
    state.userData.hiddenColumns = normalizeHiddenColumns((state.userData.hiddenColumns || []).filter(item => item !== index));
    queuePersistUserData();
    applyHiddenColumns();
    renderHiddenColumns();
  }

  function getColumnFilterDefinition(columnIndex) {
    if (columnIndex === DISTRICT_COLUMN_INDEX) {
      return { type: 'exact', options: SIVAS_DISTRICTS, placeholder: 'Tüm İlçeler' };
    }
    if ([
      TABLE_INDEX.ULUSAL,
      TABLE_INDEX.ZIYARET1,
      TABLE_INDEX.ZIYARET2,
      TABLE_INDEX.TELEFON,
      TABLE_INDEX.ASKI,
      TABLE_INDEX.IKI_YIL
    ].includes(columnIndex)) {
      return { type: 'exact', options: ['EVET', 'HAYIR'], placeholder: 'Tüm Durumlar' };
    }
    if (columnIndex === TABLE_INDEX.OY) {
      return { type: 'exact', options: VOTE_SEQUENCE, placeholder: 'Tüm Oylar' };
    }
    return { type: 'includes' };
  }

  function getFilterLabel(value) {
    if (value === 'EVET') return 'Evet';
    if (value === 'HAYIR') return 'Hayır';
    if (value === 'SEÇ') return 'Seç';
    return value;
  }

  function applyColumnFilter(columnIndex, value, match = 'includes') {
    const trimmedValue = String(nv(value, '')).trim();
    if (!trimmedValue) {
      if (activeColumnFilter && activeColumnFilter.index === columnIndex) activeColumnFilter = null;
    } else {
      activeColumnFilter = { index: columnIndex, text: trimmedValue, match };
    }
    filtre();
    contextMenuKapat();
  }

  function filtre() {
    const oy = qs('oyFiltre').value;
    const rows = [...qs('tablo').querySelectorAll('tbody tr')];
    const hasAnyFilter = Boolean(oy || activeColumnFilter);
    rows.forEach(row => {
      row.classList.remove('filtered-row');
      const rowVote = row.querySelector('.vote').dataset.val || 'SEÇ';
      const oyUygun = !oy || rowVote === oy;
      let kolonUygun = true;
      if (activeColumnFilter) {
        const cell = row.querySelectorAll('td')[activeColumnFilter.index];
        const cellValue = getCellValue(cell);
        kolonUygun = activeColumnFilter.match === 'exact'
          ? normalizeTextKey(cellValue) === normalizeTextKey(activeColumnFilter.text)
          : normalizeTextKey(cellValue).includes(normalizeTextKey(activeColumnFilter.text));
      }
      const show = oyUygun && kolonUygun;
      row.style.display = show ? '' : 'none';
      if (show && hasAnyFilter) row.classList.add('filtered-row');
    });
  }

  function filtreTemizle() {
    qs('oyFiltre').value = '';
    activeColumnFilter = null;
    contextMenuKapat();
    document.querySelectorAll('#tablo tbody tr').forEach(row => {
      row.style.display = '';
      row.classList.remove('filtered-row');
    });
  }

  function kolonMenuAc(event, columnIndex) {
    event.preventDefault();
    contextMenuKapat();
    const title = qs('tablo').querySelector(`th[data-col="${columnIndex}"]`).textContent || 'Kolon';
    const filterDefinition = getColumnFilterDefinition(columnIndex);
    const activeValue = activeColumnFilter && activeColumnFilter.index === columnIndex ? activeColumnFilter.text : '';
    const menu = document.createElement('div');
    menu.className = 'context-menu';
    menu.innerHTML = `
      <div class="context-menu-title">${escapeHtml(title)}</div>
      ${filterDefinition.type === 'exact'
        ? `<select id="contextFilterInput" class="input">
            <option value="">${escapeHtml(filterDefinition.placeholder || 'Tümü')}</option>
            ${filterDefinition.options.map(option => `
              <option value="${escapeHtml(option)}" ${option === activeValue ? 'selected' : ''}>${escapeHtml(getFilterLabel(option))}</option>
            `).join('')}
          </select>`
        : `<input id="contextFilterInput" class="input" placeholder="Metne göre filtrele" value="${escapeHtml(activeValue)}">`
      }
      <button type="button" id="contextApply">Filtrele</button>
      <button type="button" id="contextClear">Bu kolon filtresini temizle</button>
      <button type="button" id="contextHide">Sütunu gizle</button>
    `;
    menu.style.left = event.clientX + 'px';
    menu.style.top = event.clientY + 'px';
    document.body.appendChild(menu);
    const input = menu.querySelector('#contextFilterInput');
    input.focus();
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') applyColumnFilter(columnIndex, input.value, filterDefinition.type);
    });
    menu.querySelector('#contextApply').onclick = () => {
      applyColumnFilter(columnIndex, input.value, filterDefinition.type);
    };
    menu.querySelector('#contextClear').onclick = () => {
      applyColumnFilter(columnIndex, '', filterDefinition.type);
    };
    menu.querySelector('#contextHide').onclick = () => {
      sutunGizle(columnIndex);
      contextMenuKapat();
    };
    setTimeout(() => document.addEventListener('click', contextMenuKapat, { once: true }), 0);
  }

  function contextMenuKapat() {
    document.querySelectorAll('.context-menu').forEach(menu => menu.remove());
  }

  function updateFolderInfo() {
    const info = qs('folderInfo');
    const folderName = state.userData.imageDirName || '';
    if (!folderName) {
      info.textContent = '';
      info.classList.add('hidden');
      return;
    }
    info.textContent = `Seçili resim klasörü: ${folderName}`;
    info.classList.remove('hidden');
    info.classList.add('mini-note');
  }

  function listeyiCiz() {
    const alan = qs('isimSatirlari');
    alan.innerHTML = '';
    kayitlar.forEach(kayit => {
      const satir = document.createElement('div');
      satir.className = 'isim-satir';
      satir.innerHTML = aktifDuzenlemeId === kayit.id ? `
        <div class="isim-hucre">${kayit.id}</div>
        <div class="isim-hucre"><input id="isimGirdi-${kayit.id}" class="isim-girdi" type="text" value="${escapeHtml(kayit.isim)}" /></div>
        <div class="isim-hucre isim-hucre-son">
          <div class="isim-aksiyon">
            <button class="isim-buton isim-buton-kaydet" onclick="ismiKaydet(${kayit.id})">Kaydet</button>
            <button class="isim-buton isim-buton-iptal" onclick="duzenlemeyiIptalEt()">İptal</button>
          </div>
        </div>
      ` : `
        <div class="isim-hucre">${kayit.id}</div>
        <div class="isim-hucre">${escapeHtml(kayit.isim)}</div>
        <div class="isim-hucre isim-hucre-son">
          <div class="isim-aksiyon"><button class="isim-buton isim-buton-duzenle" onclick="duzenlemeyiBaslat(${kayit.id})">Düzenle</button></div>
        </div>
      `;
      alan.appendChild(satir);
    });
  }

  function duzenlemeyiBaslat(id) {
    aktifDuzenlemeId = id;
    listeyiCiz();
  }

  function ismiKaydet(id) {
    const girdi = qs(`isimGirdi-${id}`);
    const yeniIsim = girdi.value.trim() || '';
    if (!yeniIsim) {
      alert('İsim boş bırakılamaz.');
      return;
    }
    const hedef = kayitlar.find(item => item.id === id);
    if (hedef) hedef.isim = yeniIsim;
    aktifDuzenlemeId = null;
    state.userData.isimListesi = normalizeNameRecords(kayitlar);
    queuePersistUserData();
    listeyiCiz();
  }

  function duzenlemeyiIptalEt() {
    aktifDuzenlemeId = null;
    listeyiCiz();
  }

  function resimInputDegisti(input) {
    input.closest('.image-cell').querySelector('.thumb').src = input.value.trim();
    autoSaveDraft();
    filtre();
  }

  async function ensureDirectoryPermission(handle, write = false) {
    if (!handle) return false;
    const options = { mode: write ? 'readwrite' : 'read' };
    if (await handle.queryPermission(options) === 'granted') return true;
    return await handle.requestPermission(options) === 'granted';
  }

  async function resimSec(fileInput) {
    const file = fileInput.files && fileInput.files[0];
    if (!file) return;
    const wrapper = fileInput.closest('.image-cell');
    const textInput = wrapper.querySelector('input.cell');
    const img = wrapper.querySelector('.thumb');
    const savedPath = await resmiKlasoreKaydet(file);
    if (savedPath) {
      textInput.value = savedPath;
      img.src = savedPath;
      img.style.visibility = 'visible';
      autoSaveDraft();
      return;
    }
    const reader = new FileReader();
    reader.onload = event => {
      textInput.value = event.target.result;
      img.src = event.target.result;
      img.style.visibility = 'visible';
      autoSaveDraft();
    };
    reader.readAsDataURL(file);
  }

  async function klasorSec() {
    try {
      if (!window.showDirectoryPicker) return alert('Bu tarayıcı klasör seçimini desteklemiyor.');
      imageDirectoryHandle = await window.showDirectoryPicker();
      state.userData.imageDirName = imageDirectoryHandle.name || 'Seçili klasör';
      updateFolderInfo();
      await saveDirectoryHandleForCurrentUser(imageDirectoryHandle);
      queuePersistUserData(true);
    } catch (error) {
    }
  }

  async function resmiKlasoreKaydet(file) {
    try {
      if (!imageDirectoryHandle || !(await ensureDirectoryPermission(imageDirectoryHandle, true))) return null;
      const cleanName = (file.name || ('resim_' + Date.now() + '.png')).replace(/[^a-zA-Z0-9._-]/g, '_');
      const target = await imageDirectoryHandle.getFileHandle(cleanName, { create: true });
      const writable = await target.createWritable();
      await writable.write(file);
      await writable.close();
      return cleanName;
    } catch (error) {
      return null;
    }
  }

  function sil(btn) {
    btn.closest('tr').remove();
    autoSaveDraft();
    filtre();
  }

  function oyDegistir(el) {
    if (el.dataset.locked === '1') return;
    const current = el.dataset.val || 'SEÇ';
    const next = VOTE_SEQUENCE[(VOTE_SEQUENCE.indexOf(current) + 1) % VOTE_SEQUENCE.length];
    setVoteElementValue(el, next);
    satirRenkGuncelle(el.closest('tr'));
    autoSaveDraft();
    filtre();
  }

  function durumDegisti(select) {
    satirRenkGuncelle(select.closest('tr'));
    autoSaveDraft();
    loadChart();
    filtre();
  }

  async function tumunuKaydet() {
    const data = getTableData();
    const canvas = await html2canvas(qs('tableArea'), { backgroundColor: '#ffffff', scale: 1.2 });
    state.userData.history.push({
      id: Date.now(),
      tarih: tarih(),
      satir: data.length,
      img: canvas.toDataURL('image/png'),
      data
    });
    state.userData.draft = data;
    queuePersistUserData(true);
    renderHistory();
    loadChart();
    alert('Kayıt başarıyla alındı.');
  }

  function renderHistory() {
    const cards = qs('cards');
    const history = [...getHistory()].reverse();
    if (!history.length) {
      cards.className = '';
      cards.innerHTML = '<div class="empty">Henüz kayıt yok. Anasayfada tabloyu doldurup Kaydet butonuna bas.</div>';
      return;
    }
    cards.className = 'cards';
    cards.innerHTML = history.map(item => `
      <div class="card">
        <img src="${item.img}" alt="Kayıt görünümü">
        <div class="card-body">
          <h3>Kayıt #${item.id}</h3>
          <p><strong>Satır:</strong> ${item.satir}</p>
          <p><strong>Tarih:</strong> ${escapeHtml(item.tarih)}</p>
          <div class="card-actions">
            <button type="button" class="btn-primary" onclick="kaydiYukle(${item.id})">Yükle</button>
            <button type="button" class="btn-danger" onclick="kaydiSil(${item.id})">Sil</button>
          </div>
        </div>
      </div>
    `).join('');
  }

  function kaydiYukle(id) {
    const item = getHistory().find(entry => entry.id === id);
    if (!item) return;
    renderRows(item.data || []);
    showPage('ana');
    alert('Kayıt tabloya yüklendi.');
  }

  function kaydiSil(id) {
    state.userData.history = getHistory().filter(entry => entry.id !== id);
    queuePersistUserData(true);
    renderHistory();
    loadChart();
  }

  function sonKaydiYukle() {
    const history = getHistory();
    if (!history.length) return alert('Yüklenecek kayıt yok.');
    renderRows(history[history.length - 1].data || []);
    alert('Son kayıt yüklendi.');
  }

  function tabloTemizle() {
    if (!window.confirm('Tablodaki tüm satırlar temizlensin mi? Bu işlem mevcut taslağı sıfırlar.')) return;
    renderRows([]);
  }

  function buildRowExportArray(item) {
    return [
      ...item.veri, item.ulusal, item.ziyaret1, item.ziyaret1Not, item.ziyaret1Tarih,
      item.ziyaret2, item.ziyaret2Not, item.ziyaret2Tarih, item.telefonGorusmesi,
      item.telefonGorusmesiNot, item.telefonGorusmesiTarih, item.aski, item.ikiYil, item.oy, item.tarih
    ];
  }

  function normalizeHeaderValue(value) {
    return String(value || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, ' ').trim();
  }

  function buildImportHeaderMap(headers) {
    const normalizedHeaders = headers.map(normalizeHeaderValue);
    const result = {};
    Object.entries(IMPORT_FIELD_ALIASES).forEach(([field, aliases]) => {
      for (const alias of aliases) {
        const index = normalizedHeaders.findIndex(header => header === alias.name);
        if (index !== -1) {
          result[field] = { index, legacyInverted: Boolean(alias.legacyInverted) };
          break;
        }
      }
    });
    return result;
  }

  function mapExcelRowWithHeaders(row, headerMap) {
    const getValue = (field, fallback = '') => headerMap[field] ? nv(row[headerMap[field].index], fallback) : fallback;
    return normalizeRowRecord({
      veri: BASE_IMPORT_FIELDS.map(field => String(getValue(field, ''))),
      ulusal: getValue('ulusal', 'HAYIR'),
      ziyaret1: getValue('ziyaret1', 'HAYIR'),
      ziyaret1Not: getValue('ziyaret1Not', ''),
      ziyaret1Tarih: getValue('ziyaret1Tarih', ''),
      ziyaret2: getValue('ziyaret2', 'HAYIR'),
      ziyaret2Not: getValue('ziyaret2Not', ''),
      ziyaret2Tarih: getValue('ziyaret2Tarih', ''),
      telefonGorusmesi: getValue('telefonGorusmesi', 'HAYIR'),
      telefonGorusmesiNot: getValue('telefonGorusmesiNot', ''),
      telefonGorusmesiTarih: getValue('telefonGorusmesiTarih', ''),
      aski: normalizeRestrictedStatus(getValue('aski', 'HAYIR'), Boolean(headerMap.aski && headerMap.aski.legacyInverted)),
      ikiYil: normalizeRestrictedStatus(getValue('ikiYil', 'HAYIR'), Boolean(headerMap.ikiYil && headerMap.ikiYil.legacyInverted)),
      oy: getValue('oy', 'SEÇ'),
      tarih: getValue('tarih', tarih())
    });
  }

  function mapExcelRowByPosition(row, sourceSchemaVersion = CURRENT_SCHEMA_VERSION) {
    if (sourceSchemaVersion < 2) {
      return normalizeRowRecord({
        veri: Array.from({ length: 25 }, (_, index) => nv(row[index], '')),
        ziyaret1: nv(row[27], 'HAYIR'),
        ziyaret1Not: nv(row[28], ''),
        ziyaret1Tarih: nv(row[29], ''),
        ziyaret2: nv(row[30], 'HAYIR'),
        ziyaret2Not: nv(row[31], ''),
        ziyaret2Tarih: nv(row[32], ''),
        telefonGorusmesi: nv(row[33], 'HAYIR'),
        telefonGorusmesiNot: nv(row[34], ''),
        telefonGorusmesiTarih: nv(row[35], ''),
        aski: nv(row[25], 'EVET'),
        ikiYil: nv(row[26], 'EVET'),
        oy: nv(row[36], 'SEÇ'),
        tarih: nv(row[37], tarih())
      }, { sourceSchemaVersion });
    }
    if (sourceSchemaVersion < 3) {
      return normalizeRowRecord({
        veri: Array.from({ length: 25 }, (_, index) => nv(row[index], '')),
        ulusal: nv(row[25], 'HAYIR'),
        ziyaret1: nv(row[26], 'HAYIR'),
        ziyaret1Not: nv(row[27], ''),
        ziyaret1Tarih: nv(row[28], ''),
        ziyaret2: nv(row[29], 'HAYIR'),
        ziyaret2Not: nv(row[30], ''),
        ziyaret2Tarih: nv(row[31], ''),
        telefonGorusmesi: nv(row[32], 'HAYIR'),
        telefonGorusmesiNot: nv(row[33], ''),
        telefonGorusmesiTarih: nv(row[34], ''),
        aski: nv(row[35], 'HAYIR'),
        ikiYil: nv(row[36], 'HAYIR'),
        oy: nv(row[37], 'SEÇ'),
        tarih: nv(row[38], tarih())
      }, { sourceSchemaVersion });
    }
    return normalizeRowRecord({
      veri: Array.from({ length: BASE_VALUE_COUNT }, (_, index) => nv(row[index], '')),
      ulusal: nv(row[26], 'HAYIR'),
      ziyaret1: nv(row[27], 'HAYIR'),
      ziyaret1Not: nv(row[28], ''),
      ziyaret1Tarih: nv(row[29], ''),
      ziyaret2: nv(row[30], 'HAYIR'),
      ziyaret2Not: nv(row[31], ''),
      ziyaret2Tarih: nv(row[32], ''),
      telefonGorusmesi: nv(row[33], 'HAYIR'),
      telefonGorusmesiNot: nv(row[34], ''),
      telefonGorusmesiTarih: nv(row[35], ''),
      aski: nv(row[36], 'HAYIR'),
      ikiYil: nv(row[37], 'HAYIR'),
      oy: nv(row[38], 'SEÇ'),
      tarih: nv(row[39], tarih())
    });
  }

  function excel() {
    const exportTable = document.createElement('table');
    exportTable.innerHTML = `<tr>${COLUMN_TITLES.map(title => `<th>${escapeHtml(title)}</th>`).join('')}</tr>`;
    getTableData().forEach(item => {
      const tr = document.createElement('tr');
      buildRowExportArray(item).forEach(value => {
        const td = document.createElement('td');
        td.textContent = value;
        tr.appendChild(td);
      });
      exportTable.appendChild(tr);
    });
    XLSX.writeFile(XLSX.utils.table_to_book(exportTable, { sheet: 'Uyeler' }), 'uyeler.xlsx');
  }

  function exceldenYukle(input) {
    const file = input.files && input.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = event => {
      try {
        const workbook = XLSX.read(new Uint8Array(event.target.result), { type: 'array' });
        const rows = XLSX.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]], { header: 1, defval: '' });
        if (!rows.length) return alert('Excel içinde veri bulunamadı.');
        const headers = rows[0].map(item => String(nv(item, '')));
        const body = rows.slice(1).filter(row => row.some(value => String(value).trim() !== ''));
        const headerMap = buildImportHeaderMap(headers);
        const recognized = Object.keys(headerMap).length;
        const looksLegacy = normalizeHeaderValue(headers[25]) === 'aski olmama durumu' || normalizeHeaderValue(headers[33]) === 'ziyaret 3';
        const positionalSchemaVersion = looksLegacy ? 1 : (headers.length >= COLUMN_TITLES.length ? 3 : 2);
        renderRows(body.map(row => recognized >= 10 ? mapExcelRowWithHeaders(row, headerMap) : mapExcelRowByPosition(row, positionalSchemaVersion)));
        applyHiddenColumns();
        alert('Excel verileri tabloya yüklendi.');
      } catch (error) {
        alert('Excel okunamadı. Başlık sırası sistemle aynı olmalı.');
      }
    };
    reader.readAsArrayBuffer(file);
    input.value = '';
  }

  function loadChart() {
    const counts = { EVET: 0, ORTA: 0, HAYIR: 0 };
    let total = 0;
    getTableData().forEach(item => {
      if (item.aski === 'EVET' || item.ikiYil === 'EVET') return;
      total += 1;
      if (counts[item.oy] !== undefined) counts[item.oy] += 1;
    });
    qs('statTotal').textContent = String(total);
    qs('statEvet').textContent = String(counts.EVET);
    qs('statOrta').textContent = String(counts.ORTA);
    qs('statHayir').textContent = String(counts.HAYIR);
    if (chartInstance) chartInstance.destroy();
    chartInstance = new Chart(qs('chart'), {
      type: 'pie',
      data: { labels: ['EVET', 'ORTA', 'HAYIR'], datasets: [{ data: [counts.EVET, counts.ORTA, counts.HAYIR], backgroundColor: ['#22c55e', '#f59e0b', '#ef4444'], borderWidth: 0 }] },
      options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
    });
  }

  function sutunBoyutlandirBaslat(event, index) {
    event.preventDefault();
    event.stopPropagation();
    const rows = [...qs('tablo').querySelectorAll('tr')];
    const startX = event.clientX;
    const header = qs('tablo').querySelector(`th[data-col="${index}"]`);
    const startWidth = header ? header.offsetWidth : 120;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    function onMove(moveEvent) {
      const width = Math.max(70, startWidth + (moveEvent.clientX - startX));
      rows.forEach(row => {
        const cell = row.children[index];
        if (cell) {
          cell.style.width = width + 'px';
          cell.style.minWidth = width + 'px';
          cell.style.maxWidth = width + 'px';
        }
      });
    }
    function onUp() {
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }

  function showPage(id) {
    document.querySelectorAll('.page').forEach(page => page.classList.remove('active'));
    qs(id).classList.add('active');
    document.querySelectorAll('.menu button').forEach(btn => btn.classList.remove('active'));
    qs('nav-' + id).classList.add('active');
    if (id === 'kayit') renderHistory();
    if (id === 'grafik') loadChart();
  }

  async function initializeApp() {
    renderTableHeader();
    listeyiCiz();
    updateFolderInfo();
    renderRows(getDraft());
    applyHiddenColumns();
    renderHiddenColumns();
    renderHistory();
    loadChart();
    setLoginControlsDisabled(false);
    clearLoginStatus();
  }

  async function bootstrap() {
    Object.assign(window, {
      login, showPage, filtre, filtreTemizle, satirEkle, klasorSec, exceldenYukle, tabloTemizle, sonKaydiYukle,
      tumunuKaydet, excel, kolonMenuAc, sutunBoyutlandirBaslat, sil, oyDegistir, durumDegisti, sutunGoster,
      resimInputDegisti, resimSec, duzenlemeyiBaslat, ismiKaydet, duzenlemeyiIptalEt, kaydiYukle, kaydiSil,
      autoSaveDraft
    });
    renderTableHeader();
    qs('tablo').addEventListener('click', handleTableNotificationEvent);
    qs('tablo').addEventListener('focusin', handleTableNotificationEvent);
    await seedDefaultUsers();
    try {
      const defaultUser = await apiRequest('/default-user');
      qs('user').value = defaultUser.username || '';
    } catch (error) {
      qs('user').value = '';
    }
    await refreshLoginStateForUser(qs('user').value.trim());
    qs('user').addEventListener('input', async () => refreshLoginStateForUser(qs('user').value.trim()));
    qs('user').addEventListener('keydown', event => { if (event.key === 'Enter') login(); });
    qs('pass').addEventListener('keydown', event => { if (event.key === 'Enter') login(); });
    window.addEventListener('pagehide', () => queuePersistUserData(true));
  }

  bootstrap().catch(error => {
    console.error(error);
    qs('loginError').textContent = 'Uygulama başlatılamadı.';
  });
})();
