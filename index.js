const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const GLOBAL_CHAIN = "global-chain.json";
const IDENTITIES_DIR = "identities";

// Render free: filesystem non è affidabile a lungo termine, ma ok per MVP.
if (!fs.existsSync(IDENTITIES_DIR)) fs.mkdirSync(IDENTITIES_DIR);

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function readJson(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}

function identityPath(id) {
  return path.join(IDENTITIES_DIR, `${id}.json`);
}

// Messaggio canonico (niente JSON-order issues)
function canonicalMessage(payload) {
  // payload: { id, level, ts, nonce }
  return `id=${payload.id}|level=${payload.level}|ts=${payload.ts}|nonce=${payload.nonce}`;
}

// Accetta publicKey PEM (Ed25519). Esempio:
// -----BEGIN PUBLIC KEY-----
// ...
// -----END PUBLIC KEY-----
function normalizePemPublicKey(pub) {
  if (typeof pub !== "string") return null;
  const trimmed = pub.trim();
  if (!trimmed.includes("BEGIN PUBLIC KEY")) return null;
  return trimmed;
}

function getChain(id) {
  const p = identityPath(id);
  if (!fs.existsSync(p)) return null;
  return readJson(p, null);
}

function getGenesisPublicKey(chain) {
  const genesis = chain?.[0];
  const pk = genesis?.data?.publicKeyPem;
  return normalizePemPublicKey(pk);
}

function updateGlobalAnchor(id, latestHash) {
  const globalChain = readJson(GLOBAL_CHAIN, []);
  const rec = globalChain.find(r => r.id === id);
  if (rec) {
    rec.latestHash = latestHash;
    rec.timestamp = new Date().toISOString();
  } else {
    globalChain.push({ id, timestamp: new Date().toISOString(), latestHash });
  }
  writeJson(GLOBAL_CHAIN, globalChain);
}

// ==========================
// CREAZIONE IDENTITÀ (richiede publicKey PEM)
// ==========================
function creaIdentita(publicKeyPem) {
  const pk = normalizePemPublicKey(publicKeyPem);
  if (!pk) return { error: "publicKeyPem mancante o non valida (PEM PUBLIC KEY)" };

  const id = crypto.randomBytes(16).toString("hex");

  const genesisBlock = {
    index: 0,
    timestamp: new Date().toISOString(),
    event: "CREATION",
    data: {
      status: "ACTIVE",
      verificationLevel: "AI_PENDING",
      publicKeyPem: pk
    },
    previousHash: "GENESIS"
  };

  genesisBlock.hash = sha256(JSON.stringify(genesisBlock));

  const chain = [genesisBlock];
  writeJson(identityPath(id), chain);

  updateGlobalAnchor(id, genesisBlock.hash);

  return { success: true, id };
}

// ==========================
// APPEND EVENT (firma obbligatoria)
// ==========================
function appendEventSigned({ id, event, payload, signatureB64, dataExtra }) {
  const chain = getChain(id);
  if (!chain) return { error: "Identità non trovata." };

  const publicKeyPem = getGenesisPublicKey(chain);
  if (!publicKeyPem) return { error: "Public key non presente/valida in genesis." };

  if (!payload || !signatureB64) return { error: "payload e signature richiesti." };
  if (payload.id !== id) return { error: "payload.id non combacia con id." };

  const msg = canonicalMessage(payload);

  let signature;
  try {
    signature = Buffer.from(signatureB64, "base64");
  } catch {
    return { error: "signature non è base64 valida." };
  }

  // Verify Ed25519
  const ok = crypto.verify(
    null,
    Buffer.from(msg, "utf8"),
    publicKeyPem,
    signature
  );

  if (!ok) return { error: "Firma NON valida. Update rifiutato." };

  const lastBlock = chain[chain.length - 1];

  const newBlock = {
    index: chain.length,
    timestamp: new Date().toISOString(),
    event,
    data: {
      payload,           // ciò che è stato firmato
      signatureB64,      // firma
      ...dataExtra       // dati evento “umani”
    },
    previousHash: lastBlock.hash
  };

  newBlock.hash = sha256(JSON.stringify(newBlock));

  chain.push(newBlock);
  writeJson(identityPath(id), chain);

  updateGlobalAnchor(id, newBlock.hash);

  return { success: true };
}

// Mappa livelli numerici se ti serve retro-compatibilità (tu avevi level=2)
function normalizeLevel(level) {
  const map = {
    0: "AI_PENDING",
    1: "AI_VERIFIED",
    2: "SPID_VERIFIED",
    3: "JURY_APPROVED"
  };
  if (typeof level === "number") return map[level] ?? `LEVEL_${level}`;
  if (typeof level === "string") return level.trim();
  return null;
}

// ==========================
// UPDATE VERIFICA (firma obbligatoria)
// ==========================
function aggiornaVerificaFirmata({ id, payload, signatureB64 }) {
  const level = normalizeLevel(payload?.level);
  if (!level) return { error: "level non valido." };

  return appendEventSigned({
    id,
    event: "UPDATE_VERIFICATION",
    payload: { ...payload, level },
    signatureB64,
    dataExtra: {
      verificationLevel: level
    }
  });
}

// ==========================
// VERIFICA INTEGRITÀ (anchor + hash ultimo blocco)
// ==========================
function verificaIdentita(id) {
  const chain = getChain(id);
  if (!chain) return { error: "Identità non trovata." };

  const globalChain = readJson(GLOBAL_CHAIN, []);
  const record = globalChain.find(r => r.id === id);
  if (!record) return { error: "Record non presente nella Global Chain." };

  const lastBlock = chain[chain.length - 1];

  // Recalcola hash ultimo blocco (senza il campo hash)
  const { hash, ...withoutHash } = lastBlock;
  const recalculated = sha256(JSON.stringify(withoutHash));

  const valid = recalculated === record.latestHash;

  // Stato “umano” = ultimo verificationLevel visto
  let verificationLevel = chain[0]?.data?.verificationLevel ?? "AI_PENDING";
  let status = chain[0]?.data?.status ?? "ACTIVE";

  for (const b of chain) {
    if (b.event === "UPDATE_VERIFICATION" && b.data?.verificationLevel) {
      verificationLevel = b.data.verificationLevel;
    }
    if (b.event === "STATUS_SUSPENDED") status = "SUSPENDED";
    if (b.event === "STATUS_REVOKED") status = "REVOKED";
  }

  return { valid, id, status, verificationLevel, blocks: chain.length };
}

// ==========================
// LETTURA CHAIN (debug)
// ==========================
function leggiChain(id) {
  const chain = getChain(id);
  if (!chain) return { error: "Identità non trovata." };
  return { id, chain };
}

module.exports = {
  creaIdentita,
  aggiornaVerificaFirmata,
  verificaIdentita,
  leggiChain,
  canonicalMessage
};