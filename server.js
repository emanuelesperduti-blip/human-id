const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

// Optional Postgres (fallback to memory if DATABASE_URL missing)
let pg = null;
try { pg = require("pg"); } catch {}

const app = express();
app.use(cors());
app.use(express.json());

// ==========================
// Config
// ==========================
const PORT = process.env.PORT || 3000;

// Issuer keys (set on Render -> Environment)
const AI_ISSUER_KEY = process.env.AI_ISSUER_KEY || "";
const SPID_ISSUER_KEY = process.env.SPID_ISSUER_KEY || "";
const JURY_ISSUER_KEY = process.env.JURY_ISSUER_KEY || "";
// Multi-sig suspension keys (2-of-3 demo)
const SUSPEND_KEY_1 = process.env.SUSPEND_KEY_1 || "";
const SUSPEND_KEY_2 = process.env.SUSPEND_KEY_2 || "";
const SUSPEND_KEY_3 = process.env.SUSPEND_KEY_3 || "";

const DATABASE_URL = process.env.DATABASE_URL || "";

// ==========================
// Helpers
// ==========================
const nowMs = () => Date.now();
const nowSec = () => Math.floor(Date.now() / 1000);

function base64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

// DID stable from the public key DER bytes
function didFromPublicKeyPem(publicKeyPem) {
  const keyObj = crypto.createPublicKey(publicKeyPem);
  const der = keyObj.export({ type: "spki", format: "der" });
  const fp = crypto.createHash("sha256").update(der).digest(); // 32 bytes
  return `did:human:${base64url(fp)}`;
}

function requireDid(did) {
  return typeof did === "string" && did.startsWith("did:human:") && did.length > 20;
}

function verifyEd25519Signature({ publicKeyPem, message, signatureB64 }) {
  const sig = Buffer.from(signatureB64, "base64");
  // Node crypto: verify(null, message, publicKey, signature) for Ed25519
  return crypto.verify(null, Buffer.from(message, "utf8"), publicKeyPem, sig);
}

function levelFromAttestations(attList) {
  const hasAI = attList.some(a => a.type === "AI_VERIFIED" && !a.revoked);
  const hasSPID = attList.some(a => a.type === "SPID_VERIFIED" && !a.revoked);
  const hasJURY = attList.some(a => a.type === "JURY_VERIFIED" && !a.revoked);
  const suspended = attList.some(a => a.type === "SUSPENDED" && !a.revoked);

  if (suspended) return "SUSPENDED";
  if (hasAI && hasSPID && hasJURY) return "MAX_VERIFIED";
  if (hasAI && hasSPID) return "STRONG_VERIFIED";
  if (hasAI) return "AI_VERIFIED";
  return "UNVERIFIED";
}

function issuerKeyValid(type, keys) {
  if (type === "AI_VERIFIED") return !!AI_ISSUER_KEY && keys.includes(AI_ISSUER_KEY);
  if (type === "SPID_VERIFIED") return !!SPID_ISSUER_KEY && keys.includes(SPID_ISSUER_KEY);
  if (type === "JURY_VERIFIED") return !!JURY_ISSUER_KEY && keys.includes(JURY_ISSUER_KEY);
  if (type === "SUSPENDED") {
    // 2-of-3 demo
    const allowed = [SUSPEND_KEY_1, SUSPEND_KEY_2, SUSPEND_KEY_3].filter(Boolean);
    const ok = keys.filter(k => allowed.includes(k)).length;
    return ok >= 2;
  }
  return false;
}

// ==========================
// Storage Layer (DB if available, else memory)
// ==========================
const mem = {
  subjects: new Map(),       // did -> { did, publicKeyPem, createdAt }
  challenges: new Map(),     // did -> { nonce, expMs }
  attestations: new Map(),   // did -> [ { id, type, payload, issuedAt, revoked } ]
};

let pool = null;
let useDb = false;

async function initDbIfPossible() {
  if (!DATABASE_URL || !pg) return;
  pool = new pg.Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
  // Create tables (demo-safe)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS subjects (
      did TEXT PRIMARY KEY,
      public_key_pem TEXT NOT NULL,
      created_at BIGINT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS challenges (
      did TEXT PRIMARY KEY,
      nonce TEXT NOT NULL,
      exp_ms BIGINT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS attestations (
      id BIGSERIAL PRIMARY KEY,
      did TEXT NOT NULL,
      type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      issued_at BIGINT NOT NULL,
      revoked BOOLEAN NOT NULL DEFAULT FALSE
    );
  `);
  useDb = true;
}

async function upsertSubject(did, publicKeyPem) {
  const createdAt = nowMs();
  if (!useDb) {
    if (!mem.subjects.has(did)) mem.subjects.set(did, { did, publicKeyPem, createdAt });
    return;
  }
  await pool.query(
    `INSERT INTO subjects(did, public_key_pem, created_at)
     VALUES($1,$2,$3)
     ON CONFLICT(did) DO NOTHING`,
    [did, publicKeyPem, createdAt]
  );
}

async function getSubject(did) {
  if (!useDb) return mem.subjects.get(did) || null;
  const r = await pool.query(`SELECT did, public_key_pem AS "publicKeyPem", created_at AS "createdAt" FROM subjects WHERE did=$1`, [did]);
  return r.rows[0] || null;
}

async function setChallenge(did, nonce, expMs) {
  if (!useDb) {
    mem.challenges.set(did, { nonce, expMs });
    return;
  }
  await pool.query(
    `INSERT INTO challenges(did, nonce, exp_ms)
     VALUES($1,$2,$3)
     ON CONFLICT(did) DO UPDATE SET nonce=EXCLUDED.nonce, exp_ms=EXCLUDED.exp_ms`,
    [did, nonce, expMs]
  );
}

async function getChallenge(did) {
  if (!useDb) return mem.challenges.get(did) || null;
  const r = await pool.query(`SELECT nonce, exp_ms AS "expMs" FROM challenges WHERE did=$1`, [did]);
  return r.rows[0] || null;
}

async function deleteChallenge(did) {
  if (!useDb) { mem.challenges.delete(did); return; }
  await pool.query(`DELETE FROM challenges WHERE did=$1`, [did]);
}

async function addAttestation(did, type, payloadObj) {
  const issuedAt = nowMs();
  const payload_json = JSON.stringify(payloadObj || {});
  if (!useDb) {
    const list = mem.attestations.get(did) || [];
    list.push({ id: `${type}:${issuedAt}`, type, payload: payloadObj || {}, issuedAt, revoked: false });
    mem.attestations.set(did, list);
    return;
  }
  await pool.query(
    `INSERT INTO attestations(did, type, payload_json, issued_at, revoked)
     VALUES($1,$2,$3,$4,FALSE)`,
    [did, type, payload_json, issuedAt]
  );
}

async function listAttestations(did) {
  if (!useDb) return mem.attestations.get(did) || [];
  const r = await pool.query(
    `SELECT id, type, payload_json AS "payloadJson", issued_at AS "issuedAt", revoked
     FROM attestations WHERE did=$1 ORDER BY issued_at ASC`,
    [did]
  );
  return r.rows.map(x => ({
    id: x.id,
    type: x.type,
    payload: JSON.parse(x.payloadJson || "{}"),
    issuedAt: x.issuedAt,
    revoked: !!x.revoked
  }));
}

// ==========================
// Routes
// ==========================
app.get("/", (req, res) => {
  res.json({
    status: "Human-ID API is running",
    mode: useDb ? "online-persistent" : "online-demo-memory",
    endpoints: {
      register: "POST /register (or POST /create)",
      challenge: "GET /challenge/:did",
      prove: "POST /prove",
      attest: "POST /attest",
      verify: "GET /verify/:did"
    }
  });
});

// Register public key -> DID
app.post("/register", async (req, res) => {
  try {
    const { publicKeyPem } = req.body || {};
    if (!publicKeyPem || typeof publicKeyPem !== "string") {
      return res.status(400).json({ error: "publicKeyPem richiesto" });
    }

    // Validate it parses
    crypto.createPublicKey(publicKeyPem);

    const did = didFromPublicKeyPem(publicKeyPem);
    await upsertSubject(did, publicKeyPem);

    res.json({ success: true, did });
  } catch (e) {
    res.status(400).json({ error: "publicKeyPem non valido", details: String(e.message || e) });
  }
});

// Backward compatibility: /create -> /register
app.post("/create", (req, res, next) => app._router.handle({ ...req, url: "/register" }, res, next));

// Challenge
app.get("/challenge/:did", async (req, res) => {
  const did = req.params.did;
  if (!requireDid(did)) return res.status(400).json({ error: "DID non valido" });

  const subj = await getSubject(did);
  if (!subj) return res.status(404).json({ error: "Identità non trovata. Prima fai /register" });

  const nonce = crypto.randomBytes(24).toString("hex");
  const expMs = nowMs() + 60_000;

  await setChallenge(did, nonce, expMs);
  res.json({ did, nonce, expMs });
});

// Prove possession of private key
app.post("/prove", async (req, res) => {
  const { did, nonce, signatureB64 } = req.body || {};
  if (!requireDid(did) || !nonce || !signatureB64) {
    return res.status(400).json({ error: "did, nonce, signatureB64 richiesti" });
  }

  const subj = await getSubject(did);
  if (!subj) return res.status(404).json({ error: "Identità non trovata" });

  const ch = await getChallenge(did);
  if (!ch) return res.status(400).json({ error: "Challenge non trovato" });
  if (nowMs() > ch.expMs) {
    await deleteChallenge(did);
    return res.status(400).json({ error: "Challenge scaduto" });
  }
  if (ch.nonce !== nonce) return res.status(400).json({ error: "Nonce non combacia" });

  const ok = verifyEd25519Signature({
    publicKeyPem: subj.publicKeyPem,
    message: nonce,
    signatureB64
  });

  if (!ok) return res.status(401).json({ ok: false, error: "Firma non valida" });

  await deleteChallenge(did); // anti-replay
  res.json({ ok: true });
});

// Attestations (AI/SPID/JURY/SUSPENDED) - demo governance
app.post("/attest", async (req, res) => {
  const { did, type, payload, issuerKeys } = req.body || {};
  if (!requireDid(did) || !type) return res.status(400).json({ error: "did e type richiesti" });

  const subj = await getSubject(did);
  if (!subj) return res.status(404).json({ error: "Identità non trovata" });

  const keys = Array.isArray(issuerKeys) ? issuerKeys : (issuerKeys ? [issuerKeys] : []);
  if (!issuerKeyValid(type, keys)) return res.status(401).json({ error: "issuerKeys non valide per questo type" });

  await addAttestation(did, type, { ...(payload || {}), issuedAt: nowSec() });
  res.json({ success: true });
});

// Verify status
app.get("/verify/:did", async (req, res) => {
  const did = req.params.did;
  if (!requireDid(did)) return res.status(400).json({ error: "DID non valido" });

  const subj = await getSubject(did);
  if (!subj) return res.status(404).json({ error: "Identità non trovata" });

  const atts = await listAttestations(did);
  const status = levelFromAttestations(atts);

  res.json({
    valid: true,
    did,
    status,
    attestations: atts.map(a => ({
      id: a.id,
      type: a.type,
      issuedAt: a.issuedAt,
      revoked: a.revoked,
      payload: a.payload
    }))
  });
});

// ==========================
// Start
// ==========================
initDbIfPossible()
  .then(() => {
    app.listen(PORT, () => console.log(`Server avviato sulla porta ${PORT} (${useDb ? "DB" : "MEM"})`));
  })
  .catch((e) => {
    console.error("DB init error:", e);
    // still start in memory mode
    useDb = false;
    app.listen(PORT, () => console.log(`Server avviato sulla porta ${PORT} (MEM fallback)`));
  });
