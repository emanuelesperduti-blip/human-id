const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const GLOBAL_CHAIN = "global-chain.json";
const IDENTITIES_DIR = "identities";

// Assicura cartella identities
if (!fs.existsSync(IDENTITIES_DIR)) {
  fs.mkdirSync(IDENTITIES_DIR);
}

// ==========================
// HASH SHA256
// ==========================
function hash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// ==========================
// CREAZIONE IDENTITÀ
// ==========================
function creaIdentita() {
  const id = crypto.randomBytes(16).toString("hex");

  const genesisBlock = {
    index: 0,
    timestamp: new Date().toISOString(),
    event: "CREATION",
    data: {
      verificationLevel: "AI_PENDING",
      status: "ACTIVE"
    },
    previousHash: "GENESIS"
  };

  genesisBlock.hash = hash(JSON.stringify(genesisBlock));

  const chain = [genesisBlock];

  const filePath = path.join(IDENTITIES_DIR, `${id}.json`);
  fs.writeFileSync(filePath, JSON.stringify(chain, null, 2));

  registraSuGlobalChain(id, genesisBlock.hash);

  return id;
}

// ==========================
// REGISTRA SU GLOBAL CHAIN
// ==========================
function registraSuGlobalChain(id, latestHash) {
  let globalChain = [];

  if (fs.existsSync(GLOBAL_CHAIN)) {
    globalChain = JSON.parse(fs.readFileSync(GLOBAL_CHAIN));
  }

  const record = {
    id,
    timestamp: new Date().toISOString(),
    latestHash
  };

  globalChain.push(record);
  fs.writeFileSync(GLOBAL_CHAIN, JSON.stringify(globalChain, null, 2));
}

// ==========================
// AGGIORNA VERIFICA (APPEND ONLY)
// ==========================
function aggiornaVerifica(id, nuovoLivello) {
  const identityPath = path.join(IDENTITIES_DIR, `${id}.json`);

  if (!fs.existsSync(identityPath)) {
    return { error: "Identità non trovata." };
  }

  const chain = JSON.parse(fs.readFileSync(identityPath));
  const lastBlock = chain[chain.length - 1];

  const newBlock = {
    index: chain.length,
    timestamp: new Date().toISOString(),
    event: "UPDATE_VERIFICATION",
    data: {
      verificationLevel: nuovoLivello
    },
    previousHash: lastBlock.hash
  };

  newBlock.hash = hash(JSON.stringify(newBlock));

  chain.push(newBlock);
  fs.writeFileSync(identityPath, JSON.stringify(chain, null, 2));

  // Aggiorna Global Chain
  let globalChain = JSON.parse(fs.readFileSync(GLOBAL_CHAIN));
  const record = globalChain.find(r => r.id === id);

  if (record) {
    record.latestHash = newBlock.hash;
    fs.writeFileSync(GLOBAL_CHAIN, JSON.stringify(globalChain, null, 2));
  }

  return { success: true };
}

// ==========================
// VERIFICA INTEGRITÀ
// ==========================
function verificaIdentita(id) {
  const identityPath = path.join(IDENTITIES_DIR, `${id}.json`);

  if (!fs.existsSync(identityPath)) {
    return { error: "Identità non trovata." };
  }

  const microChain = JSON.parse(fs.readFileSync(identityPath));

  if (!fs.existsSync(GLOBAL_CHAIN)) {
    return { error: "Global chain non trovata." };
  }

  const globalChain = JSON.parse(fs.readFileSync(GLOBAL_CHAIN));
  const record = globalChain.find(r => r.id === id);

  if (!record) {
    return { error: "Record non presente nella Global Chain." };
  }

  const lastBlock = microChain[microChain.length - 1];

  const recalculatedHash = hash(JSON.stringify({
    index: lastBlock.index,
    timestamp: lastBlock.timestamp,
    event: lastBlock.event,
    data: lastBlock.data,
    previousHash: lastBlock.previousHash
  }));

  if (recalculatedHash === record.latestHash) {
    return { valid: true };
  } else {
    return { valid: false };
  }
}

module.exports = {
  creaIdentita,
  aggiornaVerifica,
  verificaIdentita
};