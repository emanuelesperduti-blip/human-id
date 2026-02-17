const express = require("express");
const cors = require("cors");

const {
  creaIdentita,
  aggiornaVerificaFirmata,
  verificaIdentita,
  leggiChain,
  canonicalMessage
} = require("./index");

const app = express();

app.use(cors());
app.use(express.json());

// health
app.get("/", (req, res) => {
  res.json({ status: "Human-ID API is running" });
});

// helper: ti dice esattamente cosa firmare
app.post("/message-to-sign", (req, res) => {
  const { id, level, ts, nonce } = req.body || {};
  if (!id || level === undefined || !ts || !nonce) {
    return res.status(400).json({ error: "Richiesti: id, level, ts, nonce" });
  }
  const payload = { id, level, ts, nonce };
  res.json({ payload, message: canonicalMessage(payload) });
});

// CREATE: richiede publicKeyPem (wallet genera keypair)
app.post("/create", (req, res) => {
  const { publicKeyPem } = req.body || {};
  const out = creaIdentita(publicKeyPem);
  if (out.error) return res.status(400).json(out);
  res.json(out);
});

// UPDATE (firmato)
app.post("/update", (req, res) => {
  const { id, payload, signatureB64 } = req.body || {};
  if (!id || !payload || !signatureB64) {
    return res.status(400).json({ error: "Richiesti: id, payload, signatureB64" });
  }

  const out = aggiornaVerificaFirmata({ id, payload, signatureB64 });
  if (out.error) return res.status(400).json(out);
  res.json(out);
});

// VERIFY
app.get("/verify/:id", (req, res) => {
  const out = verificaIdentita(req.params.id);
  if (out.error) return res.status(404).json(out);
  res.json(out);
});

// DEBUG: leggi la chain (solo per sviluppo)
app.get("/chain/:id", (req, res) => {
  const out = leggiChain(req.params.id);
  if (out.error) return res.status(404).json(out);
  res.json(out);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server avviato sulla porta ${PORT}`));