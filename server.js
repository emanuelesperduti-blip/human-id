const express = require("express");
const cors = require("cors");

const {
  creaIdentita,
  aggiornaVerifica,
  verificaIdentita
} = require("./index");

const app = express();

// ==========================
// MIDDLEWARE
// ==========================
app.use(cors());
app.use(express.json());

// ==========================
// ROUTE BASE (test server)
// ==========================
app.get("/", (req, res) => {
  res.json({ status: "Human-ID API is running" });
});

// ==========================
// CREA IDENTITÀ
// ==========================
app.post("/create", (req, res) => {
  try {
    const id = creaIdentita();
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ error: "Errore creazione identità" });
  }
});

// ==========================
// AGGIORNA VERIFICA
// ==========================
app.post("/update", (req, res) => {
  const { id, level } = req.body;

  if (!id || !level) {
    return res.status(400).json({ error: "id e level richiesti" });
  }

  const result = aggiornaVerifica(id, level);

  if (result.error) {
    return res.status(404).json(result);
  }

  res.json({ success: true });
});

// ==========================
// VERIFICA IDENTITÀ
// ==========================
app.get("/verify/:id", (req, res) => {
  const result = verificaIdentita(req.params.id);

  if (result.error) {
    return res.status(404).json(result);
  }

  res.json(result);
});

// ==========================
// SERVER START
// ==========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});