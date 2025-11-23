const express = require('express');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const port = 3000;

const API_PREFIX = 'sk-sm-v1-';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ========================================================================
// 1. REGISTER USER + GENERATE API KEY OTOMATIS
// ========================================================================
app.post('/register', async (req, res) => {
  const { first_name, last_name, email_address } = req.body;

  if (!first_name || !last_name || !email_address) {
    return res.status(400).json({ error: "Semua field wajib diisi." });
  }

  try {
    // Generate API Key
    const apiKey = API_PREFIX + crypto.randomBytes(24).toString('hex').toUpperCase();

    // Insert ke api_key
    const [keyResult] = await pool.execute(
      "INSERT INTO api_key (api_key, is_active) VALUES (?, 1)",
      [apiKey]
    );

    const apiKeyId = keyResult.insertId;

    // Insert ke user
    await pool.execute(
      "INSERT INTO user (first_name, last_name, email_address, fk_apikey) VALUES (?, ?, ?, ?)",
      [first_name, last_name, email_address, apiKeyId]
    );

    res.json({
      message: "User dan API key berhasil dibuat",
      api_key: apiKey
    });

  } catch (err) {
    console.error(err);

    if (err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ error: "Email sudah terdaftar." });
    }

    res.status(500).json({ error: "Gagal membuat user dan API key" });
  }
});

// ========================================================================
// 2. CEK API KEY
// ========================================================================
app.post('/cekapi', async (req, res) => {
  try {
    const fromHeader = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
    const apiKey = req.body.apiKey || fromHeader;

    if (!apiKey) {
      return res.status(400).json({ valid: false, error: 'apiKey wajib dikirim' });
    }

    if (!apiKey.startsWith(API_PREFIX)) {
      return res.status(400).json({ valid: false, error: 'Format apiKey tidak valid' });
    }

    const [rows] = await pool.execute(
      'SELECT id, is_active FROM api_key WHERE api_key = ? LIMIT 1',
      [apiKey]
    );

    if (rows.length === 0) {
      return res.status(401).json({ valid: false, error: 'API key tidak dikenali' });
    }

    if (!rows[0].is_active) {
      return res.status(403).json({ valid: false, error: 'API key nonaktif' });
    }

    return res.json({ valid: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ valid: false, error: 'Kesalahan server saat verifikasi' });
  }
});

// ========================================================================
// 3. ADMIN LOGIN
// ========================================================================
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;

  const [rows] = await pool.execute(
    "SELECT * FROM admin WHERE email = ? LIMIT 1",
    [email]
  );

  if (rows.length === 0) {
    return res.status(401).json({ error: "Admin tidak ditemukan" });
  }

  const admin = rows[0];

  const isValid = await bcrypt.compare(password, admin.password);
  if (!isValid) {
    return res.status(401).json({ error: "Password salah" });
  }

  res.json({ message: "Login berhasil" });
});

// ========================================================================
// 4. ADMIN - LIST USER
// ========================================================================
app.get('/admin/users', async (req, res) => {
  const [rows] = await pool.execute(`
    SELECT 
      user.id_user,
      user.first_name,
      user.last_name,
      user.email_address,
      api_key.api_key,
      api_key.is_active
    FROM user
    LEFT JOIN api_key ON user.fk_apikey = api_key.id
  `);

  res.json(rows);
});

// ========================================================================
// 5. ADMIN - LIST API KEYS
// ========================================================================
app.get('/admin/apikeys', async (req, res) => {
  const [rows] = await pool.execute("SELECT * FROM api_key");
  res.json(rows);
});

// ========================================================================
app.listen(port, () => {
  console.log(`Server berjalan di http://localhost:${port}`);
});
