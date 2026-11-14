// Satu pintu masuk (pemilik 14 Nov 2026: tanpa tautan email, cukup username dan password).
//   - email + password admin: dicek ke Supabase Auth, lalu harus terdaftar di gl_admin
//     (gl_fygo_admin). Sesi Supabase dikembalikan ke peramban supaya tombol admin
//     (ACC/STOP, Tambah data, Unduh Excel lengkap) langsung jalan tanpa masuk kedua.
//   - username lama (AUTH_USER, hash scrypt di AUTH_PASS_HASH): hanya lihat.
// Cookie sesi situs ditandatangani HMAC AUTH_RAHASIA, dibaca middleware.js.
import { createHmac, scryptSync, timingSafeEqual } from "node:crypto";

const UMUR_DETIK = 14 * 24 * 3600;
// URL proyek dan kunci publishable memang publik (sama dengan yang ada di index.html)
const SB_URL = "https://idezvrptuhqkwkwaonzq.supabase.co";
const SB_KEY = "sb_publishable_Hm0-sGWlq_XwDXtHHCT5JA_n6_jhg0a";

function balas(status, isi, kepala = {}) {
  return new Response(JSON.stringify(isi), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...kepala } });
}

function samaTeks(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

function passwordBenar(password) {
  return (process.env.AUTH_PASS_HASH || "").split(/\s+/).filter(Boolean).some((baris) => {
    const [garam, hash] = baris.split(":");
    const harap = Buffer.from(hash || "", "hex");
    return harap.length > 0 && timingSafeEqual(scryptSync(String(password), garam, harap.length), harap);
  });
}

async function masukSupabase(email, password) {
  const r = await fetch(`${SB_URL}/auth/v1/token?grant_type=password`, {
    method: "POST", headers: { apikey: SB_KEY, "content-type": "application/json" }, body: JSON.stringify({ email, password }),
  });
  if (!r.ok) return { salah: true };
  const s = await r.json();
  const a = await fetch(`${SB_URL}/rest/v1/rpc/gl_fygo_admin`, {
    method: "POST", headers: { apikey: SB_KEY, authorization: `Bearer ${s.access_token}`, "content-type": "application/json" }, body: "{}",
  });
  if (!a.ok || (await a.json()) !== true) return { bukanAdmin: true };
  return { sesi: { access_token: s.access_token, refresh_token: s.refresh_token } };
}

function cookieSesi(rahasia) {
  const habis = String(Math.floor(Date.now() / 1000) + UMUR_DETIK);
  const sah = createHmac("sha256", rahasia).update(habis).digest("hex");
  return `sesi=${habis}.${sah}; Path=/; Max-Age=${UMUR_DETIK}; HttpOnly; Secure; SameSite=Lax`;
}

export async function POST(request) {
  const rahasia = process.env.AUTH_RAHASIA;
  if (!rahasia) return balas(503, { ok: false, alasan: "Login belum disiapkan." });
  let isi;
  try {
    isi = await request.json();
  } catch {
    return balas(400, { ok: false, alasan: "Permintaan tidak sah." });
  }
  // Jeda kecil supaya menebak password berulang jadi lambat.
  await new Promise((r) => setTimeout(r, 400));
  const nama = String(isi.username || "").trim(), sandi = String(isi.password || "");
  if (!nama || !sandi) return balas(400, { ok: false, alasan: "Isi email dan password." });

  if (nama.includes("@")) {
    let h;
    try {
      h = await masukSupabase(nama.toLowerCase(), sandi);
    } catch {
      return balas(502, { ok: false, alasan: "Server login tidak tersambung, coba lagi." });
    }
    if (h.salah) return balas(401, { ok: false, alasan: "Email atau password salah." });
    if (h.bukanAdmin) return balas(403, { ok: false, alasan: "Akun ini bukan admin FYGO." });
    return balas(200, { ok: true, admin: true, sesi: h.sesi }, { "set-cookie": cookieSesi(rahasia) });
  }

  // username lama (hanya lihat) dimatikan 14 Nov 2026: halaman ini khusus admin
  return balas(401, { ok: false, alasan: "Masuk pakai email admin. Belum punya password? Klik Lupa password." });
}
