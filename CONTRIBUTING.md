# Contributing to CyberWatch IDS

Terima kasih atas minat Anda untuk berkontribusi pada CyberWatch IDS!

## Cara Berkontribusi

### 1. Fork & Clone

```bash
git clone https://github.com/heri99123/CyberwatchIDS.git
cd CyberwatchIDS
```

### 2. Setup Development Environment

Buka di GitHub Codespaces (recommended):

```
https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo=heri99123/CyberwatchIDS
```

Atau setup lokal:
- Node.js 18+
- Rust toolchain (https://rustup.rs)
- gcc / build-essential

### 3. Buat Branch Baru

```bash
git checkout -b feature/nama-fitur
```

### 4. Commit Convention

Gunakan format:

```
type: deskripsi singkat

- Detail perubahan 1
- Detail perubahan 2
```

Type yang valid:
- `feat`: Fitur baru
- `fix`: Bug fix
- `refactor`: Refaktor kode
- `docs`: Dokumentasi
- `ci`: CI/CD changes
- `chore`: Maintenance

### 5. Submit Pull Request

- Push ke fork Anda
- Buat Pull Request ke `main` branch
- Jelaskan perubahan dan testing yang sudah dilakukan

## Lisensi

Dengan berkontribusi, Anda menyetujui bahwa kontribusi Anda akan dilisensikan di bawah **GNU AGPL-3.0**.

## Code Style

### Rust (server-rust/)
- Gunakan `cargo fmt` sebelum commit
- Hilangkan warnings: `cargo clippy -- -D warnings`
- Semua `query_row` harus menggunakan closure
- Error handling via `AppError` enum

### Vue/Frontend (src/)
- Gunakan TypeScript strict mode
- Tailwind CSS untuk styling (no custom CSS kecuali perlu)
- ECharts untuk visualisasi data

## Testing

```bash
# Rust backend
cd server-rust
cargo test

# Frontend
npm run build
```

## Pertanyaan?

Buka issue di: https://github.com/heri99123/CyberwatchIDS/issues
