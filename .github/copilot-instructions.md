# GitHub Copilot – Repository Instructions and Memory Bank

These instructions help GitHub Copilot Chat answer accurately and tersely in this repository.

## Reply preferences
- Be short and impersonal. Prefer bullet points over paragraphs.
- Use the user's language; fall back to English if unclear.
- When asked your name, answer: "GitHub Copilot".
- Commands must be Windows PowerShell-friendly. Use `;` to chain.
- Don’t over-format unless asked. Use code fences for commands and code only when helpful.

## Environment defaults
- OS: Windows. Shell: PowerShell 5.1.
- Toolchain: MSVC (Developer Command Prompt). C++17.
- Build entry: `make.bat` (compiles C/C++ and resources, packages final exe).
- Architectures: x64 and ARM64 supported.

## Project overview (cheat sheet)
- Purpose: In-memory bypass of Chromium App-Bound Encryption (ABE) to decrypt cookies, passwords, and payments for research/education.
- Stages:
  1) Injector `chrome_inject.exe`: direct syscalls + reflective DLL injection; hosts encrypted payload as a resource.
  2) Payload `chrome_decrypt.dll`: runs in target browser; uses COM ABE service to decrypt master key, then SQLite to decrypt data.
- Core libs: `libs/sqlite` (SQLite3), `libs/chacha` (ChaCha20).
- Key sources: `src/chrome_inject.cpp`, `src/chrome_decrypt.cpp`, `src/reflective_loader.c`, `src/syscalls.*`, `src/resource.rc`.

## Build – quick answers
- One-shot build from repo root:
  ```powershell
  .\make.bat
  ```
- Output artifacts:
  - Final: `./chrome_inject.exe`
  - Intermediate: `./build/*` (objs, libs, dll, enc payload, res, trampolines)
- Common issues:
  - Not in MSVC environment: open "Developer Command Prompt for VS" and retry.
  - Missing `rc.exe` or `ml64.exe`: ensure Windows SDK and MASM are installed.

## Run – quick answers
- Show usage:
  ```powershell
  .\chrome_inject.exe --help
  ```
- Inject into Chrome (start if needed) with verbose logs and custom output path:
  ```powershell
  .\chrome_inject.exe --start-browser --verbose --output-path .\output chrome
  ```
- Supported targets: `chrome`, `brave`, `edge`.

## Data output layout
- Base: `<output>/<Browser>/<Profile>/`
- Files: `cookies.txt`, `passwords.txt`, `payments.txt` (JSON arrays)

## Style and conventions for changes
- C++17, `/O2 /MT`, minimize dependencies, keep fileless/in-memory design.
- Prefer direct syscalls path where relevant; avoid introducing WinAPI calls that defeat evasion intent.
- Keep answers and commit messages succinct; reference files with backticks.

## Safety and scope
- Research/education only. Do not provide operational misuse guidance.
- Avoid generating harmful or illegal content; include brief disclaimers when relevant.

## Memory bank – stable facts Copilot should remember
- Build is driven by `make.bat`; it compiles:
  1) SQLite static lib
  2) Payload DLL (`chrome_decrypt.dll`)
  3) `encryptor.exe` then encrypts DLL to `chrome_decrypt.enc`
  4) Compiles resources (`resource.rc`) embedding the encrypted payload
  5) Assembles syscall trampoline (x64/ARM64)
  6) Links final `chrome_inject.exe`
- Primary modules:
  - Injector: `src/chrome_inject.cpp`, `src/syscalls.cpp`, `src/syscall_trampoline_*.asm`
  - Payload: `src/chrome_decrypt.cpp`, `src/reflective_loader.c`
  - Crypto: `libs/chacha/chacha20.h`; DB: `libs/sqlite/*`
- Usage pattern:
  - `chrome_inject.exe [--start-browser] [--output-path <path>] [--verbose] <chrome|brave|edge>`
  - Default output path: `.\output\`
- Supported/tested (as of README): Chrome 138, Brave 1.80.115, Edge 139.
- Default shell is PowerShell; show commands accordingly.

## Quick file map (for navigation)
- `src/chrome_inject.cpp`: process targeting, injection, pipe I/O, orchestration.
- `src/chrome_decrypt.cpp`: COM ABE interaction, master key decryption, SQLite reads, JSON output.
- `src/reflective_loader.c`: PE mapping, IAT resolution, relocations, `DllMain` bootstrap.
- `src/syscalls.*` + `src/syscall_trampoline_*.asm`: direct syscall engine and stubs.
- `src/resource.rc`: embeds `chrome_decrypt.enc` as a resource.
- `libs/sqlite/sqlite3.c`: bundled SQLite.
- `tools/comrade_abe.py`: dynamic analyzer for ABE COM interfaces.

## Snippets Copilot can reuse
- Build and clean:
  ```powershell
  .\make.bat
  ```
- Typical run:
  ```powershell
  .\chrome_inject.exe --start-browser --verbose chrome
  ```

---

If a question is ambiguous, make at most one reasonable assumption, state it briefly, and proceed.
