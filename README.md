<div align="center">

# K7 TITAN

**Multi-language antivirus platform for Windows**

C++ · C · C# · Rust · Java · JavaScript · Python

[![.NET](https://img.shields.io/badge/.NET-9.0-512BD4)](https://dotnet.microsoft.com/)
[![C++](https://img.shields.io/badge/C%2B%2B-20-00599C)](https://isocpp.org/)
[![Rust](https://img.shields.io/badge/Rust-stable-000000)](https://www.rust-lang.org/)
[![Java](https://img.shields.io/badge/Java-21-ED8B00)](https://openjdk.org/)
[![Node](https://img.shields.io/badge/Node-%E2%89%A520-339933)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%2011-0078D6)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

## Overview

K7 TITAN is a modular antivirus platform that combines a **native scan engine**, a
**kernel-mode real-time protection driver**, and a **modern WPF desktop UI** written
across several languages, each used where it fits best.

The project is designed around one core principle: **minimize false positives**.
Nothing is quarantined without explicit confirmation, and every detection carries a
transparent score and the layer that produced it.

## Architecture

```
                          ┌───────────────────────────────┐
                          │        K7Titan.App            │  C# / WPF + Wpf.Ui
                          │      (Fluent dashboard)       │
                          └───────────────┬───────────────┘
                                          │
                          ┌───────────────▼───────────────┐
                          │        K7Titan.Core           │  C# / .NET 9
                          │  orchestration · quarantine   │
                          └───────┬───────────────┬───────┘
                                  │               │
             ┌────────────────────▼───┐     ┌─────▼────────────────────┐
             │ K7Titan.Engine.Interop │     │   K7Titan.Realtime       │  C#
             │   P/Invoke boundary    │     │  watcher + filter client │
             └────────────┬───────────┘     └─────┬────────────────────┘
                          │                       │  fltlib.dll
             ┌────────────▼───────────┐     ┌─────▼────────────────────┐
             │   K7Titan.Engine (C++) │     │ K7Titan.Driver (C, WDK)  │
             │  PE · hash · YARA · heu│     │  filesystem minifilter   │
             └────────────┬───────────┘     └──────────────────────────┘
                          │
        ┌─────────────────┼──────────────────┬─────────────────┐
        │                 │                  │                 │
 ┌──────▼─────┐    ┌──────▼──────┐    ┌──────▼──────┐   ┌───────▼────────┐
 │ Rust core  │    │ C helper lib│    │ Java CLI    │   │ Node.js sig    │
 │ sha256/entu│    │ hex/crc32/io│    │ analyzer    │   │ update server  │
 └────────────┘    └─────────────┘    └─────────────┘   └────────────────┘

        Detection data: YARA rules (/rules)  ·  SHA-256 DB (/data/signatures)
        Tooling: Python signature generator (/tools/signature-gen)
```

## Language map

| Language | Component | Role |
|----------|-----------|------|
| **C++ 20** | `K7Titan.Engine` | Scan engine: PE parsing, SHA-256/MD5, rule engine, heuristics |
| **C 11** | `K7Titan.Driver` | Filesystem minifilter (WDK) for real-time interception |
| **C 11** | `K7Titan.CLib` | Low-level helpers (hex, CRC-32, file I/O, string/entropy) |
| **C# / .NET 9** | `K7Titan.App`, `Core`, `Engine.Interop`, `Realtime` | UI, orchestration, interop, real-time service |
| **Rust** | `K7Titan.Rust` | Crypto core: SHA-256, Shannon entropy, CRC-32, scoring |
| **Java 21** | `K7Titan.Java` | Static analyzer CLI (Maven): scanner, heuristics, JSON report |
| **JavaScript** | `tools/k7-sigserver` | Signature update server + status/lookup API |
| **Python** | `tools/signature-gen` | Signature database generator (multi-hash + entropy) |

## Detection engine — layered

1. **Signature (SHA-256)** — exact match against the hash database (`data/signatures/db.json`).
2. **YARA rules** — pattern matching for known families and scripts (`rules/*.yar`).
3. **Heuristics** — Shannon entropy of packed/encrypted blobs, suspicious API/string patterns.
4. **Scoring** — each layer contributes to a confidence score; the UI shows *why* a file was flagged.

## False-positive policy

- Detections are presented to the user **before** any action.
- Quarantine always requires explicit confirmation (see `IQuarantineService`).
- Heuristic matches are tagged low-confidence and **never auto-quarantined**.
- Exclusions and user allow-lists are first-class.

## Project layout

```
K7 AntiVirus/
├─ K7Titan.sln
├─ Directory.Build.props
├─ global.json
├─ src/
│  ├─ K7Titan.App/              # WPF UI (Wpf.Ui)
│  ├─ K7Titan.Core/             # orchestration + quarantine
│  ├─ K7Titan.Engine.Interop/   # P/Invoke to native engine
│  ├─ K7Titan.Realtime/         # real-time inspection
│  ├─ K7Titan.Engine/           # C++ scan engine (CMake)
│  ├─ K7Titan.Driver/           # C minifilter (WDK)
│  ├─ K7Titan.CLib/             # C helper library
│  ├─ K7Titan.Rust/             # Rust crypto/hash core
│  └─ K7Titan.Java/             # Java analyzer CLI
├─ rules/                       # YARA rules
├─ data/signatures/             # hash database
├─ tools/                       # Python + Node.js tooling
├─ tests/                       # xUnit + native tests
└─ scripts/build-all.ps1        # full build
```

## Building

**Prerequisites**

- Visual Studio 2022 with *Desktop development with C++* and the **WDK**
- .NET SDK 9.0
- Rust (stable), Java 21, Python 3, Node.js 20+
- CMake (bundled with VS) and Ninja

**One-command build**

```powershell
pwsh ./scripts/build-all.ps1
```

**Run the UI**

```powershell
dotnet run --project src/K7Titan.App
```

## Testing

```powershell
dotnet test K7Titan.sln        # xUnit engine + core tests
cd src/K7Titan.Rust; cargo test # Rust crypto unit tests
```

The .NET suite includes end-to-end tests that write the **EICAR** test file and
assert the native engine flags it, that clean files are never flagged, that the
scan orchestrator aggregates detections, and that the file walker survives
unreadable directories. The Rust core ships its own known-vector unit tests
(SHA-256, entropy, CRC-32).

## Roadmap

- [x] Native scan engine (hash + heuristics)
- [x] PE32/PE32+ parser (sections, imports, .NET detection)
- [x] Built-in rule engine + simplified YARA (`.yar`) rule loader
- [x] C# ⇄ C++ interop and WPF dashboard (5 pages)
- [x] EICAR detection end-to-end
- [x] Minifilter driver scaffold (compiles against WDK)
- [x] Multi-module Rust core (hash / entropy / scoring)
- [x] Java analyzer CLI with JSON reporting
- [ ] Full YARA integration via libyara
- [ ] Kernel ⇄ user-mode message loop and blocking
- [ ] Web-threat and USB scanning modules
- [ ] Signature auto-update from `k7-sigserver`

## License

MIT — see [LICENSE](LICENSE).

> K7 TITAN is an educational / portfolio antivirus project. Do not use it as your
> sole protection in production environments.
