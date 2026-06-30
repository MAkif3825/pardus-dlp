# Pardus Mini-DLP (Data Loss Prevention) System

An eBPF-powered, asynchronous security monitoring agent designed to detect unauthorized access to sensitive files on Pardus Linux systems.

---

## 🚀 Features

* **Near-Zero Runtime Overhead**: Uses kernel-space eBPF tracepoints (`sys_enter_openat`) to asynchronously capture file access events without blocking host applications.
* **Dynamic Policy Watchlist**: Ingests monitoring targets dynamically from a user-specified text file at runtime without requiring code recompilation.
* **Context-Aware Absolute Path Resolution**: Bridges the kernel-to-user space gap by reconstructing relative pathing structures utilizing the `/proc/<pid>/cwd` filesystem alongside native `realpath` verification.
* **Standard Telemetry Output**: Emits structured JSON alerts correlating system metadata for seamless integration with downstream Security Information and Event Management (SIEM) systems.

---

## 📂 Project Architecture & Directory Layout

```text
pardus-dlp/
├── Makefile               # Root Makefile (triggers compilation in src/)
├── policy.txt             # Active sensitive directory watchlist targets
└── src/
    ├── main.c             # Lifecycle & Initialization
    ├── dispatch.c/.h      # Central Event Traffic Loop
    ├── Makefile           # Your updated modular build system
    │
    ├── kernel/            # KERNEL LAYER: eBPF code handlers
    │   ├── pardus_dlp.bpf.c
    │   └── pardus_dlp.h
    ├── core/              # STATEFUL ENGINES: Policy & Data matchers
    │   ├── policy.c
    │   └── policy.h
    ├── detectors/         # PIPELINE DETECTORS: Static compile-time modules
    │   ├── detector.h
    │   └── policy_detector.c
    └── utils/             # STATELESS UTILITIES: Helper tools
        ├── event_utils.c/.h
        └── alert.c/.h
```

---

## 📋 Monitored Telemetry Data Correlation
Each generated event completely correlates the following security data vectors:

| Field Metric | Category | Description |
| :--- | :--- | :--- |
| `timestamp` | Audit Time | Accurate system logging execution timestamp |
| `process_name` | Süreç (Process) | The command application performing the read/write execution |
| `pid` / `uid` | Süreç / Kullanıcı | Process ID and numeric User ID tracking the initiator identity |
| `file_path` | Dosya Yolu | Completely normalized, absolute destination path targeting files |
| `action` | İşlem Tipi | System mitigation directive category status label |

---

## 🛠️ Building and Running

### 1. Clone the repository

There are now two supported build paths:

- use system packages only
- or use vendored `libbpf` / `bpftool` submodules

Clone normally if you want to rely on system packages:

```sh
git clone https://github.com/your_username/your_new_repository.git
```

Clone recursively only if you want the vendored toolchain:

```sh
git clone https://github.com/your_username/your_new_repository.git --recursive
```

If you already cloned without submodules and later want the vendored copies:

```sh
git submodule update --init --recursive
```

### 2. Install dependencies

On Ubuntu, you may run `make install` or

```sh
sudo apt-get install -y --no-install-recommends \
        libbpf-dev libelf1 libelf-dev zlib1g-dev \
        make clang llvm pkg-config
```

to install the system-toolchain dependencies.

By default, the build prefers the system `libbpf` and a `bpftool` executable available on `PATH`. If those are unavailable, it falls back to vendored `libbpf/` and `bpftool/` submodules when present.

You can force vendored mode explicitly:

```sh
make USE_VENDORED_LIBBPF=1 USE_VENDORED_BPFTOOL=1
```

Note: the package name that provides `bpftool` is distro-specific. On some systems it is not a standalone `bpftool` package.

### 3. Configure Your Policy Watchlist
Create a `policy.txt` configuration file within the project root directory and declare your sensitive targets—one per line:
```text
/etc/passwd
/etc/shadow
/home/pardus/secret
```

### 4. Compile the module

Execute the build through the top-level Makefile:

```bash
make clean && make
```

The build now works in either of these modes:

- system mode, preferred by default: `libbpf-dev` is installed and `bpftool` is available on `PATH`
- vendored mode: `libbpf/` and `bpftool/` submodules are present, or forced with `USE_VENDORED_LIBBPF=1 USE_VENDORED_BPFTOOL=1`

### 5. Launch the Security Agent
Execute the compiled binary from the root directory by supplying your designated watchlist pathway via the required `-p` parameter:
```bash
sudo ./src/pardus_dlp -a access.csv -e extensions.txt -m malware_db.txt
```

### Directing Output to a JSON Log File (Optional)
To stream telemetry alerts straight into a persistent JSON tracking log while keeping standard screen visibility, utilize the Unix stream splitter pipeline:
```bash
sudo ./src/pardus_dlp -p policy.txt -e extensions.txt -m malware_db.txt | tee -a dlp_alerts.json
```
