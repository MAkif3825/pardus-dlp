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
├── Makefile               # Optimized compilation & build pipeline for libbpf
├── policy.txt             # Your local active watchlist targets (git-ignored)
├── policy.txt.example     # Publicly visible mock watchlist profile template
└── src/
    ├── bootstrap.c        # User-space configuration engine, normalizer, & logger
    ├── bootstrap.bpf.c    # Kernel-space eBPF tracepoint handler probe
    └── bootstrap.h        # Shared data contract struct layout definitions
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

### Prerequisites
Ensure your development environment contains `clang`, `llvm`, `libelf-dev`, and standard `build-essential` packages.

### 1. Configure Your Policy Watchlist
Create a `policy.txt` configuration file within the project root directory and declare your sensitive targets—one per line:
```text
/etc/passwd
/etc/shadow
/home/pardus/secret
```

### 2. Compile the Module
Execute the automation compilation scripts via the main Makefile layout:
```bash
make clean && make
```

### 3. Launch the Security Agent
Execute the compiled binary from the root directory by supplying your designated watchlist pathway via the required `-p` parameter:
```bash
sudo ./bootstrap -p policy.txt
```

### 4. Directing Output to a JSON Log File (Optional)
To stream telemetry alerts straight into a persistent JSON tracking log while keeping standard screen visibility, utilize the Unix stream splitter pipeline:
```bash
sudo ./bootstrap -p policy.txt | tee -a dlp_alerts.json
```