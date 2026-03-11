# qrptonote OS Security Audit

Before using qrptonote with sensitive data, run this one-time audit to verify
your Linux environment is configured to support all of qrptonote's security
guarantees (mlock, prctl, ASLR, ptrace scope, etc.).

## Requirements
- Python 3.8+
- Ubuntu 20.04 LTS or newer (Debian-based Linux)
- Standard system tools: `sysctl`, `findmnt`, `lsblk`, `readelf`

## Run
```bash
python3 tools/audit/qrptonote_audit.py
```

Open `qrptonote_security_report.html` in your browser when it finishes.

## What it checks
| Domain | Why it matters |
|---|---|
| ASLR / ptrace_scope | Validates `prctl(PR_SET_DUMPABLE, 0)` is actually effective |
| mlock limits | Ensures the 4 KiB cleartext buffer can be pinned to RAM |
| Swap encryption | Prevents key material leaking to unencrypted swap |
| Spectre / Meltdown | Cache-timing attacks against AES-256-GCM |
| Binary hardening | PIE, Full RELRO, NX, stack canary |
| IOMMU / Thunderbolt | DMA attacks bypass all software protections |
| AppArmor, Secure Boot | Defence-in-depth around the vault file |
