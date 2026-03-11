#!/usr/bin/env python3
"""
qrptonote Security Audit Tool
==============================
Audits the local Ubuntu/Linux environment to verify that the qrptonote
Rust application can run securely.  Checks:

  • Kernel memory-safety mitigations (ASLR, kptr_restrict, …)
  • ptrace / core-dump controls (for prctl PR_SET_DUMPABLE)
  • mlock limits (for mlocked secure buffers)
  • Swap presence & encryption
  • AppArmor / SELinux
  • Binary hardening flags (PIE, RELRO, stack canary, NX)
  • USB / Thunderbolt / DMA attack surface
  • Filesystem security (noexec, /tmp, /proc)
  • Entropy / RNG quality
  • General kernel hardening sysctl knobs

Generates a colour-coded HTML report: qrptonote_security_report.html
"""

import datetime
import grp
import html
import json
import os
import platform
import pwd
import re
import shutil
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────
#  Data model
# ──────────────────────────────────────────────────────────────────────────────

PASS  = "PASS"
WARN  = "WARN"
FAIL  = "FAIL"
INFO  = "INFO"

@dataclass
class Finding:
    category: str
    title: str
    status: str          # PASS | WARN | FAIL | INFO
    detail: str
    recommendation: str = ""
    cve: str = ""        # optional CVE / advisory reference

@dataclass
class AuditReport:
    findings: List[Finding] = field(default_factory=list)

    def add(self, *args, **kwargs):
        self.findings.append(Finding(*args, **kwargs))

    @property
    def counts(self):
        from collections import Counter
        return Counter(f.status for f in self.findings)

# ──────────────────────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _read(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text().strip()
    except Exception:
        return default

def _cmd(args, timeout=8) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"command not found: {args[0]}"
    except Exception as e:
        return -1, "", str(e)

def _sysctl(key: str) -> Optional[str]:
    rc, out, _ = _cmd(["sysctl", "-n", key])
    return out if rc == 0 else None

def _which(binary: str) -> bool:
    return shutil.which(binary) is not None

# ──────────────────────────────────────────────────────────────────────────────
#  Check functions – one per security domain
# ──────────────────────────────────────────────────────────────────────────────

def check_kernel_info(report: AuditReport):
    uname = platform.uname()
    report.add(
        "System", "Kernel version",
        INFO,
        f"{uname.system} {uname.release} ({uname.machine})",
    )
    # Minimum kernel for a reliable mlock + Argon2 + AES-NI stack is ~5.4 LTS
    parts = uname.release.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1])
        if major < 5 or (major == 5 and minor < 4):
            report.add("System", "Kernel too old",
                WARN,
                f"Kernel {uname.release} predates several memory-safety features.",
                "Upgrade to Ubuntu 20.04 LTS (kernel 5.4+) or newer.")
        else:
            report.add("System", "Kernel version is modern",
                PASS, f"{uname.release} ≥ 5.4 LTS baseline.")
    except Exception:
        report.add("System", "Could not parse kernel version", WARN, uname.release)

    distro = _read("/etc/os-release")
    report.add("System", "OS release", INFO, distro.replace("\n", "  |  "))


def check_aslr(report: AuditReport):
    """
    Address-Space Layout Randomisation.
    /proc/sys/kernel/randomize_va_space:
      0 = disabled (BAD)
      1 = partial (stack/mmap but not heap)
      2 = full (heap too)  ← required
    """
    val = _read("/proc/sys/kernel/randomize_va_space", "unknown")
    if val == "2":
        report.add("Kernel mitigations", "ASLR",
            PASS, f"randomize_va_space = 2 (full ASLR enabled).")
    elif val == "1":
        report.add("Kernel mitigations", "ASLR partial",
            WARN, f"randomize_va_space = 1 (heap not randomised).",
            "Set kernel.randomize_va_space = 2 in /etc/sysctl.conf")
    else:
        report.add("Kernel mitigations", "ASLR DISABLED",
            FAIL, f"randomize_va_space = {val}",
            "echo 2 | sudo tee /proc/sys/kernel/randomize_va_space",
            "CVE-2016-3672")


def check_ptrace(report: AuditReport):
    """
    Yama ptrace_scope limits which processes can ptrace others.
    qrptonote calls prctl(PR_SET_DUMPABLE, 0) to harden itself, but
    a permissive ptrace_scope still allows root to attach.

      0 = unrestricted (any process can PTRACE_ATTACH any peer-UID process)
      1 = restricted   (only parent can ptrace; our prctl works here)
      2 = admin-only   (only CAP_SYS_PTRACE / root)
      3 = no ptrace at all
    """
    val = _read("/proc/sys/kernel/yama/ptrace_scope", "unknown")
    if val == "unknown":
        report.add("Process isolation", "Yama ptrace_scope",
            WARN, "Yama LSM not loaded; ptrace_scope file missing.",
            "Ensure CONFIG_SECURITY_YAMA=y in kernel config.")
    elif val == "0":
        report.add("Process isolation", "ptrace_scope UNRESTRICTED",
            FAIL, "ptrace_scope = 0: any user-space process can attach to qrptonote "
                  "and read its memory, bypassing prctl(PR_SET_DUMPABLE, 0).",
            "echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n"
            "Also add:  kernel.yama.ptrace_scope = 1  to /etc/sysctl.d/10-ptrace.conf")
    elif val == "1":
        report.add("Process isolation", "ptrace_scope = 1 (restricted)",
            PASS, "Only a parent process can ptrace qrptonote. "
                  "Combined with prctl(PR_SET_DUMPABLE,0) this is solid.")
    elif val in ("2", "3"):
        report.add("Process isolation", f"ptrace_scope = {val} (hardened)",
            PASS, f"ptrace_scope = {val}: excellent; even admin-level ptrace is restricted.")
    else:
        report.add("Process isolation", "ptrace_scope unexpected value",
            INFO, f"ptrace_scope = {val}")


def check_core_dumps(report: AuditReport):
    """
    Core dumps can contain AES keys / plaintext passwords from heap/stack.
    qrptonote disables core dumps via prctl(PR_SET_DUMPABLE, 0), but the
    OS-level default should also be locked down.
    """
    # Kernel core pattern
    pattern = _read("/proc/sys/kernel/core_pattern", "unknown")
    if pattern.startswith("|"):
        report.add("Core dumps", "core_pattern pipes to userspace",
            WARN,
            f"core_pattern = '{pattern}'\n"
            "Piping to a crash reporter (e.g. apport) can persist core files on disk.",
            "Consider disabling apport for production/sensitive hosts:\n"
            "  sudo systemctl disable --now apport")
    elif pattern in ("", "core"):
        report.add("Core dumps", "core_pattern writes to disk",
            WARN,
            f"core_pattern = '{pattern}' — cores written to CWD.",
            "echo '/dev/null' | sudo tee /proc/sys/kernel/core_pattern")
    else:
        report.add("Core dumps", f"core_pattern = '{pattern}'", INFO,
            "Verify this does not persist plaintext to disk.")

    # fs.suid_dumpable
    suid = _read("/proc/sys/fs/suid_dumpable", "unknown")
    if suid == "0":
        report.add("Core dumps", "fs.suid_dumpable = 0",
            PASS, "Set-UID / privileged processes will not dump cores.")
    else:
        report.add("Core dumps", f"fs.suid_dumpable = {suid}",
            WARN, "Non-zero suid_dumpable may let privileged processes write cores.",
            "echo 0 | sudo tee /proc/sys/fs/suid_dumpable")

    # ulimit -c for the current shell session
    rc, out, _ = _cmd(["bash", "-c", "ulimit -c"])
    report.add("Core dumps", f"ulimit -c (current session) = '{out}'",
        PASS if out == "0" else WARN,
        "Value '0' means no cores from this session. qrptonote's own prctl also suppresses them.",
        "" if out == "0" else "Set 'ulimit -c 0' in your shell profile or /etc/security/limits.conf")


def check_mlock(report: AuditReport):
    """
    qrptonote uses mlock() to keep key material out of swap.
    The OS must permit this for unprivileged processes.
    RLIMIT_MEMLOCK controls how many bytes a non-root process can lock.
    """
    rc, out, _ = _cmd(["bash", "-c", "ulimit -l"])
    report.add("Memory locking (mlock)", f"ulimit -l = '{out}'",
        PASS if out == "unlimited" else WARN,
        f"Current mlock limit: {out} KB.\n"
        "qrptonote needs to mlock its key buffers. 'unlimited' is ideal;\n"
        "at minimum a few MB is required (keys + Argon2 working set).",
        "" if out == "unlimited" else
        "Add to /etc/security/limits.conf:\n"
        "  * soft memlock 65536\n"
        "  * hard memlock 65536\n"
        "(or 'unlimited' for single-user workstation)")

    # Check if /proc/PID/status shows VmLck for a live process (informational)
    report.add("Memory locking (mlock)", "MADV_DONTDUMP kernel support",
        PASS if Path("/proc/sys/vm/overcommit_memory").exists() else INFO,
        "MADV_DONTDUMP (used by qrptonote) is supported since Linux 3.4.")


def check_swap(report: AuditReport):
    """
    Swap can leak mlock'd-but-not-yet-locked pages or pages from before
    mlock was called.  Encrypted swap is required for full key confidentiality.
    """
    swap_info = _read("/proc/swaps", "")
    lines = [l for l in swap_info.splitlines() if not l.startswith("Filename")]

    if not lines:
        report.add("Swap encryption", "No swap partitions/files found",
            PASS, "No swap means no risk of key material persisting to disk via swap.")
        return

    report.add("Swap encryption", f"Swap present ({len(lines)} swap device(s))",
        INFO, "\n".join(lines))

    # Check for dm-crypt / LUKS swap encryption
    rc, lsblk, _ = _cmd(["lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT", "--json"])
    encrypted_swap = False
    if rc == 0:
        try:
            data = json.loads(lsblk)
            def walk(nodes):
                for n in nodes:
                    if n.get("mountpoint") == "[SWAP]":
                        if n.get("type") in ("crypt",) or "crypt" in n.get("fstype", ""):
                            return True
                    if walk(n.get("children", [])):
                        return True
                return False
            encrypted_swap = walk(data.get("blockdevices", []))
        except Exception:
            pass

    if encrypted_swap:
        report.add("Swap encryption", "Swap is encrypted (dm-crypt/LUKS)",
            PASS, "Encrypted swap prevents key material from persisting to disk.")
    else:
        report.add("Swap encryption", "Swap does NOT appear to be encrypted",
            FAIL,
            "Unencrypted swap can persist heap/stack contents including AES keys and passwords.",
            "Enable encrypted swap:\n"
            "  Ubuntu: install cryptsetup, edit /etc/crypttab to add swap entry.\n"
            "  Or disable swap entirely if the system has enough RAM:\n"
            "    sudo swapoff -a && sudo sed -i '/swap/d' /etc/fstab")


def check_kptr_restrict(report: AuditReport):
    val = _sysctl("kernel.kptr_restrict")
    if val == "2":
        report.add("Kernel pointer exposure", "kptr_restrict = 2",
            PASS, "Kernel pointers hidden from all users (even root in dmesg).")
    elif val == "1":
        report.add("Kernel pointer exposure", "kptr_restrict = 1",
            PASS, "Kernel pointers hidden from unprivileged users.")
    else:
        report.add("Kernel pointer exposure", f"kptr_restrict = {val}",
            WARN, "Kernel pointers may be readable, aiding KASLR bypass.",
            "echo 2 | sudo tee /proc/sys/kernel/kptr_restrict")


def check_dmesg_restrict(report: AuditReport):
    val = _sysctl("kernel.dmesg_restrict")
    if val == "1":
        report.add("Kernel log access", "dmesg_restrict = 1",
            PASS, "Unprivileged users cannot read kernel ring buffer.")
    else:
        report.add("Kernel log access", f"dmesg_restrict = {val}",
            WARN, "dmesg readable by unprivileged users (can leak kernel addresses).",
            "echo 1 | sudo tee /proc/sys/kernel/dmesg_restrict")


def check_perf_paranoid(report: AuditReport):
    val = _sysctl("kernel.perf_event_paranoid")
    if val is None:
        report.add("Perf events", "perf_event_paranoid not found", INFO, "")
        return
    try:
        v = int(val)
    except ValueError:
        report.add("Perf events", f"perf_event_paranoid = {val}", INFO, "")
        return

    if v >= 2:
        report.add("Perf events", f"perf_event_paranoid = {val}",
            PASS, "Unprivileged perf access restricted; side-channel risk reduced.")
    elif v == 1:
        report.add("Perf events", f"perf_event_paranoid = {val}",
            WARN, "Perf events partially restricted.",
            "echo 3 | sudo tee /proc/sys/kernel/perf_event_paranoid")
    else:
        report.add("Perf events", f"perf_event_paranoid = {val}",
            FAIL, "Perf events unrestricted: timing/cache side-channels possible.",
            "echo 3 | sudo tee /proc/sys/kernel/perf_event_paranoid",
            "CVE-2015-3339")


def check_spectre_meltdown(report: AuditReport):
    """
    Check /sys/devices/system/cpu/vulnerabilities/ for known side-channels.
    These can leak AES key bits via cache timing if mitigations are off.
    """
    vuln_dir = Path("/sys/devices/system/cpu/vulnerabilities")
    if not vuln_dir.exists():
        report.add("CPU mitigations", "Vulnerability directory not found",
            INFO, "/sys/devices/system/cpu/vulnerabilities missing (VM or older kernel?).")
        return

    for vuln_file in sorted(vuln_dir.iterdir()):
        status = _read(str(vuln_file))
        low = status.lower()
        if "not affected" in low:
            sev = PASS
        elif "mitigation" in low:
            sev = PASS
        elif "vulnerable" in low:
            sev = FAIL
        else:
            sev = INFO
        report.add("CPU mitigations", vuln_file.name, sev, status,
            "Apply OS security updates (sudo apt update && sudo apt dist-upgrade)" if sev == FAIL else "")


def check_apparmor(report: AuditReport):
    val = _read("/sys/module/apparmor/parameters/enabled", "N")
    if val == "Y":
        report.add("Mandatory Access Control", "AppArmor enabled",
            PASS, "AppArmor is active.")
        rc, out, _ = _cmd(["aa-status", "--json"])
        if rc == 0:
            try:
                data = json.loads(out)
                profiles = data.get("profiles", {})
                report.add("MAC", f"AppArmor profiles loaded: {len(profiles)}",
                    INFO, ", ".join(list(profiles.keys())[:10]) + ("…" if len(profiles) > 10 else ""))
            except Exception:
                pass
    else:
        report.add("Mandatory Access Control", "AppArmor not active",
            WARN,
            "AppArmor is not enabled. Mandatory Access Control provides defence-in-depth.",
            "sudo apt install apparmor apparmor-utils && sudo systemctl enable --now apparmor")

    # SELinux
    rc, out, _ = _cmd(["sestatus"])
    if rc == 0:
        report.add("MAC", "SELinux status", INFO, out[:200])


def check_binary_hardening(report: AuditReport):
    """
    Locate the qrptonote binary and check ELF hardening flags.
    Uses checksec (if installed) or manual readelf analysis.
    """
    # Try common install locations
    candidates = [
        Path("./target/release/qrptonote"),
        Path("./qrptonote"),
        Path(os.path.expanduser("~/.cargo/bin/qrptonote")),
        Path("/usr/local/bin/qrptonote"),
        Path("/usr/bin/qrptonote"),
    ]
    # Also try `which`
    rc, out, _ = _cmd(["which", "qrptonote"])
    if rc == 0 and out:
        candidates.insert(0, Path(out))

    binary = next((p for p in candidates if p.exists()), None)

    if binary is None:
        report.add("Binary hardening", "qrptonote binary not found",
            INFO,
            "Could not locate qrptonote binary at common paths.\n"
            "Run this audit from the project root or after 'cargo build --release'.\n"
            "Checked: " + ", ".join(str(p) for p in candidates))
        return

    report.add("Binary hardening", f"Binary found: {binary}", INFO, str(binary))

    if _which("checksec"):
        rc, out, err = _cmd(["checksec", "--file", str(binary), "--output", "json"])
        if rc == 0:
            try:
                data = json.loads(out)
                file_data = data.get(str(binary), next(iter(data.values()), {}))
                flags = [
                    ("RELRO",      file_data.get("relro", "?"),   "Full RELRO",    PASS, FAIL),
                    ("Stack Canary", file_data.get("canary", "?"), "yes",           PASS, WARN),
                    ("NX / W^X",   file_data.get("nx", "?"),      "yes",           PASS, FAIL),
                    ("PIE",        file_data.get("pie", "?"),      "yes",           PASS, FAIL),
                    ("FORTIFY",    file_data.get("fortify_source","?"), "yes",      PASS, WARN),
                    ("Stripped",   file_data.get("symbols", "?"), "no",            PASS, INFO),
                ]
                for name, val, good, good_sev, bad_sev in flags:
                    ok = good.lower() in val.lower()
                    report.add("Binary hardening", f"{name}: {val}",
                        good_sev if ok else bad_sev, "")
                return
            except Exception as e:
                report.add("Binary hardening", "checksec JSON parse error",
                    INFO, str(e))

    # Fallback: manual readelf analysis
    rc, out, _ = _cmd(["readelf", "-d", str(binary)])
    if rc != 0:
        report.add("Binary hardening", "readelf not available",
            INFO, "Install binutils for ELF analysis: sudo apt install binutils")
        return

    # PIE: ET_DYN in ELF header
    rc2, hdr, _ = _cmd(["readelf", "-h", str(binary)])
    pie = "EXEC" not in hdr and "DYN" in hdr
    report.add("Binary hardening", f"PIE: {'yes' if pie else 'NO'}",
        PASS if pie else FAIL,
        "Position-Independent Executable makes ASLR effective for the binary itself.",
        "" if pie else "Rebuild with: RUSTFLAGS='-C relocation-model=pic' cargo build --release")

    # RELRO: GNU_RELRO segment
    relro = "GNU_RELRO" in out
    bind_now = "BIND_NOW" in out or "(FLAGS)" in out  # heuristic
    relro_level = "Full" if (relro and bind_now) else ("Partial" if relro else "None")
    report.add("Binary hardening", f"RELRO: {relro_level}",
        PASS if relro_level == "Full" else (WARN if relro_level == "Partial" else FAIL),
        "RELRO marks the GOT read-only after startup, defeating GOT-overwrite attacks.")

    # NX: GNU_STACK flags
    rc3, stack_out, _ = _cmd(["readelf", "-l", str(binary)])
    nx = "GNU_STACK" in stack_out and "RWE" not in stack_out
    report.add("Binary hardening", f"NX (non-executable stack): {'yes' if nx else 'NO'}",
        PASS if nx else FAIL, "")


def check_usb_dma(report: AuditReport):
    """
    Thunderbolt / FireWire / DMA attacks can read physical memory directly,
    bypassing all software protections including prctl and mlock.
    """
    # Thunderbolt security level
    tb_dir = Path("/sys/bus/thunderbolt/devices")
    tb_security = Path("/sys/bus/thunderbolt/devices/domain0/security")
    if tb_security.exists():
        level = _read(str(tb_security))
        if level in ("secure", "dponly", "user"):
            report.add("DMA attack surface", f"Thunderbolt security = '{level}'",
                PASS, f"Thunderbolt is restricted to '{level}' mode.")
        else:
            report.add("DMA attack surface", f"Thunderbolt security = '{level}'",
                WARN, f"Thunderbolt mode '{level}' may allow DMA attacks via PCIe.",
                "Set Thunderbolt to 'user' or 'secure' mode in BIOS/UEFI firmware settings.")
    else:
        report.add("DMA attack surface", "No Thunderbolt domain found",
            INFO, "No Thunderbolt controllers detected (or not exposed to OS).")

    # IOMMU
    rc, dmesg, _ = _cmd(["dmesg"])
    iommu_active = any(x in dmesg for x in ("Intel IOMMU", "AMD-Vi", "DMAR: IOMMU", "iommu: Default domain"))
    report.add("DMA attack surface", "IOMMU (VT-d / AMD-Vi)",
        PASS if iommu_active else WARN,
        "IOMMU active — DMA remapping protects physical memory." if iommu_active
        else "IOMMU not detected in dmesg. Physical DMA attacks possible from PCIe peripherals.",
        "" if iommu_active else
        "Enable in BIOS (Intel VT-d / AMD-Vi) and add 'intel_iommu=on' or 'amd_iommu=on' to GRUB_CMDLINE_LINUX.")

    # Kernel lockdown mode
    lockdown = _read("/sys/kernel/security/lockdown", "unknown")
    if lockdown in ("none", "unknown", ""):
        report.add("DMA attack surface", f"Kernel lockdown = '{lockdown}'",
            WARN, "Kernel lockdown mode is off; physical memory (/dev/mem) may be accessible.",
            "Enable Secure Boot or add 'lockdown=confidentiality' to kernel command line.")
    else:
        report.add("DMA attack surface", f"Kernel lockdown = '{lockdown}'",
            PASS, f"Kernel lockdown active in '{lockdown}' mode.")


def check_entropy(report: AuditReport):
    """
    qrptonote uses ChaCha20-based CSPRNG (via OsRng in rand crate).
    The OS must have sufficient entropy at startup.
    """
    ent = _read("/proc/sys/kernel/random/entropy_avail", "unknown")
    try:
        e = int(ent)
        if e >= 256:
            report.add("Entropy / RNG", f"entropy_avail = {e}",
                PASS, f"{e} bits available; OsRng will not block.")
        elif e >= 64:
            report.add("Entropy / RNG", f"entropy_avail = {e}",
                WARN, "Low entropy; early-boot key generation may block.",
                "Install haveged or jitterentropy: sudo apt install haveged")
        else:
            report.add("Entropy / RNG", f"entropy_avail = {e}",
                FAIL, "Very low entropy! Key generation could block or produce weak randomness.",
                "sudo apt install haveged && sudo systemctl enable --now haveged")
    except ValueError:
        report.add("Entropy / RNG", f"entropy_avail = {ent}", INFO, "")

    # Check for getrandom(2) support (Linux 3.17+)
    rc, uname, _ = _cmd(["uname", "-r"])
    report.add("Entropy / RNG", "getrandom(2) syscall",
        PASS, "Supported on Linux 3.17+; Rust's OsRng uses getrandom automatically.")


def check_filesystem(report: AuditReport):
    """
    /tmp should be noexec; /proc should be restricted.
    """
    rc, mounts_out, _ = _cmd(["findmnt", "--json", "--output", "TARGET,OPTIONS"])
    mounts = {}
    if rc == 0:
        try:
            data = json.loads(mounts_out)
            def walk_fs(nodes):
                for n in nodes:
                    mounts[n["target"]] = n.get("options", "")
                    walk_fs(n.get("children", []))
            walk_fs(data.get("filesystems", []))
        except Exception:
            pass

    tmp_opts = mounts.get("/tmp", mounts.get("tmpfs /tmp", ""))
    if "noexec" in tmp_opts:
        report.add("Filesystem", "/tmp mounted noexec", PASS, tmp_opts)
    else:
        report.add("Filesystem", "/tmp may be executable",
            WARN, f"/tmp options: '{tmp_opts}'",
            "Mount /tmp with noexec,nosuid:\n"
            "  Add to /etc/fstab:  tmpfs /tmp tmpfs defaults,noexec,nosuid,size=512M 0 0")

    # hidepid on /proc
    proc_opts = mounts.get("/proc", "")
    if "hidepid=2" in proc_opts or "hidepid=invisible" in proc_opts:
        report.add("Filesystem", "/proc hidepid=2 (processes hidden)",
            PASS, "Other users cannot see each other's /proc/<PID> entries.")
    else:
        report.add("Filesystem", "/proc hidepid not set",
            WARN, f"/proc options: '{proc_opts}'\n"
            "Any user can enumerate all PIDs and read some /proc/<PID> entries.",
            "Add to /etc/fstab: proc /proc proc defaults,hidepid=2,gid=<proc_gid> 0 0\n"
            "Then: sudo mount -o remount,hidepid=2 /proc")


def check_user_environment(report: AuditReport):
    uid = os.getuid()
    username = pwd.getpwuid(uid).pw_name
    groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]

    report.add("User environment", f"Running as: {username} (uid={uid})",
        WARN if uid == 0 else PASS,
        "Running qrptonote as root is unnecessary and expands attack surface." if uid == 0
        else "Non-root user — good.",
        "Run qrptonote as a normal user, not root." if uid == 0 else "")

    if "sudo" in groups or "wheel" in groups:
        report.add("User environment", f"User in sudo/wheel group",
            WARN, f"Groups: {', '.join(groups)}\n"
            "A compromised process inheriting sudo rights is a privilege escalation risk.",
            "Consider running qrptonote from a restricted account without sudo.")

    # Check umask
    rc, umask_out, _ = _cmd(["bash", "-c", "umask"])
    report.add("User environment", f"umask = {umask_out}",
        PASS if umask_out in ("0027", "0077", "077", "027") else WARN,
        "Restrictive umask prevents vault file being world-readable.",
        "" if umask_out in ("0027", "0077", "077", "027") else
        "Set umask 0077 in ~/.bashrc or /etc/profile to protect new files.")


def check_ssh_agent_forwarding(report: AuditReport):
    """
    SSH agent forwarding can let a remote host access keys in your agent.
    qrptonote credentials could be indirectly exposed via a hijacked agent socket.
    """
    ssh_auth = os.environ.get("SSH_AUTH_SOCK", "")
    if ssh_auth:
        report.add("SSH/Agent", "SSH_AUTH_SOCK is set in environment",
            WARN,
            f"SSH_AUTH_SOCK={ssh_auth}\n"
            "If running qrptonote inside an SSH session with agent forwarding, "
            "a compromised remote host could use your agent.",
            "Avoid agent forwarding (ForwardAgent no in ~/.ssh/config). "
            "Use -o ForwardAgent=no when SSHing if unsure.")
    else:
        report.add("SSH/Agent", "SSH_AUTH_SOCK not set", PASS,
            "No SSH agent forwarding detected in this session.")


def check_secureboot(report: AuditReport):
    rc, out, _ = _cmd(["mokutil", "--sb-state"])
    if rc == 0:
        if "SecureBoot enabled" in out:
            report.add("Boot integrity", "Secure Boot enabled",
                PASS, "UEFI Secure Boot is active; bootloader and kernel are signed.")
        else:
            report.add("Boot integrity", "Secure Boot disabled",
                WARN, out,
                "Enable Secure Boot in UEFI firmware settings for boot-chain integrity.")
    else:
        report.add("Boot integrity", "Could not determine Secure Boot state",
            INFO, "mokutil not installed: sudo apt install mokutil")


def check_disk_encryption(report: AuditReport):
    """
    Full-disk encryption protects the vault file and any accidental cleartext
    written by the OS (journal, temp files, etc.) when the machine is off.
    """
    rc, out, _ = _cmd(["lsblk", "-o", "NAME,TYPE,FSTYPE", "--json"])
    has_luks = False
    if rc == 0:
        try:
            data = json.loads(out)
            def find_luks(nodes):
                for n in nodes:
                    if n.get("fstype") in ("crypto_LUKS",) or n.get("type") == "crypt":
                        return True
                    if find_luks(n.get("children", [])):
                        return True
                return False
            has_luks = find_luks(data.get("blockdevices", []))
        except Exception:
            pass

    if has_luks:
        report.add("Disk encryption", "LUKS encryption detected",
            PASS, "At least one LUKS-encrypted block device found.")
    else:
        report.add("Disk encryption", "No LUKS encryption found",
            WARN,
            "Full-disk encryption was not detected. If the vault file is on an unencrypted disk, "
            "physical access could allow offline brute-force attacks (Argon2id provides "
            "strong resistance, but FDE adds another defence layer).",
            "Use Ubuntu's built-in LUKS FDE during install, or encrypt the vault partition manually.")


def check_aes_ni(report: AuditReport):
    """
    AES-NI is required for constant-time AES-256-GCM (avoids timing side-channels).
    """
    cpuinfo = _read("/proc/cpuinfo")
    if "aes" in cpuinfo.lower():
        report.add("CPU features", "AES-NI supported",
            PASS, "Hardware AES acceleration available; constant-time AES-256-GCM guaranteed.")
    else:
        report.add("CPU features", "AES-NI NOT detected",
            WARN,
            "Software AES implementations may be vulnerable to cache-timing attacks.",
            "Consider a platform with AES-NI for production use.")

    if "rdrand" in cpuinfo.lower() or "rdseed" in cpuinfo.lower():
        report.add("CPU features", "RDRAND/RDSEED available",
            PASS, "Hardware entropy source present; strengthens OsRng.")
    else:
        report.add("CPU features", "RDRAND/RDSEED not found",
            INFO, "No hardware RNG; OsRng falls back to /dev/urandom (still cryptographically secure).")


def check_running_services(report: AuditReport):
    """
    Unnecessary running services expand the attack surface.
    Highlight any that are known to be high-risk.
    """
    high_risk = {
        "telnet":       "Telnet transmits data in cleartext.",
        "rsh":          "Remote Shell is unauthenticated.",
        "rlogin":       "Remote Login is unauthenticated.",
        "tftp":         "TFTP has no authentication.",
        "vnc":          "VNC often misconfigured; can expose desktop.",
        "x11":          "X11 forwarding can sniff keystrokes.",
        "avahi-daemon": "mDNS advertisement leaks host/service info.",
        "cups":          "Printing service rarely needed on a vault host.",
        "bluetooth":    "Bluetooth expands wireless attack surface.",
    }
    rc, out, _ = _cmd(["systemctl", "list-units", "--state=running", "--no-pager", "--plain"])
    found = []
    for svc, reason in high_risk.items():
        if svc in out:
            found.append(f"  ⚠  {svc}: {reason}")

    if found:
        report.add("Running services", "High-risk services detected",
            WARN, "\n".join(found),
            "Disable unused services: sudo systemctl disable --now <service>")
    else:
        report.add("Running services", "No high-risk services detected in running set",
            PASS, "Common high-risk services not found in active systemd units.")


# ──────────────────────────────────────────────────────────────────────────────
#  HTML report renderer
# ──────────────────────────────────────────────────────────────────────────────

STATUS_COLOUR = {
    PASS: ("#1a7f4b", "#eafaf1", "✅"),
    WARN: ("#7d5a00", "#fffbe6", "⚠️"),
    FAIL: ("#9b1c1c", "#fef2f2", "❌"),
    INFO: ("#1e40af", "#eff6ff", "ℹ️"),
}

def _badge(status: str) -> str:
    fg, bg, icon = STATUS_COLOUR.get(status, ("#333", "#f9f9f9", "?"))
    return (f'<span class="badge" style="background:{bg};color:{fg};'
            f'border:1px solid {fg}33">{icon} {status}</span>')

def render_html(report: AuditReport, generated_at: str) -> str:
    counts = report.counts
    total = len(report.findings)
    score_pct = int(100 * (counts[PASS] + counts[INFO]) / total) if total else 0

    by_cat: dict = {}
    for f in report.findings:
        by_cat.setdefault(f.category, []).append(f)

    rows = []
    for cat, findings in by_cat.items():
        rows.append(f'<tr class="cat-row"><td colspan="3"><strong>{html.escape(cat)}</strong></td></tr>')
        for f in findings:
            fg, bg, icon = STATUS_COLOUR.get(f.status, ("#333", "#f9f9f9", "?"))
            rec_html = ""
            if f.recommendation:
                rec_html = (f'<div class="rec">💡 <strong>Fix:</strong> '
                            f'<code>{html.escape(f.recommendation)}</code></div>')
            cve_html = ""
            if f.cve:
                cve_html = f' <span class="cve">{html.escape(f.cve)}</span>'
            detail_pre = f'<pre class="detail">{html.escape(f.detail)}</pre>' if f.detail else ""
            rows.append(f"""
            <tr style="background:{bg}">
              <td style="white-space:nowrap">{_badge(f.status)}</td>
              <td><strong>{html.escape(f.title)}</strong>{cve_html}
                  {detail_pre}{rec_html}</td>
            </tr>""")

    table_html = "\n".join(rows)

    summary_items = "".join(
        f'<div class="sum-item" style="color:{STATUS_COLOUR[s][0]}">'
        f'{STATUS_COLOUR[s][2]} <strong>{counts[s]}</strong> {s}</div>'
        for s in [FAIL, WARN, PASS, INFO]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>qrptonote Security Audit Report</title>
<style>
  :root {{
    --bg: #0f1117; --surface: #1a1d27; --border: #2e3142;
    --text: #e2e8f0; --muted: #94a3b8;
    --accent: #6366f1;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: var(--bg); color: var(--text);
    padding: 2rem; font-size: 14px; line-height: 1.6;
  }}
  header {{
    border-bottom: 2px solid var(--accent);
    padding-bottom: 1.5rem; margin-bottom: 2rem;
  }}
  h1 {{ font-size: 1.8rem; color: #fff; }}
  h1 span {{ color: var(--accent); }}
  .meta {{ color: var(--muted); margin-top: .4rem; font-size: 0.85rem; }}
  .summary {{
    display: flex; gap: 1.5rem; flex-wrap: wrap;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 1.2rem 1.8rem; margin-bottom: 2rem;
  }}
  .sum-item {{ font-size: 1.1rem; }}
  .score {{
    margin-left: auto; font-size: 2.5rem; font-weight: 700;
    color: {'#1a7f4b' if score_pct >= 80 else '#7d5a00' if score_pct >= 50 else '#9b1c1c'};
  }}
  table {{
    width: 100%; border-collapse: collapse;
    background: var(--surface); border-radius: 10px; overflow: hidden;
    box-shadow: 0 2px 12px rgba(0,0,0,.4);
  }}
  tr {{ border-bottom: 1px solid var(--border); }}
  td {{ padding: .7rem 1rem; vertical-align: top; }}
  .cat-row td {{
    background: var(--border); color: #fff;
    font-size: .9rem; letter-spacing: .06em; text-transform: uppercase;
    padding: .5rem 1rem;
  }}
  .badge {{
    display: inline-block; padding: .15rem .55rem;
    border-radius: 4px; font-size: .78rem; font-weight: 700;
    white-space: nowrap;
  }}
  pre.detail {{
    background: rgba(0,0,0,.25); border-radius: 6px;
    padding: .5rem .8rem; margin-top: .4rem;
    font-size: .8rem; white-space: pre-wrap; word-break: break-word;
    color: #cbd5e1; border-left: 3px solid #4b5563;
  }}
  .rec {{
    background: rgba(99,102,241,.12); border-radius: 6px;
    padding: .4rem .8rem; margin-top: .4rem; font-size: .82rem;
  }}
  .rec code {{ font-family: monospace; font-size: .8rem; white-space: pre-wrap; }}
  .cve {{
    background: #7c3aed22; color: #a78bfa;
    font-size: .72rem; border-radius: 3px;
    padding: .05rem .35rem; margin-left: .4rem;
    border: 1px solid #7c3aed55;
  }}
  footer {{
    margin-top: 2.5rem; text-align: center;
    color: var(--muted); font-size: .8rem;
  }}
</style>
</head>
<body>
<header>
  <h1>🔐 <span>qrptonote</span> Security Audit Report</h1>
  <div class="meta">
    Host: {html.escape(socket.gethostname())} &nbsp;|&nbsp;
    Kernel: {html.escape(platform.uname().release)} &nbsp;|&nbsp;
    Generated: {html.escape(generated_at)}
  </div>
</header>

<div class="summary">
  {summary_items}
  <div class="score">{score_pct}%</div>
</div>

<table>
  <colgroup>
    <col style="width:100px">
    <col>
  </colgroup>
  <tbody>
    {table_html}
  </tbody>
</table>

<footer>
  Generated by qrptonote_audit.py &nbsp;·&nbsp;
  Checks cover: ASLR · ptrace · core-dump · mlock · swap · AppArmor ·
  binary hardening · DMA · Spectre/Meltdown · entropy · FDE
</footer>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print("\n  🔍  qrptonote Security Audit")
    print("  " + "─" * 50)
    print(f"  Host   : {socket.gethostname()}")
    print(f"  Kernel : {platform.uname().release}")
    print(f"  Time   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  " + "─" * 50)

    report = AuditReport()

    checks = [
        ("System info",            check_kernel_info),
        ("ASLR",                   check_aslr),
        ("ptrace scope",           check_ptrace),
        ("Core dumps",             check_core_dumps),
        ("mlock limits",           check_mlock),
        ("Swap encryption",        check_swap),
        ("kptr_restrict",          check_kptr_restrict),
        ("dmesg_restrict",         check_dmesg_restrict),
        ("perf_event_paranoid",    check_perf_paranoid),
        ("Spectre/Meltdown",       check_spectre_meltdown),
        ("AppArmor / SELinux",     check_apparmor),
        ("Binary hardening",       check_binary_hardening),
        ("USB / DMA / IOMMU",      check_usb_dma),
        ("Entropy / RNG",          check_entropy),
        ("Filesystem",             check_filesystem),
        ("User environment",       check_user_environment),
        ("SSH agent",              check_ssh_agent_forwarding),
        ("Secure Boot",            check_secureboot),
        ("Disk encryption",        check_disk_encryption),
        ("AES-NI / RDRAND",        check_aes_ni),
        ("Running services",       check_running_services),
    ]

    for name, fn in checks:
        print(f"  [ .. ]  Checking {name} …", end="\r", flush=True)
        try:
            fn(report)
        except Exception as e:
            report.add(name, f"Audit check failed: {name}", WARN, str(e))
        print(f"  [ ✓  ]  {name:<35}", flush=True)

    counts = report.counts
    print()
    print(f"  Results:  ❌ {counts[FAIL]} FAIL   ⚠️  {counts[WARN]} WARN   "
          f"✅ {counts[PASS]} PASS   ℹ️  {counts[INFO]} INFO")
    print()

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_out = render_html(report, ts)

    out_path = Path("qrptonote_security_report.html")
    out_path.write_text(html_out, encoding="utf-8")
    print(f"  📄  Report saved → {out_path.resolve()}")
    print()

    if counts[FAIL] > 0:
        print("  ⛔  CRITICAL issues found — see FAIL items in report.")
    elif counts[WARN] > 0:
        print("  ⚠️   Warnings found — review WARN items in report.")
    else:
        print("  ✅  All checks passed!")
    print()


if __name__ == "__main__":
    main()
