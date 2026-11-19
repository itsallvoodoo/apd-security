#!/usr/bin/env python3
import datetime
import json
import os
import re
import socket
import subprocess
import sys

CERT_EXTS = {".crt", ".pem", ".cer", ".der"}
KEY_EXTS = {".key", ".pub"}
KEYSTORE_EXTS = {".p12", ".pfx", ".jks"}


def run_cmd(cmd, input_data=None, timeout=10):
    try:
        res = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as exc:
        return -1, "", str(exc)


def classify_pqc_risk(algo_str, context="asymmetric"):
    """
    Classify algorithm vulnerability against quantum threats:
    - CRITICAL: Broken classically (SHA-1, MD5, RSA<2048, DSA, 3DES, RC4, TLS<1.2)
    - HIGH: Quantum-vulnerable key exchange (HNDL risk: classical ECDHE/DH/RSA KEX)
    - MEDIUM: Quantum-vulnerable auth/signatures (RSA>=2048, ECDSA, Ed25519)
    - LOW: Symmetric/Hash weakened by Grover's algorithm (AES-128, SHA-256)
    - QUANTUM-SAFE: PQC / Hybrid PQC (ML-KEM, ML-DSA, sntrup761) or CNSA 2.0 symmetric (AES-256, SHA-384/512)
    """
    a = algo_str.upper()

    if any(k in a for k in ["ML-KEM", "MLKEM", "KYBER", "ML-DSA", "MLDSA", "DILITHIUM", "SLH-DSA", "SPHINCS", "SNTRUP761"]):
        return "QUANTUM-SAFE", "Post-quantum or hybrid PQC algorithm resistant to Shor's algorithm."

    if any(k in a for k in ["MD5", "SHA1", "SHA-1", "DSA", "3DES", "DES-CBC", "RC4", "TLS1.0", "TLS1.1", "TLSV1 ", "TLSV1.1"]):
        return "CRITICAL", "Classically weak or deprecated algorithm; remediate immediately regardless of PQC."

    if "RSA" in a:
        m = re.search(r"(\d{3,5})", a)
        bits = int(m.group(1)) if m else 2048
        if bits < 2048:
            return "CRITICAL", f"RSA-{bits} is classically weak (<2048 bits) and broken by Shor's algorithm."
        if context == "kex":
            return "HIGH", f"RSA-{bits} key exchange is vulnerable to Harvest-Now-Decrypt-Later (HNDL)."
        return "MEDIUM", f"RSA-{bits} signature/identity is vulnerable to Shor's algorithm (migrate to ML-DSA)."

    if any(k in a for k in ["ECDSA", "ECDH", "ED25519", "ED448", "CURVE25519", "P-256", "P-384", "P-521", "PRIME256V1", "SECP", "DH-", "DIFFIE-HELLMAN"]):
        if context == "kex":
            return "HIGH", "Classical ECDH/DH key exchange is vulnerable to Harvest-Now-Decrypt-Later (HNDL)."
        return "MEDIUM", "Elliptic-curve / Edwards signature is vulnerable to Shor's algorithm (migrate to ML-DSA)."

    if any(k in a for k in ["AES-256", "AES256", "SHA-384", "SHA384", "SHA-512", "SHA512"]):
        return "QUANTUM-SAFE", "Meets CNSA 2.0 symmetric/hash quantum-resistance thresholds."

    if any(k in a for k in ["AES-128", "AES128", "CHACHA20", "SHA-256", "SHA256"]):
        return "LOW", "Security margin halved by Grover's algorithm; prefer AES-256/SHA-384 for long-term CNSA 2.0."

    return "INFO", "Manual review recommended."


def get_crypto_policy():
    policy = {"current": "UNKNOWN", "custom_modules": [], "pqc_risk": "INFO", "notes": ""}
    state_file = "/etc/crypto-policies/state/current"
    if os.path.exists(state_file):
        with open(state_file, "r", encoding="utf-8", errors="ignore") as f:
            policy["current"] = f.read().strip()

    mod_dir = "/etc/crypto-policies/policies/modules"
    if os.path.isdir(mod_dir):
        policy["custom_modules"] = sorted(os.listdir(mod_dir))

    cur = policy["current"].upper()
    if "LEGACY" in cur:
        policy["pqc_risk"] = "CRITICAL"
        policy["notes"] = "LEGACY policy permits SHA-1 and older TLS; neither classically secure nor PQC-ready."
    elif "FUTURE" in cur or "FIPS" in cur:
        policy["pqc_risk"] = "MEDIUM"
        policy["notes"] = f"{cur} enforces strong classical baselines (>=2048/3072-bit), but still lacks PQC KEM/signatures on RHEL 9."
    else:
        policy["pqc_risk"] = "HIGH"
        policy["notes"] = "DEFAULT policy relies on classical ECDHE/RSA/ECDSA, leaving TLS/SSH sessions exposed to HNDL."
    return policy


def get_crypto_packages_and_openssl():
    pkgs = ["openssl", "openssl-libs", "gnutls", "nss", "openssh-server", "libgcrypt", "oqsprovider", "liboqs"]
    installed = {}
    for p in pkgs:
        rc, out, _ = run_cmd(["rpm", "-q", p])
        installed[p] = out if rc == 0 else "not_installed"

    _, providers_out, _ = run_cmd(["openssl", "list", "-providers"])
    _, kems_out, _ = run_cmd(["openssl", "list", "-kem-algorithms"])
    pqc_kems = [
        line.strip()
        for line in kems_out.splitlines()
        if any(k in line.lower() for k in ["mlkem", "kyber", "frodo", "bike", "hqc"])
    ]

    return {
        "packages": installed,
        "openssl_providers": providers_out,
        "pqc_kem_algorithms_available": pqc_kems,
    }


def scan_sshd():
    rc, out, err = run_cmd(["sshd", "-T"])
    if rc != 0:
        return {"status": "unavailable", "error": err}

    directives = {}
    for key in ["kexalgorithms", "hostkeyalgorithms", "ciphers", "macs", "pubkeyacceptedalgorithms"]:
        m = re.search(rf"^{key}\s+(.+)$", out, re.MULTILINE)
        if m:
            directives[key] = m.group(1).split(",")

    kex_list = directives.get("kexalgorithms", [])
    hybrid_kex = [k for k in kex_list if any(p in k.lower() for p in ["sntrup761", "mlkem", "kyber"])]
    if hybrid_kex:
        kex_risk = "QUANTUM-SAFE"
        kex_note = f"Hybrid PQC key exchange enabled ({', '.join(hybrid_kex)})."
    else:
        kex_risk = "HIGH"
        kex_note = "Only classical KEX enabled; SSH traffic is vulnerable to Harvest-Now-Decrypt-Later."

    host_algos = directives.get("hostkeyalgorithms", [])
    host_risk, host_note = classify_pqc_risk(",".join(host_algos), context="asymmetric")

    return {
        "status": "active",
        "kex_algorithms": kex_list,
        "hybrid_pqc_kex_present": hybrid_kex,
        "kex_pqc_risk": kex_risk,
        "kex_notes": kex_note,
        "host_key_algorithms": host_algos,
        "host_key_pqc_risk": host_risk,
        "host_key_notes": host_note,
        "ciphers": directives.get("ciphers", []),
        "macs": directives.get("macs", []),
    }


def parse_x509(filepath):
    rc, out, _ = run_cmd(["openssl", "x509", "-in", filepath, "-noout", "-text", "-subject", "-enddate"])
    if rc != 0:
        return None

    pub_algo = "Unknown"
    m_algo = re.search(r"Public Key Algorithm:\s*(.+)", out)
    if m_algo:
        raw_algo = m_algo.group(1).strip()
        if "rsaEncryption" in raw_algo:
            m_bits = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", out)
            bits = m_bits.group(1) if m_bits else "?"
            pub_algo = f"RSA-{bits}"
        elif "id-ecPublicKey" in raw_algo:
            m_curve = re.search(r"(?:NIST CURVE|ASN1 OID):\s*(.+)", out)
            curve = m_curve.group(1).strip() if m_curve else "EC"
            pub_algo = f"ECDSA-{curve}"
        else:
            pub_algo = raw_algo

    sig_algo = "Unknown"
    m_sig = re.search(r"Signature Algorithm:\s*(.+)", out)
    if m_sig:
        sig_algo = m_sig.group(1).strip()

    subject = ""
    m_sub = re.search(r"subject=(.+)", out)
    if m_sub:
        subject = m_sub.group(1).strip()

    not_after = ""
    m_exp = re.search(r"notAfter=(.+)", out)
    if m_exp:
        not_after = m_exp.group(1).strip()

    risk, note = classify_pqc_risk(f"{pub_algo} {sig_algo}", context="asymmetric")
    return {
        "path": filepath,
        "type": "X.509 Certificate",
        "algorithm": pub_algo,
        "signature_algorithm": sig_algo,
        "subject": subject,
        "expires": not_after,
        "pqc_risk": risk,
        "pqc_notes": note,
    }


def parse_key(filepath):
    if filepath.endswith(".pub"):
        rc, out, _ = run_cmd(["ssh-keygen", "-l", "-f", filepath])
        if rc == 0 and out:
            parts = out.split()
            bits = parts[0]
            m_type = re.search(r"\(([^)]+)\)$", out)
            ktype = m_type.group(1) if m_type else "SSH-KEY"
            algo = f"{ktype}-{bits}" if ktype == "RSA" else ktype
            risk, note = classify_pqc_risk(algo, context="asymmetric")
            return {
                "path": filepath,
                "type": "SSH Public Key",
                "algorithm": algo,
                "signature_algorithm": "N/A",
                "subject": "N/A",
                "expires": "N/A",
                "pqc_risk": risk,
                "pqc_notes": note,
            }

    rc, pub_pem, _ = run_cmd(["openssl", "pkey", "-in", filepath, "-passin", "pass:", "-pubout"])
    if rc != 0:
        rc2, out, _ = run_cmd(["openssl", "pkey", "-pubin", "-in", filepath, "-noout", "-text"])
        if rc2 != 0:
            return {
                "path": filepath,
                "type": "Encrypted/Unreadable Key",
                "algorithm": "Encrypted or Non-Standard Key",
                "signature_algorithm": "N/A",
                "subject": "N/A",
                "expires": "N/A",
                "pqc_risk": "INFO",
                "pqc_notes": "Passphrase-protected or unsupported key format; inspect manually.",
            }
    else:
        _, out, _ = run_cmd(["openssl", "pkey", "-pubin", "-noout", "-text"], input_data=pub_pem)

    algo = "Unknown Key"
    first_line = out.splitlines()[0] if out else ""
    m_bits = re.search(r"\((\d+)\s*bit\)", first_line)
    bits = m_bits.group(1) if m_bits else ""
    if "RSA" in first_line:
        algo = f"RSA-{bits}"
    elif "EC" in first_line:
        m_curve = re.search(r"(?:NIST CURVE|ASN1 OID):\s*(.+)", out)
        curve = m_curve.group(1).strip() if m_curve else bits
        algo = f"EC-{curve}"
    elif "ED25519" in first_line.upper():
        algo = "Ed25519"
    elif "ED448" in first_line.upper():
        algo = "Ed448"
    elif first_line:
        algo = first_line

    risk, note = classify_pqc_risk(algo, context="asymmetric")
    return {
        "path": filepath,
        "type": "Private/Public Key",
        "algorithm": algo,
        "signature_algorithm": "N/A",
        "subject": "N/A",
        "expires": "N/A",
        "pqc_risk": risk,
        "pqc_notes": note,
    }


def scan_filesystem_assets(pki_paths, exclude_paths):
    assets = []
    seen = set()
    excluded = set(exclude_paths)

    for base in pki_paths:
        if not os.path.exists(base):
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in excluded]
            for fname in files:
                fpath = os.path.join(root, fname)
                if fpath in seen or fpath in excluded or os.path.islink(fpath):
                    continue
                seen.add(fpath)

                _, ext = os.path.splitext(fname.lower())
                if ext in KEYSTORE_EXTS:
                    assets.append({
                        "path": fpath,
                        "type": "PKCS#12/Java Keystore",
                        "algorithm": "Keystore Container",
                        "signature_algorithm": "N/A",
                        "subject": "N/A",
                        "expires": "N/A",
                        "pqc_risk": "INFO",
                        "pqc_notes": "Encrypted keystore container; audit contents with keytool/openssl.",
                    })
                    continue

                if ext not in CERT_EXTS and ext not in KEY_EXTS and not fname.startswith("ssh_host_"):
                    continue

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        header = f.read(512)
                except Exception:
                    continue

                item = None
                if "BEGIN CERTIFICATE" in header:
                    item = parse_x509(fpath)
                elif "PRIVATE KEY" in header or "PUBLIC KEY" in header or fname.endswith(".pub"):
                    item = parse_key(fpath)

                if item:
                    assets.append(item)

    return assets


def scan_service_tls_configs(web_conf_dirs):
    findings = []
    pattern = re.compile(
        r"^\s*(SSLCipherSuite|SSLProtocol|ssl_ciphers|ssl_protocols|ssl-default-bind-ciphers|smtpd_tls_protocols|ssl_min_protocol)\s+(.+)$",
        re.IGNORECASE,
    )
    for d in web_conf_dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for fname in files:
                if not fname.endswith((".conf", ".cfg", ".cf")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for idx, line in enumerate(f, 1):
                            m = pattern.match(line)
                            if m:
                                directive, val = m.group(1), m.group(2).strip()
                                ctx = "kex" if "cipher" in directive.lower() else "protocol"
                                risk, note = classify_pqc_risk(val, context=ctx)
                                findings.append({
                                    "file": fpath,
                                    "line": idx,
                                    "directive": directive,
                                    "value": val,
                                    "pqc_risk": risk,
                                    "pqc_notes": note,
                                })
                except Exception:
                    continue
    return findings


def main():
    cfg = json.loads(sys.argv[1])
    pki_paths = cfg["pki_paths"]
    exclude_paths = cfg["exclude_paths"]
    web_conf_dirs = cfg["web_conf_dirs"]
    out_json = cfg["out_json"]
    out_md = cfg["out_md"]

    hostname = socket.getfqdn()
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    crypto_policy = get_crypto_policy()
    libraries = get_crypto_packages_and_openssl()
    ssh_audit = scan_sshd()
    assets = scan_filesystem_assets(pki_paths, exclude_paths)
    service_configs = scan_service_tls_configs(web_conf_dirs)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "QUANTUM-SAFE": 5}
    assets.sort(key=lambda x: severity_order.get(x["pqc_risk"], 9))

    counts = {k: 0 for k in severity_order}
    for a in assets:
        counts[a["pqc_risk"]] = counts.get(a["pqc_risk"], 0) + 1
    if ssh_audit.get("status") == "active":
        counts[ssh_audit["kex_pqc_risk"]] += 1
        counts[ssh_audit["host_key_pqc_risk"]] += 1

    cbom = {
        "bomFormat": "CycloneDX-CBOM-Inspired",
        "specVersion": "1.6",
        "timestamp": timestamp,
        "host": hostname,
        "risk_summary": counts,
        "system_crypto_policy": crypto_policy,
        "libraries_and_providers": libraries,
        "ssh_configuration": ssh_audit,
        "service_tls_configs": service_configs,
        "cryptographic_assets": assets,
    }

    with open(out_json, "w", encoding="utf-8") as jf:
        json.dump(cbom, jf, indent=2)

    md = [
        "# Cryptographic Bill of Materials (CBOM) & PQC Risk Report",
        f"- **Host:** `{hostname}`",
        f"- **Generated (UTC):** `{timestamp}`",
        f"- **System Crypto Policy:** `{crypto_policy['current']}` (**{crypto_policy['pqc_risk']}** — {crypto_policy['notes']})",
        f"- **Available PQC OpenSSL KEMs:** `{', '.join(libraries['pqc_kem_algorithms_available']) or 'None detected (OpenSSL 3.0 classical baseline)'}`",
        "",
        "## 1. PQC Risk Summary",
        "| Severity | Count | Quantum Threat Context |",
        "| :--- | :---: | :--- |",
        f"| **CRITICAL** | {counts['CRITICAL']} | Classically broken/deprecated (SHA-1, MD5, RSA<2048, TLS 1.0/1.1) |",
        f"| **HIGH** | {counts['HIGH']} | Classical Key Exchange vulnerable to **Harvest-Now-Decrypt-Later (HNDL)** |",
        f"| **MEDIUM** | {counts['MEDIUM']} | Asymmetric Certificates/Keys vulnerable to **Shor's Algorithm** (RSA/ECDSA/Ed25519) |",
        f"| **LOW** | {counts['LOW']} | Symmetric/Hash weakened by **Grover's Algorithm** (AES-128, SHA-256) |",
        f"| **QUANTUM-SAFE** | {counts['QUANTUM-SAFE']} | Hybrid PQC / ML-KEM / ML-DSA or CNSA 2.0 symmetric (AES-256, SHA-384+) |",
        f"| **INFO** | {counts['INFO']} | Encrypted keystores or items requiring manual inspection |",
        "",
        "## 2. SSH Daemon Cryptography (`sshd -T`)",
    ]

    if ssh_audit.get("status") == "active":
        md.extend([
            f"- **Key Exchange PQC Risk:** `{ssh_audit['kex_pqc_risk']}` — {ssh_audit['kex_notes']}",
            f"- **Host Key PQC Risk:** `{ssh_audit['host_key_pqc_risk']}` — {ssh_audit['host_key_notes']}",
            f"- **Active KEX Algorithms:** `{', '.join(ssh_audit['kex_algorithms'])}`",
            f"- **Active Host Key Algorithms:** `{', '.join(ssh_audit['host_key_algorithms'])}`",
        ])
    else:
        md.append("- `sshd` not active or could not be queried.")

    md.extend([
        "",
        "## 3. Discovered Certificates & Keys",
        "| Risk | Algorithm | Signature | Type | Location | Notes |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ])
    for a in assets:
        md.append(f"| **{a['pqc_risk']}** | `{a['algorithm']}` | `{a['signature_algorithm']}` | {a['type']} | `{a['path']}` | {a['pqc_notes']} |")

    if service_configs:
        md.extend([
            "",
            "## 4. Service TLS Directives",
            "| Risk | Service Config | Directive | Value |",
            "| :--- | :--- | :--- | :--- |",
        ])
        for c in service_configs:
            md.append(f"| **{c['pqc_risk']}** | `{c['file']}:{c['line']}` | `{c['directive']}` | `{c['value']}` |")

    with open(out_md, "w", encoding="utf-8") as mf:
        mf.write("\n".join(md) + "\n")

    print(json.dumps(counts))


if __name__ == "__main__":
    main()
