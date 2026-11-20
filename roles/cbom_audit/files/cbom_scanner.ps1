param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath
)

$ErrorActionPreference = "SilentlyContinue"
$cfg = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json

function Classify-PqcRisk {
    param(
        [string]$AlgoStr,
        [string]$Context = "asymmetric"
    )

    $a = $AlgoStr.ToUpper()

    if ($a -match "ML-KEM|MLKEM|KYBER|ML-DSA|MLDSA|DILITHIUM|SLH-DSA|SPHINCS|SNTRUP761") {
        return @{ Risk = "QUANTUM-SAFE"; Note = "Post-quantum or hybrid PQC algorithm resistant to Shor's algorithm." }
    }

    if ($a -match "MD5|SHA1|SHA-1|\bDSA\b|3DES|DES-CBC|RC4|TLS 1\.0|TLS 1\.1|SSL 3\.0|SSL 2\.0") {
        return @{ Risk = "CRITICAL"; Note = "Classically weak or deprecated algorithm; remediate immediately regardless of PQC." }
    }

    if ($a -match "RSA") {
        $bits = 2048
        if ($a -match "(\d{3,5})") { $bits = [int]$Matches[1] }
        if ($bits -lt 2048) {
            return @{ Risk = "CRITICAL"; Note = "RSA-$bits is classically weak (<2048 bits) and broken by Shor's algorithm." }
        }
        if ($Context -eq "kex") {
            return @{ Risk = "HIGH"; Note = "RSA-$bits key exchange is vulnerable to Harvest-Now-Decrypt-Later (HNDL)." }
        }
        return @{ Risk = "MEDIUM"; Note = "RSA-$bits signature/identity is vulnerable to Shor's algorithm (migrate to ML-DSA)." }
    }

    if ($a -match "ECDSA|ECDHE|ECDH|ED25519|ED448|P-256|P-384|P-521|NISTP|DHE|DIFFIE-HELLMAN") {
        if ($Context -eq "kex") {
            return @{ Risk = "HIGH"; Note = "Classical ECDHE/DHE key exchange is vulnerable to Harvest-Now-Decrypt-Later (HNDL)." }
        }
        return @{ Risk = "MEDIUM"; Note = "Elliptic-curve / Edwards signature is vulnerable to Shor's algorithm (migrate to ML-DSA)." }
    }

    if ($a -match "AES-256|AES256|AES_256|SHA-384|SHA384|SHA-512|SHA512") {
        return @{ Risk = "QUANTUM-SAFE"; Note = "Meets CNSA 2.0 symmetric/hash quantum-resistance thresholds." }
    }

    if ($a -match "AES-128|AES128|AES_128|CHACHA20|SHA-256|SHA256") {
        return @{ Risk = "LOW"; Note = "Security margin halved by Grover's algorithm; prefer AES-256/SHA-384 for long-term CNSA 2.0." }
    }

    return @{ Risk = "INFO"; Note = "Manual review recommended." }
}

function Get-SChannelPolicy {
    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    $protocols = @("SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
    $state = @{}
    $legacyEnabled = $false

    foreach ($p in $protocols) {
        $srvKey = "$base\$p\Server"
        if (Test-Path $srvKey) {
            $props = Get-ItemProperty -Path $srvKey
            $enabled = if ($null -ne $props.Enabled) { [bool]$props.Enabled } else { "OS Default" }
            $state[$p] = $enabled
            if (($p -in @("SSL 3.0", "TLS 1.0", "TLS 1.1")) -and ($enabled -eq $true)) {
                $legacyEnabled = $true
            }
        } else {
            $state[$p] = "OS Default"
        }
    }

    $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
    if ($legacyEnabled) {
        $risk = "CRITICAL"
        $notes = "Legacy SSL/TLS (<1.2) explicitly enabled in SChannel registry on $osCaption."
    } else {
        $risk = "HIGH"
        $notes = "SChannel relies on classical ECDHE/RSA/ECDSA key exchange on $osCaption (exposed to HNDL until SymCrypt PQC is enabled)."
    }

    return @{
        current        = $osCaption
        protocol_state = $state
        pqc_risk       = $risk
        notes          = $notes
    }
}

function Get-WindowsTlsSuites {
    $suites = @()
    $pqcSuites = @()
    $rawSuites = Get-TlsCipherSuite
    if ($rawSuites) {
        foreach ($s in $rawSuites) {
            $suites += $s.Name
            if ($s.Name -match "MLKEM|KYBER") {
                $pqcSuites += $s.Name
            }
        }
    }
    return @{
        active_cipher_suites         = @($suites)
        pqc_kem_algorithms_available = @($pqcSuites)
    }
}

function Get-HttpSslBindings {
    $bindings = @{}
    $raw = netsh http show sslcert 2>$null
    if (-not $raw) { return $bindings }

    $currentTarget = ""
    foreach ($line in $raw) {
        if ($line -match "^\s*(IP:port|Hostname:port)\s*:\s*(.+)$") {
            $currentTarget = $Matches[2].Trim()
        } elseif ($line -match "^\s*Certificate Hash\s*:\s*([0-9a-fA-F]+)") {
            $hash = $Matches[1].Trim().ToUpper()
            if ($currentTarget) {
                if (-not $bindings.ContainsKey($hash)) { $bindings[$hash] = @() }
                $bindings[$hash] += $currentTarget
            }
        }
    }
    return $bindings
}

function Get-CertPublicKeyAlgorithm {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

    $oidName = $Cert.PublicKey.Oid.FriendlyName
    if ($oidName -match "RSA") {
        try {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Cert)
            if ($rsa) { return "RSA-$($rsa.KeySize)" }
        } catch {}
        if ($Cert.PublicKey.Key) { return "RSA-$($Cert.PublicKey.Key.KeySize)" }
        return "RSA"
    }

    if ($oidName -match "ECC|ECDSA") {
        try {
            $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Cert)
            if ($ecdsa) {
                $curve = $ecdsa.ExportParameters($false).Curve.Oid.FriendlyName
                if (-not $curve) { $curve = "$($ecdsa.KeySize)-bit" }
                return "ECDSA-$curve"
            }
        } catch {}
        if ($Cert.PublicKey.Key) { return "ECDSA-$($Cert.PublicKey.Key.KeySize)" }
        return "ECDSA"
    }

    return $oidName
}

function Get-StoreCertificates {
    param([string[]]$Stores, [hashtable]$Bindings)

    $assets = @()
    foreach ($storePath in $Stores) {
        if (-not (Test-Path $storePath)) { continue }
        $certs = Get-ChildItem -Path $storePath
        foreach ($c in $certs) {
            $pubAlgo = Get-CertPublicKeyAlgorithm -Cert $c
            $sigAlgo = $c.SignatureAlgorithm.FriendlyName
            $class = Classify-PqcRisk -AlgoStr "$pubAlgo $sigAlgo" -Context "asymmetric"
            $thumb = $c.Thumbprint.ToUpper()
            $boundTo = if ($Bindings.ContainsKey($thumb)) { " [Bound: $($Bindings[$thumb] -join ', ')]" } else { "" }

            $assets += @{
                path                = "$storePath\$thumb$boundTo"
                type                = "X.509 Certificate (Windows Store)"
                algorithm           = $pubAlgo
                signature_algorithm = $sigAlgo
                subject             = $c.Subject
                expires             = $c.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ")
                pqc_risk            = $class.Risk
                pqc_notes           = $class.Note
            }
        }
    }
    return $assets
}

function Get-FileAssets {
    param([string[]]$Paths)

    $assets = @()
    $exts = @(".pfx", ".p12", ".cer", ".crt", ".pem", ".key")
    foreach ($base in $Paths) {
        if (-not (Test-Path $base)) { continue }
        $files = Get-ChildItem -Path $base -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
            ($exts -contains $_.Extension.ToLower()) -and ($_.FullName -notlike "C:\ProgramData\Microsoft\*")
        }
        foreach ($f in $files) {
            $ext = $f.Extension.ToLower()
            if ($ext -in @(".pfx", ".p12")) {
                $assets += @{
                    path                = $f.FullName
                    type                = "PKCS#12 Keystore"
                    algorithm           = "Keystore Container"
                    signature_algorithm = "N/A"
                    subject             = "N/A"
                    expires             = "N/A"
                    pqc_risk            = "INFO"
                    pqc_notes           = "Password-protected PKCS#12 container; inspect certificate contents manually."
                }
            } elseif ($ext -eq ".key") {
                $assets += @{
                    path                = $f.FullName
                    type                = "Private Key File"
                    algorithm           = "PEM/DER Private Key"
                    signature_algorithm = "N/A"
                    subject             = "N/A"
                    expires             = "N/A"
                    pqc_risk            = "INFO"
                    pqc_notes           = "Standalone private key file on disk; verify paired certificate algorithm."
                }
            } elseif ($ext -in @(".cer", ".crt", ".pem")) {
                try {
                    $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($f.FullName)
                    $algo = Get-CertPublicKeyAlgorithm -Cert $x509
                    $sig = $x509.SignatureAlgorithm.FriendlyName
                    $class = Classify-PqcRisk -AlgoStr "$algo $sig" -Context "asymmetric"
                    $assets += @{
                        path                = $f.FullName
                        type                = "X.509 Certificate (File)"
                        algorithm           = $algo
                        signature_algorithm = $sig
                        subject             = $x509.Subject
                        expires             = $x509.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ")
                        pqc_risk            = $class.Risk
                        pqc_notes           = $class.Note
                    }
                } catch {
                    $assets += @{
                        path                = $f.FullName
                        type                = "PEM/Key File"
                        algorithm           = "Unparsed PEM/Key"
                        signature_algorithm = "N/A"
                        subject             = "N/A"
                        expires             = "N/A"
                        pqc_risk            = "INFO"
                        pqc_notes           = "Private key or multi-block PEM file; inspect manually."
                    }
                }
            }
        }
    }
    return $assets
}

function Get-WindowsOpenSshAudit {
    $sshdExe = Get-Command sshd.exe -ErrorAction SilentlyContinue
    if (-not $sshdExe) {
        return @{ status = "not_installed" }
    }
    $out = & $sshdExe.Source -T 2>$null
    if (-not $out) {
        return @{ status = "installed_inactive" }
    }

    $kex = @()
    $hostAlgos = @()
    foreach ($line in $out) {
        if ($line -match "^kexalgorithms\s+(.+)$") { $kex = $Matches[1].Split(",") }
        if ($line -match "^hostkeyalgorithms\s+(.+)$") { $hostAlgos = $Matches[1].Split(",") }
    }

    $hybrid = $kex | Where-Object { $_ -match "sntrup761|mlkem|kyber" }
    if ($hybrid) {
        $kexRisk = "QUANTUM-SAFE"
        $kexNote = "Hybrid PQC key exchange enabled ($($hybrid -join ', '))."
    } else {
        $kexRisk = "HIGH"
        $kexNote = "Only classical KEX enabled; SSH traffic is vulnerable to Harvest-Now-Decrypt-Later."
    }

    $hostClass = Classify-PqcRisk -AlgoStr ($hostAlgos -join ",") -Context "asymmetric"
    return @{
        status                  = "active"
        kex_algorithms          = @($kex)
        hybrid_pqc_kex_present  = @($hybrid)
        kex_pqc_risk            = $kexRisk
        kex_notes               = $kexNote
        host_key_algorithms     = @($hostAlgos)
        host_key_pqc_risk       = $hostClass.Risk
        host_key_notes          = $hostClass.Note
    }
}

$hostname = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$schannel = Get-SChannelPolicy
$tlsSuites = Get-WindowsTlsSuites
$bindings = Get-HttpSslBindings
$sshAudit = Get-WindowsOpenSshAudit

$assets = @()
$assets += Get-StoreCertificates -Stores $cfg.cert_stores -Bindings $bindings
$assets += Get-FileAssets -Paths $cfg.file_search_paths

$severityOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3; "INFO" = 4; "QUANTUM-SAFE" = 5 }
$assets = @($assets | Sort-Object { $severityOrder[$_.pqc_risk] })

$counts = @{ "CRITICAL" = 0; "HIGH" = 0; "MEDIUM" = 0; "LOW" = 0; "INFO" = 0; "QUANTUM-SAFE" = 0 }
foreach ($a in $assets) {
    $counts[$a.pqc_risk]++
}
if ($sshAudit.status -eq "active") {
    $counts[$sshAudit.kex_pqc_risk]++
    $counts[$sshAudit.host_key_pqc_risk]++
}

$cbom = @{
    bomFormat               = "CycloneDX-CBOM-Inspired"
    specVersion             = "1.6"
    timestamp               = $timestamp
    host                    = $hostname
    risk_summary            = $counts
    system_crypto_policy    = $schannel
    libraries_and_providers = $tlsSuites
    ssh_configuration       = $sshAudit
    cryptographic_assets    = @($assets)
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$jsonOut = $cbom | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($cfg.out_json, $jsonOut, $utf8NoBom)

$pqcKemStr = if ($tlsSuites.pqc_kem_algorithms_available.Count -gt 0) {
    $tlsSuites.pqc_kem_algorithms_available -join ", "
} else {
    "None detected (Classical SChannel baseline)"
}

$md = @(
    "# Cryptographic Bill of Materials (CBOM) & PQC Risk Report",
    "- **Host:** ``$hostname``",
    "- **Generated (UTC):** ``$timestamp``",
    "- **OS / SChannel Policy:** ``$($schannel.current)`` (**$($schannel.pqc_risk)** -- $($schannel.notes))",
    "- **Available PQC TLS KEMs:** ``$pqcKemStr``",
    "",
    "## 1. PQC Risk Summary",
    "| Severity | Count | Quantum Threat Context |",
    "| :--- | :---: | :--- |",
    "| **CRITICAL** | $($counts['CRITICAL']) | Classically broken/deprecated (SHA-1, MD5, RSA<2048, TLS 1.0/1.1) |",
    "| **HIGH** | $($counts['HIGH']) | Classical Key Exchange vulnerable to **Harvest-Now-Decrypt-Later (HNDL)** |",
    "| **MEDIUM** | $($counts['MEDIUM']) | Asymmetric Certificates/Keys vulnerable to **Shor's Algorithm** (RSA/ECDSA/Ed25519) |",
    "| **LOW** | $($counts['LOW']) | Symmetric/Hash weakened by **Grover's Algorithm** (AES-128, SHA-256) |",
    "| **QUANTUM-SAFE** | $($counts['QUANTUM-SAFE']) | Hybrid PQC / ML-KEM / ML-DSA or CNSA 2.0 symmetric (AES-256, SHA-384+) |",
    "| **INFO** | $($counts['INFO']) | Encrypted keystores or items requiring manual inspection |",
    "",
    "## 2. Windows OpenSSH Server",
    $(if ($sshAudit.status -eq "active") {
        "- **Key Exchange PQC Risk:** ``$($sshAudit.kex_pqc_risk)`` -- $($sshAudit.kex_notes)`n- **Host Key PQC Risk:** ``$($sshAudit.host_key_pqc_risk)`` -- $($sshAudit.host_key_notes)"
    } else {
        "- Windows OpenSSH Server status: ``$($sshAudit.status)``."
    }),
    "",
    "## 3. Discovered Certificates & Keystores",
    "| Risk | Algorithm | Signature | Type | Location | Notes |",
    "| :--- | :--- | :--- | :--- | :--- | :--- |"
)

foreach ($a in $assets) {
    $md += "| **$($a.pqc_risk)** | ``$($a.algorithm)`` | ``$($a.signature_algorithm)`` | $($a.type) | ``$($a.path)`` | $($a.pqc_notes) |"
}

[System.IO.File]::WriteAllText($cfg.out_md, ($md -join "`n") + "`n", $utf8NoBom)

$summaryJson = $counts | ConvertTo-Json -Compress
Write-Output $summaryJson