<#
.SYNOPSIS
    Interactive wizard to pull CUCM service log files (emservice.log and
    its rotated siblings, or any other Cisco service) via the Log
    Collection SOAP API.

.DESCRIPTION
    Talks to the Serviceability "Log Collection" SOAP service:
      https://<host>:8443/logcollectionservice2/services/LogCollectionPortTypeService

    Flow:
      1. Discover real service names + node names on this cluster
         (listNodeServiceLogs with no NodeName restriction - confirmed
         live 2026-09-21 that omitting NodeName still returns valid
         results; the WSDL declares the return type unbounded, so a real
         multi-node cluster should come back as multiple entries here -
         not independently verified on a real multi-node system yet,
         only inferred from the schema + single-node lab testing).
      2. Ask which service, which node(s) (or ALL), and a time window:
         ALL archived logs / relative (last N days/hours/minutes) /
         explicit date (converted to an equivalent relative offset
         under the hood - see the big caveat below).
      3. selectLogFiles for the matching window, GetOneFile per result.

    IMPORTANT CAVEAT, confirmed live 2026-09-21 against the lab CUCM:
    explicit FromDate/ToDate genuinely does not work through this
    OnDemand + DownloadtoClient combination - tried several date formats
    and range widths, all real CUCM-side "Error: logcollectionservice
    -101" rejections, not a formatting issue on this end. Working theory:
    explicit dates may only be valid for the *scheduled* job types, not
    a one-off OnDemand pull. Worked around it: "explicit date" in the
    wizard computes the day/hour/minute delta from now and feeds that
    into the confirmed-working RelText/RelTime mechanism instead.
    RelTime is a byte in CUCM's own schema (max 127) - the coarsest unit
    (Months) x 127 is used for "ALL", which reaches ~10.5 years back;
    that's the real ceiling of what this script can ever reach, in any
    mode, given CUCM's own field type.

    Also confirmed live: `selectLogFiles` has no per-node request
    filter at all - CUCM always searches the whole cluster and returns
    results *grouped by node* in the response (<Node><name>...
    <ServiceList>...). So "pick a node" in this script is a post-filter
    on the response, not something sent to CUCM.

    Other gotchas from the original single-purpose version, still true:
      - Every field in FileSelectionCriteria is REQUIRED by field order
        (XSD sequence, all minOccurs=1) even though several are marked
        nillable in the WSDL. xsi:nil on the ones you don't need throws
        "Error: logcollectionservice -102" - use plain EMPTY elements
        instead (e.g. <SearchStr></SearchStr>), not xsi:nil.
      - TimeZone isn't free text - it must exactly match the string
        CUCM's own getTimeZone operation returns for this server (this
        script calls it automatically).
      - Every response (not just GetOneFile's) comes back as a real
        MIME/XOP multipart envelope.
      - PowerShell unwraps a 1-element array into a bare string on
        return by default - the unary comma (`return , $x`) is used
        throughout to prevent that; a real bug hit building the first
        version of this script.
      - GetOneFile's response carries a genuine binary attachment
        (the gzipped log file itself). Decoding the raw HTTP response
        bytes as UTF-8 text is LOSSY for binary data - any byte that
        isn't valid standalone UTF-8 (common throughout compressed
        data, e.g. gzip's own 0x8B magic byte) gets silently replaced
        with U+FFFD, permanently destroying it. Confirmed real 2026-09-25
        against a real corrupted pull: every attachment came out
        BOM-prefixed and unrecoverably damaged. Fixed by using Latin-1
        (ISO-8859-1) instead of UTF-8 for the byte<->string round-trip -
        Latin-1 maps all 256 byte values 1:1 with zero loss, so the
        existing regex-based MIME splitting keeps working unchanged,
        and the final save now writes raw bytes directly instead of
        going through Set-Content's own encoding (which also added the
        observed BOM). Never swap this back to UTF-8.

.NOTES
    Required settings (env vars, or a .env file - see -EnvFile below):
      CUCM_HOST           - CUCM node hostname or IP (any node in the
                             cluster - queries still return all nodes)
      CUCM_SOAP_USER       - Application User configured for SOAP access
      CUCM_SOAP_PASSWORD   - that user's password

    Self-signed cert handling: CUCM's Tomcat cert is almost never trusted
    by the calling host, so this script disables cert validation for
    these calls. Normal for internal CUCM traffic, don't reuse for
    anything internet-facing.
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "./logs",

    # Plain KEY=VALUE file (CUCM_HOST/CUCM_SOAP_USER/CUCM_SOAP_PASSWORD),
    # loaded instead of real machine environment variables. Defaults to a
    # ".env" file next to this script; silently skipped if it doesn't
    # exist. Real env vars already set in the session win over the file -
    # if a run behaves like it's ignoring your .env edits, check for a
    # stale env var in the current shell first (bit us for real
    # 2026-09-21 chasing an unrelated-looking 401).
    [string]$EnvFile = (Join-Path $PSScriptRoot ".env"),

    # Skip all interactive prompts and go straight with these choices -
    # useful for re-running the same pull without re-answering the wizard.
    [string]$ServiceName,
    [string]$NodeName,        # "" or omitted = ALL nodes
    [ValidateSet("All", "Relative", "Explicit")]
    [string]$RangeMode,
    [string]$RelText = "Days",
    [int]$RelTime = 1,
    [datetime]$ExplicitDate
)

$ErrorActionPreference = "Stop"

# Clear these unconditionally before loading anything - a stale value left
# over from an earlier session in the same PowerShell window silently wins
# over any .env edit otherwise, since env vars used to take priority on
# purpose. Real incident 2026-09-21: burned an hour chasing a fake "CUCM
# permissions" problem that was actually just this. Now this script always
# reflects whatever the .env file (or a fresh prompt) actually says.
Remove-Item Env:\CUCM_HOST, Env:\CUCM_SOAP_USER, Env:\CUCM_SOAP_PASSWORD, Env:\CUCM_SOAP_PASSWORD_ENC -ErrorAction SilentlyContinue

function Import-DotEnv {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    foreach ($line in Get-Content $Path) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) { continue }
        $idx = $trimmed.IndexOf("=")
        if ($idx -lt 1) { continue }
        $key = $trimmed.Substring(0, $idx).Trim()
        $value = $trimmed.Substring($idx + 1).Trim()
        if ($value.Length -ge 2 -and (
            ($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))
        )) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        Set-Item -Path "env:$key" -Value $value
    }
}

function New-DotEnvInteractive {
    <# Prompts for the 3 settings and writes a fresh .env. The password is
    NOT stored in plain text - it's run through ConvertFrom-SecureString,
    which is Windows DPAPI encryption tied to the current user + machine
    (real, reversible encryption, not a hash - a hash can't work here
    since the script has to send the real plaintext password to CUCM's
    Basic Auth, it just can't be recovered from a one-way hash). This is
    "lazy" in the sense that it's a couple of built-in cmdlet calls, not
    a from-scratch crypto implementation - but it's genuine OS-level
    encryption, not just obfuscation. Real caveat: DPAPI-encrypted text
    only decrypts for the same Windows user on the same machine it was
    encrypted on - if this .env gets copied to a different PC or user
    account, the password won't decrypt there and this wizard will need
    to be re-run to generate a new one on that machine. #>
    param([string]$Path)

    Write-Host "No .env found at $Path - let's create one."
    $newHost = Read-Host "CUCM host/IP"
    $newUser = Read-Host "SOAP Application User"
    $securePass = Read-Host "Password (hidden)" -AsSecureString
    $encPass = ConvertFrom-SecureString $securePass

    @(
        "CUCM_HOST=$newHost"
        "CUCM_SOAP_USER=$newUser"
        "CUCM_SOAP_PASSWORD_ENC=$encPass"
    ) | Set-Content -Path $Path
    Write-Host "Saved $Path (password stored DPAPI-encrypted, not plain text)."
}

if (-not (Test-Path $EnvFile)) {
    New-DotEnvInteractive -Path $EnvFile
}
Import-DotEnv -Path $EnvFile

$CucmHost = $env:CUCM_HOST
$SoapUser = $env:CUCM_SOAP_USER

# Support both the new encrypted form and a plain CUCM_SOAP_PASSWORD for
# anyone who typed one in by hand instead of using the wizard above.
if ($env:CUCM_SOAP_PASSWORD_ENC) {
    $secure = ConvertTo-SecureString $env:CUCM_SOAP_PASSWORD_ENC
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $SoapPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
} else {
    $SoapPass = $env:CUCM_SOAP_PASSWORD
}

if (-not $CucmHost) { throw "CUCM_HOST is not set (env var or $EnvFile)." }
if (-not $SoapUser) { throw "CUCM_SOAP_USER is not set (env var or $EnvFile)." }
if (-not $SoapPass) { throw "CUCM_SOAP_PASSWORD / CUCM_SOAP_PASSWORD_ENC is not set (env var or $EnvFile)." }

function Get-CucmServiceUrl {
    <# Each CUCM cluster node runs its own independent Log Collection
    service against its own local filesystem - there's no cross-node
    aggregation. selectLogFiles only ever searches whichever node's
    Tomcat actually receives the request, confirmed live 2026-09-21 (the
    response's own multi-<Node> schema shape misleadingly suggested
    otherwise). So "pull from every node" means literally connecting to
    every node's own hostname in turn, not one call to $CucmHost. #>
    param([string]$TargetHost)
    return "https://$($TargetHost):8443/logcollectionservice2/services/LogCollectionPortTypeService"
}

$ns = "http://schemas.cisco.com/ast/soap"

$pair = "$($SoapUser):$($SoapPass)"
$basicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
$authHeader = @{ Authorization = "Basic $basicAuth" }

if ($PSVersionTable.PSVersion.Major -ge 7) {
    $skipCert = @{ SkipCertificateCheck = $true }
} else {
    add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) {
        return true;
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    $skipCert = @{}
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Lossless byte<->string codec, used ANYWHERE a raw HTTP response might
# carry binary data (every Log Collection response is a MIME/XOP envelope,
# and GetOneFile's carries a real binary attachment). UTF-8 is lossy for
# arbitrary binary - any byte that isn't valid standalone UTF-8 gets
# silently replaced with U+FFFD, permanently destroying it (confirmed
# real 2026-09-25: every GetOneFile pull came out BOM-prefixed and
# unrecoverably corrupted before this fix). Latin-1 (ISO-8859-1) maps all
# 256 byte values 1:1 with zero loss, so the existing regex-based MIME
# splitting below still works unchanged, and the bytes can be perfectly
# reconstructed afterward with GetBytes() on the same encoding. Never use
# UTF8/[System.Text.Encoding]::UTF8 for this round-trip.
$binarySafeEncoding = [System.Text.Encoding]::GetEncoding(28591)

function Get-MimeParts {
    param([string]$Raw)
    $boundaryMatch = [regex]::Match($Raw, '--(MIMEBoundary\S+)')
    if (-not $boundaryMatch.Success) {
        return , @($Raw)
    }
    $boundary = $boundaryMatch.Groups[1].Value
    $rawParts = $Raw -split [regex]::Escape("--$boundary")
    $bodies = @()
    foreach ($p in $rawParts) {
        if ($p.Trim().Length -eq 0 -or $p.Trim() -eq "--") { continue }
        $split = $p -split "`r`n`r`n", 2
        if ($split.Count -eq 2) {
            $bodies += $split[1]
        } else {
            $bodies += $p
        }
    }
    return , $bodies
}

function Invoke-CucmSoap {
    param(
        [string]$TargetHost,
        [string]$SoapAction,
        [string]$Body
    )
    $serviceUrl = Get-CucmServiceUrl -TargetHost $TargetHost
    $headers = $authHeader.Clone()
    $headers["SOAPAction"] = "`"$SoapAction`""

    Write-Debug "=== Request: $SoapAction ($TargetHost) ==="
    Write-Debug $Body

    # Invoke-WebRequest has its own built-in -Debug tracing (separate from
    # our Write-Debug calls) that dumps full request/response headers -
    # including the Basic Auth header, which is trivially base64-decodable
    # back to the real username:password. Suppressed just for this one
    # call so a shared debug transcript can't leak credentials; our own
    # Write-Debug calls above/below (body only, no headers) still fire
    # normally since $DebugPreference is restored right after.
    $savedDebugPreference = $DebugPreference
    $DebugPreference = "SilentlyContinue"
    try {
        $resp = Invoke-WebRequest -Uri $serviceUrl -Method Post -Headers $headers `
            -ContentType "text/xml; charset=utf-8" -Body $Body @skipCert
    } catch {
        $webResp = $_.Exception.Response
        Write-Host "[ERROR] $SoapAction failed: $($_.Exception.Message)"
        if ($webResp) {
            Write-Host "[ERROR] HTTP Status: $([int]$webResp.StatusCode) $($webResp.StatusCode)"
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                Write-Host "[ERROR] Response body: $($_.ErrorDetails.Message)"
            }
        }
        throw
    } finally {
        $DebugPreference = $savedDebugPreference
    }

    if ($resp.Content -is [byte[]]) {
        $raw = $binarySafeEncoding.GetString($resp.Content)
    } else {
        $raw = $resp.Content
    }
    $envelope = (Get-MimeParts -Raw $raw)[0]
    Write-Debug "=== Response: $SoapAction ==="
    Write-Debug $envelope
    return $envelope
}

function Get-CucmTimeZoneString {
    param([string]$TargetHost)
    $body = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:log="$ns">
  <soapenv:Body>
    <log:LocalHost>$TargetHost</log:LocalHost>
  </soapenv:Body>
</soapenv:Envelope>
"@
    $raw = Invoke-CucmSoap -TargetHost $TargetHost -SoapAction "getTimeZone" -Body $body
    $xml = [xml]$raw
    $inner = [xml]$xml.Envelope.Body.TimeZone.'#text'
    return $inner.TimeZone.LocalTimeZone.value
}

function Get-CucmClusterCatalog {
    <# Discovery call - listNodeServiceLogs with NO NodeName restriction.
    Unlike selectLogFiles (which only ever sees whichever node you're
    connected to - see Get-CucmServiceUrl), this call genuinely returns
    every node in the cluster regardless of which node you connect to -
    confirmed live 2026-09-21 against a real multi-node prod cluster.
    Only needs to be called once, against any single node. #>
    param([string]$TargetHost)
    $body = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:log="$ns">
  <soapenv:Body>
    <log:listNodeServiceLogs>
      <log:ListRequest></log:ListRequest>
    </log:listNodeServiceLogs>
  </soapenv:Body>
</soapenv:Envelope>
"@
    $raw = Invoke-CucmSoap -TargetHost $TargetHost -SoapAction "listNodeServiceLogs" -Body $body
    $xml = [xml]$raw
    $ns_mgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns_mgr.AddNamespace("ns1", $ns)
    $nodes = $xml.SelectNodes("//ns1:listNodeServiceLogsReturn", $ns_mgr)
    $result = @()
    foreach ($n in $nodes) {
        $nodeName = $n.SelectSingleNode("ns1:name", $ns_mgr).InnerText
        $services = $n.SelectNodes("ns1:ServiceLog/ns1:item", $ns_mgr) | ForEach-Object { $_.InnerText }
        $result += [PSCustomObject]@{ NodeName = $nodeName; Services = $services }
    }
    return , $result
}

function Get-CucmLogFileList {
    <# selectLogFiles only ever searches $TargetHost's own node - see
    Get-CucmServiceUrl's comment for why. Tags every result with
    $TargetHost directly rather than trusting the response's own <Node>
    <name> field, which is empty on some systems even for a genuine
    match (confirmed on the lab box) - we already know which node we
    asked, no need to trust CUCM to tell us back correctly. #>
    param(
        [string]$TargetHost,
        [string]$ServiceName,
        [string]$RelText,
        [int]$RelTime
    )
    $tz = Get-CucmTimeZoneString -TargetHost $TargetHost

    $body = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:log="$ns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Body>
    <log:selectLogFiles>
      <log:FileSelectionCriteria>
        <log:ServiceLogs>
          <log:item>$ServiceName</log:item>
        </log:ServiceLogs>
        <log:SystemLogs></log:SystemLogs>
        <log:SearchStr></log:SearchStr>
        <log:Frequency>OnDemand</log:Frequency>
        <log:JobType>DownloadtoClient</log:JobType>
        <log:ToDate></log:ToDate>
        <log:FromDate></log:FromDate>
        <log:TimeZone>$tz</log:TimeZone>
        <log:RelText>$RelText</log:RelText>
        <log:RelTime>$RelTime</log:RelTime>
        <log:Port>0</log:Port>
        <log:IPAddress></log:IPAddress>
        <log:UserName></log:UserName>
        <log:Password></log:Password>
        <log:ZipInfo>false</log:ZipInfo>
        <log:RemoteFolder></log:RemoteFolder>
      </log:FileSelectionCriteria>
    </log:selectLogFiles>
  </soapenv:Body>
</soapenv:Envelope>
"@
    $raw = Invoke-CucmSoap -TargetHost $TargetHost -SoapAction "selectLogFiles" -Body $body
    $xml = [xml]$raw
    $ns_mgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns_mgr.AddNamespace("ns1", $ns)

    $result = @()
    $files = $xml.SelectNodes("//ns1:SchemaFileSelectionResult/ns1:Node//ns1:File", $ns_mgr)
    foreach ($f in $files) {
        $result += [PSCustomObject]@{
            NodeName     = $TargetHost
            Name         = $f.SelectSingleNode("ns1:name", $ns_mgr).InnerText
            AbsolutePath = $f.SelectSingleNode("ns1:absolutepath", $ns_mgr).InnerText
            SizeBytes    = $f.SelectSingleNode("ns1:filesize", $ns_mgr).InnerText
            Modified     = $f.SelectSingleNode("ns1:modifiedDate", $ns_mgr).InnerText
        }
    }
    return , $result
}

function Get-CucmLogFileContent {
    param(
        [string]$TargetHost,
        [string]$AbsolutePath
    )
    $serviceUrl = Get-CucmServiceUrl -TargetHost $TargetHost

    $body = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:log="$ns">
  <soapenv:Body>
    <log:FileName>$AbsolutePath</log:FileName>
  </soapenv:Body>
</soapenv:Envelope>
"@
    $headers = $authHeader.Clone()
    $headers["SOAPAction"] = "`"GetOneFile`""
    Write-Debug "=== Request: GetOneFile ($TargetHost, $AbsolutePath) ==="
    # Same credential-leak guard as Invoke-CucmSoap - see the comment there.
    $savedDebugPreference = $DebugPreference
    $DebugPreference = "SilentlyContinue"
    try {
        $resp = Invoke-WebRequest -Uri $serviceUrl -Method Post -Headers $headers `
            -ContentType "text/xml; charset=utf-8" -Body $body @skipCert
    } finally {
        $DebugPreference = $savedDebugPreference
    }
    if ($resp.Content -is [byte[]]) {
        $raw = $binarySafeEncoding.GetString($resp.Content)
    } else {
        $raw = $resp.Content
    }

    $parts = Get-MimeParts -Raw $raw
    if ($parts.Count -lt 2) {
        Write-Warning "No attachment part found for $AbsolutePath - returning SOAP envelope instead."
        return $parts[0]
    }
    return $parts[1]
}

function Invoke-CucmNodeDownload {
    <# Fetches every file for one node, sequentially, from within its own
    runspace - one of these runs concurrently per node (see the
    RunspacePool setup below). Deliberately self-contained: a runspace
    doesn't inherit the caller's function/variable scope, so everything
    it needs (GetOneFile call, MIME split, binary-safe save) is
    reimplemented here rather than calling back into the main script's
    Get-CucmLogFileContent/Get-MimeParts. Runspaces DO share the same
    process as the caller (unlike Start-Job, which spawns a whole
    separate PowerShell.exe), so the self-signed-cert trust already set
    up once via ServicePointManager in the main script body applies here
    too - no need to redo that per node. #>
    param($TargetHost, $NodeFiles, $AuthHeader, $SkipCert, $NodeDir, $BinaryEncoding)

    function Get-MimePartsLocal {
        param([string]$Raw)
        $boundaryMatch = [regex]::Match($Raw, '--(MIMEBoundary\S+)')
        if (-not $boundaryMatch.Success) { return , @($Raw) }
        $boundary = $boundaryMatch.Groups[1].Value
        $rawParts = $Raw -split [regex]::Escape("--$boundary")
        $bodies = @()
        foreach ($p in $rawParts) {
            if ($p.Trim().Length -eq 0 -or $p.Trim() -eq "--") { continue }
            $split = $p -split "`r`n`r`n", 2
            if ($split.Count -eq 2) { $bodies += $split[1] } else { $bodies += $p }
        }
        return , $bodies
    }

    $serviceUrl = "https://$($TargetHost):8443/logcollectionservice2/services/LogCollectionPortTypeService"
    $results = @()

    foreach ($f in $NodeFiles) {
        try {
            $body = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:log="http://schemas.cisco.com/ast/soap">
  <soapenv:Body>
    <log:FileName>$($f.AbsolutePath)</log:FileName>
  </soapenv:Body>
</soapenv:Envelope>
"@
            $headers = $AuthHeader.Clone()
            $headers["SOAPAction"] = '"GetOneFile"'
            $resp = Invoke-WebRequest -Uri $serviceUrl -Method Post -Headers $headers `
                -ContentType "text/xml; charset=utf-8" -Body $body @SkipCert

            $raw = if ($resp.Content -is [byte[]]) { $BinaryEncoding.GetString($resp.Content) } else { $resp.Content }
            $parts = Get-MimePartsLocal -Raw $raw
            $content = if ($parts.Count -ge 2) { $parts[1] } else { $parts[0] }

            $outPath = Join-Path $NodeDir $f.Name
            [System.IO.File]::WriteAllBytes($outPath, $BinaryEncoding.GetBytes($content))
            $results += "OK: $($f.Name)"
        } catch {
            $results += "FAIL: $($f.Name) - $($_.Exception.Message)"
        }
    }
    return , $results
}

# ============ Interactive wizard (skipped for any param already supplied) ============

Write-Host "Discovering services/nodes on $CucmHost ..."
$catalog = Get-CucmClusterCatalog -TargetHost $CucmHost
$allNodeNames = $catalog | ForEach-Object { $_.NodeName }
$allServiceNames = $catalog | ForEach-Object { $_.Services } | Select-Object -Unique | Sort-Object

if (-not $ServiceName) {
    Write-Host "`nAvailable services (showing ones with 'Extension Mobility' or 'CDR' or 'AXL' highlighted first):"
    $highlighted = $allServiceNames | Where-Object { $_ -match "Extension Mobility|CDR|AXL" }
    $rest = $allServiceNames | Where-Object { $_ -notin $highlighted }
    $ordered = @($highlighted) + @($rest)
    for ($i = 0; $i -lt $ordered.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f $i, $ordered[$i])
    }
    $choice = Read-Host "`nPick a service by number (default: Cisco Extension Mobility)"
    if ([string]::IsNullOrWhiteSpace($choice)) {
        $ServiceName = "Cisco Extension Mobility"
    } else {
        $ServiceName = $ordered[[int]$choice]
    }
}

if (-not $PSBoundParameters.ContainsKey('NodeName')) {
    Write-Host "`nAvailable nodes: $($allNodeNames -join ', ')"
    $nodeChoice = Read-Host "Pull from a specific node, or leave blank for ALL nodes"
    $NodeName = $nodeChoice.Trim()
}

if (-not $RangeMode) {
    Write-Host "`nHow much history do you want?"
    Write-Host "  [1] ALL archived logs for this service (as far back as CUCM's RelTime field can reach - up to ~10.5 years)"
    Write-Host "  [2] Relative window (last N days/hours/minutes)"
    Write-Host "  [3] Explicit start date (converted to an equivalent relative window under the hood - see script notes for why)"
    $rangeChoice = Read-Host "Pick 1, 2, or 3 (default: 2)"
    switch ($rangeChoice) {
        "1" { $RangeMode = "All" }
        "3" { $RangeMode = "Explicit" }
        default { $RangeMode = "Relative" }
    }
}

switch ($RangeMode) {
    "All" {
        $RelText = "Months"
        $RelTime = 127   # CUCM's RelTime field is a byte (max 127) - this is the real ceiling, not a chosen default.
    }
    "Relative" {
        if (-not $PSBoundParameters.ContainsKey('RelText') -or -not $PSBoundParameters.ContainsKey('RelTime')) {
            $unit = Read-Host "Unit - Minutes/Hours/Days/Weeks/Months (default: Days)"
            if ([string]::IsNullOrWhiteSpace($unit)) { $unit = "Days" }
            $RelText = $unit
            $amount = Read-Host "How many $unit back? (default: 1)"
            if ([string]::IsNullOrWhiteSpace($amount)) { $amount = 1 }
            $RelTime = [int]$amount
        }
        if ($RelTime -gt 127) {
            Write-Warning "RelTime capped at 127 by CUCM's own schema (byte field) - clamping down from $RelTime."
            $RelTime = 127
        }
    }
    "Explicit" {
        if (-not $PSBoundParameters.ContainsKey('ExplicitDate')) {
            $dateStr = Read-Host "Start date (e.g. 2026-08-01) - logs from then until now"
            $ExplicitDate = [datetime]$dateStr
        }
        $span = (Get-Date) - $ExplicitDate
        $totalDays = [Math]::Ceiling($span.TotalDays)
        if ($totalDays -le 127) {
            $RelText = "Days"; $RelTime = $totalDays
        } elseif ([Math]::Ceiling($totalDays / 7) -le 127) {
            $RelText = "Weeks"; $RelTime = [Math]::Ceiling($totalDays / 7)
        } elseif ([Math]::Ceiling($totalDays / 30) -le 127) {
            $RelText = "Months"; $RelTime = [Math]::Ceiling($totalDays / 30)
        } else {
            Write-Warning "That date is further back than CUCM's RelTime field can reach (~10.5 years via Months) - using the max instead."
            $RelText = "Months"; $RelTime = 127
        }
        Write-Host "Converted '$ExplicitDate' to an equivalent window: last $RelTime $RelText"
    }
}

# --- main ---
if (-not $PSBoundParameters.ContainsKey('OutputDir')) {
    $OutputDir = "./logs-$(Get-Date -Format 'yyyyMMdd-HHmm')"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$targetNodes = if ($NodeName) { , @($NodeName) } else { $allNodeNames }
Write-Debug "Query parameters: ServiceName='$ServiceName' Nodes=$($targetNodes -join ', ') RelText='$RelText' RelTime=$RelTime"
Write-Host "`nQuerying $ServiceName logs, last $RelTime $RelText, across $($targetNodes.Count) node(s): $($targetNodes -join ', ') ..."

# selectLogFiles only ever sees the node it's connected to (see
# Get-CucmServiceUrl) - "all nodes" means a separate call per node, not
# one call that happens to cover everything.
$files = @()
foreach ($node in $targetNodes) {
    Write-Host "  querying $node ..."
    try {
        $files += Get-CucmLogFileList -TargetHost $node -ServiceName $ServiceName -RelText $RelText -RelTime $RelTime
    } catch {
        Write-Warning "  Failed to query $node - $($_.Exception.Message)"
    }
}

if (-not $files -or $files.Count -eq 0) {
    Write-Warning "No files returned for '$ServiceName' in that window$(if ($NodeName) { " on node $NodeName" })."
    return
}

function ConvertFrom-CucmModifiedDate {
    <# CUCM's modifiedDate is a `date`-command-style string with a US
    timezone abbreviation ("Tue Sep 15 08:18:10 CDT 2026") - .NET's
    [datetime] cast doesn't recognize "CDT"/"CST" and throws. Strip the
    abbreviation and parse the rest with an explicit format; falls back
    to $null (skipped by callers) rather than crashing the whole run over
    a display-only summary line. #>
    param([string]$Value)
    try {
        $stripped = $Value -replace '\s+[A-Z]{2,4}\s+(\d{4})$', ' $1'
        return [datetime]::ParseExact($stripped, "ddd MMM dd HH:mm:ss yyyy", $null)
    } catch {
        return $null
    }
}

$totalBytes = ($files | ForEach-Object { [long]$_.SizeBytes } | Measure-Object -Sum).Sum
$totalMB = [Math]::Round($totalBytes / 1MB, 1)
$parsedDates = $files | ForEach-Object { ConvertFrom-CucmModifiedDate $_.Modified } | Where-Object { $_ }
$earliest = if ($parsedDates) { ($parsedDates | Sort-Object | Select-Object -First 1) } else { "(unknown)" }
$latest = if ($parsedDates) { ($parsedDates | Sort-Object | Select-Object -Last 1) } else { "(unknown)" }

Write-Host "`nFound $($files.Count) file(s), ~$totalMB MB total, spanning $earliest to $latest :"
$files | ForEach-Object { Write-Host "  [$($_.NodeName)] $($_.Name) ($($_.SizeBytes) bytes, modified $($_.Modified))" }

Write-Host "`n$($files.Count) file(s) / ~$totalMB MB - you asked for the last $RelTime $RelText, but the actual span above is what CUCM is about to hand back."
$confirm = Read-Host "Proceed with download? [y/N]"
if ($confirm -notmatch '^[Yy]') {
    Write-Host "Aborted - nothing downloaded."
    return
}

# One concurrent stream per node - each node's Log Collection service is
# independent, so this is safe to parallelize across nodes. Files within
# a single node are still fetched sequentially (one runspace per node,
# not per file) - deliberate, since hammering one node's Tomcat with many
# concurrent GetOneFile calls is more likely to cause problems than help.
$filesByNode = $files | Group-Object NodeName

# Runspaces in the pool don't inherit function definitions from this
# script's scope automatically (only variables/state can be shared, and
# only if explicitly passed) - share Invoke-CucmNodeDownload explicitly
# via InitialSessionState so AddCommand("Invoke-CucmNodeDownload") below
# actually resolves inside each runspace. Has to be built BEFORE creating
# the pool and passed into the constructor - the plain
# CreateRunspacePool(min, max) overload leaves .InitialSessionState null,
# it's not something you can populate after the fact.
$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$funcEntry = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry(
    "Invoke-CucmNodeDownload", ${function:Invoke-CucmNodeDownload})
$iss.Commands.Add($funcEntry)

$pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $filesByNode.Count), $iss, $Host)
$pool.Open()

Write-Host "`nDownloading from $($filesByNode.Count) node(s) in parallel, one stream per node ..."
$running = @()
foreach ($group in $filesByNode) {
    $nodeDir = Join-Path $OutputDir $group.Name
    New-Item -ItemType Directory -Path $nodeDir -Force | Out-Null

    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddCommand("Invoke-CucmNodeDownload").
        AddParameter("TargetHost", $group.Name).
        AddParameter("NodeFiles", $group.Group).
        AddParameter("AuthHeader", $authHeader).
        AddParameter("SkipCert", $skipCert).
        AddParameter("NodeDir", $nodeDir).
        AddParameter("BinaryEncoding", $binarySafeEncoding)
    $running += [PSCustomObject]@{ Node = $group.Name; Pipe = $ps; Handle = $ps.BeginInvoke() }
}

foreach ($r in $running) {
    $out = $r.Pipe.EndInvoke($r.Handle)
    Write-Host "`n--- $($r.Node) ---"
    $out | ForEach-Object { Write-Host "  $_" }
    $r.Pipe.Dispose()
}
$pool.Close()
$pool.Dispose()
