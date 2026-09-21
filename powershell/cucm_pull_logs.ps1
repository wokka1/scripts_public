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

$ServiceUrl = "https://$($CucmHost):8443/logcollectionservice2/services/LogCollectionPortTypeService"
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
        [string]$SoapAction,
        [string]$Body
    )
    $headers = $authHeader.Clone()
    $headers["SOAPAction"] = "`"$SoapAction`""

    Write-Debug "=== Request: $SoapAction ==="
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
        $resp = Invoke-WebRequest -Uri $ServiceUrl -Method Post -Headers $headers `
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
        $raw = [System.Text.Encoding]::UTF8.GetString($resp.Content)
    } else {
        $raw = $resp.Content
    }
    $envelope = (Get-MimeParts -Raw $raw)[0]
    Write-Debug "=== Response: $SoapAction ==="
    Write-Debug $envelope
    return $envelope
}

function Get-CucmTimeZoneString {
    $body = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:log="$ns">
  <soapenv:Body>
    <log:LocalHost>$CucmHost</log:LocalHost>
  </soapenv:Body>
</soapenv:Envelope>
"@
    $raw = Invoke-CucmSoap -SoapAction "getTimeZone" -Body $body
    $xml = [xml]$raw
    $inner = [xml]$xml.Envelope.Body.TimeZone.'#text'
    return $inner.TimeZone.LocalTimeZone.value
}

function Get-CucmClusterCatalog {
    <# Discovery call - listNodeServiceLogs with NO NodeName restriction.
    Returns one object per node found: Node name + the real ServiceLog
    names available there. Confirmed live: an empty <ListRequest></...>
    still returns valid data (this lab cluster only has one node, so
    multi-node behavior is inferred from the WSDL's unbounded return
    type, not independently confirmed). #>
    $body = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:log="$ns">
  <soapenv:Body>
    <log:listNodeServiceLogs>
      <log:ListRequest></log:ListRequest>
    </log:listNodeServiceLogs>
  </soapenv:Body>
</soapenv:Envelope>
"@
    $raw = Invoke-CucmSoap -SoapAction "listNodeServiceLogs" -Body $body
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
    <# selectLogFiles - no per-node request filter exists in this API;
    CUCM always searches the whole cluster and groups results by node in
    the response. Returns every matching file across every node, each
    tagged with which node it actually came from - filter by NodeName
    afterward if the wizard asked for a specific one. #>
    param(
        [string]$ServiceName,
        [string]$RelText,
        [int]$RelTime
    )
    $tz = Get-CucmTimeZoneString

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
    $raw = Invoke-CucmSoap -SoapAction "selectLogFiles" -Body $body
    $xml = [xml]$raw
    $ns_mgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns_mgr.AddNamespace("ns1", $ns)

    $result = @()
    $nodeNodes = $xml.SelectNodes("//ns1:SchemaFileSelectionResult/ns1:Node", $ns_mgr)
    foreach ($node in $nodeNodes) {
        $thisNodeName = $node.SelectSingleNode("ns1:name", $ns_mgr).InnerText
        $files = $node.SelectNodes(".//ns1:File", $ns_mgr)
        foreach ($f in $files) {
            $result += [PSCustomObject]@{
                NodeName     = $thisNodeName
                Name         = $f.SelectSingleNode("ns1:name", $ns_mgr).InnerText
                AbsolutePath = $f.SelectSingleNode("ns1:absolutepath", $ns_mgr).InnerText
                SizeBytes    = $f.SelectSingleNode("ns1:filesize", $ns_mgr).InnerText
                Modified     = $f.SelectSingleNode("ns1:modifiedDate", $ns_mgr).InnerText
            }
        }
    }
    return , $result
}

function Get-CucmLogFileContent {
    param([string]$AbsolutePath)

    $body = @"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:log="$ns">
  <soapenv:Body>
    <log:FileName>$AbsolutePath</log:FileName>
  </soapenv:Body>
</soapenv:Envelope>
"@
    $headers = $authHeader.Clone()
    $headers["SOAPAction"] = "`"GetOneFile`""
    Write-Debug "=== Request: GetOneFile ($AbsolutePath) ==="
    # Same credential-leak guard as Invoke-CucmSoap - see the comment there.
    $savedDebugPreference = $DebugPreference
    $DebugPreference = "SilentlyContinue"
    try {
        $resp = Invoke-WebRequest -Uri $ServiceUrl -Method Post -Headers $headers `
            -ContentType "text/xml; charset=utf-8" -Body $body @skipCert
    } finally {
        $DebugPreference = $savedDebugPreference
    }
    if ($resp.Content -is [byte[]]) {
        $raw = [System.Text.Encoding]::UTF8.GetString($resp.Content)
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

# ============ Interactive wizard (skipped for any param already supplied) ============

Write-Host "Discovering services/nodes on $CucmHost ..."
$catalog = Get-CucmClusterCatalog
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
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Write-Debug "Query parameters: ServiceName='$ServiceName' NodeName='$NodeName' RelText='$RelText' RelTime=$RelTime"
Write-Host "`nQuerying $ServiceName logs, last $RelTime $RelText ..."
$files = Get-CucmLogFileList -ServiceName $ServiceName -RelText $RelText -RelTime $RelTime

if ($NodeName) {
    $blankNodeCount = ($files | Where-Object { [string]::IsNullOrWhiteSpace($_.NodeName) }).Count
    if ($blankNodeCount -gt 0) {
        Write-Warning "$blankNodeCount of $($files.Count) file(s) came back with NO node name from CUCM (confirmed happens on some systems - see script notes). Filtering to '$NodeName' will silently drop those - if you get 0 results below, this is almost certainly why, not a real 'wrong node' answer."
    }
    $files = $files | Where-Object { $_.NodeName -eq $NodeName }
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

foreach ($f in $files) {
    Write-Host "`nFetching $($f.Name) from $($f.NodeName) ..."
    try {
        $content = Get-CucmLogFileContent -AbsolutePath $f.AbsolutePath
        $nodeDir = Join-Path $OutputDir $f.NodeName
        New-Item -ItemType Directory -Path $nodeDir -Force | Out-Null
        $outPath = Join-Path $nodeDir $f.Name
        Set-Content -Path $outPath -Value $content -Encoding UTF8 -NoNewline
        Write-Host "  -> saved to $outPath"
    } catch {
        Write-Warning "  Failed to fetch $($f.Name) - $($_.Exception.Message)"
    }
}
