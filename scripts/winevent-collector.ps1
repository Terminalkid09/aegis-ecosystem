<#
.SYNOPSIS
  Collector Windows Event Log -> Aegis SIEM (/api/v1/ingest).

.DESCRIPTION
  Legge i canali di Windows con `Get-WinEvent` (API documentata e disponibile
  su ogni Windows: nessun driver, nessuna firma, nessuna installazione) e li
  spedisce all'endpoint di ingestione del brain come NDJSON, nel formato che il
  parser `windows_event` riconosce.

  Perche' cosi' e non un driver ETW: un consumer ETW in user-mode non richiede
  certificati, e' esattamente il livello di telemetria che serve a un SIEM
  (osservare, correlare, rilevare). La prevenzione inline invece richiede
  firme kernel: fuori scope, dichiarato in docs/V4_SCOPE.md.

  Stato incrementale: un file di bookmark per canale con l'ultimo RecordId
  inviato. `-Once` = una passata, `-Follow` = polling continuo (default 15s).

.EXAMPLE
  # Una passata, senza spedire (vedi cosa produrrebbe)
  .\winevent-collector.ps1 -Once -DryRun

.EXAMPLE
  # Invio continuo dei canali Security e System
  .\winevent-collector.ps1 -Follow -Channels Security,System `
      -BaseUrl http://127.0.0.1:8000 -ApiKey $env:AEGIS_API_KEY
#>
[CmdletBinding()]
param(
    [string[]] $Channels = @('Security', 'System', 'Application'),
    [string]   $SourceName = 'win-local',
    [string]   $BaseUrl = 'http://127.0.0.1:8000',
    [string]   $ApiKey = $env:AEGIS_API_KEY,
    [int]      $MaxEvents = 200,
    [int]      $IntervalSeconds = 15,
    [string]   $StateFile = "$env:TEMP\aegis-winevent-state.json",
    [int]      $LookbackHours = 24,
    # Windows Firewall log: e' l'unico modo di avere telemetria di rete reale
    # su Windows senza installare Zeek/Suricata. Va abilitato in
    # wf.msc -> Proprieta' profilo -> Log -> "Registra connessioni ignorate".
    [switch]   $IncludeFirewallLog,
    [string]   $FirewallLogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log",
    [int]      $FirewallMaxLines = 500,
    [switch]   $Once,
    [switch]   $Follow,
    [switch]   $DryRun,
    [switch]   $InsecureSkipTlsCheck,
    # Applica una maschera ai campi che possono contenere dati personali prima
    # dell'invio (il brain rifa' la redazione, questo evita di farli uscire).
    [switch]   $Redact
)

$ErrorActionPreference = 'Stop'

# EventID che interessano a un SOC: autenticazione, privilegi, persistenza,
# esecuzione, difesa. Il resto e' rumore per il volume che porta.
$InterestingIds = @(
    104, 1102,                     # log svuotato
    4624, 4625, 4634, 4647, 4648, 4672,  # logon / privilegi
    4688, 4689,                    # processi
    4697, 4698, 4699, 4702,        # servizi e scheduled task
    4720, 4722, 4724, 4726, 4728, 4732, 4756,  # account e gruppi
    7045,                          # service install (System)
    5156, 5158                     # filtro rete Windows
)

function Convert-EventToRecord {
    param(
        [object] $Event,
        [string] $Channel,
        [switch] $Mask
    )

    # EventData -> hashtable {nome -> valore}. Il parser lato brain usa sia
    # `EventData.TargetUserName` sia il nome piatto, quindi mappiamo entrambi.
    $data = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($node in $xml.Event.EventData.Data) {
            if ($node.Name) { $data[$node.Name] = [string]$node.'#text' }
        }
    } catch { }

    $record = [ordered]@{
        Id          = $Event.Id
        Level       = $Event.Level
        Provider    = $Event.ProviderName
        Channel     = $Channel
        Computer    = $Event.MachineName
        TimeCreated = $Event.TimeCreated.ToUniversalTime().ToString('o')
        RecordId    = $Event.RecordId
        Message     = ($Event.Message -replace '\s+', ' ')
        EventData   = $data
    }

    if ($Mask) {
        # Maschera PII: nomi utente, domini e IP restano correlabili ma non
        # identificano (hash stabile), come fa la redazione lato brain.
        foreach ($field in @('TargetUserName', 'SubjectUserName', 'IpAddress', 'WorkstationName')) {
            if ($record.EventData.ContainsKey($field) -and $record.EventData[$field]) {
                $sha = [System.Security.Cryptography.SHA256]::Create()
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($record.EventData[$field])
                $hash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
                $record.EventData[$field] = "sha256:$($hash.Substring(0,16))"
            }
        }
    }

    return $record
}

function Read-State {
    if (Test-Path $StateFile) {
        try { return Get-Content $StateFile -Raw | ConvertFrom-Json } catch { }
    }
    return [pscustomobject]@{}
}

function Save-State {
    param([object] $State)
    $dir = Split-Path -Parent $StateFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $State | ConvertTo-Json -Depth 4 | Set-Content -Path $StateFile -Encoding UTF8
}

function Send-Batch {
    param([object[]] $Records, [string] $Parser = 'windows_event', [string] $Source = $SourceName)

    if (-not $Records -or $Records.Count -eq 0) { return $true }

    $ndjson = ($Records | ForEach-Object {
        if ($_ -is [string]) { $_ } else { $_ | ConvertTo-Json -Compress -Depth 6 }
    }) -join "`n"
    $uri = "$BaseUrl/api/v1/ingest/$Source" + "?parser=$Parser"

    # Il body va spedito come stringa JSON (NDJSON fra virgolette): inviare
    # NDJSON grezzo con Content-Type application/json produce un 422 di parsing,
    # perche' il body non e' un singolo documento JSON valido.
    $body = ConvertTo-Json -InputObject $ndjson -Compress

    if ($DryRun) {
        Write-Host "[dry-run] $($Records.Count) eventi pronti per $uri" -ForegroundColor DarkGray
        Write-Host $ndjson
        return $true
    }

    $headers = @{}
    if ($ApiKey) { $headers['X-Api-Key'] = $ApiKey }
    $params = @{
        Uri         = $uri
        Method      = 'POST'
        Body        = $body
        ContentType = 'application/json'
        Headers     = $headers
        TimeoutSec  = 30
    }
    if ($InsecureSkipTlsCheck) { $params['SkipCertificateCheck'] = $true }

    try {
        $response = Invoke-RestMethod @params
        Write-Host ("[ok] {0} eventi -> stored={1} alerts={2} sigma={3} corr={4}" -f `
            $Records.Count, $response.stored, $response.alerts, $response.sigma, $response.correlation) `
            -ForegroundColor Green
        return $true
    } catch {
        $detail = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }
        Write-Warning "invio fallito: $detail"
        return $false
    }
}

function Get-RecordsForChannel {
    param([string] $Channel, [object] $State)

    $lastId = 0
    if ($State.PSObject.Properties.Name -contains $Channel) { $lastId = [int64]$State.$Channel }

    $filter = @{
        LogName   = $Channel
        Id        = $InterestingIds
        StartTime = (Get-Date).AddHours(-$LookbackHours)
    }
    try {
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        # Canale assente o senza permessi (es. Security senza admin): non e' un
        # errore fatale, si continua con gli altri canali.
        Write-Verbose "canale $Channel non leggibile: $($_.Exception.Message)"
        return @()
    }
    if (-not $events) { return @() }

    $fresh = $events | Where-Object { $_.RecordId -gt $lastId } | Sort-Object RecordId
    if (-not $fresh) { return @() }

    $max = ($fresh | Measure-Object -Property RecordId -Maximum).Maximum
    $State | Add-Member -NotePropertyName $Channel -NotePropertyValue $max -Force

    return @($fresh | ForEach-Object { Convert-EventToRecord -Event $_ -Channel $Channel -Mask:$Redact })
}

function Get-FirewallRecords {
    param([object] $State)

    if (-not (Test-Path $FirewallLogPath)) {
        Write-Verbose "firewall log assente: $FirewallLogPath"
        return @()
    }

    $lines = @(Get-Content -Path $FirewallLogPath -ErrorAction SilentlyContinue)
    if ($lines.Count -eq 0) { return @() }

    $sentKey = 'FirewallLines'
    $already = 0
    if ($State.PSObject.Properties.Name -contains $sentKey) { $already = [int]$State.$sentKey }
    # Log ruotato o troncato: si riparte da zero invece di saltare righe nuove.
    if ($already -gt $lines.Count) { $already = 0 }

    $fresh = $lines[$already..($lines.Count - 1)]
    $State | Add-Member -NotePropertyName $sentKey -NotePropertyValue $lines.Count -Force

    $interesting = @($fresh | Where-Object { $_ -and $_ -notmatch '^#' -and $_ -match '(DROP|ALLOW)' })
    if ($interesting.Count -gt $FirewallMaxLines) {
        $interesting = $interesting[($interesting.Count - $FirewallMaxLines)..($interesting.Count - 1)]
    }
    return $interesting
}

function Invoke-Sweep {
    param([object] $State)
    $total = 0
    foreach ($channel in $Channels) {
        $records = Get-RecordsForChannel -Channel $channel -State $State
        if ($records.Count -gt 0) {
            if (Send-Batch -Records $records) { $total += $records.Count }
        }
    }
    if ($IncludeFirewallLog) {
        $fw = Get-FirewallRecords -State $State
        if ($fw.Count -gt 0) {
            if (Send-Batch -Records $fw -Parser 'pfirewall' -Source "$SourceName-fw") {
                $total += $fw.Count
            }
        }
    }
    Save-State -State $State
    return $total
}

if (-not $ApiKey -and -not $DryRun) {
    Write-Warning "Nessuna ApiKey: l'ingestione rispondera' 401. Usa -ApiKey oppure -DryRun."
}

$state = Read-State
Write-Host "Aegis Windows Event Collector -> $BaseUrl (sorgente: $SourceName)" -ForegroundColor Cyan
Write-Host "Canali: $($Channels -join ', ') | lookback ${LookbackHours}h" -ForegroundColor Cyan
if ($IncludeFirewallLog) {
    Write-Host "Firewall log: $FirewallLogPath" -ForegroundColor Cyan
}

if ($Once) {
    [void](Invoke-Sweep -State $state)
    exit 0
}

# Default: follow (anche senza -Follow, per evitare l'errore classico di
# lanciare lo script e non vedere nulla).
while ($true) {
    try {
        [void](Invoke-Sweep -State $state)
    } catch {
        Write-Warning "sweep fallito: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $IntervalSeconds
}
