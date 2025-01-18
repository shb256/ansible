$ApiToken = $env:Token
if (-not (Get-Command "choco" -ErrorAction SilentlyContinue)) {
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
} else {
    Write-Host "Chocolatey ist bereits installiert. Aktualisierung wird durchgeführt..."
    choco upgrade chocolatey -y
}
choco upgrade wireguard -y
choco upgrade openssh --params "/SSHServerFeature" -y

# Konfigurationsvariablen
$NetboxUrl = "https://nb.durchhalten.org/api"  # URL zu deiner NetBox API

echo $ApiToken
$ComputerName = $env:COMPUTERNAME
$InterfaceName = "WG_WTS"                  # Das gewünschte Interface
$wgConfigPath = "C:\Program Files\WireGuard\$InterfaceName.conf"
$source="dcim"

# Header für die Authentifizierung
$Headers = @{
    "Authorization" = "Token $ApiToken"
    "Content-Type"  = "application/json"
}

# Funktion, um den Computer in NetBox zu finden
function Get-DeviceFromNetbox {
    param (
        [string]$ComputerName
    )
    $typ ="dcim"
    $url = "$NetboxUrl/$source/devices/?name=$ComputerName"
    $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get
    
    if ($response.results.Count -eq 0) {
        # Falls kein Gerät gefunden, prüfe auf virtuelle Maschinen
        $url = "$NetboxUrl/virtualization/virtual-machines/?name=$ComputerName"
        $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get
        $typ = "virtualization"
    }
    if ($response.results.Count -eq 0) {
        Write-Host "Kein Gerät oder VM mit dem Namen '$ComputerName' gefunden. Erstelle neues Gerät."

        # Gerätedaten für die Erstellung vorbereiten
        $deviceData = @{
            name        = $ComputerName
            device_role = 8
            device_type = 39
            status      = "active"  # Standardstatus
        }

        # POST-Anfrage zum Erstellen des Geräts
        $url = "$NetboxUrl/dcim/devices/"
        $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method Post -Body ($deviceData | ConvertTo-Json -Depth 10)

        Write-Host "Neues Gerät erstellt: $($response.name) mit ID: $($response.id)"
        $typ = "dcim"
    }
    return @{
        Results = $response.results
        Source  = $typ
    }
}

# Funktion, um Interfaces des Computers abzurufen
function Get-InterfaceFromNetbox {
    param (
        [string]$DeviceId,
        [string]$InterfaceName,
        [string]$tenantID
    )
    $url = "$NetboxUrl/$source/interfaces/?device_id=$DeviceId&name=$InterfaceName"
    $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get
    return $response.results
}

# Funktion, um die IP-Adresse des Interfaces abzurufen
function Get-IpAddressFromNetbox {
    param (
        [string]$InterfaceId,
        [string]$SubnetId
    )
    $url = "$NetboxUrl/ipam/ip-addresses/?interface_id=$InterfaceId"
    if ($Source -eq "virtualization") {
        $url = "$NetboxUrl/ipam/ip-addresses/?vminterface_id=$InterfaceId"
        }
    
    $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get

 # Wenn keine IP-Adresse hinterlegt ist, finde die nächste freie IP
    if ($response.results.Count -eq 0) {
        # URL für freie IP-Adressen aus dem angegebenen Subnetz
        $freeIpUrl = "$NetboxUrl/ipam/prefixes/$SubnetId/available-ips/"

        # Abrufen der freien IP-Adresse
        $freeIpResponse = Invoke-RestMethod -Uri $freeIpUrl -Headers $Headers -Method Get
        if ($freeIpResponse.results.Count -gt 0) {
            # Nächste freie IP-Adresse auswählen
            $freeIp = $freeIpResponse[0].address
            write-host "XXXX $freeIp XXX"
            # IP-Adresse dem Interface zuweisen
            $assignIpUrl = "$NetboxUrl/ipam/ip-addresses/"
            $objtyp =  "dcim.interface"
            if($Source -eq "virtualization"){
                $objtyp="virtualization.vminterface"
            }
            $assignIpBody = @{
                address         = $freeIp
                status          = "active"
                assigned_object_id       = $InterfaceId
                assigned_object_type = $objtyp
                vrf            = 4
                description    = $ComputerName
                tenant = $tenantID
            }

            # IP-Adresse in Netbox hinzufügen
            ##$assignResponse = Invoke-RestMethod -Uri $assignIpUrl -Headers $Headers -Method Post -Body ($assignIpBody | ConvertTo-Json -Depth 2)
# JSON-Daten in den Body der Anfrage umwandeln
$assignIpBodyJson = $assignIpBody | ConvertTo-Json -Depth 3

# POST-Anfrage mit JSON-Body
$assignResponse = Invoke-RestMethod -Uri $assignIpUrl -Headers $Headers -Method Post -Body $assignIpBodyJson
            # Rückgabe der zugewiesenen IP-Adresse
            return $assignResponse
        }
        else {
            Write-Error "Keine verfügbare IP-Adresse im Subnetz mit der ID $SubnetId gefunden."
        }
    }

    # Wenn IP-Adresse bereits vorhanden ist, Rückgabe der Ergebnisse
    
    return $response.results
}

# Funktion, um Zusatzinformationen zum Interface zu holen
function Get-InterfaceDetails {
    param (
        [string]$InterfaceId
    )
    $url = "$NetboxUrl/$source/interfaces/$InterfaceId/"
    $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get
    return $response
}

# Funktion, um Local Context des Geräts zu aktualisieren
function Update-LocalContext {
    param (
        [string]$DeviceId,
        [string]$Key,
        [string]$Value
    )
    $url = "$NetboxUrl/dcim/devices/$DeviceId/"
    echo "hier"
    if ($Source -eq "virtualization") {
    echo "da"
        $url = "$NetboxUrl/virtualization/virtual-machines/$DeviceId/"
    }
    $deviceData = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get
    $localContext = $deviceData.local_context_data

    if (-not $localContext) {
        $localContext = [PSCustomObject]@{}
    }
    if ($localContext.PSObject.Properties.Match($InterfaceName+"_PublicKeyClient")) {
        $localContext.PSObject.Properties.Remove($InterfaceName+"_PublicKeyClient")
    }
    
    $localContext | Add-Member -MemberType NoteProperty -Name $InterfaceName"_PublicKeyClient" -Value $Value
    $payload = @{
        "local_context_data" = $localContext
    }
    $jsonPayload = $payload | ConvertTo-Json -Depth 10 -Compress
    $null = Invoke-RestMethod -Uri $url -Headers $Headers -Method Patch -Body $jsonPayload -ContentType "application/json"
}
# Filtere den Adapter nach Namen und Beschreibung
$adapter = Get-NetAdapter | Where-Object {
    $_.Name -eq "WG_WTS" -and $_.InterfaceDescription -like "WireGuard Tunnel*"
}

# Überprüfen, ob ein Adapter gefunden wurde
if ($adapter) {
    Write-Host "Der WireGuard-Tunnel 'WG_WTS' ist aktiv."
    $adapter | Format-Table Name, InterfaceDescription, Status -AutoSize
} else {


# Hauptablauf
Write-Output "Suche nach Gerät '$ComputerName' in NetBox..."
$res = Get-DeviceFromNetbox -ComputerName $ComputerName
$device = $res["Results"]
$source = $res["Source"]
if ($device.Count -eq 0) {
    Write-Error "Gerät '$ComputerName' nicht gefunden!"
    exit 1
}
$deviceId = $device[0].id
$PublicKeyEndPoint = $device[0].config_context.WG_WTS_PublicKeyServer
$Endpoint = $device[0].config_context.WG_WTS_Endpoint
$PersistentKeepalive = $device[0].config_context.WG_WTS_PersistentKeepalive
$AllowedIPs = $device[0].config_context.WG_WTS_AllowedIPs
$pubSshKey = $device[0].config_context.pubSshKey
$IpPrefix = $device[0].config_context.WG_WTS_IPPrefix
$tenantID = $device[0].tenant.id

Write-Output "Gerät gefunden: ID = $deviceId"

Write-Output "Suche nach Interface '$InterfaceName'..."
$interface = Get-InterfaceFromNetbox -DeviceId $deviceId -InterfaceName $InterfaceName -tenantID $tenantID
if ($interface.Count -eq 0) {
    Write-Error "Interface '$InterfaceName' nicht gefunden!"
    exit 1
}

$interfaceId = $interface[0].id
Write-Output "Interface gefunden: ID = $interfaceId"

Write-Output "Suche nach IP-Adresse des Interfaces..."
$ipAddress = Get-IpAddressFromNetbox -InterfaceId $interfaceId -SubnetId $IpPrefix
if ($ipAddress.Count -eq 0) {
    Write-Error "Keine IP-Adresse für Interface '$InterfaceName' gefunden!"
    exit 1
}

$ip = $ipAddress[0].address
$ip = $ip -replace "/\d+$", "/32"

Write-Output "IP-Adresse gefunden: $ip"

$privateKey = & 'C:\Program Files\WireGuard\wg.exe'  genkey
$publicKey = $privateKey | & 'C:\Program Files\WireGuard\wg.exe'  pubkey

Write-Output "Lade öffentlichen Schlüssel in NetBox hoch..."
Update-LocalContext -DeviceId $deviceId -Key "WTS_Pub_WG" -Value $publicKey
Write-Output "Öffentlicher Schlüssel erfolgreich hochgeladen."






# Inhalt der Konfigurationsdatei
$wgConfigContent = @"
[Interface]
PrivateKey = $privateKey
Address = $ip

[Peer]
PublicKey = $PublicKeyEndPoint
Endpoint = $Endpoint
AllowedIPs = $AllowedIPs
PersistentKeepalive = $PersistentKeepalive
"@

# Verzeichnis erstellen, falls es nicht existiert
$wgFolderPath = Split-Path -Path $wgConfigPath
if (-not (Test-Path -Path $wgFolderPath)) {
    New-Item -ItemType Directory -Path $wgFolderPath -Force | Out-Null
}
# Konfigurationsdatei erstellen oder überschreiben
Set-Content -Path $wgConfigPath -Value $wgConfigContent -Force
# Bestätigung ausgeben
Write-Output "WireGuard-Konfigurationsdatei wurde unter '$wgConfigPath' erstellt."


$FilePath = "C:\ProgramData\ssh\administrators_authorized_keys"

# Sicherstellen, dass das Verzeichnis existiert
if (-not (Test-Path -Path (Split-Path $FilePath))) {
    New-Item -ItemType Directory -Path (Split-Path $FilePath) -Force
}

# Inhalt in die Datei schreiben
Set-Content -Path $FilePath -Value $pubSshKey

# Überprüfen, ob die Datei erfolgreich geschrieben wurde
if (Test-Path -Path $FilePath) {
    Write-Host "Inhalt wurde erfolgreich in die Datei geschrieben: $FilePath"
    icacls.exe C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant "Administratoren:F" /grant "SYSTEM:F"
} else {
    Write-Host "Fehler: Datei konnte nicht erstellt werden."
}

New-NetFirewallRule -DisplayName "Allow Traffic from 172.16.3.233 WTS" -Direction Inbound -Action Allow -RemoteAddress 172.16.3.233 -Protocol Any
New-NetFirewallRule -DisplayName "Allow Traffic from 10.240.255.0/24 WTS" -Direction Inbound -Action Allow -RemoteAddress 10.240.255.0/24 -Protocol Any

& 'C:\Program Files\WireGuard\wireguard.exe'  /installtunnelservice "$wgConfigPath"


# Ziel-Dateipfad
$FilePath = "C:\ProgramData\ssh\sshd_config"

# Hinzuzufügender Inhalt
$ContentToAdd = @"
Match Group administratoren
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"@

# Sicherstellen, dass die Datei existiert
if (-not (Test-Path -Path $FilePath)) {
    Write-Host "Fehler: Datei '$FilePath' existiert nicht."
    return
}

# Überprüfen, ob der Inhalt bereits vorhanden ist
if (Get-Content -Path $FilePath | Select-String -SimpleMatch "Match Group administratoren") {
    Write-Host "Die Konfiguration ist bereits vorhanden."
} else {
    # Inhalt zur Datei hinzufügen
    Add-Content -Path $FilePath -Value $ContentToAdd -Encoding UTF8
    Write-Host "Inhalt wurde erfolgreich zur Datei hinzugefügt."
}

restart-service sshd
    Write-Host "Kein WireGuard-Tunnel mit dem Namen 'WG_WTS' und der Beschreibung 'WireGuard Tunnel' gefunden."
}
#RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1

Write-Output "Skript abgeschlossen. Ergebnisse:"
