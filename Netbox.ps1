param (
    [string]$ApiToken       # Definiert den Parameter "DeviceId" als string
)
#Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
#choco install wireguard -y

# Konfigurationsvariablen
$NetboxUrl = "https://nb.durchhalten.org/api"  # URL zu deiner NetBox API
#$ApiToken = ""            # Dein NetBox API-Token
$ComputerName = "ASW-PC-02"     # Der Name des gesuchten Computers
$ComputerName = $env:COMPUTERNAME
$InterfaceName = "WG_WTS"                  # Das gewünschte Interface
$wgConfigPath = "C:\Program Files\WireGuard\$InterfaceName.conf"
$source="dcim"

# Header für die Authentifizierung
$Headers = @{
    "Authorization" = "Token $ApiToken"
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
    
    return @{
        Results = $response.results
        Source  = $typ
    }
}

# Funktion, um Interfaces des Computers abzurufen
function Get-InterfaceFromNetbox {
    param (
        [string]$DeviceId,
        [string]$InterfaceName
    )
    $url = "$NetboxUrl/$source/interfaces/?device_id=$DeviceId&name=$InterfaceName"
    $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get
    return $response.results
}

# Funktion, um die IP-Adresse des Interfaces abzurufen
function Get-IpAddressFromNetbox {
    param (
        [string]$InterfaceId
    )
    $url = "$NetboxUrl/ipam/ip-addresses/?interface_id=$InterfaceId"
    if ($Source -eq "virtualization") {
        $url = "$NetboxUrl/ipam/ip-addresses/?vminterface_id=$InterfaceId"
        }
    
    $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get
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
Write-Output "Gerät gefunden: ID = $deviceId"

Write-Output "Suche nach Interface '$InterfaceName'..."
$interface = Get-InterfaceFromNetbox -DeviceId $deviceId -InterfaceName $InterfaceName
if ($interface.Count -eq 0) {
    Write-Error "Interface '$InterfaceName' nicht gefunden!"
    exit 1
}

$interfaceId = $interface[0].id
Write-Output "Interface gefunden: ID = $interfaceId"

Write-Output "Suche nach IP-Adresse des Interfaces..."
$ipAddress = Get-IpAddressFromNetbox -InterfaceId $interfaceId
if ($ipAddress.Count -eq 0) {
    Write-Error "Keine IP-Adresse für Interface '$InterfaceName' gefunden!"
    exit 1
}

$ip = $ipAddress[0].address
Write-Output "IP-Adresse gefunden: $ip"

$privateKey = wg genkey
$publicKey = $privateKey | wg pubkey

Write-Output "Lade öffentlichen Schlüssel in NetBox hoch..."
Update-LocalContext -DeviceId $deviceId -Key "WTS_Pub_WG" -Value $publicKey
Write-Output "Öffentlicher Schlüssel erfolgreich hochgeladen."


$PublicKey = $device[0].config_context.WG_WTS_PublicKeyServer
$Endpoint = $device[0].config_context.WG_WTS_Endpoint
$PersistentKeepalive = $device[0].config_context.WG_WTS_PersistentKeepalive
$AllowedIPs = $device[0].config_context.WG_WTS_AllowedIPs

# Inhalt der Konfigurationsdatei
$wgConfigContent = @"
[Interface]
PrivateKey = $privateKey
Address = $ip

[Peer]
PublicKey = $PublicKey
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

New-NetFirewallRule -DisplayName "Allow Traffic from 172.16.3.233 WTS" -Direction Inbound -Action Allow -RemoteAddress 172.16.3.233 -Protocol Any
New-NetFirewallRule -DisplayName "Allow Traffic from 10.240.255.0/24 WTS" -Direction Inbound -Action Allow -RemoteAddress 10.240.255.0/24 -Protocol Any

wireguard /installtunnelservice "$wgConfigPath"

Write-Output "Skript abgeschlossen. Ergebnisse:"
