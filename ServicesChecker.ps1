#requires -Version 5.1
<#
    Psico Checker :: by Psicoseado
    Requiere PowerShell 5.1 y privilegios de administrador.

    Cambios principales:
      - Salida alineada con campos de ancho fijo.
      - Deteccion de procesos Minecraft por linea de comandos (incluye otros usuarios).
      - Lectura robusta del estado del USN Journal.
      - Correccion del path de IFEO y de las fechas de ultima modificacion.
      - Manejo de errores para que un fallo aislado no detenga el escaneo.
#>

# --- Configuracion de consola -------------------------------------------------
$ErrorActionPreference = 'SilentlyContinue'
$script:ScanIssues = [Collections.Generic.List[object]]::new()

try {
    $chcp = Join-Path $env:SystemRoot 'System32\chcp.com'
    if (Test-Path -LiteralPath $chcp -PathType Leaf) { & $chcp 65001 > $null }
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {}

try { Clear-Host } catch {}
try { $Host.UI.RawUI.WindowTitle = 'Psico Checker :: by Psicoseado' } catch {}

# --- Variables de diseno ------------------------------------------------------
$titleIndex   = '  '
$infoIndex    = '    '
$fieldWidth   = 20
$regNameWidth = 22

$titleColor   = 'Cyan'
$subtColor    = 'DarkGray'
$textColor    = 'White'
$successColor = 'Green'
$dangerColor  = 'Red'
$warnColor    = 'Yellow'
$formatDate   = 'dd-MM-yyyy HH:mm:ss'

$bannerFrom  = @(0, 255, 128)
$bannerTo    = @(190, 0, 255)
$frameFrom   = @(0, 190, 255)
$frameTo     = @(200, 0, 255)
$sectionFrom = @(0, 255, 140)
$sectionTo   = @(180, 0, 255)

$panelWidth = 70
$panelInner = $panelWidth - 2

# --- Comprobacion de privilegios ---------------------------------------------
function Test-IsAdmin {
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

if (-not (Test-IsAdmin)) {
    Write-Host ''
    Write-Host '  [ERROR] SE REQUIEREN PRIVILEGIOS DE ADMINISTRADOR' -ForegroundColor White -BackgroundColor Red
    Write-Host '          Ejecuta el script desde una consola elevada.' -ForegroundColor $warnColor
    Write-Host ''
    Start-Sleep -Seconds 5
    exit 1
}

# --- Utilidades nativas -------------------------------------------------------
if (-not ('PsicoKernel32' -as [type])) {
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Text;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

public class PsicoKernel32
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll")]
    public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
}

public class PsicoRegUtil
{
    public const uint HKEY_LOCAL_MACHINE = 0x80000002;
    public const uint HKEY_CURRENT_USER  = 0x80000001;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int RegOpenKeyEx(
        UIntPtr hKey,
        string lpSubKey,
        uint ulOptions,
        int samDesired,
        out SafeRegistryHandle phkResult);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegQueryInfoKey(
        SafeRegistryHandle hKey,
        StringBuilder lpClass,
        ref uint lpcClass,
        IntPtr lpReserved,
        out uint lpcSubKeys,
        out uint lpcbMaxSubKeyLen,
        out uint lpcbMaxClassLen,
        out uint lpcValues,
        out uint lpcbMaxValueNameLen,
        out uint lpcbMaxValueLen,
        out uint lpcbSecurityDescriptor,
        out long lpftLastWriteTime);

    public static DateTime? GetLastWriteTime(uint hive, string subKey)
    {
        SafeRegistryHandle hKey;
        int result = RegOpenKeyEx((UIntPtr)hive, subKey, 0, 0x20019, out hKey);
        if (result != 0 || hKey == null || hKey.IsInvalid)
        {
            return null;
        }

        try
        {
            uint classLength = 0;
            uint subKeys;
            uint maxSubKeyLength;
            uint maxClassLength;
            uint values;
            uint maxValueNameLength;
            uint maxValueLength;
            uint securityDescriptor;
            long fileTime;

            result = RegQueryInfoKey(
                hKey,
                null,
                ref classLength,
                IntPtr.Zero,
                out subKeys,
                out maxSubKeyLength,
                out maxClassLength,
                out values,
                out maxValueNameLength,
                out maxValueLength,
                out securityDescriptor,
                out fileTime);

            if (result != 0 || fileTime <= 0)
            {
                return null;
            }

            return DateTime.FromFileTimeUtc(fileTime).ToLocalTime();
        }
        catch
        {
            return null;
        }
        finally
        {
            hKey.Dispose();
        }
    }
}
'@ -ErrorAction Stop
    } catch {
        Write-Host ''
        Write-Host "  [ERROR] No se pudieron cargar las utilidades nativas: $($_.Exception.Message)" -ForegroundColor $dangerColor
        Write-Host ''
        Start-Sleep -Seconds 5
        exit 1
    }
}

$script:VtEnabled = $false
try {
    $stdOut = [PsicoKernel32]::GetStdHandle(-11)
    $vtMode = [uint32]0
    if ([PsicoKernel32]::GetConsoleMode($stdOut, [ref]$vtMode)) {
        $script:VtEnabled = [PsicoKernel32]::SetConsoleMode($stdOut, $vtMode -bor 0x0004)
    }
} catch {}

# --- Funciones visuales -------------------------------------------------------
function Center-Inner {
    param(
        [string]$Text,
        [int]$Width
    )

    if ($Text.Length -ge $Width) { return $Text.Substring(0, $Width) }
    $left = [int](($Width - $Text.Length) / 2)
    $right = $Width - $Text.Length - $left
    return (' ' * $left) + $Text + (' ' * $right)
}

function Write-SectionHeader {
    param([string]$Title)

    $label = "  [ $Title ] "
    if ($label.Length -gt $panelInner) { $label = $label.Substring(0, $panelInner) }
    $fill = '═' * ($panelInner - $label.Length)

    Write-Host ''
    Write-GradientRow ('╔' + ('═' * $panelInner) + '╗') $sectionFrom $sectionTo
    Write-Host '║' -ForegroundColor DarkCyan -NoNewline
    Write-Host $label -ForegroundColor $titleColor -NoNewline
    Write-Host $fill -ForegroundColor DarkCyan -NoNewline
    Write-Host '║' -ForegroundColor DarkCyan
    Write-GradientRow ('╚' + ('═' * $panelInner) + '╝') $sectionFrom $sectionTo
    Write-Host ''
}

function Write-SubSection {
    param([string]$Title)

    $lineLength = [Math]::Max(0, 62 - $Title.Length)
    Write-Host ($titleIndex + '◆ ') -ForegroundColor Magenta -NoNewline
    Write-Host $Title -ForegroundColor $titleColor -NoNewline
    Write-Host (' ' + ('─' * $lineLength)) -ForegroundColor $subtColor
}

function Write-Field {
    param(
        [string]$Label,
        [AllowNull()][string]$Value,
        [int]$Width = $fieldWidth,
        [string]$LabelColor = $textColor,
        [string]$ValueColor = $textColor,
        [string]$Indent = $infoIndex
    )

    if ($null -eq $Value) { $Value = '' }
    Write-Host ($Indent + $Label.PadRight($Width)) -ForegroundColor $LabelColor -NoNewline
    Write-Host $Value -ForegroundColor $ValueColor
}

function Write-ThinSeparator {
    param(
        [string]$Indent = $infoIndex,
        [int]$Width = 58
    )

    Write-Host ($Indent + ('─' * $Width)) -ForegroundColor $subtColor
}

function Write-Int {
    param(
        [string]$Indent,
        [string]$Symbol,
        [string]$Message
    )

    Write-Host ($Indent + ' [') -ForegroundColor DarkCyan -NoNewline
    Write-Host $Symbol -ForegroundColor Magenta -NoNewline
    Write-Host '] ' -ForegroundColor DarkCyan -NoNewline
    Write-Host $Message -ForegroundColor $warnColor
}

function Format-Duration {
    param($Value)

    if ($null -eq $Value -or $Value -isnot [TimeSpan]) { return 'Unknown' }
    return ('{0}d {1}h {2}m {3}s' -f $Value.Days, $Value.Hours, $Value.Minutes, $Value.Seconds)
}

function Test-ArchiveAttribute {
    param([IO.FileAttributes]$Attributes)

    return (($Attributes -band [IO.FileAttributes]::Archive) -eq [IO.FileAttributes]::Archive)
}

function Add-ScanIssue {
    param(
        [string]$Area,
        [string]$Detail
    )

    if ([string]::IsNullOrWhiteSpace($Area)) { $Area = 'General' }
    if ([string]::IsNullOrWhiteSpace($Detail)) { $Detail = 'Unknown error' }

    $script:ScanIssues.Add([pscustomobject]@{
        Area   = $Area
        Detail = $Detail
    })
}

function Get-RegistryEvidence {
    param(
        [string]$Path,
        [string]$Name
    )

    $result = [pscustomobject]@{
        Status    = 'Unknown'
        Value     = $null
        LastWrite = $null
        Error     = $null
    }

    try {
        $null = Get-Item -LiteralPath $Path -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        $result.Status = 'Key missing'
        return $result
    } catch [System.UnauthorizedAccessException] {
        $result.Status = 'Access denied'
        $result.Error = $_.Exception.Message
        return $result
    } catch [System.Security.SecurityException] {
        $result.Status = 'Access denied'
        $result.Error = $_.Exception.Message
        return $result
    } catch {
        $message = [string]$_.Exception.Message
        if ($message -match '(?i)denied|unauthorized|not allowed|security') {
            $result.Status = 'Access denied'
        } else {
            $result.Status = 'Read error'
        }
        $result.Error = $message
        return $result
    }

    try {
        $property = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        $result.Status = 'Present'
        $result.Value = $property.$Name
    } catch [System.Management.Automation.ItemNotFoundException] {
        $result.Status = 'Value missing'
    } catch [System.UnauthorizedAccessException] {
        $result.Status = 'Access denied'
        $result.Error = $_.Exception.Message
    } catch [System.Security.SecurityException] {
        $result.Status = 'Access denied'
        $result.Error = $_.Exception.Message
    } catch {
        $message = [string]$_.Exception.Message
        if ($message -match '(?i)property.*(not found|does not exist)|no.*property') {
            $result.Status = 'Value missing'
        } elseif ($message -match '(?i)denied|unauthorized|not allowed|security') {
            $result.Status = 'Access denied'
        } else {
            $result.Status = 'Read error'
        }
        $result.Error = $message
    }

    return $result
}

function Get-PathEvidence {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return 'Unknown' }

    if (Test-Path -LiteralPath $Path) { return 'Present' }

    try {
        $null = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return 'Present'
    } catch [System.Management.Automation.ItemNotFoundException] {
        return 'Missing'
    } catch [System.UnauthorizedAccessException] {
        return 'Access denied'
    } catch [System.Security.SecurityException] {
        return 'Access denied'
    } catch {
        if ([string]$_.Exception.Message -match '(?i)denied|unauthorized|not allowed|security') {
            return 'Access denied'
        }
        return 'Read error'
    }
}

function Normalize-MountPoint {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    return ($Path.TrimEnd('\')).ToUpperInvariant()
}

function Get-PathValueColor {
    param([string]$Status)

    switch ($Status) {
        'Present'       { return $successColor }
        'Missing'       { return $textColor }
        'Access denied' { return $warnColor }
        'Read error'    { return $warnColor }
        default         { return $warnColor }
    }
}

function Format-Bytes {
    param([double]$Bytes)

    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes / 1KB)) }
    return ('{0:N0} B' -f $Bytes)
}

function Get-UsageColor {
    param([double]$Percent)

    if ($Percent -ge 85) { return $dangerColor }
    if ($Percent -ge 60) { return $warnColor }
    return $successColor
}

function Write-UsageBar {
    param(
        [string]$Label,
        [double]$Percent,
        [string]$Suffix = ''
    )

    $barWidth = 20
    $value = [Math]::Max(0, [Math]::Min(100, [Math]::Round($Percent, 0)))
    $filled = [int][Math]::Round(($value / 100) * $barWidth)
    if ($filled -gt $barWidth) { $filled = $barWidth }
    if ($filled -lt 0) { $filled = 0 }
    $empty = $barWidth - $filled
    $color = Get-UsageColor $value

    Write-Host ($infoIndex + $Label.PadRight($fieldWidth)) -ForegroundColor $textColor -NoNewline
    Write-Host '[' -ForegroundColor $subtColor -NoNewline
    Write-Host ('█' * $filled) -ForegroundColor $color -NoNewline
    Write-Host ('░' * $empty) -ForegroundColor $subtColor -NoNewline
    Write-Host '] ' -ForegroundColor $subtColor -NoNewline
    Write-Host ('{0,3}%' -f $value) -ForegroundColor $color -NoNewline

    if ($Suffix) {
        Write-Host ('  ' + $Suffix) -ForegroundColor $subtColor
    } else {
        Write-Host ''
    }
}

function Write-GradientRow {
    param(
        [string]$Text,
        [int[]]$FromRGB,
        [int[]]$ToRGB
    )

    if (-not $script:VtEnabled) {
        Write-Host $Text -ForegroundColor $titleColor
        return
    }

    $builder = [Text.StringBuilder]::new()
    $visibleLength = [Math]::Max($Text.Length, 1)

    for ($i = 0; $i -lt $Text.Length; $i++) {
        $character = $Text[$i]
        if ($character -eq ' ') {
            [void]$builder.Append($character)
            continue
        }

        $t = if ($visibleLength -gt 1) { $i / [double]($visibleLength - 1) } else { 1.0 }
        $r = [int]($FromRGB[0] + ($ToRGB[0] - $FromRGB[0]) * $t)
        $g = [int]($FromRGB[1] + ($ToRGB[1] - $FromRGB[1]) * $t)
        $b = [int]($FromRGB[2] + ($ToRGB[2] - $FromRGB[2]) * $t)

        [void]$builder.Append("$([char]27)[38;2;$r;$g;${b}m").Append($character)
    }

    [void]$builder.Append("$([char]27)[0m")
    Write-Host $builder.ToString()
}

# --- Funciones de lectura -----------------------------------------------------
function Get-Drives {
    $maxLength = 1024
    $result = [Collections.Generic.List[object]]::new()
    $volumes = @(Get-CimInstance -ClassName Win32_Volume -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveType -ne 5 } |
        Sort-Object DriveLetter)

    foreach ($volume in $volumes) {
        $devicePath = $volume.DeviceID
        if ($volume.DriveLetter) {
            $buffer = [Text.StringBuilder]::new($maxLength)
            $length = [PsicoKernel32]::QueryDosDevice($volume.DriveLetter, $buffer, $maxLength)
            if ($length -gt 0) { $devicePath = $buffer.ToString() }
        }

        $fileSystem = if ($volume.FileSystem) { $volume.FileSystem } else { 'RAW' }
        $driveLetter = if ($volume.DriveLetter) { $volume.DriveLetter } else { '[NO LETTER]' }

        $result.Add([pscustomobject]@{
            DriveLetter = $driveLetter
            Label       = $volume.Label
            FileSystem  = $fileSystem
            Capacity    = $volume.Capacity
            DriveType   = $volume.DriveType
            DevicePath  = $devicePath
        })
    }

    return $result.ToArray()
}

function Get-VolumeEncryptionInfo {
    param($Volume)

    $info = [pscustomobject]@{
        Encrypted  = 'UNKNOWN'
        Type       = 'UNVERIFIED'
        Access     = 'UNVERIFIED'
        LiveUnlock = 'UNKNOWN'
        MemAcquire = 'UNKNOWN'
        Priority   = 'REVIEW'
        Evidence   = 'Sin evidencia de cifrado'
    }

    $hasLetter = $Volume.DriveLetter -ne '[NO LETTER]'
    $mountPoint = if ($hasLetter) { (Normalize-MountPoint $Volume.DriveLetter) } else { '' }
    $bitLockerError = $null
    $encryptableError = $null
    $bitLockerRead = $false
    $encryptableRead = $false

    # 1) BitLocker management cmdlet (authoritative when available).
    $bitLockerAvailable = Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($hasLetter -and $bitLockerAvailable) {
        try {
            $bitLocker = Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
            $bitLockerRead = $true
            $volumeStatus = [string]$bitLocker.VolumeStatus
            $lockStatus = [string]$bitLocker.LockStatus
            $protection = [string]$bitLocker.ProtectionStatus
            $method = [string]$bitLocker.EncryptionMethod

            if ($volumeStatus -eq 'FullyDecrypted') {
                $info.Encrypted  = 'NO'
                $info.Type       = 'CLEAR'
                $info.Access     = 'CLEAR'
                $info.LiveUnlock = 'NO'
                $info.MemAcquire = 'NO'
                $info.Priority   = 'LOW'
                $info.Evidence   = "BitLocker: FullyDecrypted (protection $protection)"
            } elseif ($volumeStatus -in @('FullyEncrypted', 'EncryptionInProgress', 'EncryptionPaused', 'DecryptionInProgress', 'DecryptionPaused')) {
                $info.Encrypted  = 'YES'
                $info.Type       = 'BITLOCKER (' + $method + ')'
                if ($lockStatus -eq 'Locked') {
                    $info.Access     = 'ENCRYPTED_LOCKED'
                    $info.LiveUnlock = 'NO'
                    $info.MemAcquire = 'YES'
                } else {
                    $info.Access     = 'ENCRYPTED_UNCOVERED'
                    $info.LiveUnlock = 'YES'
                    $info.MemAcquire = 'YES'
                }
                $info.Priority = 'HIGH'
                $info.Evidence = "BitLocker: $volumeStatus / $lockStatus (protection $protection)"
            } else {
                $info.Encrypted = 'UNKNOWN'
                $info.Type      = 'BITLOCKER (' + $volumeStatus + ')'
                $info.Evidence  = "BitLocker devolvio un estado no concluyente: $volumeStatus"
            }
        } catch [System.UnauthorizedAccessException] {
            $bitLockerError = 'access denied'
            Add-ScanIssue 'Connected drives' "BitLocker: acceso denegado para $mountPoint"
        } catch {
            $bitLockerError = $_.Exception.Message
            Add-ScanIssue 'Connected drives' "BitLocker fallo para el volumen $($Volume.DriveLetter): $($bitLockerError)"
        }
    }

    # 2) Fallback: Win32_EncryptableVolume (normalized mount point comparison).
    if ($hasLetter -and -not $bitLockerRead) {
        try {
            $encryptables = @(Get-CimInstance -Namespace 'root\cimv2\security\microsoftvolumeencryption' `
                -ClassName Win32_EncryptableVolume -ErrorAction Stop)
            $encryptableRead = $true

            $encryptable = $encryptables |
                Where-Object { (Normalize-MountPoint ([string]$_.DriveLetter)) -eq $mountPoint } |
                Select-Object -First 1

            if ($encryptable) {
                $protectionStatus = [int]$encryptable.ProtectionStatus
                if ($protectionStatus -eq 1) {
                    $info.Encrypted  = 'YES'
                    $info.Type       = 'DEVICE ENCRYPTION'
                    $info.Access     = 'ENCRYPTED_UNCOVERED'
                    $info.LiveUnlock = 'YES'
                    $info.MemAcquire = 'YES'
                    $info.Priority   = 'HIGH'
                    $info.Evidence   = 'Win32_EncryptableVolume: ProtectionStatus=1'
                } elseif ($protectionStatus -eq 0) {
                    $info.Encrypted  = 'NO'
                    $info.Type       = 'CLEAR'
                    $info.Access     = 'CLEAR'
                    $info.LiveUnlock = 'NO'
                    $info.MemAcquire = 'NO'
                    $info.Priority   = 'LOW'
                    $info.Evidence   = 'Win32_EncryptableVolume: ProtectionStatus=0'
                } else {
                    $info.Encrypted = 'UNKNOWN'
                    $info.Type      = 'DEVICE ENCRYPTION (unknown state)'
                    $info.Evidence  = "Win32_EncryptableVolume: ProtectionStatus=$protectionStatus"
                }
            } else {
                $info.Evidence = 'Win32_EncryptableVolume no reporto este volumen'
            }
        } catch [System.UnauthorizedAccessException] {
            $encryptableError = 'access denied'
            Add-ScanIssue 'Connected drives' "Win32_EncryptableVolume: acceso denegado para $mountPoint"
        } catch {
            $encryptableError = $_.Exception.Message
        }
    }

    # 3) Filesystem sanity: a RAW volume is not proof of encryption.
    $fileSystem = [string]$Volume.FileSystem
    if ($fileSystem -eq 'RAW' -and $info.Encrypted -ne 'YES') {
        $info.Encrypted  = 'UNKNOWN'
        $info.Type       = 'RAW / UNVERIFIED'
        $info.Access     = 'UNVERIFIED'
        $info.LiveUnlock = 'UNKNOWN'
        $info.MemAcquire = 'UNKNOWN'
        $info.Priority   = 'REVIEW'
        $info.Evidence   = 'Filesystem RAW: puede estar cifrado, corrupto o sin formatear; no se puede afirmar cifrado'
        Add-ScanIssue 'Connected drives' "Volumen RAW sin verificacion: $($Volume.DriveLetter) ($(Format-Bytes ([double]$Volume.Capacity)))"
    } elseif (-not $hasLetter -and $info.Encrypted -ne 'YES') {
        $info.Encrypted  = 'UNKNOWN'
        $info.Access     = 'UNVERIFIED'
        $info.LiveUnlock = 'UNKNOWN'
        $info.MemAcquire = 'UNKNOWN'
        $label = [string]$Volume.Label
        $capacity = [double]$Volume.Capacity
        $isSystemLike = ($label -match '(?i)system|recovery|efi|boot') -or ($capacity -gt 0 -and $capacity -le 2GB)
        if ($isSystemLike) {
            $info.Type     = 'NO LETTER / SYSTEM'
            $info.Priority = 'INFO'
            $info.Evidence = 'Particion de sistema/recuperacion: el cifrado no se puede verificar por montaje'
        } else {
            $info.Type     = 'NO LETTER / UNVERIFIED'
            $info.Priority = 'REVIEW'
            $info.Evidence = 'Volumen sin letra: no se puede verificar el cifrado por montaje'
        }
    } elseif ($info.Encrypted -eq 'UNKNOWN' -and -not $bitLockerRead -and -not $encryptableRead) {
        $info.Evidence = 'No se pudo leer BitLocker ni Win32_EncryptableVolume'
        if ($bitLockerError) { $info.Evidence += " (BitLocker: $bitLockerError)" }
        if ($encryptableError) { $info.Evidence += " (EncryptableVolume: $encryptableError)" }
    }

    return $info
}

function Get-ServiceFacts {
    param(
        [string]$ServiceName,
        $ProcessId
    )

    $facts = [Collections.Generic.List[object]]::new()

    switch ($ServiceName) {
        'SysMain' {
            $prefetchKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
            $prefetchEvidence = Get-RegistryEvidence -Path $prefetchKey -Name 'EnablePrefetcher'

            switch ($prefetchEvidence.Status) {
                'Present' {
                    $value = $prefetchEvidence.Value
                    if ($null -eq $value) {
                        $facts.Add([pscustomobject]@{ Label = 'EnablePrefetcher:'; Value = 'Not set (system default)'; Color = $textColor })
                    } else {
                        $number = [int]$value
                        $label = switch ($number) {
                            0 { 'Disabled (0)' }
                            1 { 'Enabled (apps)' }
                            2 { 'Enabled (boot)' }
                            3 { 'Enabled (apps+boot)' }
                            default { "Value $number" }
                        }
                        $factColor = if ($number -eq 0) { $warnColor } else { $successColor }
                        $facts.Add([pscustomobject]@{ Label = 'EnablePrefetcher:'; Value = $label; Color = $factColor })
                    }
                }
                'Value missing' {
                    $facts.Add([pscustomobject]@{ Label = 'EnablePrefetcher:'; Value = 'Not set (system default)'; Color = $textColor })
                }
                'Access denied' {
                    $facts.Add([pscustomobject]@{ Label = 'EnablePrefetcher:'; Value = 'UNKNOWN (access denied)'; Color = $warnColor })
                    Add-ScanIssue 'SysMain' "No se pudo leer EnablePrefetcher: $($prefetchEvidence.Error)"
                }
                'Key missing' {
                    $facts.Add([pscustomobject]@{ Label = 'EnablePrefetcher:'; Value = 'UNKNOWN (key missing)'; Color = $warnColor })
                }
                default {
                    $facts.Add([pscustomobject]@{ Label = 'EnablePrefetcher:'; Value = 'UNKNOWN (read error)'; Color = $warnColor })
                    Add-ScanIssue 'SysMain' "Error al leer EnablePrefetcher: $($prefetchEvidence.Error)"
                }
            }

            $prefetchDisabled = ($prefetchEvidence.Status -eq 'Present' -and $null -ne $prefetchEvidence.Value -and [int]$prefetchEvidence.Value -eq 0)
            $prefetchFolder = Join-Path $env:SystemRoot 'Prefetch'
            $folderStatus = Get-PathEvidence $prefetchFolder
            if ($folderStatus -eq 'Present') {
                try {
                    $prefetchFiles = @(Get-ChildItem -LiteralPath $prefetchFolder -Filter '*.pf' -Force -File -ErrorAction Stop)
                    $filesColor = if ($prefetchFiles.Count -eq 0) {
                        if ($prefetchDisabled) { $textColor } else { $warnColor }
                    } else {
                        $textColor
                    }
                    $facts.Add([pscustomobject]@{ Label = 'Prefetch files:'; Value = [string]$prefetchFiles.Count; Color = $filesColor })
                } catch {
                    $facts.Add([pscustomobject]@{ Label = 'Prefetch files:'; Value = 'UNKNOWN (read error)'; Color = $warnColor })
                    Add-ScanIssue 'SysMain' "No se pudo enumerar Prefetch: $($_.Exception.Message)"
                }
            } elseif ($folderStatus -eq 'Access denied') {
                $facts.Add([pscustomobject]@{ Label = 'Prefetch files:'; Value = 'UNKNOWN (access denied)'; Color = $warnColor })
                Add-ScanIssue 'SysMain' 'Acceso denegado a la carpeta Prefetch'
            } else {
                $facts.Add([pscustomobject]@{ Label = 'Prefetch files:'; Value = 'Folder missing'; Color = $(if ($prefetchDisabled) { $textColor } else { $warnColor }) })
            }

            $layoutPath = Join-Path $prefetchFolder 'Layout.ini'
            $layoutStatus = Get-PathEvidence $layoutPath
            $layoutColor = if ($layoutStatus -eq 'Present') { $successColor } elseif ($layoutStatus -eq 'Missing') { $textColor } else { $warnColor }
            $facts.Add([pscustomobject]@{
                Label = 'Layout.ini:'
                Value = $layoutStatus
                Color = $layoutColor
            })
        }
        'PcaSvc' {
            $pcaEvidence = Get-RegistryEvidence -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisabledPCA'

            switch ($pcaEvidence.Status) {
                'Present' {
                    if ($null -ne $pcaEvidence.Value -and [int]$pcaEvidence.Value -eq 1) {
                        $facts.Add([pscustomobject]@{ Label = 'PCA policy:'; Value = 'Disabled (DisabledPCA=1)'; Color = $warnColor })
                    } else {
                        $facts.Add([pscustomobject]@{ Label = 'PCA policy:'; Value = 'Enabled'; Color = $successColor })
                    }
                }
                'Value missing' {
                    $facts.Add([pscustomobject]@{ Label = 'PCA policy:'; Value = 'Not set (default enabled)'; Color = $textColor })
                }
                'Key missing' {
                    $facts.Add([pscustomobject]@{ Label = 'PCA policy:'; Value = 'Not configured (key missing)'; Color = $textColor })
                }
                'Access denied' {
                    $facts.Add([pscustomobject]@{ Label = 'PCA policy:'; Value = 'UNKNOWN (access denied)'; Color = $warnColor })
                    Add-ScanIssue 'PcaSvc' "No se pudo leer DisabledPCA: $($pcaEvidence.Error)"
                }
                default {
                    $facts.Add([pscustomobject]@{ Label = 'PCA policy:'; Value = 'UNKNOWN (read error)'; Color = $warnColor })
                    Add-ScanIssue 'PcaSvc' "Error al leer DisabledPCA: $($pcaEvidence.Error)"
                }
            }

            $pcaStore = Join-Path $env:SystemRoot 'appcompat\pca'
            $storeStatus = Get-PathEvidence $pcaStore
            if ($storeStatus -eq 'Present') {
                try {
                    $storeCount = @(Get-ChildItem -LiteralPath $pcaStore -Force -File -ErrorAction Stop).Count
                    $storeColor = $textColor
                    $facts.Add([pscustomobject]@{ Label = 'PCA store:'; Value = "$storeCount files"; Color = $storeColor })
                } catch {
                    $facts.Add([pscustomobject]@{ Label = 'PCA store:'; Value = 'UNKNOWN (read error)'; Color = $warnColor })
                    Add-ScanIssue 'PcaSvc' "No se pudo enumerar $pcaStore : $($_.Exception.Message)"
                }
            } else {
                $facts.Add([pscustomobject]@{ Label = 'PCA store:'; Value = $storeStatus; Color = (Get-PathValueColor $storeStatus) })
            }
        }
        'EventLog' {
            $logFolder = Join-Path $env:SystemRoot 'System32\winevt\Logs'
            $logStatus = Get-PathEvidence $logFolder
            if ($logStatus -eq 'Present') {
                try {
                    $logs = @(Get-ChildItem -LiteralPath $logFolder -Filter '*.evtx' -Force -File -ErrorAction Stop)
                    $logColor = if ($logs.Count -eq 0) { $warnColor } else { $textColor }
                    $facts.Add([pscustomobject]@{ Label = 'Event logs:'; Value = "$($logs.Count) files"; Color = $logColor })

                    $logMin = @($logs | Where-Object { $_.Length -lt 68KB }).Count
                    $facts.Add([pscustomobject]@{ Label = 'Logs < 68KB:'; Value = [string]$logMin; Color = $textColor })
                } catch {
                    $facts.Add([pscustomobject]@{ Label = 'Event logs:'; Value = 'UNKNOWN (read error)'; Color = $warnColor })
                    $facts.Add([pscustomobject]@{ Label = 'Logs < 68KB:'; Value = 'UNKNOWN'; Color = $warnColor })
                    Add-ScanIssue 'EventLog' "No se pudo enumerar $logFolder : $($_.Exception.Message)"
                }
            } else {
                $facts.Add([pscustomobject]@{ Label = 'Event logs:'; Value = $logStatus; Color = (Get-PathValueColor $logStatus) })
                $facts.Add([pscustomobject]@{ Label = 'Logs < 68KB:'; Value = 'UNKNOWN'; Color = $warnColor })
                Add-ScanIssue 'EventLog' "No se pudo leer la carpeta de logs: $logStatus"
            }
        }
        'Schedule' {
            $scheduledTasks = @()
            $taskError = $null
            try {
                $scheduledTasks = @(Get-ScheduledTask -ErrorAction Stop)
            } catch {
                $taskError = $_.Exception.Message
            }

            if ($scheduledTasks.Count -gt 0) {
                $taskCount = $scheduledTasks.Count
                $disabledTasks = @($scheduledTasks | Where-Object { [string]$_.State -eq 'Disabled' }).Count
                $facts.Add([pscustomobject]@{ Label = 'Scheduled tasks:'; Value = [string]$taskCount; Color = $textColor })
                $facts.Add([pscustomobject]@{ Label = 'Disabled tasks:'; Value = [string]$disabledTasks; Color = $textColor })
            } else {
                $tasksFolder = Join-Path $env:SystemRoot 'System32\Tasks'
                $folderStatus = Get-PathEvidence $tasksFolder
                if ($folderStatus -eq 'Present') {
                    try {
                        $taskFiles = @(Get-ChildItem -LiteralPath $tasksFolder -Force -File -Recurse -ErrorAction Stop)
                        if ($taskFiles.Count -gt 0) {
                            $facts.Add([pscustomobject]@{ Label = 'Task files:'; Value = [string]$taskFiles.Count; Color = $textColor })
                            $emptyTasks = @($taskFiles | Where-Object { $_.Length -eq 0 }).Count
                            $facts.Add([pscustomobject]@{ Label = 'Empty tasks:'; Value = [string]$emptyTasks; Color = $(if ($emptyTasks -gt 0) { $warnColor } else { $textColor }) })
                        } else {
                            $facts.Add([pscustomobject]@{ Label = 'Scheduled tasks:'; Value = 'Unreadable'; Color = $warnColor })
                        }
                    } catch {
                        $facts.Add([pscustomobject]@{ Label = 'Scheduled tasks:'; Value = 'UNKNOWN (read error)'; Color = $warnColor })
                        Add-ScanIssue 'Schedule' "No se pudo enumerar $tasksFolder : $($_.Exception.Message)"
                    }
                } else {
                    $facts.Add([pscustomobject]@{ Label = 'Scheduled tasks:'; Value = $folderStatus; Color = (Get-PathValueColor $folderStatus) })
                }
                if ($taskError) { Add-ScanIssue 'Schedule' "Get-ScheduledTask fallo: $taskError" }
            }
        }
        'DiagTrack' {
            $telemetryEvidence = Get-RegistryEvidence -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry'

            switch ($telemetryEvidence.Status) {
                'Present' {
                    $facts.Add([pscustomobject]@{ Label = 'Telemetry policy:'; Value = [string]$telemetryEvidence.Value; Color = $textColor })
                }
                'Value missing' {
                    $facts.Add([pscustomobject]@{ Label = 'Telemetry policy:'; Value = 'Not set (system default)'; Color = $textColor })
                }
                'Key missing' {
                    $facts.Add([pscustomobject]@{ Label = 'Telemetry policy:'; Value = 'Not configured (key missing)'; Color = $textColor })
                }
                'Access denied' {
                    $facts.Add([pscustomobject]@{ Label = 'Telemetry policy:'; Value = 'UNKNOWN (access denied)'; Color = $warnColor })
                    Add-ScanIssue 'DiagTrack' "No se pudo leer AllowTelemetry: $($telemetryEvidence.Error)"
                }
                default {
                    $facts.Add([pscustomobject]@{ Label = 'Telemetry policy:'; Value = 'UNKNOWN (read error)'; Color = $warnColor })
                    Add-ScanIssue 'DiagTrack' "Error al leer AllowTelemetry: $($telemetryEvidence.Error)"
                }
            }

            $logFolder = Join-Path $env:SystemRoot 'System32\winevt\Logs'
            $logStatus = Get-PathEvidence $logFolder
            if ($logStatus -eq 'Present') {
                $diagLogs = @(Get-ChildItem -LiteralPath $logFolder -Force -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '(?i)DiagTrack|UniversalTelemetryClient' })
                $diagColor = if ($diagLogs.Count -gt 0) { $successColor } else { $subtColor }
                $diagValue = if ($diagLogs.Count -gt 0) { "$($diagLogs.Count) log(s)" } else { 'Not present' }
                $facts.Add([pscustomobject]@{ Label = 'Telemetry logs:'; Value = $diagValue; Color = $diagColor })
            } else {
                $facts.Add([pscustomobject]@{ Label = 'Telemetry logs:'; Value = $logStatus; Color = (Get-PathValueColor $logStatus) })
            }
        }
        'DusmSvc' {
            $sruDb = Join-Path $env:SystemRoot 'System32\sru\SRUDB.dat'
            $sruStatus = Get-PathEvidence $sruDb
            $facts.Add([pscustomobject]@{ Label = 'SRUM DB:'; Value = $sruStatus; Color = (Get-PathValueColor $sruStatus) })

            $sruLog = Join-Path $env:SystemRoot 'System32\sru\SRU.log'
            $sruLogStatus = Get-PathEvidence $sruLog
            $facts.Add([pscustomobject]@{ Label = 'SRUM log:'; Value = $sruLogStatus; Color = (Get-PathValueColor $sruLogStatus) })
        }
        'Appinfo' {
            $luaEvidence = Get-RegistryEvidence -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'

            switch ($luaEvidence.Status) {
                'Present' {
                    $uacEnabled = ([int]$luaEvidence.Value -ne 0)
                    $uacColor = if ($uacEnabled) { $successColor } else { $dangerColor }
                    $uacText = if ($uacEnabled) { 'Enabled' } else { 'Disabled (EnableLUA=0)' }
                    $facts.Add([pscustomobject]@{ Label = 'UAC:'; Value = $uacText; Color = $uacColor })
                }
                'Value missing' {
                    $facts.Add([pscustomobject]@{ Label = 'UAC:'; Value = 'Not set (default enabled)'; Color = $textColor })
                }
                'Key missing' {
                    $facts.Add([pscustomobject]@{ Label = 'UAC:'; Value = 'Key missing (default enabled)'; Color = $textColor })
                }
                'Access denied' {
                    $facts.Add([pscustomobject]@{ Label = 'UAC:'; Value = 'UNKNOWN (access denied)'; Color = $warnColor })
                    Add-ScanIssue 'Appinfo' "No se pudo leer EnableLUA: $($luaEvidence.Error)"
                }
                default {
                    $facts.Add([pscustomobject]@{ Label = 'UAC:'; Value = 'UNKNOWN (read error)'; Color = $warnColor })
                    Add-ScanIssue 'Appinfo' "Error al leer EnableLUA: $($luaEvidence.Error)"
                }
            }
        }
        'DcomLaunch' {
            if (-not $processSnapshot) {
                $facts.Add([pscustomobject]@{ Label = 'Child processes:'; Value = 'UNKNOWN (snapshot unavailable)'; Color = $warnColor })
                Add-ScanIssue 'DcomLaunch' 'No se pudo obtener la lista de procesos'
            } else {
                $children = 0
                if ($ProcessId) {
                    $children = @($processSnapshot | Where-Object { [int]$_.ParentProcessId -eq [int]$ProcessId }).Count
                }
                $facts.Add([pscustomobject]@{ Label = 'Child processes:'; Value = [string]$children; Color = $textColor })
            }
        }
        'WSearch' {
            $edbPath = Join-Path $env:ProgramData 'Microsoft\Search\Data\Applications\Windows\Windows.edb'
            $edbStatus = Get-PathEvidence $edbPath
            $facts.Add([pscustomobject]@{ Label = 'Index DB:'; Value = $edbStatus; Color = (Get-PathValueColor $edbStatus) })
        }
        'BAM' {
            $bamState = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State'
            $bamStatus = Get-PathEvidence $bamState
            $facts.Add([pscustomobject]@{ Label = 'BAM state:'; Value = $bamStatus; Color = (Get-PathValueColor $bamStatus) })
        }
        'DPS' {
            $wdiKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI'
            $wdiStatus = Get-PathEvidence $wdiKey
            if ($wdiStatus -eq 'Present') {
                $facts.Add([pscustomobject]@{ Label = 'WDI policy:'; Value = 'Configured'; Color = $textColor })
            } elseif ($wdiStatus -eq 'Access denied') {
                $facts.Add([pscustomobject]@{ Label = 'WDI policy:'; Value = 'UNKNOWN (access denied)'; Color = $warnColor })
            } else {
                $facts.Add([pscustomobject]@{ Label = 'WDI policy:'; Value = 'Not configured'; Color = $textColor })
            }
        }
    }

    return $facts.ToArray()
}

function Get-ServiceEventFacts {
    param(
        $BootTime,
        [hashtable]$ServiceMap
    )

    $facts = @{}
    $since = if ($BootTime) { $BootTime.AddMinutes(-1) } else { (Get-Date).AddDays(-7) }

    $meta = [pscustomobject]@{
        Has7036       = $false
        NoEvents7036  = $false
        ReadError7036 = $false
        Has7040       = $false
        NoEvents7040  = $false
        ReadError7040 = $false
        Has7045       = $false
        LastError     = $null
    }
    $facts['__meta'] = $meta

    foreach ($eventId in @(7036, 7040, 7045)) {
        $events = @()
        try {
            $events = @(Get-WinEvent -FilterHashtable @{
                LogName   = 'System'
                Id        = $eventId
                StartTime = $since
            } -ErrorAction Stop)
        } catch {
            $meta.LastError = $_.Exception.Message
            $noEvents = $meta.LastError -match '(?i)No events were found|No matching events'
            if ($noEvents) {
                if ($eventId -eq 7036) { $meta.Has7036 = $true; $meta.NoEvents7036 = $true }
                elseif ($eventId -eq 7040) { $meta.Has7040 = $true; $meta.NoEvents7040 = $true }
                elseif ($eventId -eq 7045) { $meta.Has7045 = $true }
            } else {
                if ($eventId -eq 7036) { $meta.ReadError7036 = $true }
                elseif ($eventId -eq 7040) { $meta.ReadError7040 = $true }
                if ($eventId -eq 7036) {
                    Add-ScanIssue 'Service Status' "No se pudieron leer eventos SCM 7036: $($meta.LastError)"
                }
            }
            continue
        }

        switch ($eventId) {
            7036 { $meta.Has7036 = $true }
            7040 { $meta.Has7040 = $true }
            7045 { $meta.Has7045 = $true }
        }

        foreach ($event in $events) {
            try {
                [xml]$xml = $event.ToXml()
                $data = @{}
                foreach ($entry in @($xml.Event.EventData.Data)) {
                    if ($entry.Name) { $data[[string]$entry.Name] = [string]$entry.'#text' }
                }

                $keys = @()
                if ($eventId -eq 7036) {
                    $displayName = [string]$data['param1']
                    if ($displayName) {
                        if ($ServiceMap.ContainsKey($displayName)) {
                            $keys += $ServiceMap[$displayName]
                        } else {
                            $keys += $displayName
                        }
                    }
                } elseif ($eventId -eq 7040) {
                    if ($data['param4']) { $keys += [string]$data['param4'] }
                } else {
                    if ($data['ServiceName']) { $keys += [string]$data['ServiceName'] }
                }

                foreach ($key in $keys) {
                    if ([string]::IsNullOrWhiteSpace($key)) { continue }

                    if (-not $facts.ContainsKey($key)) {
                        $facts[$key] = [pscustomobject]@{
                            Starts   = [Collections.Generic.List[datetime]]::new()
                            Stops    = [Collections.Generic.List[datetime]]::new()
                            Changes  = [Collections.Generic.List[object]]::new()
                            Installs = [Collections.Generic.List[datetime]]::new()
                        }
                    }

                    if ($eventId -eq 7036) {
                        $state = [string]$data['param2']
                        if ($state -eq 'running') {
                            $facts[$key].Starts.Add($event.TimeCreated)
                        } elseif ($state -eq 'stopped') {
                            $facts[$key].Stops.Add($event.TimeCreated)
                        }
                    } elseif ($eventId -eq 7040) {
                        $facts[$key].Changes.Add([pscustomobject]@{
                            Time = $event.TimeCreated
                            From = [string]$data['param2']
                            To   = [string]$data['param3']
                        })
                    } else {
                        $facts[$key].Installs.Add($event.TimeCreated)
                    }
                }
            } catch {}
        }
    }

    return $facts
}

function Split-CommandLine {
    param([string]$CommandLine)

    $tokens = [Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $tokens.ToArray() }

    $builder = [Text.StringBuilder]::new()
    $inQuotes = $false

    for ($i = 0; $i -lt $CommandLine.Length; $i++) {
        $character = $CommandLine[$i]

        if ($character -eq '"') {
            if ($inQuotes -and ($i + 1) -lt $CommandLine.Length -and $CommandLine[$i + 1] -eq '"') {
                [void]$builder.Append('"')
                $i++
            } else {
                $inQuotes = -not $inQuotes
            }
        } elseif ([char]::IsWhiteSpace($character) -and -not $inQuotes) {
            if ($builder.Length -gt 0) {
                $tokens.Add($builder.ToString())
                [void]$builder.Clear()
            }
        } else {
            [void]$builder.Append($character)
        }
    }

    if ($builder.Length -gt 0) { $tokens.Add($builder.ToString()) }
    return $tokens.ToArray()
}

function Get-LaunchInfo {
    param([string]$CommandLine)

    $info = [pscustomobject]@{
        IsMinecraft = $false
        GameDir     = $null
        Arguments   = [Collections.Generic.List[object]]::new()
    }

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $info }

    $minecraftPatterns = @(
        'net\.minecraft',
        '--gameDir',
        '-Dminecraft',
        '--assetIndex',
        'fabric-loader',
        'net\.fabricmc',
        'cpw\.mods',
        'theseus',
        'lunarclient',
        'badlion'
    )

    foreach ($pattern in $minecraftPatterns) {
        if ($CommandLine -match $pattern) {
            $info.IsMinecraft = $true
            break
        }
    }

    $tokens = @(Split-CommandLine -CommandLine $CommandLine)
    $valueSwitches = @(
        'Dloader.addMods',
        'Dloader.modsFolder',
        'Dloader.modsDir',
        'Dfabric.addMods',
        'Dfabric.modsFolder',
        'Dfabric.modsDir',
        'javaagent',
        'workdir',
        'gameDir',
        'Dgamedir'
    )

    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $token = $tokens[$i]
        if (-not $token.StartsWith('-')) { continue }

        $raw = $token.TrimStart('-')
        $name = $raw
        $value = $null
        $separator = $raw.IndexOfAny([char[]]@('=', ':'))

        if ($separator -ge 0) {
            $name = $raw.Substring(0, $separator)
            $value = $raw.Substring($separator + 1).Trim('"')
        } elseif (
            ($i + 1) -lt $tokens.Count -and
            -not $tokens[$i + 1].StartsWith('-') -and
            ($valueSwitches -contains $name)
        ) {
            $value = $tokens[$i + 1].Trim('"')
            $i++
        }

        if ($name -match '^(?:D)?gameDir$') {
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $info.GameDir = $value
                $info.IsMinecraft = $true
            }
            continue
        }

        if ($name -match '^(?:Dloader\.(?:addMods|modsFolder|modsDir)|Dfabric\.(?:addMods|modsFolder|modsDir)|javaagent|workdir)$') {
            $argumentColor = $warnColor
            if ($name -eq 'javaagent' -and $value -and $value -match '(?i)theseus\.jar') {
                $argumentColor = $successColor
            } elseif ($name -eq 'workdir') {
                $argumentColor = $subtColor
            }

            $info.Arguments.Add([pscustomobject]@{
                Name  = $name
                Value = if ($null -ne $value) { $value } else { '(no value)' }
                Color = $argumentColor
            })

            if ($name -match '^(?:Dloader|Dfabric)\.') {
                $info.IsMinecraft = $true
            }
        }
    }

    return $info
}

function Get-JavaLauncherExecutions {
    param([string]$Path)

    $results = [ordered]@{}
    $lastDate = $null
    $dateRegexes = @(
        '\[(?<d>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})',
        '\[(?<d>\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2})',
        '\[(?<d>\d{1,2}/\d{1,2}/\d{4}[ T]\d{1,2}:\d{2}:\d{2})'
    )

    $script:JavaLauncherReadError = $null
    $lines = @()
    try {
        $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
    } catch {
        $script:JavaLauncherReadError = $_.Exception.Message
        Add-ScanIssue 'TEMP' "No se pudo leer $Path : $($_.Exception.Message)"
    }

    foreach ($line in $lines) {
        $lineDate = $null

        foreach ($regex in $dateRegexes) {
            $match = [regex]::Match($line, $regex)
            if ($match.Success) {
                $parsed = [datetime]::MinValue
                if ([datetime]::TryParse(
                        $match.Groups['d'].Value,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::None,
                        [ref]$parsed)) {
                    $lineDate = $parsed
                }
                break
            }
        }

        if ($lineDate) { $lastDate = $lineDate }

        $jarMatch = [regex]::Match($line, '(?i)-jar(?:\s+|=)(?:"(?<jar>[^"]+)"|(?<jar>[^\s]+))')
        if ($jarMatch.Success) {
            $jarPath = $jarMatch.Groups['jar'].Value.Trim('"', "'")
            $jarPath = $jarPath.TrimEnd([char[]]@(')', ']', '}', ',', ';'))
            if ($jarPath -notmatch '^\\\\') { $jarPath = $jarPath -replace '\\\\', '\' }
            if (-not [string]::IsNullOrWhiteSpace($jarPath)) {
                $when = if ($lineDate) { $lineDate } elseif ($lastDate) { $lastDate } else { $null }
                $isJavaJar = [bool]($line -match '(?i)\bjava(?:w)?(?:\.exe)?\b.*\s-jar(?:\s+|=)')
                $results[$jarPath] = [pscustomobject]@{
                    Date    = $when
                    JavaJar = $isJavaJar
                }
            }
        }
    }

    $list = [Collections.Generic.List[object]]::new()
    foreach ($key in $results.Keys) {
        $list.Add([pscustomobject]@{
            Jar     = $key
            Date    = $results[$key].Date
            JavaJar = $results[$key].JavaJar
        })
    }

    return $list.ToArray()
}

function Get-DeletedPrefetchCount {
    param([string]$Volume = 'C:')

    $result = [pscustomobject]@{
        Events = $null
        Files  = $null
        Status = 'Unavailable'
        Detail = $null
    }

    $token   = [guid]::NewGuid().ToString('N')
    $runDir  = Join-Path $env:TEMP ('psico_usn_' + $token)
    $outFile = Join-Path $runDir 'journal.csv'
    $errFile = Join-Path $runDir 'journal.err'
    $letter  = ($Volume -replace '[:\\/]', '').Trim()

    if ([string]::IsNullOrWhiteSpace($letter)) {
        $result.Status = 'Invalid volume'
        return $result
    }

    $fsutil = Join-Path $env:SystemRoot 'System32\fsutil.exe'
    if (-not (Test-Path -LiteralPath $fsutil -PathType Leaf)) {
        $result.Status = 'fsutil missing'
        $result.Detail = $fsutil
        Add-ScanIssue 'Prefetch / USN' "No se encontro fsutil.exe en $fsutil"
        return $result
    }

    $prefetchRel = '\Windows\Prefetch'
    if ($env:SystemRoot -match '^[A-Za-z]:\\(.*)$') {
        $prefetchRel = '\' + $Matches[1].TrimEnd('\') + '\Prefetch'
    }
    $prefetchPrefix = ($prefetchRel.TrimEnd('\') + '\').ToUpperInvariant()

    $process = $null
    $parser = $null
    try {
        $null = New-Item -ItemType Directory -Path $runDir -Force -ErrorAction Stop

        $process = Start-Process -FilePath $fsutil `
            -ArgumentList @('usn', 'readjournal', ($letter + ':'), 'csv') `
            -NoNewWindow -PassThru `
            -RedirectStandardOutput $outFile `
            -RedirectStandardError $errFile `
            -ErrorAction Stop

        $fsutilTimeoutMs = 180000
        $finished = $process.WaitForExit($fsutilTimeoutMs)
        if (-not $finished) {
            try { $process.Kill() } catch {}
            $result.Status = 'Timeout'
            $result.Detail = "fsutil no termino en $([int]($fsutilTimeoutMs / 1000)) segundos"
            Add-ScanIssue 'Prefetch / USN' 'fsutil usn readjournal supero el tiempo limite'
            return $result
        }

        $errText = ''
        if (Test-Path -LiteralPath $errFile) {
            $errText = [IO.File]::ReadAllText($errFile).Trim()
        }

        if ($errText -match '(?i)access is denied|denied|privilege|not have') {
            $result.Status = 'Access denied'
            $result.Detail = $errText
            Add-ScanIssue 'Prefetch / USN' "fsutil denego el acceso al journal: $errText"
            return $result
        }

        $exitCode = 'unknown'
        try {
            $process.Refresh()
            $exitValue = $process.ExitCode
            if ($null -ne $exitValue) { $exitCode = $exitValue }
        } catch {}

        if (-not (Test-Path -LiteralPath $outFile)) {
            $result.Status = 'No output'
            $result.Detail = if ($errText) { $errText } else { "fsutil no genero salida (exit code $exitCode)" }
            Add-ScanIssue 'Prefetch / USN' 'fsutil no genero salida CSV'
            return $result
        }

        $firstLine = Get-Content -LiteralPath $outFile -TotalCount 1 -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($firstLine)) {
            $result.Status = 'No output'
            $result.Detail = if ($errText) { $errText } else { "La salida CSV del journal esta vacia (exit code $exitCode)" }
            Add-ScanIssue 'Prefetch / USN' 'La salida CSV del journal esta vacia'
            return $result
        }

        $outputHead = @(Get-Content -LiteralPath $outFile -TotalCount 5 -ErrorAction SilentlyContinue)
        $combinedHead = ($errText + ' ' + ($outputHead -join ' '))
        if ($combinedHead -match '(?i)access is denied|access denied|not have|privilege') {
            $result.Status = 'Access denied'
            $result.Detail = $combinedHead.Trim()
            Add-ScanIssue 'Prefetch / USN' "fsutil denego el acceso al journal: $($result.Detail)"
            return $result
        }

        Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
        $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($outFile)
        $parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
        $parser.SetDelimiters(',')
        $parser.HasFieldsEnclosedInQuotes = $true
        $parser.TrimWhiteSpace = $false

        $header = $null
        while (-not $parser.EndOfData) {
            $fields = $null
            try { $fields = $parser.ReadFields() } catch { break }
            if ($null -eq $fields -or $fields.Count -lt 2) { continue }
            if ($fields[0] -ne 'Usn') { continue }
            if ([Array]::IndexOf($fields, 'File name') -ge 0) { $header = $fields; break }
        }

        if (-not $header) {
            $result.Status = 'Parse error'
            $result.Detail = 'No se encontro la cabecera CSV (Usn, File name, ...) en la salida de fsutil'
            Add-ScanIssue 'Prefetch / USN' $result.Detail
            return $result
        }

        $nameIdx = [Array]::IndexOf($header, 'File name')
        $reasonIdx = [Array]::IndexOf($header, 'Reason #')
        $reasonTextIdx = [Array]::IndexOf($header, 'Reason')
        $parentIdx = [Array]::IndexOf($header, 'Parent file ID')

        if ($nameIdx -lt 0 -or $reasonIdx -lt 0) {
            $result.Status = 'Parse error'
            $result.Detail = 'Faltan columnas esperadas (File name, Reason #)'
            Add-ScanIssue 'Prefetch / USN' $result.Detail
            return $result
        }

        # fsutil emits only leaf names, so the directory must be resolved through Parent file ID.
        $prefetchFullPath = Join-Path $env:SystemRoot 'Prefetch'
        $prefetchId = $null
        $idError = $null
        try {
            $idOutput = @(& $fsutil file queryfileid $prefetchFullPath 2>&1)
            $idText = (($idOutput | ForEach-Object { [string]$_ }) -join ' ').Trim()
            $idMatch = [regex]::Match($idText, '(?i)File ID is\s+(0x[0-9A-Fa-f]+)')
            if ($idMatch.Success) {
                $prefetchId = $idMatch.Groups[1].Value.Substring(2).PadLeft(32, '0').ToLowerInvariant()
            } else {
                $idError = $idText
            }
        } catch {
            $idError = $_.Exception.Message
        }

        $deleteEvents = 0
        $deletedFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $totalRows = 0
        $pfRows = 0
        $parseFailures = 0
        $hasPathNames = $false

        while (-not $parser.EndOfData) {
            $fields = $null
            try {
                $fields = $parser.ReadFields()
            } catch {
                $parseFailures++
                continue
            }
            if ($null -eq $fields) { continue }
            if ($fields.Count -le $nameIdx) { continue }
            $totalRows++

            $name = [string]$fields[$nameIdx]
            if ([string]::IsNullOrWhiteSpace($name)) { continue }

            $leaf = $name
            $inPrefetch = $false

            if ($name.IndexOf('\') -ge 0 -or $name.IndexOf('/') -ge 0 -or $name -match '^[A-Za-z]:') {
                $hasPathNames = $true
                $normalized = ($name -replace '/', '\')
                $normalized = ($normalized -replace '^\\\\\?\\', '')
                $normalized = ($normalized -replace '^\\\?\?\\', '')
                $normalized = ($normalized -replace '\\{2,}', '\')
                if ($normalized -match '^[A-Za-z]:') { $normalized = $normalized.Substring(2) }
                $normalized = '\' + $normalized.TrimStart('\')
                $upperPath = $normalized.ToUpperInvariant()

                if ($upperPath.StartsWith($prefetchPrefix, [StringComparison]::OrdinalIgnoreCase) -and $upperPath.Length -gt $prefetchPrefix.Length) {
                    $inPrefetch = $true
                    $leaf = $normalized.Substring($normalized.LastIndexOf('\') + 1)
                }
            } elseif ($null -ne $prefetchId -and $parentIdx -ge 0 -and $fields.Count -gt $parentIdx) {
                $recordParent = ([string]$fields[$parentIdx]).Trim().ToLowerInvariant()
                if ($recordParent -match '^[0-9A-Fa-f]{1,32}$') {
                    $recordParent = $recordParent.PadLeft(32, '0')
                    if ($recordParent -eq $prefetchId) { $inPrefetch = $true }
                }
            }

            if (-not $inPrefetch) { continue }
            if (-not $leaf.EndsWith('.pf', [StringComparison]::OrdinalIgnoreCase)) { continue }
            $pfRows++

            $reasonRaw = [string]$fields[$reasonIdx]
            $reasonText = ''
            if ($reasonTextIdx -ge 0 -and $fields.Count -gt $reasonTextIdx) {
                $reasonText = [string]$fields[$reasonTextIdx]
            }

            $isDelete = $false
            $reasonValue = $null
            if ($reasonRaw -match '^0x([0-9A-Fa-f]{1,16})$') {
                $reasonValue = [Convert]::ToInt64($Matches[1], 16)
            } elseif ($reasonRaw -match '^\d{1,19}$') {
                $reasonValue = [Convert]::ToInt64($reasonRaw)
            }

            if ($null -ne $reasonValue) {
                $isDelete = (($reasonValue -band 0x200) -ne 0)
            } elseif ($reasonText -match '(?i)delete') {
                $isDelete = $true
            }

            if ($isDelete) {
                $deleteEvents++
                [void]$deletedFiles.Add($leaf.ToUpperInvariant())
            }
        }

        if ($null -eq $prefetchId -and -not $hasPathNames) {
            $result.Status = 'Unknown (Prefetch folder ID unavailable)'
            $result.Detail = if ($idError) {
                "No se pudo verificar que los .pf pertenezcan a $prefetchFullPath : $idError"
            } else {
                "No se pudo obtener el File ID de $prefetchFullPath"
            }
            Add-ScanIssue 'Prefetch / USN' $result.Detail
            return $result
        }

        if ($parseFailures -gt 0) {
            Add-ScanIssue 'Prefetch / USN' "$parseFailures linea(s) del journal no se pudieron parsear"
        }

        $methodText = if ($hasPathNames) { 'ruta completa' } else { "parent file ID 0x$prefetchId" }

        $result.Events = $deleteEvents
        $result.Files = $deletedFiles.Count
        $result.Detail = "Filas: $totalRows; .pf en Prefetch: $pfRows; metodo: $methodText"
        $result.Status = 'OK'
    } catch {
        $result.Status = 'Read error'
        $result.Detail = $_.Exception.Message
        Add-ScanIssue 'Prefetch / USN' "Error al ejecutar fsutil: $($_.Exception.Message)"
    } finally {
        if ($parser) {
            try { $parser.Close() } catch {}
        }
        if ($process -and -not $process.HasExited) {
            try { $process.Kill() } catch {}
        }
        Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    return $result
}

# --- Banner y cabecera --------------------------------------------------------
$psicoBanner = @(
    '██████╗  ███████╗ ██╗  ██████╗  ██████╗',
    '██╔══██╗ ██╔════╝ ██║ ██╔════╝ ██╔═══██╗',
    '██████╔╝ ███████╗ ██║ ██║      ██║   ██║',
    '██╔═══╝  ╚════██║ ██║ ██║      ██║   ██║',
    '██║      ███████║ ██║ ╚██████╗ ╚██████╔╝',
    '╚═╝      ╚══════╝ ╚═╝  ╚═════╝  ╚═════╝'
)

$checkerBanner = @(
    ' ██████╗ ██╗  ██╗ ███████╗  ██████╗ ██╗  ██╗ ███████╗ ██████╗',
    '██╔════╝ ██║  ██║ ██╔════╝ ██╔════╝ ██║ ██╔╝ ██╔════╝ ██╔══██╗',
    '██║      ███████║ █████╗   ██║      █████╔╝  █████╗   ██████╔╝',
    '██║      ██╔══██║ ██╔══╝   ██║      ██╔═██╗  ██╔══╝   ██╔══██╗',
    '╚██████╗ ██║  ██║ ███████╗ ╚██████╗ ██║  ██╗ ███████╗ ██║  ██║',
    ' ╚═════╝ ╚═╝  ╚═╝ ╚══════╝  ╚═════╝ ╚═╝  ╚═╝ ╚══════╝ ╚═╝  ╚═╝'
)

Write-GradientRow ('╔' + ('═' * $panelInner) + '╗') $frameFrom $frameTo
Write-GradientRow ('║' + (' ' * $panelInner) + '║') $frameFrom $frameTo

foreach ($row in $psicoBanner) {
    Write-GradientRow ('║' + (Center-Inner $row $panelInner) + '║') $bannerFrom $bannerTo
}

Write-GradientRow ('║' + (' ' * $panelInner) + '║') $frameFrom $frameTo

foreach ($row in $checkerBanner) {
    Write-GradientRow ('║' + (Center-Inner $row $panelInner) + '║') $bannerFrom $bannerTo
}

Write-GradientRow ('║' + (' ' * $panelInner) + '║') $frameFrom $frameTo
Write-GradientRow ('║' + (Center-Inner '»» @psicoseado ««' $panelInner) + '║') $frameFrom $frameTo
Write-GradientRow ('║' + (' ' * $panelInner) + '║') $frameFrom $frameTo
Write-GradientRow ('╚' + ('═' * $panelInner) + '╝') $frameFrom $frameTo
Write-Host ''

$startDate = Get-Date
$osCaption = 'Windows'
try { $osCaption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption } catch {}

$infoLine1 = '  EQUIPO   : ' + $env:COMPUTERNAME.PadRight(24) + 'USUARIO : ' + $env:USERNAME
$infoLine2 = '  SISTEMA  : ' + $osCaption
$infoLine3 = '  FECHA    : ' + $startDate.ToString('dd-MM-yyyy HH:mm:ss')

Write-GradientRow ('╔' + ('═' * $panelInner) + '╗') $frameFrom $frameTo
foreach ($line in @($infoLine1, $infoLine2, $infoLine3)) {
    if ($line.Length -gt $panelInner) { $line = $line.Substring(0, $panelInner) }
    Write-Host '║' -ForegroundColor DarkCyan -NoNewline
    Write-Host $line.PadRight($panelInner) -ForegroundColor $textColor -NoNewline
    Write-Host '║' -ForegroundColor DarkCyan
}
Write-GradientRow ('╚' + ('═' * $panelInner) + '╝') $frameFrom $frameTo
Write-Host ''

# --- GENERAL INFORMATION ------------------------------------------------------
Write-SectionHeader 'GENERAL INFORMATION'

Write-SubSection 'System boot time'
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($osInfo) {
    $bootTime = $osInfo.LastBootUpTime
    $upTime = (Get-Date) - $bootTime
    Write-Host ($infoIndex + 'Last Boot:'.PadRight($fieldWidth)) -ForegroundColor $textColor -NoNewline
    Write-Host ($bootTime.ToString($formatDate) + ' ') -ForegroundColor $successColor -NoNewline
    Write-Host ('(' + (Format-Duration $upTime) + ')') -ForegroundColor $textColor
} else {
    Write-Field 'Last Boot:' 'Unknown' $fieldWidth $textColor $warnColor
}

Write-Host ''
Write-SubSection 'Connected drives'
$drives = @(Get-Drives)
if ($drives.Count -gt 0) {
    $driveNumber = 0

    foreach ($drive in $drives) {
        $driveNumber++
        $encryption = Get-VolumeEncryptionInfo -Volume $drive
        $capacityText = if ($drive.Capacity) { Format-Bytes ([double]$drive.Capacity) } else { 'Unknown' }
        $labelText = if ($drive.Label) { $drive.Label } else { '(no label)' }
        $priorityColor = switch ($encryption.Priority) {
            'CRITICAL' { $dangerColor }
            'HIGH'     { $warnColor }
            'REVIEW'   { $warnColor }
            'INFO'     { $subtColor }
            default    { $successColor }
        }

        if ($driveNumber -gt 1) {
            Write-Host ''
            Write-ThinSeparator
        }

        Write-Host ($infoIndex + $drive.DriveLetter + '  ' + $drive.FileSystem + '  ' + $labelText) -ForegroundColor $titleColor
        Write-Field 'Capacity:' $capacityText $fieldWidth $textColor $subtColor
        Write-Field 'Device:' $drive.DevicePath $fieldWidth $textColor $subtColor
        Write-Field 'Encrypted:' $encryption.Encrypted $fieldWidth $textColor $priorityColor
        Write-Field 'Type:' $encryption.Type $fieldWidth $textColor $priorityColor
        Write-Field 'Access:' $encryption.Access $fieldWidth $textColor $priorityColor
        Write-Field 'Live:' $encryption.LiveUnlock $fieldWidth $textColor $priorityColor
        Write-Field 'RAM:' $encryption.MemAcquire $fieldWidth $textColor $priorityColor
        Write-Field 'Priority:' $encryption.Priority $fieldWidth $textColor $priorityColor
        if ($encryption.Evidence) {
            Write-Host ($infoIndex + '  |- ' + $encryption.Evidence) -ForegroundColor $subtColor
        }
    }
} else {
    Write-Host ($infoIndex + 'No drives found') -ForegroundColor $warnColor
}

Write-Host ''
Write-SubSection 'Minecraft Information'
$javaProcesses = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction SilentlyContinue)
$foundAnyMc = $false

foreach ($process in $javaProcesses) {
    $launchInfo = Get-LaunchInfo -CommandLine $process.CommandLine
    if (-not $launchInfo.IsMinecraft) { continue }

    $foundAnyMc = $true
    $processId = $process.ProcessId
    $liveProcess = Get-Process -Id $processId -ErrorAction SilentlyContinue
    $startTime = $process.CreationDate
    if (-not $startTime -and $liveProcess) { $startTime = $liveProcess.StartTime }

    $processUpTime = if ($startTime) { (Get-Date) - $startTime } else { $null }
    $processName = if ($liveProcess -and $liveProcess.MainWindowTitle) {
        $liveProcess.MainWindowTitle
    } else {
        $process.Name
    }
    $gameDir = if ($launchInfo.GameDir) { $launchInfo.GameDir } else { 'Unknown' }

    Write-Host ($infoIndex + "MC process found '$processName' ($processId) ") -ForegroundColor $textColor -NoNewline
    Write-Host (Format-Duration $processUpTime) -ForegroundColor $textColor
    Write-Field 'Folder:' $gameDir $fieldWidth $textColor $subtColor

    if ($launchInfo.Arguments.Count -gt 0) {
        Write-Host ($infoIndex + 'Arguments:') -ForegroundColor $textColor
        foreach ($argument in $launchInfo.Arguments) {
            Write-Host ($infoIndex + '  - ' + $argument.Name + ': ') -ForegroundColor $subtColor -NoNewline
            Write-Host $argument.Value -ForegroundColor $argument.Color
        }
    }

    Write-Host ''
}

if (-not $foundAnyMc) {
    Write-Host ($infoIndex + 'No Minecraft processes found...') -ForegroundColor $warnColor
}

Write-Host ''
Write-SubSection 'Java -jar launches (since boot)'

if (-not $bootTime) {
    $bootFallback = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($bootFallback) { $bootTime = $bootFallback.LastBootUpTime }
}

$dcomLaunchPid = $null
$dcomService = Get-CimInstance -ClassName Win32_Service -Filter "Name='DcomLaunch'" -ErrorAction SilentlyContinue
if ($dcomService) { $dcomLaunchPid = [int]$dcomService.ProcessId }

$processSnapshot = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)
$processMap = @{}
foreach ($processEntry in $processSnapshot) {
    $processMap[[int]$processEntry.ProcessId] = $processEntry
}

$jarLaunches = [Collections.Generic.List[object]]::new()

foreach ($processEntry in $processSnapshot) {
    $commandLine = $processEntry.CommandLine
    if ([string]::IsNullOrWhiteSpace($commandLine)) { continue }
    if ($commandLine -notmatch '(?i)\bjava(?:w)?(?:\.exe)?\b.*?\s-jar(?:\s+|=)') { continue }

    $created = $processEntry.CreationDate
    if ($bootTime -and $created -and $created -lt $bootTime) { continue }

    $parentPid = [int]$processEntry.ParentProcessId
    $parentName = 'Unknown'
    $cursor = $parentPid
    $underDcomLaunch = $false
    $guard = 0

    while ($cursor -and $guard -lt 12) {
        $guard++

        if ($dcomLaunchPid -and $cursor -eq $dcomLaunchPid) { $underDcomLaunch = $true }

        $parentEntry = $processMap[$cursor]
        if (-not $parentEntry) { break }

        if ($parentName -eq 'Unknown') { $parentName = $parentEntry.Name }

        $next = [int]$parentEntry.ParentProcessId
        if ($next -eq $cursor) { break }
        $cursor = $next
    }

    $jarPath = ''
    $jarMatch = [regex]::Match($commandLine, '(?i)-jar(?:\s+|=)(?:"(?<jar>[^"]+)"|(?<jar>[^\s]+))')
    if ($jarMatch.Success) {
        $jarPath = $jarMatch.Groups['jar'].Value.Trim('"', "'")
        $jarPath = $jarPath.TrimEnd([char[]]@(')', ']', '}', ',', ';'))
    }

    $jarLaunches.Add([pscustomobject]@{
        ProcessId       = $processEntry.ProcessId
        Name            = $processEntry.Name
        Created         = $created
        ParentName      = $parentName
        ParentPid       = $parentPid
        UnderDcomLaunch = $underDcomLaunch
        Jar             = $jarPath
    })
}

if ($dcomService) {
    $dcomChildCount = @($processSnapshot | Where-Object { [int]$_.ParentProcessId -eq $dcomLaunchPid }).Count
    Write-Field 'DcomLaunch PID:' ([string]$dcomLaunchPid) $fieldWidth $textColor $successColor
    Write-Field 'Children:' ([string]$dcomChildCount) $fieldWidth $textColor $subtColor
} else {
    Write-Field 'DcomLaunch PID:' 'Not found' $fieldWidth $textColor $warnColor
}

if ($jarLaunches.Count -eq 0) {
    Write-Host ($infoIndex + 'No java -jar launches found since boot.') -ForegroundColor $successColor
} else {
    Write-Host ($infoIndex + 'Launch(es):'.PadRight($fieldWidth)) -ForegroundColor $textColor -NoNewline
    Write-Host ([string]$jarLaunches.Count) -ForegroundColor $textColor

    $counter = 0
    foreach ($launch in $jarLaunches) {
        $counter++
        $launchDate = if ($launch.Created) { $launch.Created.ToString($formatDate) } else { 'Unknown' }
        $jarText = if ($launch.Jar) { $launch.Jar } else { 'Unknown' }

        Write-Host ($infoIndex + "  $counter. $launchDate  PID $($launch.ProcessId)  $($launch.Name)") -ForegroundColor $titleColor
        Write-Host ($infoIndex + '     |- Jar:        ') -ForegroundColor $subtColor -NoNewline
        Write-Host $jarText -ForegroundColor $textColor
        Write-Host ($infoIndex + '     |- Parent:     ') -ForegroundColor $subtColor -NoNewline
        Write-Host ("$($launch.ParentName) ($($launch.ParentPid))") -ForegroundColor $textColor
        Write-Host ($infoIndex + '     |- DcomLaunch: ') -ForegroundColor $subtColor -NoNewline

        if ($launch.UnderDcomLaunch) {
            Write-Host 'Yes (normal for jar launched from Explorer)' -ForegroundColor $textColor
        } else {
            Write-Host 'No' -ForegroundColor $textColor
        }
    }
}

# --- HARDWARE UTILIZATION -----------------------------------------------------
Write-SectionHeader 'HARDWARE UTILIZATION'

Write-SubSection 'CPU'
$cpuInfo = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1

if ($cpuInfo) {
    Write-Field 'Model:' $cpuInfo.Name.Trim() $fieldWidth $textColor $subtColor
    Write-Field 'Cores / Threads:' ("{0} / {1}" -f $cpuInfo.NumberOfCores, $cpuInfo.NumberOfLogicalProcessors) $fieldWidth $textColor $subtColor
    Write-Field 'Max clock:' ("{0:N0} MHz" -f $cpuInfo.MaxClockSpeed) $fieldWidth $textColor $subtColor

    $cpuUsage = $null
    if ($null -ne $cpuInfo.LoadPercentage) {
        $cpuUsage = [double]$cpuInfo.LoadPercentage
    } else {
        try {
            $cpuUsage = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop).CounterSamples[0].CookedValue
        } catch {}
    }

    if ($null -ne $cpuUsage) {
        Write-UsageBar 'Usage:' $cpuUsage
    } else {
        Write-Field 'Usage:' 'Unavailable' $fieldWidth $textColor $warnColor
    }
} else {
    Write-Host ($infoIndex + 'CPU information unavailable') -ForegroundColor $warnColor
}

Write-Host ''
Write-SubSection 'Memory'
$memInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

if ($memInfo -and $memInfo.TotalVisibleMemorySize) {
    $totalMemory = [double]$memInfo.TotalVisibleMemorySize * 1KB
    $freeMemory  = [double]$memInfo.FreePhysicalMemory * 1KB
    $usedMemory  = $totalMemory - $freeMemory
    $memPercent  = if ($totalMemory -gt 0) { ($usedMemory / $totalMemory) * 100 } else { 0 }

    Write-Field 'Installed:' (Format-Bytes $totalMemory) $fieldWidth $textColor $subtColor
    Write-Field 'In use:' (Format-Bytes $usedMemory) $fieldWidth $textColor $subtColor
    Write-Field 'Available:' (Format-Bytes $freeMemory) $fieldWidth $textColor $subtColor
    Write-UsageBar 'Usage:' $memPercent
} else {
    Write-Host ($infoIndex + 'Memory information unavailable') -ForegroundColor $warnColor
}

Write-Host ''
Write-SubSection 'GPU'
$gpuInfo = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue | Where-Object { $_.Name })

if ($gpuInfo.Count -gt 0) {
    $gpuCounter = 0

    foreach ($gpu in $gpuInfo) {
        $gpuCounter++
        if ($gpuInfo.Count -gt 1) {
            Write-Host ($infoIndex + "GPU $gpuCounter") -ForegroundColor $titleColor
        }

        Write-Field 'Model:' $gpu.Name $fieldWidth $textColor $subtColor
        Write-Field 'Driver:' $gpu.DriverVersion $fieldWidth $textColor $subtColor
        $vramText = if ($gpu.AdapterRAM -and $gpu.AdapterRAM -gt 0) { Format-Bytes ([double]$gpu.AdapterRAM) } else { 'Unknown' }
        Write-Field 'VRAM (reported):' $vramText $fieldWidth $textColor $subtColor
    }

    $gpuUsage = $null
    try {
        $gpuSamples = @((Get-Counter '\GPU Engine(*)\Utilization Percentage' -ErrorAction Stop).CounterSamples |
            Where-Object { $_.CookedValue -ge 0 })

        if ($gpuSamples.Count -gt 0) {
            $gpuUsage = ($gpuSamples | Measure-Object -Property CookedValue -Maximum).Maximum
        }
    } catch {}

    if ($null -ne $gpuUsage) {
        Write-UsageBar 'Usage:' ([double]$gpuUsage) '(busiest engine)'
    } else {
        Write-Field 'Usage:' 'Unavailable' $fieldWidth $textColor $warnColor
    }
} else {
    Write-Host ($infoIndex + 'GPU information unavailable') -ForegroundColor $warnColor
}

Write-Host ''
Write-SubSection 'Disk'
$diskActivity = $null
try {
    $diskIdle = (Get-Counter '\PhysicalDisk(_Total)\% Idle Time' -ErrorAction Stop).CounterSamples[0].CookedValue
    $diskActivity = 100 - $diskIdle
} catch {}

if ($null -ne $diskActivity) {
    Write-UsageBar 'Activity:' ([double]$diskActivity)
}

$diskInfo = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | Sort-Object DeviceID)
if ($diskInfo.Count -gt 0) {
    foreach ($disk in $diskInfo) {
        $diskTotal = if ($disk.Size) { [double]$disk.Size } else { 0 }
        $diskFree  = if ($disk.FreeSpace) { [double]$disk.FreeSpace } else { 0 }
        $diskUsed  = $diskTotal - $diskFree
        $diskPercent = if ($diskTotal -gt 0) { ($diskUsed / $diskTotal) * 100 } else { 0 }
        $diskSuffix = (Format-Bytes $diskUsed) + ' used of ' + (Format-Bytes $diskTotal)

        Write-UsageBar ("$($disk.DeviceID)") $diskPercent $diskSuffix
    }
} else {
    Write-Host ($infoIndex + 'No fixed drives found') -ForegroundColor $warnColor
}

# --- SERVICE STATUS -----------------------------------------------------------
Write-SectionHeader 'SERVICE STATUS'

if (-not $bootTime) {
    $bootFallback = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($bootFallback) { $bootTime = $bootFallback.LastBootUpTime }
}

$serviceNames = @(
    'SysMain',
    'PcaSvc',
    'DPS',
    'EventLog',
    'Schedule',
    'DiagTrack',
    'DusmSvc',
    'Appinfo',
    'DcomLaunch',
    'wsearch',
    'BAM'
)
$serviceInfo = [Collections.Generic.List[object]]::new()
$allServices = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)
$allDrivers  = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue)
$serviceMap  = @{}

foreach ($serviceEntry in @($allServices) + @($allDrivers)) {
    if ($serviceEntry.DisplayName) { $serviceMap[[string]$serviceEntry.DisplayName] = [string]$serviceEntry.Name }
    if ($serviceEntry.Name) { $serviceMap[[string]$serviceEntry.Name] = [string]$serviceEntry.Name }
}

$serviceEvents = Get-ServiceEventFacts -BootTime $bootTime -ServiceMap $serviceMap

foreach ($serviceName in $serviceNames) {
    $info = $allServices | Where-Object { $_.Name -eq $serviceName } | Select-Object -First 1
    $isDriver = $false

    if (-not $info) {
        $info = $allDrivers | Where-Object { $_.Name -eq $serviceName } | Select-Object -First 1
        $isDriver = $true
    }

    if ($info) {
        $processId = $null
        if (-not $isDriver -and $info.ProcessId) { $processId = [uint32]$info.ProcessId }

        $startTime = $null
        if ($processId) {
            $processEntry = $processSnapshot | Where-Object { [int]$_.ProcessId -eq [int]$processId } | Select-Object -First 1
            if ($processEntry) { $startTime = $processEntry.CreationDate }

            if (-not $startTime) {
                $liveProcess = Get-Process -Id $processId -ErrorAction SilentlyContinue
                if ($liveProcess) {
                    try { $startTime = $liveProcess.StartTime } catch {}
                }
            }
        }

        $serviceInfo.Add([pscustomobject]@{
            Name        = $info.Name
            DisplayName = $info.DisplayName
            State       = [string]$info.State
            StartMode   = [string]$info.StartMode
            Start       = $startTime
            PID         = $processId
            IsDriver    = $isDriver
        })
    } else {
        $serviceInfo.Add([pscustomobject]@{
            Name        = $serviceName
            DisplayName = $serviceName
            State       = 'Not Found'
            StartMode   = 'Unknown'
            Start       = $null
            PID         = $null
            IsDriver    = $false
        })
    }
}

$serviceNumber = 0
foreach ($service in $serviceInfo) {
    $serviceNumber++
    $statusColor = if ($service.State -eq 'Running') { $successColor } else { $warnColor }
    $startTimeText = if ($service.Start) {
        $service.Start.ToString($formatDate)
    } elseif ($service.State -eq 'Running') {
        'N/A (shared/hosted process)'
    } else {
        'N/A'
    }

    $eventInfo = $serviceEvents[$service.Name]
    $eventMeta = $serviceEvents['__meta']
    $starts = @()
    $stops = @()
    $changes = @()
    $installs = @()

    if ($eventInfo) {
        $starts = @($eventInfo.Starts)
        $stops = @($eventInfo.Stops)
        $changes = @($eventInfo.Changes)
        $installs = @($eventInfo.Installs)
    }

    $sharedPid = $false
    if ($service.PID) {
        $sharedPid = @($allServices | Where-Object { $_.ProcessId -eq $service.PID }).Count -gt 1
    }

    # A restart requires SCM evidence: a stop followed by a start. Never infer it
    # from a late process creation time, which is normal on slow boots.
    $restartTimes = [Collections.Generic.List[datetime]]::new()
    foreach ($stopTime in $stops) {
        $nextStart = $starts | Where-Object { $_ -gt $stopTime } | Sort-Object | Select-Object -First 1
        if ($nextStart) { $restartTimes.Add($nextStart) }
    }
    $restartTimes = @($restartTimes | Sort-Object -Unique)

    $ownScmEvidence = (($starts.Count + $stops.Count) -gt 0)

    if ($restartTimes.Count -gt 0) {
        $lastRestart = $restartTimes[-1]
        $restartedText = 'Yes (' + $lastRestart.ToString($formatDate) + ') - context only'
        $restartedColor = $warnColor
    } elseif ($sharedPid -and -not $ownScmEvidence) {
        $restartedText = 'Unknown (shared PID ' + $service.PID
        if ($eventMeta -and $eventMeta.ReadError7036) { $restartedText += '; 7036 read error' }
        elseif ($eventMeta -and $eventMeta.NoEvents7036) { $restartedText += '; no 7036 events since boot' }
        else { $restartedText += '; no per-service 7036 evidence' }
        $restartedText += ')'
        $restartedColor = $warnColor
    } elseif (-not $eventMeta -or $eventMeta.ReadError7036) {
        $restartedText = 'Unknown (7036 read error)'
        $restartedColor = $warnColor
    } elseif ($eventMeta.NoEvents7036) {
        $restartedText = 'Unknown (no 7036 events since boot)'
        $restartedColor = $warnColor
    } elseif ($ownScmEvidence) {
        $restartedText = 'No (no SCM stop/start)'
        $restartedColor = $successColor
    } else {
        $restartedText = 'No (no 7036 events for this service)'
        $restartedColor = $successColor
    }

    if ($changes.Count -gt 0) {
        $lastChange = $changes | Sort-Object Time | Select-Object -Last 1
        $changeText = $lastChange.From + ' -> ' + $lastChange.To + ' (' + $lastChange.Time.ToString($formatDate) + ')'
        if ($changes.Count -gt 1) { $changeText += " - $($changes.Count) changes total" }
        $changeColor = $warnColor
    } elseif ($eventMeta -and $eventMeta.ReadError7040) {
        $changeText = 'Unknown (7040 read error)'
        $changeColor = $warnColor
    } elseif ($eventMeta -and $eventMeta.NoEvents7040) {
        $changeText = 'Unknown (no 7040 events since boot)'
        $changeColor = $warnColor
    } elseif ($eventMeta -and $eventMeta.Has7040) {
        $changeText = 'No (no 7040 change)'
        $changeColor = $successColor
    } else {
        $changeText = 'Unknown (7040 unavailable)'
        $changeColor = $warnColor
    }

    if ($serviceNumber -gt 1) {
        Write-Host ''
    }

    Write-ThinSeparator
    $serviceLabel = if ($service.Name -ieq 'BAM') { 'BAM' } else { $service.Name }
    Write-Host ($infoIndex + $serviceLabel.PadRight(16)) -ForegroundColor $titleColor -NoNewline
    Write-Host ($service.State.PadRight(12)) -ForegroundColor $statusColor -NoNewline
    $pidText = if ($service.PID) { "PID $($service.PID)" } elseif ($service.IsDriver) { 'Driver' } else { 'PID N/A' }
    Write-Host $pidText -ForegroundColor $subtColor
    Write-ThinSeparator

    Write-Field 'Start mode:' $service.StartMode $fieldWidth $textColor $subtColor
    Write-Field 'Started:' $startTimeText $fieldWidth $textColor $subtColor
    Write-Field 'Restarted:' $restartedText $fieldWidth $textColor $restartedColor
    Write-Field 'Config changed:' $changeText $fieldWidth $textColor $changeColor

    if ($installs.Count -gt 0) {
        $installTimes = @($installs | Sort-Object)
        Write-Field 'Installed:' ($installTimes[-1].ToString($formatDate)) $fieldWidth $textColor $warnColor
    }

    $facts = @(Get-ServiceFacts -ServiceName $service.Name -ProcessId $service.PID)
    if ($facts.Count -gt 0) {
        Write-ThinSeparator
        foreach ($fact in $facts) {
            Write-Field $fact.Label $fact.Value $fieldWidth $textColor $fact.Color
        }
    }
}

# --- SUSPICIOUS EVENT LOGS ----------------------------------------------------
Write-SectionHeader 'SUSPICIOUS EVENT LOGS'

$winevt = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels'
$eventLog = 'SYSTEM\CurrentControlSet\Services\EventLog'
$events = @(
    @{
        Message  = 'USN Journal Cleared'
        Log      = '(Ntfs/Operational 3079)'
        LogName  = 'Microsoft-Windows-Ntfs/Operational'
        Registry = "$winevt\Microsoft-Windows-Ntfs/Operational"
        EventId  = 3079
    },
    @{
        Message  = 'Event Logs Cleared'
        Log      = '(System 104)'
        LogName  = 'System'
        Registry = "$eventLog\System"
        EventId  = 104
    },
    @{
        Message  = 'Security Log Cleared'
        Log      = '(Security 1102)'
        LogName  = 'Security'
        Registry = "$eventLog\Security"
        EventId  = 1102
    },
    @{
        Message  = 'EventLog Started'
        Log      = '(System 6005)'
        LogName  = 'System'
        Registry = "$eventLog\System"
        EventId  = 6005
    },
    @{
        Message  = 'System time changed'
        Log      = '(Security 4616)'
        LogName  = 'Security'
        Registry = "$eventLog\Security"
        EventId  = 4616
    },
    @{
        Message  = 'Last executed pipeline'
        Log      = '(PowerShell/Operational 4103)'
        LogName  = 'Microsoft-Windows-PowerShell/Operational'
        Registry = "$winevt\Microsoft-Windows-PowerShell/Operational"
        EventId  = 4103
    }
)

foreach ($event in $events) {
    $lastEventRecord = $null
    $eventReadError = $null
    try {
        $lastEventRecord = Get-WinEvent -LogName $event.LogName -FilterXPath "*[System[EventID=$($event.EventId)]]" -MaxEvents 1 -ErrorAction Stop
    } catch {
        $eventReadError = $_.Exception.Message
    }

    if ($lastEventRecord) {
        $lastEventText = $lastEventRecord.TimeCreated.ToString($formatDate)
        $eventColor = $successColor
    } elseif ($eventReadError -match '(?i)No events were found|No matching events') {
        $lastEventText = 'No records found'
        $eventColor = $subtColor
    } elseif ($eventReadError -match '(?i)not found|does not exist|No such') {
        $lastEventText = 'Log not found'
        $eventColor = $warnColor
    } else {
        $lastEventText = 'UNKNOWN (read error)'
        $eventColor = $warnColor
        Add-ScanIssue 'Event logs' "No se pudo leer $($event.LogName) (ID $($event.EventId)): $eventReadError"
    }

    $lastWrite = $null
    try {
        $lastWrite = [PsicoRegUtil]::GetLastWriteTime([PsicoRegUtil]::HKEY_LOCAL_MACHINE, $event.Registry)
    } catch {}

    $lastWriteText = if ($lastWrite) { $lastWrite.ToString($formatDate) } else { 'Unknown' }

    Write-Host ($titleIndex + $event.Message.PadRight(24) + ': ') -ForegroundColor $textColor -NoNewline
    Write-Host ($lastEventText.PadRight(20) + ' ') -ForegroundColor $eventColor -NoNewline
    Write-Host $event.Log -ForegroundColor $subtColor
    Write-Field 'Last modified:' $lastWriteText $fieldWidth $textColor $subtColor
    Write-Host ''
}

# --- COMMON FILES -------------------------------------------------------------
Write-SectionHeader 'COMMON FILES'

$recyclePath = "$env:SystemDrive\`$Recycle.bin"
Write-SubSection 'Recycle Bin'

if (Test-Path -LiteralPath $recyclePath) {
    $recycleRoot = Get-Item -LiteralPath $recyclePath -Force
    $lastModified = $recycleRoot.LastWriteTime
    $totalItems = 0
    $lastItem = $null
    $recycleError = $null

    try {
        foreach ($sidFolder in @(Get-ChildItem -LiteralPath $recyclePath -Force -Directory -ErrorAction Stop)) {
            if ($sidFolder.LastWriteTime -gt $lastModified) { $lastModified = $sidFolder.LastWriteTime }

            foreach ($item in @(Get-ChildItem -LiteralPath $sidFolder.FullName -Force -ErrorAction Stop)) {
                $totalItems++
                if ($null -eq $lastItem -or $item.LastWriteTime -ge $lastItem.LastWriteTime) {
                    $lastItem = $item
                }
            }
        }
    } catch {
        $recycleError = $_.Exception.Message
        Add-ScanIssue 'Recycle Bin' "No se pudo enumerar $recyclePath : $($_.Exception.Message)"
    }

    if ($recycleError) {
        Write-Field 'Total Items:' 'UNKNOWN (read error)' $fieldWidth $textColor $warnColor
        Write-Field 'Last Deleted Item:' 'UNKNOWN (read error)' $fieldWidth $textColor $warnColor
        Write-Field 'Modified Time:' $lastModified.ToString($formatDate) $fieldWidth $textColor $subtColor
    } else {
        $lastItemText = if ($lastItem) { $lastItem.Name } else { 'No items found' }
        Write-Field 'Total Items:' $totalItems $fieldWidth $textColor $subtColor
        Write-Field 'Last Deleted Item:' $lastItemText $fieldWidth $textColor $subtColor
        Write-Field 'Modified Time:' $lastModified.ToString($formatDate) $fieldWidth $textColor $subtColor
    }
} else {
    Write-Host ($infoIndex + "$recyclePath not found.") -ForegroundColor $warnColor
}

Write-Host ''
Write-SubSection 'Console Host History'
$consoleHistPath = $null
try { $consoleHistPath = (Get-PSReadLineOption).HistorySavePath } catch {}

if ($consoleHistPath -and (Test-Path -LiteralPath $consoleHistPath)) {
    $historyFile = Get-Item -LiteralPath $consoleHistPath -Force
    $lastLine = $null
    $historyError = $null
    try {
        $lastLine = Get-Content -LiteralPath $consoleHistPath -Last 1 -ErrorAction Stop
    } catch {
        $historyError = $_.Exception.Message
        Add-ScanIssue 'Console history' "No se pudo leer $consoleHistPath : $($_.Exception.Message)"
    }
    $attributes = $historyFile.Attributes
    $lastModified = $historyFile.LastWriteTime

    $status = if ($attributes -ne [IO.FileAttributes]::Archive) { $attributes.ToString() } else { 'Normal' }
    $statusColor = if ($status -eq 'Normal') { $successColor } else { $warnColor }
    if ($historyError) {
        $lastCommand = 'UNKNOWN (read error)'
    } elseif ($lastLine -eq '}') {
        $lastCommand = 'ScriptBlock'
    } elseif ($lastLine) {
        $lastCommand = $lastLine
    } else {
        $lastCommand = '(empty)'
    }

    Write-Field 'Last Command:' $lastCommand $fieldWidth $textColor $(if ($historyError) { $warnColor } else { $subtColor })
    Write-Field 'File Attributes:' $status $fieldWidth $textColor $statusColor
    Write-Field 'Modified Time:' $lastModified.ToString($formatDate) $fieldWidth $textColor $subtColor
} else {
    Write-Host ($infoIndex + 'History file not found.') -ForegroundColor $warnColor
}

Write-Host ''
Write-SubSection 'Hosts'
$hostsPath = Join-Path $env:SystemRoot 'System32\Drivers\etc\hosts'

function Get-HostsLineClass {
    param([string]$Line)

    $clean = $Line
    $commentIndex = $clean.IndexOf('#')
    if ($commentIndex -ge 0) { $clean = $clean.Substring(0, $commentIndex) }
    $clean = $clean.Trim()
    if ([string]::IsNullOrWhiteSpace($clean)) { return 'Malformed' }

    $parts = @($clean -split '\s+' | Where-Object { $_ -ne '' })
    if ($parts.Count -lt 2) { return 'Malformed' }

    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$ip)) { return 'Malformed' }

    $hostNames = @($parts[1..($parts.Count - 1)] | ForEach-Object { $_.ToLowerInvariant() })
    $localNames = @(
        'localhost', 'localhost.localdomain', 'local', 'broadcasthost',
        'ip6-localhost', 'ip6-loopback', 'ip6-localnet', 'ip6-mcastprefix',
        'ip6-allnodes', 'ip6-allrouters', 'ip6-allhosts'
    )

    $bytes = $ip.GetAddressBytes()
    $isLoopbackOrUnspecified = $false
    $isPrivate = $false

    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $isLoopbackOrUnspecified = ($bytes[0] -eq 127) -or ($bytes[0] -eq 0)
        $isPrivate = ($bytes[0] -eq 10) -or
                     ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
                     ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
                     ($bytes[0] -eq 169 -and $bytes[1] -eq 254)
    } else {
        $isLoopbackOrUnspecified = [System.Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([System.Net.IPAddress]::IPv6Any)
        $isPrivate = $ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal
    }

    if ($isLoopbackOrUnspecified) {
        $onlyLocalNames = $true
        foreach ($hostName in $hostNames) {
            if ($localNames -notcontains $hostName) { $onlyLocalNames = $false; break }
        }
        if ($onlyLocalNames) { return 'Benign' }
        return 'Blocklist'
    }

    if ($isPrivate) { return 'LocalOverride' }
    return 'Redirect'
}

if (Test-Path -LiteralPath $hostsPath) {
    $hostsFile = Get-Item -LiteralPath $hostsPath -Force
    $attributes = $hostsFile.Attributes
    $attributeColor = if (Test-ArchiveAttribute $attributes) { $successColor } else { $warnColor }
    $lastModified = $hostsFile.LastWriteTime
    $content = @()
    $hostsError = $null
    try {
        $content = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop)
    } catch {
        $hostsError = $_.Exception.Message
        Add-ScanIssue 'Hosts file' "No se pudo leer $hostsPath : $($_.Exception.Message)"
    }
    $activeEntries = [Collections.Generic.List[string]]::new()
    $benignCount = 0
    $blocklistCount = 0
    $localOverrideCount = 0
    $redirects = [Collections.Generic.List[string]]::new()
    $malformed = [Collections.Generic.List[string]]::new()

    foreach ($line in $content) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith('#')) { continue }

        $activeEntries.Add($trimmed)

        switch (Get-HostsLineClass -Line $trimmed) {
            'Benign'        { $benignCount++ }
            'Blocklist'     { $blocklistCount++ }
            'LocalOverride' { $localOverrideCount++ }
            'Redirect'      { $redirects.Add($trimmed) }
            default         { $malformed.Add($trimmed) }
        }
    }

    Write-Field 'File Attributes:' $attributes.ToString() $fieldWidth $textColor $attributeColor
    Write-Field 'Modified Time:' $lastModified.ToString($formatDate) $fieldWidth $textColor $subtColor
    Write-Host ($infoIndex + 'Active entries:'.PadRight($fieldWidth)) -ForegroundColor $textColor -NoNewline

    if ($hostsError) {
        Write-Host 'UNKNOWN (read error)' -ForegroundColor $warnColor
    } elseif ($activeEntries.Count -eq 0) {
        Write-Host 'None (default hosts file)' -ForegroundColor $successColor
    } else {
        $parts = @("$($activeEntries.Count) total")
        if ($benignCount -gt 0) { $parts += "$benignCount local/default" }
        if ($blocklistCount -gt 0) { $parts += "$blocklistCount blocklist" }
        if ($localOverrideCount -gt 0) { $parts += "$localOverrideCount LAN override" }
        if ($redirects.Count -gt 0) { $parts += "$($redirects.Count) public redirect" }
        if ($malformed.Count -gt 0) { $parts += "$($malformed.Count) malformed" }
        $entriesColor = if ($redirects.Count -gt 0 -or $malformed.Count -gt 0) { $warnColor } else { $textColor }
        Write-Host ($parts -join ', ') -ForegroundColor $entriesColor

        if ($redirects.Count -gt 0) {
            $maxShow = 3
            for ($i = 0; $i -lt [Math]::Min($maxShow, $redirects.Count); $i++) {
                Write-Host ($infoIndex + '  |- Public redirect: ') -ForegroundColor $subtColor -NoNewline
                Write-Host $redirects[$i] -ForegroundColor $warnColor
            }
            if ($redirects.Count -gt $maxShow) {
                Write-Host ($infoIndex + "  |- And $($redirects.Count - $maxShow) more public redirect(s)...") -ForegroundColor $subtColor
            }
        }
        if ($malformed.Count -gt 0) {
            for ($i = 0; $i -lt [Math]::Min(3, $malformed.Count); $i++) {
                Write-Host ($infoIndex + '  |- Malformed: ') -ForegroundColor $subtColor -NoNewline
                Write-Host $malformed[$i] -ForegroundColor $warnColor
            }
        }
    }
} else {
    Write-Host ($infoIndex + "Hosts not found in '$hostsPath'") -ForegroundColor $warnColor
}

Write-Host ''
Write-SubSection 'USNJournal ($UsnJrnl:$J)'

$usnUrl      = 'https://github.com/Orbdiff/CheckDeletedUSN/releases/download/v0.2.1/CheckDeletedUSN.exe'
$usnHash     = '3CC655225C8F9B829AD446E4390C5C738F8E3DDB560493A52EE269AA00AADF42'
$usnRoot     = Join-Path $env:ProgramData 'PsicoChecker\tools\v0.2.1'
$usnRunDir   = Join-Path $usnRoot ([guid]::NewGuid().ToString('N'))
$usnExe      = Join-Path $usnRunDir 'CheckDeletedUSN.exe'
$usnPartial  = $usnExe + '.partial'
$usnInFile   = Join-Path $usnRunDir 'input.txt'
$usnOutFile  = Join-Path $usnRunDir 'output.txt'
$usnErrFile  = Join-Path $usnRunDir 'error.txt'
$usnPath     = 'C:\$Extend\$UsnJrnl:$J'
$usnCreated  = $null
$usnState    = 'Unknown'
$usnError    = $null
$usnSignature = 'Not checked'
$usnProcess  = $null

try {
    $null = New-Item -ItemType Directory -Path $usnRunDir -Force -ErrorAction Stop

    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    if (Test-Path -LiteralPath $icacls -PathType Leaf) {
        $account = if ($env:USERDOMAIN) { "$($env:USERDOMAIN)\$($env:USERNAME)" } else { $env:USERNAME }
        $aclOutput = & $icacls $usnRunDir /inheritance:r /grant:r "$($account):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1
        if ($LASTEXITCODE -ne 0) {
            Add-ScanIssue 'USNJournal' "No se pudieron restringir los permisos de $usnRunDir : $($aclOutput -join ' ')"
        }
    }

    Invoke-WebRequest -Uri $usnUrl -UseBasicParsing -OutFile $usnPartial -ErrorAction Stop

    $downloadedHash = Get-FileHash -LiteralPath $usnPartial -Algorithm SHA256 -ErrorAction Stop
    if ($downloadedHash.Hash -ne $usnHash) {
        throw 'El archivo descargado no coincide con el hash esperado.'
    }

    Move-Item -LiteralPath $usnPartial -Destination $usnExe -Force -ErrorAction Stop

    $signature = Get-AuthenticodeSignature -LiteralPath $usnExe -ErrorAction Stop
    $usnSignature = [string]$signature.Status
    if ($signature.SignerCertificate) {
        $usnSignature += ' / ' + [string]$signature.SignerCertificate.Subject
    }

    if ($signature.Status -notin @('Valid', 'NotSigned')) {
        throw "Firma Authenticode no valida: $($signature.Status)"
    }

    Remove-Item -LiteralPath $usnOutFile, $usnErrFile -Force -ErrorAction SilentlyContinue
    [IO.File]::WriteAllText($usnInFile, "`r`n")

    # Re-verify immediately before execution (TOCTOU window reduction).
    $finalHash = Get-FileHash -LiteralPath $usnExe -Algorithm SHA256 -ErrorAction Stop
    if ($finalHash.Hash -ne $usnHash) {
        throw 'El ejecutable cambio entre la verificacion y la ejecucion.'
    }
    if (-not (Test-Path -LiteralPath $usnExe -PathType Leaf)) {
        throw 'El ejecutable desaparecio antes de la ejecucion.'
    }

    $usnProcess = Start-Process -FilePath $usnExe `
        -RedirectStandardInput $usnInFile `
        -RedirectStandardOutput $usnOutFile `
        -RedirectStandardError $usnErrFile `
        -NoNewWindow -PassThru -ErrorAction Stop

    if (-not $usnProcess.WaitForExit(15000)) {
        try { $usnProcess.Kill() } catch {}
        try { $usnProcess.WaitForExit(3000) | Out-Null } catch {}
    }

    $usnRaw = ''
    if (Test-Path -LiteralPath $usnOutFile) { $usnRaw += [IO.File]::ReadAllText($usnOutFile) }
    if (Test-Path -LiteralPath $usnErrFile) { $usnRaw += "`n" + [IO.File]::ReadAllText($usnErrFile) }

    $pathMatch = [regex]::Match($usnRaw, '(?im)Checking USN Journal at path:\s*(?<v>.+)')
    if ($pathMatch.Success) { $usnPath = $pathMatch.Groups['v'].Value.Trim() }

    $createdMatch = [regex]::Match($usnRaw, '(?im)USN Journal creation time:\s*(?<v>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})')
    if ($createdMatch.Success) { $usnCreated = $createdMatch.Groups['v'].Value }

    if ($usnRaw -match '(?i)\$UsnJrnl:\$J Intact!') {
        $usnState = 'Intact'
    } elseif ($usnRaw -match '(?i)very likely that the USN Journal was deleted') {
        $usnState = 'Deleted (created after boot)'
    } elseif ($usnRaw -match '(?i)\$UsnJrnl:\$J not found') {
        $usnState = 'Not found'
    } elseif ($usnRaw -match '(?i)Failed to open') {
        $usnState = 'Access denied'
    } elseif ($usnRaw -match '(?i)Failed to enable SeDebugPrivilege') {
        $usnState = 'Access denied (SeDebugPrivilege)'
    }
} catch {
    $usnError = $_.Exception.Message
    Add-ScanIssue 'USNJournal' "CheckDeletedUSN fallo: $($_.Exception.Message)"
} finally {
    if ($usnProcess -and -not $usnProcess.HasExited) {
        try { $usnProcess.Kill() } catch {}
    }
    Remove-Item -LiteralPath $usnRunDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($usnError) {
    Write-Field 'Check:' 'Failed' $fieldWidth $textColor $dangerColor
    Write-Host ($infoIndex + '  ' + $usnError) -ForegroundColor $subtColor
} else {
    $stateColor = if ($usnState -eq 'Intact') {
        $successColor
    } elseif ($usnState -like 'Deleted*') {
        $dangerColor
    } else {
        $warnColor
    }

    $usnCreatedText = if ($usnCreated) { $usnCreated } else { 'Unknown' }
    Write-Field 'File Path:' $usnPath $fieldWidth $textColor $subtColor
    Write-Field 'Created:' $usnCreatedText $fieldWidth $textColor $subtColor
    Write-Field 'State:' $usnState $fieldWidth $textColor $stateColor
    $signatureColor = if ($usnSignature -eq 'Valid' -or $usnSignature -like 'Valid / *') {
        $successColor
    } else {
        $warnColor
    }
    Write-Field 'Signature:' $usnSignature $fieldWidth $textColor $signatureColor
}

Write-Host ''
Write-SubSection 'TEMP'
$tmp = $env:TEMP

if (Test-Path -LiteralPath $tmp) {
    $javaLauncherPath = Join-Path $tmp 'JavaLauncher.log'
    $javaLauncherStatus = Get-PathEvidence $javaLauncherPath
    $javaLauncher = $null
    if ($javaLauncherStatus -eq 'Present') {
        try { $javaLauncher = Get-Item -LiteralPath $javaLauncherPath -Force -ErrorAction Stop } catch { $javaLauncherStatus = 'Access denied' }
    }

    Write-Host ($infoIndex + 'JavaLauncher:'.PadRight($fieldWidth)) -ForegroundColor $textColor -NoNewline
    if ($javaLauncherStatus -eq 'Access denied') {
        Write-Host 'UNKNOWN (access denied)' -ForegroundColor $warnColor
        Add-ScanIssue 'TEMP' "Acceso denegado a $javaLauncherPath"
    } elseif ($javaLauncher) {
        Write-Host 'JavaLauncher.log found' -ForegroundColor $subtColor

        $attributes = $javaLauncher.Attributes
        $attributeColor = if (Test-ArchiveAttribute $attributes) { $successColor } else { $warnColor }
        Write-Field 'File Attributes:' $attributes.ToString() $fieldWidth $textColor $attributeColor

        $executions = @(Get-JavaLauncherExecutions -Path $javaLauncher.FullName)
        if ($script:JavaLauncherReadError) {
            Write-Field 'java -jar:' 'UNKNOWN (read error)' $fieldWidth $textColor $warnColor
        } elseif ($executions.Count -gt 0) {
            $javaJarCount = @($executions | Where-Object { $_.JavaJar }).Count
            $javaJarText = if ($javaJarCount -gt 0) { "Yes ($javaJarCount)" } else { 'Not detected' }
            $javaJarColor = if ($javaJarCount -gt 0) { $successColor } else { $warnColor }
            Write-Field 'java -jar:' $javaJarText $fieldWidth $textColor $javaJarColor

            Write-Host ($infoIndex + 'Execution(s):') -ForegroundColor $textColor
            $counter = 0

            foreach ($execution in $executions) {
                $counter++
                $dateText = if ($execution.Date) { $execution.Date.ToString($formatDate) } else { 'Unknown' }
                Write-Host ($infoIndex + "  $counter. $dateText : ") -ForegroundColor $subtColor -NoNewline
                Write-Host $execution.Jar -ForegroundColor $textColor
                Write-Host ($infoIndex + '     |- java -jar: ') -ForegroundColor $subtColor -NoNewline

                if ($execution.JavaJar) {
                    Write-Host 'Yes' -ForegroundColor $successColor
                } else {
                    Write-Host 'Not detected' -ForegroundColor $warnColor
                }
            }
        } else {
            Write-Host ($infoIndex + 'No java -jar entries found') -ForegroundColor $successColor
        }
    } else {
        Write-Host 'JavaLauncher.log not found' -ForegroundColor $successColor
    }

    Write-Host ''
    $jnativeHook = @()
    $jnativeError = $null
    try {
        $jnativeHook = @(Get-ChildItem -LiteralPath $tmp -Filter 'JNativeHook*' -Force -File -ErrorAction Stop | Sort-Object LastWriteTime)
    } catch {
        $jnativeError = $_.Exception.Message
        Add-ScanIssue 'TEMP' "No se pudo enumerar JNativeHook en $tmp : $($_.Exception.Message)"
    }
    Write-Host ($infoIndex + 'JNativeHook:'.PadRight($fieldWidth)) -ForegroundColor $textColor -NoNewline

    if ($jnativeError) {
        Write-Host 'UNKNOWN (read error)' -ForegroundColor $warnColor
    } elseif ($jnativeHook.Count -gt 0) {
        Write-Host 'JNativeHook files found' -ForegroundColor $subtColor
        $counter = 0

        foreach ($file in $jnativeHook) {
            $counter++
            $modifiedText = $file.LastWriteTime.ToString($formatDate)
            Write-Host ($infoIndex + "  $counter. $modifiedText : ") -ForegroundColor $subtColor -NoNewline
            Write-Host $file.FullName -ForegroundColor $warnColor
        }
    } else {
        Write-Host 'No JNativeHook files found' -ForegroundColor $successColor
    }
} else {
    Write-Host ($infoIndex + "$tmp not found.") -ForegroundColor $warnColor
}

# --- PREFETCH INTEGRITY -------------------------------------------------------
Write-SectionHeader 'PREFETCH INTEGRITY'

$prefetchPath = Join-Path $env:SystemRoot 'Prefetch'
$prefetchFindings = [Collections.Generic.List[object]]::new()
$duplicatedHashes = @()
$prefetchStatus = 'Not found'
$prefetchColor = $warnColor
$prefetchCount = 0
$loggedCount = 0
$readOnlyCount = 0
$hiddenCount = 0
$unreadableCount = 0
$unexpectedHeaderCount = 0
$deletedPrefetch = $null
$prefetchDisabled = $false
$recreatedAfterBoot = $false
$recreatedText = 'No'
$recreatedColor = $textColor

$prefetchPolicy = Get-RegistryEvidence -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnablePrefetcher'
if ($prefetchPolicy.Status -eq 'Present' -and $null -ne $prefetchPolicy.Value -and [int]$prefetchPolicy.Value -eq 0) {
    $prefetchDisabled = $true
}

$prefetchFolderStatus = Get-PathEvidence $prefetchPath
if ($prefetchFolderStatus -eq 'Present') {
    $prefetchFiles = @()
    $prefetchReadError = $null
    try {
        $prefetchFiles = @(Get-ChildItem -LiteralPath $prefetchPath -Filter '*.pf' -Force -File -ErrorAction Stop)
    } catch {
        $prefetchReadError = $_.Exception.Message
        Add-ScanIssue 'Prefetch Integrity' "No se pudo enumerar $prefetchPath : $($_.Exception.Message)"
    }
    $prefetchCount = $prefetchFiles.Count
    $hashTable = @{}

    foreach ($file in $prefetchFiles) {
        $isHidden = (($file.Attributes -band [IO.FileAttributes]::Hidden) -eq [IO.FileAttributes]::Hidden)
        $isReadOnly = $file.IsReadOnly

        if ($isReadOnly) { $readOnlyCount++ }
        if ($isHidden) { $hiddenCount++ }

        # Attributes are observations only, never proof of tampering.
        if ($isReadOnly -and $isHidden) {
            $prefetchFindings.Add([pscustomobject]@{ Type = 'Read-only and hidden attribute'; File = $file.Name; Severity = 'Info' })
        } elseif ($isReadOnly) {
            $prefetchFindings.Add([pscustomobject]@{ Type = 'Read-only attribute'; File = $file.Name; Severity = 'Info' })
        } elseif ($isHidden) {
            $prefetchFindings.Add([pscustomobject]@{ Type = 'Hidden attribute'; File = $file.Name; Severity = 'Info' })
        }

        $header = ''
        $readOk = $false
        try {
            $buffer = New-Object byte[] 4
            $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            try {
                $bytesRead = $stream.Read($buffer, 0, 4)
            } finally {
                $stream.Dispose()
            }
            $readOk = $true
            if ($bytesRead -gt 0) { $header = [Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead) }
        } catch {}

        $validHeader = $header.StartsWith('MAM', [StringComparison]::OrdinalIgnoreCase) -or
                       $header.StartsWith('SCCA', [StringComparison]::OrdinalIgnoreCase)

        if (-not $readOk) {
            $unreadableCount++
            $prefetchFindings.Add([pscustomobject]@{ Type = 'Could not read header'; File = $file.Name; Severity = 'Review' })
        } elseif ($validHeader) {
            $loggedCount++
        } else {
            $unexpectedHeaderCount++
            $headerText = if ([string]::IsNullOrWhiteSpace($header)) { '(empty)' } else { $header.Trim([char[]]@([char]0)) }
            $prefetchFindings.Add([pscustomobject]@{ Type = "Unexpected header '$headerText' (expected MAM/SCCA)"; File = $file.Name; Severity = 'Review' })
        }

        $hash = $null
        try {
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {}

        if (-not $hash) {
            $prefetchFindings.Add([pscustomobject]@{ Type = 'Could not calculate SHA256'; File = $file.Name; Severity = 'Review' })
            $hash = "UNREADABLE:$($file.Name)"
        }

        if ($hashTable.ContainsKey($hash)) {
            $hashTable[$hash].Add($file.Name)
        } else {
            $hashTable[$hash] = [Collections.Generic.List[string]]::new()
            $hashTable[$hash].Add($file.Name)
        }
    }

    $duplicatedHashes = @($hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 })

    if ($prefetchReadError) {
        $prefetchStatus = 'Unknown (read error)'
        $prefetchColor = $warnColor
    } elseif ($prefetchCount -eq 0) {
        if ($prefetchDisabled) {
            $prefetchStatus = 'Empty (prefetch disabled)'
            $prefetchColor = $textColor
        } else {
            $prefetchStatus = 'Empty / Review'
            $prefetchColor = $warnColor
        }
    } elseif ($unreadableCount -gt 0 -or $unexpectedHeaderCount -gt 0) {
        $prefetchStatus = 'Review'
        $prefetchColor = $warnColor
    } else {
        $prefetchStatus = 'Clean'
        $prefetchColor = $successColor
    }

    $deletedPrefetch = Get-DeletedPrefetchCount -Volume $env:SystemDrive

    try {
        $folderInfo = Get-Item -LiteralPath $prefetchPath -Force -ErrorAction Stop
        if ($bootTime -and $folderInfo.CreationTime -gt $bootTime) {
            $recreatedAfterBoot = $true
            $usnNote = ''
            if ($deletedPrefetch -and $deletedPrefetch.Status -eq 'OK') {
                $usnNote = "; USN deletions: $($deletedPrefetch.Events)"
            }
            $recreatedText = 'Yes (' + $folderInfo.CreationTime.ToString($formatDate) + $usnNote + ')'
            $recreatedColor = $warnColor
            $prefetchFindings.Add([pscustomobject]@{
                Type     = 'Prefetch folder created after boot'
                File     = $folderInfo.CreationTime.ToString($formatDate)
                Severity = 'Review'
            })
            if ($prefetchStatus -eq 'Clean') {
                $prefetchStatus = 'Review'
                $prefetchColor = $warnColor
            }
        }
    } catch {}
} elseif ($prefetchFolderStatus -eq 'Access denied') {
    $prefetchStatus = 'Unknown (access denied)'
    $prefetchColor = $warnColor
    Add-ScanIssue 'Prefetch Integrity' "Acceso denegado a $prefetchPath"
} else {
    $prefetchStatus = if ($prefetchDisabled) { 'Not found (prefetch disabled)' } else { 'Not found' }
    $prefetchColor = if ($prefetchDisabled) { $textColor } else { $warnColor }
}

Write-Host ($titleIndex + 'Prefetch status:'.PadRight($fieldWidth) + $prefetchStatus) -ForegroundColor $prefetchColor

if ($prefetchStatus -like 'Not found*') {
    Write-Host ($infoIndex + "Path: $prefetchPath") -ForegroundColor $subtColor
} else {
    $deletedText = 'N/A'
    $deletedColor = $subtColor
    $deletedFilesText = 'N/A'
    $deletedFilesColor = $subtColor
    $usnStatusText = 'Unavailable'
    $usnStatusColor = $warnColor

    if ($deletedPrefetch) {
        if ($deletedPrefetch.Status -eq 'OK') {
            $deletedText = [string]$deletedPrefetch.Events
            $deletedColor = $textColor
            $deletedFilesText = [string]$deletedPrefetch.Files
            $deletedFilesColor = $textColor
            $usnStatusText = 'OK'
            $usnStatusColor = $successColor
        } else {
            $deletedText = 'UNKNOWN'
            $deletedColor = $warnColor
            $deletedFilesText = 'UNKNOWN'
            $deletedFilesColor = $warnColor
            $usnStatusText = $deletedPrefetch.Status
            $usnStatusColor = $warnColor
        }
    }

    $loggedColor = if ($loggedCount -gt 0) { $textColor } elseif ($prefetchCount -gt 0) { $warnColor } else { $textColor }

    if ($prefetchStatus -like 'Unknown*') {
        $prefetchFilesText = 'UNKNOWN'
        $loggedText = 'UNKNOWN'
        $readOnlyText = 'UNKNOWN'
        $hiddenText = 'UNKNOWN'
        $prefetchFilesColor = $warnColor
        $loggedColor = $warnColor
        $readOnlyColor = $warnColor
    } else {
        $prefetchFilesText = [string]$prefetchCount
        $loggedText = [string]$loggedCount
        $readOnlyText = [string]$readOnlyCount
        $hiddenText = [string]$hiddenCount
        $prefetchFilesColor = $textColor
        $readOnlyColor = $textColor
    }

    Write-Field 'Prefetch files:' $prefetchFilesText $fieldWidth $textColor $prefetchFilesColor
    Write-Field 'Logged (MAM/SCCA):' $loggedText $fieldWidth $textColor $loggedColor
    Write-Field 'Read-only:' $readOnlyText $fieldWidth $textColor $readOnlyColor
    Write-Field 'Hidden:' $hiddenText $fieldWidth $textColor $textColor
    Write-Field 'Recreated after boot:' $recreatedText $fieldWidth $textColor $recreatedColor
    Write-Field 'Deleted events (USN):' $deletedText $fieldWidth $textColor $deletedColor
    Write-Field 'Deleted unique files:' $deletedFilesText $fieldWidth $textColor $deletedFilesColor
    Write-Field 'USN read status:' $usnStatusText $fieldWidth $textColor $usnStatusColor
    if ($deletedPrefetch -and $deletedPrefetch.Detail -and $deletedPrefetch.Status -ne 'OK') {
        Write-Host ($infoIndex + '  |- ' + $deletedPrefetch.Detail) -ForegroundColor $warnColor
    }
    Write-Host ''

    foreach ($finding in $prefetchFindings) {
        $findingColor = if ($finding.Severity -eq 'Review') { $warnColor } else { $subtColor }
        Write-Int $infoIndex '-' $finding.Type
        Write-Host ($infoIndex + '  |- File: ') -ForegroundColor $subtColor -NoNewline
        Write-Host $finding.File -ForegroundColor $findingColor
    }

    foreach ($group in $duplicatedHashes) {
        Write-Int $infoIndex '-' 'Duplicated hash (observation)'
        Write-Host ($infoIndex + '  |- Files: ') -ForegroundColor $subtColor -NoNewline

        $groupFiles = @($group.Value)
        for ($i = 0; $i -lt $groupFiles.Count; $i++) {
            if ($i -gt 0) { Write-Host ', ' -ForegroundColor $subtColor -NoNewline }
            Write-Host $groupFiles[$i] -ForegroundColor $subtColor -NoNewline
        }

        Write-Host ''
        Write-Host ($infoIndex + '  |- Hash:  ' + $group.Key) -ForegroundColor $subtColor
    }
}

# --- REGISTRY -----------------------------------------------------------------
Write-SectionHeader 'REGISTRY'

$registryItems = @(
    @{ Name = 'PowerShell Logging'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Key = 'EnableScriptBlockLogging'; Disabled = 0 }
    @{ Name = 'Activities Cache'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Key = 'EnableActivityFeed'; Disabled = 0 }
    @{ Name = 'Prefetch Enabled'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'; Key = 'EnablePrefetcher'; Disabled = 0 }
    @{ Name = 'PCA Client Enabled'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'; Key = 'DisabledPCA'; Disabled = 1 }
    @{ Name = 'Command Prompt'; Path = 'HKCU:\Software\Policies\Microsoft\Windows\System'; Key = 'DisableCMD'; Disabled = 1 }
)

foreach ($item in $registryItems) {
    $evidence = Get-RegistryEvidence -Path $item.Path -Name $item.Key
    $itemColor = $successColor
    $status = ''
    $statusColor = $textColor

    switch ($evidence.Status) {
        'Present' {
            $value = $evidence.Value
            if ($null -eq $value) {
                $status = 'Not set'
                $statusColor = $textColor
            } elseif ($value -eq $item.Disabled) {
                $status = 'Disabled'
                $statusColor = $warnColor
            } else {
                $status = if ($item.Name -ne 'Command Prompt') { 'Enabled' } else { 'Available' }
                $statusColor = $successColor
            }
        }
        'Value missing' {
            $status = 'Not configured'
            $statusColor = $textColor
        }
        'Key missing' {
            $status = 'Key missing'
            $statusColor = $textColor
        }
        'Access denied' {
            $status = 'UNKNOWN (access denied)'
            $statusColor = $warnColor
            Add-ScanIssue 'Registry' "Acceso denegado a $($item.Path) -> $($item.Key)"
        }
        default {
            $status = 'UNKNOWN (read error)'
            $statusColor = $warnColor
            Add-ScanIssue 'Registry' "No se pudo leer $($item.Path) -> $($item.Key): $($evidence.Error)"
        }
    }

    $hive = [PsicoRegUtil]::HKEY_LOCAL_MACHINE
    $relativePath = ''
    if ($item.Path.StartsWith('HKLM:\', [StringComparison]::OrdinalIgnoreCase)) {
        $hive = [PsicoRegUtil]::HKEY_LOCAL_MACHINE
        $relativePath = $item.Path.Substring(6)
    } elseif ($item.Path.StartsWith('HKCU:\', [StringComparison]::OrdinalIgnoreCase)) {
        $hive = [PsicoRegUtil]::HKEY_CURRENT_USER
        $relativePath = $item.Path.Substring(6)
    }

    $lastWrite = $null
    if ($relativePath) {
        try { $lastWrite = [PsicoRegUtil]::GetLastWriteTime($hive, $relativePath) } catch {}
    }

    $lastWriteText = if ($lastWrite) {
        if ($lastWrite.Year -le 1601) { '(Never Modified)' } else { "($($lastWrite.ToString('yyyy-MM-dd HH:mm')))" }
    } else {
        'Unknown'
    }

    Write-Host ($infoIndex + $item.Name.PadRight($regNameWidth) + ' ') -ForegroundColor $textColor -NoNewline
    Write-Host ($status.PadRight(24)) -ForegroundColor $statusColor -NoNewline
    Write-Host $lastWriteText -ForegroundColor $subtColor
}

$ifeoPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$debuggers = [Collections.Generic.List[object]]::new()
$deniedKeys = [Collections.Generic.List[string]]::new()
$ifeoStatus = Get-PathEvidence $ifeoPath
$ifeoEnumerationError = $null
$ifeoMissing = $false

function Get-DebuggerAssessment {
    param(
        [string]$Debugger,
        [string]$KeyName
    )

    $result = [pscustomobject]@{
        Target    = $Debugger
        Path      = $null
        Evidence  = 'Unknown'
        Signature = 'Unknown'
        Signer    = $null
        Verdict   = 'Review'
        Color     = $warnColor
    }

    if ([string]::IsNullOrWhiteSpace($Debugger)) {
        $result.Evidence = 'Not set'
        return $result
    }

    # IFEO Debugger == executable name is a compatibility shim, not a hijack.
    # It is still listed and verified; it is never hidden.
    $debuggerBase = [IO.Path]::GetFileNameWithoutExtension($Debugger.Trim('"', "'"))
    $keyBase = [IO.Path]::GetFileNameWithoutExtension($KeyName)
    $isSelfReference = ($debuggerBase -and $keyBase -and ($debuggerBase -ieq $keyBase))

    $expanded = [Environment]::ExpandEnvironmentVariables($Debugger.Trim())
    $target = $expanded
    if ($target -match '^"([^"]+)"') {
        $target = $Matches[1]
    } elseif ($target -match '^(.+?\.(?:exe|com|bat|cmd))(?:\s|$)') {
        $target = $Matches[1]
    }

    if (-not [IO.Path]::IsPathRooted($target)) {
        $candidates = @(
            (Join-Path $env:SystemRoot $target),
            (Join-Path $env:SystemRoot (Join-Path 'System32' $target)),
            (Join-Path $env:ProgramFiles $target)
        )
        $found = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
        if ($found) { $target = $found }
    }

    $result.Path = $target
    $evidence = Get-PathEvidence $target
    $result.Evidence = $evidence
    if ($evidence -ne 'Present') {
        $result.Verdict = 'Debugger target missing'
        $result.Color = $warnColor
        return $result
    }

    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $target -ErrorAction Stop
        $result.Signature = [string]$sig.Status
        if ($sig.SignerCertificate) { $result.Signer = [string]$sig.SignerCertificate.Subject }
    } catch {
        $result.Signature = 'Unknown'
    }

    if ($isSelfReference) {
        $result.Verdict = 'Self-reference (no hijack)'
        $result.Color = $textColor
        return $result
    }

    $signedByMicrosoft = ($result.Signer -match '(?i)Microsoft')
    if ($result.Signature -eq 'Valid' -and $signedByMicrosoft) {
        $result.Verdict = 'Microsoft-signed'
        $result.Color = $textColor
    } elseif ($result.Signature -eq 'Valid') {
        $result.Verdict = 'Third-party signed'
        $result.Color = $warnColor
    } else {
        $result.Verdict = 'Unsigned/invalid signature'
        $result.Color = $dangerColor
    }

    return $result
}

if ($ifeoStatus -eq 'Present') {
    $ifeoKeys = @()
    try {
        $ifeoKeys = @(Get-ChildItem -LiteralPath $ifeoPath -ErrorAction Stop)
    } catch {
        $message = [string]$_.Exception.Message
        if ($_.Exception -is [System.Security.SecurityException] -or $message -match '(?i)denied|unauthorized|not allowed') {
            $ifeoEnumerationError = 'access denied'
            Add-ScanIssue 'IFEO' "Acceso denegado a $ifeoPath"
        } else {
            $ifeoEnumerationError = $message
            Add-ScanIssue 'IFEO' "No se pudo enumerar $ifeoPath : $message"
        }
    }

    foreach ($key in $ifeoKeys) {
        try {
            $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            if ($properties.Debugger) {
                $assessment = Get-DebuggerAssessment -Debugger ([string]$properties.Debugger) -KeyName $key.PSChildName
                $debuggers.Add([pscustomobject]@{
                    Key        = $key.PSChildName
                    Debugger   = [string]$properties.Debugger
                    Assessment = $assessment
                })
            }
        } catch {
            $deniedKeys.Add($key.PSChildName)
            Add-ScanIssue 'IFEO' "No se pudo leer la clave $($key.PSChildName): $($_.Exception.Message)"
        }
    }
} elseif ($ifeoStatus -eq 'Access denied') {
    $ifeoEnumerationError = 'access denied'
    Add-ScanIssue 'IFEO' "Acceso denegado a $ifeoPath"
} elseif ($ifeoStatus -eq 'Missing') {
    $ifeoMissing = $true
} else {
    $ifeoEnumerationError = $ifeoStatus
}

Write-Host ($infoIndex + 'Debuggers (IFEO):'.PadRight($fieldWidth)) -ForegroundColor $textColor -NoNewline
if ($ifeoEnumerationError) {
    $ifeoStatusText = if ($ifeoEnumerationError -eq 'access denied') { 'UNKNOWN (access denied)' } else { 'UNKNOWN (read error)' }
    Write-Host $ifeoStatusText -ForegroundColor $warnColor
} elseif ($ifeoMissing) {
    Write-Host 'Not present' -ForegroundColor $textColor
} elseif ($debuggers.Count -eq 0) {
    if ($deniedKeys.Count -gt 0) {
        Write-Host 'UNKNOWN (some keys unreadable)' -ForegroundColor $warnColor
    } else {
        Write-Host 'Not found' -ForegroundColor $successColor
    }
} else {
    # Every IFEO Debugger entry is listed; nothing is suppressed by allowlist.
    $hasUnsigned = @($debuggers | Where-Object { $_.Assessment.Verdict -eq 'Unsigned/invalid signature' }).Count -gt 0
    $hasMissing = @($debuggers | Where-Object { $_.Assessment.Verdict -eq 'Debugger target missing' }).Count -gt 0
    $summaryColor = if ($hasUnsigned) { $dangerColor } elseif ($hasMissing) { $warnColor } else { $textColor }
    Write-Host ("{0} found" -f $debuggers.Count) -ForegroundColor $summaryColor
    $counter = 0

    foreach ($debugger in $debuggers) {
        $counter++
        Write-Int $infoIndex $counter 'Debugger found'
        Write-Host ($infoIndex + '  |- Executable: ') -ForegroundColor $subtColor -NoNewline
        Write-Host $debugger.Key -ForegroundColor $textColor
        Write-Host ($infoIndex + '  |- Debugger:   ') -ForegroundColor $subtColor -NoNewline
        Write-Host $debugger.Debugger -ForegroundColor $debugger.Assessment.Color
        Write-Host ($infoIndex + '  |- Target:     ') -ForegroundColor $subtColor -NoNewline
        Write-Host ($(if ($debugger.Assessment.Path) { $debugger.Assessment.Path } else { 'Unknown' })) -ForegroundColor $subtColor
        Write-Host ($infoIndex + '  |- Verified:   ') -ForegroundColor $subtColor -NoNewline
        Write-Host ("$($debugger.Assessment.Verdict) (signature: $($debugger.Assessment.Signature), path: $($debugger.Assessment.Evidence))") -ForegroundColor $debugger.Assessment.Color
    }
}

if ($deniedKeys.Count -gt 0) {
    Write-Int $infoIndex '-' 'Some IFEO keys could not be read'
    foreach ($deniedKey in $deniedKeys) {
        Write-Host ($infoIndex + '  |- ' + $deniedKey) -ForegroundColor $warnColor
    }
}

# --- SCREEN CAPTURE PROCESSES -------------------------------------------------
Write-SectionHeader 'SCREEN CAPTURE PROCESSES'

function ConvertTo-LocalFilePath {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $path = $Value.Trim().Trim('"').Trim("'")

    if ($path -match '^(?i)file:///(.+)$') {
        $path = $Matches[1]
        try { $path = [Uri]::UnescapeDataString($path) } catch {}
        if ($path -match '^/[A-Za-z]:/') { $path = $path.Substring(1) }
    }

    $path = $path -replace '/', '\'
    if ($path -match '^[A-Za-z]:\\') { return $path }
    return $null
}

function Get-HtmlApiEvidence {
    param([string]$Path)

    $result = [pscustomobject]@{
        Read    = $false
        Strong  = $false
        Matches = @()
        Error   = $null
    }

    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $result }

    $stream = $null
    try {
        $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($file.Length -le 0 -or $file.Length -gt 5MB) { return $result }

        $buffer = New-Object byte[] 262144
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { return $result }

        $text = [Text.Encoding]::UTF8.GetString($buffer, 0, $read)
        $pattern = '(?i)(getDisplayMedia|MediaRecorder|desktopCapturer|RecordRTC|tabCapture|screencast|grabador de pantalla|grabaci[oó]n de pantalla)'
        $apiMatches = [regex]::Matches($text, $pattern)
        $names = @($apiMatches | ForEach-Object { $_.Value } | Sort-Object -Unique)

        $result.Read = $true
        $result.Matches = $names
        $result.Strong = ($names.Count -gt 0)
    } catch {
        $result.Error = $_.Exception.Message
    } finally {
        if ($stream) { $stream.Dispose() }
    }

    return $result
}

function Get-BrowserRecorderFindings {
    $findings = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $browserNames = @(
        'chrome','firefox','msedge','opera','opera_gx','brave','vivaldi',
        'browser','waterfox','librewolf','palemoon','tor','torbrowser',
        'chromium','epicbrowser','slimjet','comodo','msedgewebview2','electron'
    )

    foreach ($proc in @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)) {
        try {
            if (-not $proc.Name) { continue }

            $baseName = [IO.Path]::GetFileNameWithoutExtension([string]$proc.Name).ToLower()
            if ($browserNames -notcontains $baseName) { continue }

            $commandLine = [string]$proc.CommandLine

            $candidatePath = $null
            $candidateUrl = ''
            $appMatch = [regex]::Match($commandLine, '(?i)--app(?:=|\s+)(?:"(?<u>[^"]+)"|''(?<u>[^'']+)''|(?<u>\S+))')
            if ($appMatch.Success) { $candidateUrl = $appMatch.Groups['u'].Value.Trim() }

            if (-not $candidateUrl) {
                $htmlMatch = [regex]::Match($commandLine, '(?i)(?<u>(?:[a-z]:\\|file:///|https?://)[^\s"'']+\.html?)')
                if ($htmlMatch.Success) { $candidateUrl = $htmlMatch.Groups['u'].Value }
            }

            if ($candidateUrl) { $candidatePath = ConvertTo-LocalFilePath $candidateUrl }

            # Only a local HTML file actually opened by the browser and containing
            # recording APIs qualifies. Titles/URLs/keywords alone are not evidence.
            if (-not $candidatePath) { continue }

            $fileEvidence = Get-HtmlApiEvidence -Path $candidatePath
            if (-not ($fileEvidence -and $fileEvidence.Strong)) { continue }

            $kind = 'HTML recorder candidate'
            $confidence = if ($fileEvidence.Matches.Count -ge 2) { 'Medium' } else { 'Low' }
            $detail = "$candidatePath (APIs: $($fileEvidence.Matches -join ', '))"
            $evidence = 'Local file opened by browser contains recording APIs; no active capture verified'

            $key = "$kind|$baseName|$detail"
            if (-not $seen.Add($key)) { continue }

            $findings.Add([pscustomobject]@{
                Kind        = $kind
                Name        = "$($proc.Name) (PID $($proc.ProcessId))"
                Detail      = $detail
                Confidence  = $confidence
                Evidence    = $evidence
                ProcessName = $baseName
            })
        } catch {}
    }

    return $findings.ToArray()
}

function Invoke-ScreenCaptureKiller {
    $captureEngines = @(
        'obs','obs32','obs64','streamlabs','camtasia','bandicam','xsplit',
        'fraps','action','dxtory','sharex','screenrec','flashback','bdcam'
    )

    $browserNames = @(
        'chrome','firefox','msedge','opera','opera_gx','brave','vivaldi',
        'browser','waterfox','librewolf','palemoon','tor','torbrowser',
        'chromium','epicbrowser','slimjet','comodo','msedgewebview2'
    )

    $shareApps = @(
        'discord','discordcanary','discordptb','teams','ms-teams','zoom','slack',
        'skype','telegram','whatsapp','steam','steamwebhelper','overwolf',
        'medal','gamebar','xboxgamebar','xboxgamebarwidgets','nvcontainer',
        'nvdisplay.container','amdsoftware','radeonsoftware'
    )

    $recorderFindings = @()
    try {
        $recorderFindings = @(Get-BrowserRecorderFindings)
    } catch {
        Add-ScanIssue 'Screen capture' "No se pudieron enumerar grabadoras: $($_.Exception.Message)"
    }

    $detected = [Collections.Generic.List[object]]::new()
    $capableApps = [ordered]@{}

    # Capture engines are listed individually so they can be closed on request.
    # Browsers and screen-share apps are inventoried as capture-capable only:
    # running does not mean recording, and they are never closed automatically.
    foreach ($proc in @(Get-Process -ErrorAction SilentlyContinue)) {
        try {
            $name = $proc.Name.ToLower()

            if ($captureEngines -contains $name) {
                $detected.Add([pscustomobject]@{
                    Name     = $proc.Name
                    PID      = $proc.Id
                    Category = 'Capture engine'
                    Closable = $true
                })
            } elseif (($browserNames -contains $name) -or ($shareApps -contains $name)) {
                if ($capableApps.Contains($name)) {
                    $capableApps[$name] = [int]$capableApps[$name] + 1
                } else {
                    $capableApps[$name] = 1
                }
            }
        } catch {}
    }

    if ($detected.Count -eq 0 -and $recorderFindings.Count -eq 0 -and $capableApps.Count -eq 0) {
        Write-Host ($infoIndex + 'No capture-capable processes or verified HTML recorder evidence detected.') -ForegroundColor $successColor
        return
    }

    if ($detected.Count -gt 0) {
        Write-Host ''
        Write-Host ($infoIndex + 'Capture engines running (closable on request):') -ForegroundColor $warnColor
        foreach ($item in $detected) {
            Write-Host ($infoIndex + ('  - {0}.exe [PID {1}]' -f $item.Name, $item.PID)) -ForegroundColor $titleColor
        }
    }

    if ($capableApps.Count -gt 0) {
        Write-Host ''
        Write-Host ($infoIndex + 'Capture-capable apps/browsers (report only, never closed):') -ForegroundColor $subtColor
        foreach ($entry in $capableApps.GetEnumerator()) {
            Write-Host ($infoIndex + ('  - {0}.exe x{1} [running does not mean recording]' -f $entry.Key, $entry.Value)) -ForegroundColor $textColor
        }
    }

    if ($recorderFindings.Count -gt 0) {
        Write-Host ''
        Write-Host ($infoIndex + 'HTML recorder candidates (not proof of active recording):') -ForegroundColor $warnColor

        foreach ($finding in $recorderFindings) {
            Write-Host ($infoIndex + ('  - [{0}] {1}' -f $finding.Kind, $finding.Name)) -ForegroundColor $titleColor
            Write-Host ($infoIndex + '      |- Confidence: ' + $finding.Confidence) -ForegroundColor $subtColor
            Write-Host ($infoIndex + '      |- Evidence:   ' + $finding.Evidence) -ForegroundColor $subtColor
            if ($finding.Detail) {
                Write-Host ($infoIndex + '      |- Detail:     ' + $finding.Detail) -ForegroundColor $subtColor
            }
        }
    }

    $closable = @($detected | Where-Object { $_.Closable })
    if ($closable.Count -eq 0) {
        Write-Host ''
        Write-Host ($infoIndex + 'No capture engine available to close. Nothing was terminated.') -ForegroundColor $warnColor
        return
    }

    Write-Host ''
    Write-Host ($infoIndex + 'Process closing is report-only by default.') -ForegroundColor $subtColor
    Write-Host ($infoIndex + '[D] Do nothing (default)') -ForegroundColor $textColor
    Write-Host ($infoIndex + '[G] Graceful close one capture engine') -ForegroundColor $textColor
    Write-Host ($infoIndex + '[F] Force kill one capture engine (requires typing KILL)') -ForegroundColor $textColor
    Write-Host ''
    Write-Host ($infoIndex + 'Closable capture engines:') -ForegroundColor $subtColor
    for ($i = 0; $i -lt $closable.Count; $i++) {
        Write-Host ($infoIndex + ('  [{0}] {1}.exe [PID {2}]' -f ($i + 1), $closable[$i].Name, $closable[$i].PID)) -ForegroundColor $titleColor
    }
    Write-Host ''

    $choice = Read-Host '  Select option (D / G / F) [D]'
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = 'D' }

    switch ($choice.ToUpper()) {
        'G' {
            $selection = Read-Host '  Enter the engine number to close gracefully'
            $index = 0
            if (-not [int]::TryParse($selection, [ref]$index) -or $index -lt 1 -or $index -gt $closable.Count) {
                Write-Host '[Error] Invalid selection. Nothing was closed.' -ForegroundColor $dangerColor
                return
            }

            $target = $closable[$index - 1]
            try {
                $proc = Get-Process -Id $target.PID -ErrorAction Stop
                if ($proc.MainWindowHandle -eq 0) {
                    Write-Host "[Info] $($target.Name).exe (PID $($target.PID)) has no main window; use force kill if needed." -ForegroundColor $warnColor
                    return
                }

                $sent = $proc.CloseMainWindow()
                if (-not $sent) {
                    Write-Host "[Info] Could not send a close request to PID $($target.PID)." -ForegroundColor $warnColor
                    return
                }

                if ($proc.WaitForExit(5000)) {
                    Write-Host "[Closed] $($target.Name).exe (PID $($target.PID))" -ForegroundColor $successColor
                } else {
                    Write-Host "[Still running] PID $($target.PID) did not exit after 5 seconds. Not forced." -ForegroundColor $warnColor
                }
            } catch {
                Write-Host "[Error] $($_.Exception.Message)" -ForegroundColor $dangerColor
            }
        }
        'F' {
            $selection = Read-Host '  Enter the engine number to force kill'
            $index = 0
            if (-not [int]::TryParse($selection, [ref]$index) -or $index -lt 1 -or $index -gt $closable.Count) {
                Write-Host '[Error] Invalid selection. Nothing was closed.' -ForegroundColor $dangerColor
                return
            }

            $target = $closable[$index - 1]
            Write-Host ''
            Write-Host "[Warning] Unsaved work in $($target.Name).exe (PID $($target.PID)) will be lost." -ForegroundColor $dangerColor
            $confirm = Read-Host '  Type KILL to continue'
            if ($confirm -cne 'KILL') {
                Write-Host '[Cancelled] Nothing was closed.' -ForegroundColor $successColor
                return
            }

            try {
                Stop-Process -Id $target.PID -Force -ErrorAction Stop
                Write-Host "[Killed] $($target.Name).exe (PID $($target.PID))" -ForegroundColor $dangerColor
            } catch {
                Write-Host "[Error] $($_.Exception.Message)" -ForegroundColor $dangerColor
            }
        }
        default {
            Write-Host '[Report only] No process was closed.' -ForegroundColor $successColor
        }
    }
}

Invoke-ScreenCaptureKiller

# --- READ ERRORS ---------------------------------------------------------------
Write-Host ''
Write-SectionHeader 'READ ERRORS'

$scanIssues = @($script:ScanIssues | Sort-Object Area, Detail -Unique)

if ($scanIssues.Count -eq 0) {
    Write-Host ($infoIndex + 'No read errors recorded.') -ForegroundColor $successColor
} else {
    Write-Host ($infoIndex + ("{0} check(s) could not be fully verified:" -f $scanIssues.Count)) -ForegroundColor $warnColor
    Write-Host ''

    foreach ($areaGroup in @($scanIssues | Group-Object Area | Sort-Object Name)) {
        Write-Host ($infoIndex + '[' + $areaGroup.Name + ']') -ForegroundColor $titleColor
        foreach ($issue in @($areaGroup.Group)) {
            Write-Host ($infoIndex + '  |- ' + $issue.Detail) -ForegroundColor $warnColor
        }
    }

    Write-Host ''
    Write-Host ($infoIndex + 'Treat UNKNOWN / REVIEW results as unverified, not as clean.') -ForegroundColor $subtColor
}

# --- Footer -------------------------------------------------------------------
Write-Host ''
Write-GradientRow ('╔' + ('═' * $panelInner) + '╗') $frameFrom $frameTo
Write-GradientRow ('║' + (Center-Inner 'ESCANEO COMPLETADO' $panelInner) + '║') $frameFrom $frameTo
Write-GradientRow ('╚' + ('═' * $panelInner) + '╝') $frameFrom $frameTo
Write-Host ''
