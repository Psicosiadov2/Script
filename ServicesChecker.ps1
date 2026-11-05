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

try {
    chcp 65001 > $null
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
        Encrypted  = 'NO'
        Type       = 'CLEAR'
        Access     = 'CLEAR'
        LiveUnlock = 'NO'
        MemAcquire = 'NO'
        Priority   = 'LOW'
    }

    $hasLetter = $Volume.DriveLetter -ne '[NO LETTER]'

    if ($hasLetter) {
        $bitLockerAvailable = Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue

        if ($bitLockerAvailable) {
            try {
                $bitLocker = Get-BitLockerVolume -MountPoint $Volume.DriveLetter -ErrorAction Stop
                if ($bitLocker.VolumeStatus -ne 'FullyDecrypted') {
                    $info.Encrypted  = 'YES'
                    $info.Type       = 'BITLOCKER (' + $bitLocker.EncryptionMethod + ')'
                    $info.Access     = 'ENCRYPTED_UNCOVERED'
                    $info.LiveUnlock = 'YES'
                    $info.MemAcquire = 'YES'
                    $info.Priority   = 'HIGH'
                }
            } catch {}
        }

        if ($info.Encrypted -eq 'NO') {
            try {
                $mountPoint = $Volume.DriveLetter + '\'
                $encryptable = Get-CimInstance -Namespace 'root\cimv2\security\microsoftvolumeencryption' `
                    -ClassName Win32_EncryptableVolume -ErrorAction Stop |
                    Where-Object { $_.DriveLetter -eq $mountPoint } |
                    Select-Object -First 1

                if ($encryptable -and $encryptable.ProtectionStatus -eq 1) {
                    $info.Encrypted  = 'YES'
                    $info.Type       = 'DEVICE ENCRYPTION'
                    $info.Access     = 'ENCRYPTED_UNCOVERED'
                    $info.LiveUnlock = 'YES'
                    $info.MemAcquire = 'YES'
                    $info.Priority   = 'HIGH'
                }
            } catch {}
        }
    }

    $fileSystem = $Volume.FileSystem
    if (($null -eq $fileSystem -or $fileSystem -eq 'RAW') -and $Volume.Capacity -gt 1GB) {
        $info.Encrypted  = 'YES'
        $info.Type       = 'THIRD-PARTY FULL DISK'
        $info.Access     = 'ENCRYPTED_LOCKED'
        $info.LiveUnlock = 'NO'
        $info.MemAcquire = 'YES'
        $info.Priority   = 'CRITICAL'
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
            $prefetchValue = $null
            try {
                $prefetchValue = (Get-ItemProperty -LiteralPath $prefetchKey -Name 'EnablePrefetcher' -ErrorAction Stop).EnablePrefetcher
            } catch {}

            if ($null -eq $prefetchValue) {
                $facts.Add([pscustomobject]@{ Label = 'EnablePrefetcher:'; Value = 'Unknown'; Color = $warnColor })
            } else {
                $value = [int]$prefetchValue
                $label = switch ($value) {
                    0 { 'Disabled (0)' }
                    1 { 'Enabled (apps)' }
                    2 { 'Enabled (boot)' }
                    3 { 'Enabled (apps+boot)' }
                    default { "Value $value" }
                }
                $factColor = if ($value -eq 0) { $dangerColor } else { $successColor }
                $facts.Add([pscustomobject]@{ Label = 'EnablePrefetcher:'; Value = $label; Color = $factColor })
            }

            $prefetchFolder = Join-Path $env:SystemRoot 'Prefetch'
            $prefetchFiles = @(Get-ChildItem -LiteralPath $prefetchFolder -Filter '*.pf' -Force -File -ErrorAction SilentlyContinue)
            $filesColor = if ($prefetchFiles.Count -eq 0) { $dangerColor } else { $textColor }
            $facts.Add([pscustomobject]@{ Label = 'Prefetch files:'; Value = [string]$prefetchFiles.Count; Color = $filesColor })

            $layoutPath = Join-Path $prefetchFolder 'Layout.ini'
            $layoutColor = if (Test-Path -LiteralPath $layoutPath) { $successColor } else { $dangerColor }
            $layoutValue = if (Test-Path -LiteralPath $layoutPath) { 'Present' } else { 'Missing' }
            $facts.Add([pscustomobject]@{ Label = 'Layout.ini:'; Value = $layoutValue; Color = $layoutColor })
        }
        'PcaSvc' {
            $pcaValue = $null
            try {
                $pcaValue = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisabledPCA' -ErrorAction Stop).DisabledPCA
            } catch {}

            if ($null -ne $pcaValue -and [int]$pcaValue -eq 1) {
                $facts.Add([pscustomobject]@{ Label = 'PCA policy:'; Value = 'Disabled (DisabledPCA=1)'; Color = $dangerColor })
            } else {
                $facts.Add([pscustomobject]@{ Label = 'PCA policy:'; Value = 'Enabled'; Color = $successColor })
            }

            $pcaStore = Join-Path $env:SystemRoot 'appcompat\pca'
            if (Test-Path -LiteralPath $pcaStore) {
                $storeCount = @(Get-ChildItem -LiteralPath $pcaStore -Force -File -ErrorAction SilentlyContinue).Count
                $storeColor = if ($storeCount -eq 0) { $warnColor } else { $textColor }
                $facts.Add([pscustomobject]@{ Label = 'PCA store:'; Value = "$storeCount files"; Color = $storeColor })
            } else {
                $facts.Add([pscustomobject]@{ Label = 'PCA store:'; Value = 'Missing'; Color = $dangerColor })
            }
        }
        'EventLog' {
            $logFolder = Join-Path $env:SystemRoot 'System32\winevt\Logs'
            $logCount = @(Get-ChildItem -LiteralPath $logFolder -Filter '*.evtx' -Force -File -ErrorAction SilentlyContinue).Count
            $logColor = if ($logCount -eq 0) { $dangerColor } else { $textColor }
            $facts.Add([pscustomobject]@{ Label = 'Event logs:'; Value = "$logCount files"; Color = $logColor })

            $logMin = @(Get-ChildItem -LiteralPath $logFolder -Filter '*.evtx' -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -lt 68KB }).Count
            $minColor = if ($logMin -gt 0) { $warnColor } else { $successColor }
            $facts.Add([pscustomobject]@{ Label = 'Small/cleared:'; Value = [string]$logMin; Color = $minColor })
        }
        'Schedule' {
            $scheduledTasks = @()
            try { $scheduledTasks = @(Get-ScheduledTask -ErrorAction Stop) } catch {}

            if ($scheduledTasks.Count -gt 0) {
                $taskCount = $scheduledTasks.Count
                $disabledTasks = @($scheduledTasks | Where-Object { [string]$_.State -eq 'Disabled' }).Count
                $facts.Add([pscustomobject]@{ Label = 'Scheduled tasks:'; Value = [string]$taskCount; Color = $textColor })
                $disabledColor = if ($disabledTasks -gt 0) { $warnColor } else { $successColor }
                $facts.Add([pscustomobject]@{ Label = 'Disabled tasks:'; Value = [string]$disabledTasks; Color = $disabledColor })
            } else {
                $tasksFolder = Join-Path $env:SystemRoot 'System32\Tasks'
                $taskFiles = @(Get-ChildItem -LiteralPath $tasksFolder -Force -File -Recurse -ErrorAction SilentlyContinue)
                if ($taskFiles.Count -gt 0) {
                    $facts.Add([pscustomobject]@{ Label = 'Task files:'; Value = [string]$taskFiles.Count; Color = $textColor })
                    $emptyTasks = @($taskFiles | Where-Object { $_.Length -eq 0 }).Count
                    $emptyColor = if ($emptyTasks -gt 0) { $dangerColor } else { $successColor }
                    $facts.Add([pscustomobject]@{ Label = 'Empty tasks:'; Value = [string]$emptyTasks; Color = $emptyColor })
                } else {
                    $facts.Add([pscustomobject]@{ Label = 'Scheduled tasks:'; Value = 'Unreadable'; Color = $warnColor })
                }
            }
        }
        'DiagTrack' {
            $telemetry = $null
            try {
                $telemetry = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -ErrorAction Stop).AllowTelemetry
            } catch {}

            if ($null -ne $telemetry) {
                $facts.Add([pscustomobject]@{ Label = 'Telemetry policy:'; Value = [string]$telemetry; Color = $textColor })
            } else {
                $facts.Add([pscustomobject]@{ Label = 'Telemetry policy:'; Value = 'Default'; Color = $textColor })
            }

            $logFolder = Join-Path $env:SystemRoot 'System32\winevt\Logs'
            $diagLogs = @(Get-ChildItem -LiteralPath $logFolder -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)DiagTrack|UniversalTelemetryClient' })
            $diagColor = if ($diagLogs.Count -gt 0) { $successColor } else { $subtColor }
            $diagValue = if ($diagLogs.Count -gt 0) { "$($diagLogs.Count) log(s)" } else { 'Not present' }
            $facts.Add([pscustomobject]@{ Label = 'Telemetry logs:'; Value = $diagValue; Color = $diagColor })
        }
        'DusmSvc' {
            $sruDb = Join-Path $env:SystemRoot 'System32\sru\SRUDB.dat'
            $sruExists = Test-Path -LiteralPath $sruDb
            $sruColor = if ($sruExists) { $successColor } else { $dangerColor }
            $sruText = if ($sruExists) { 'Present' } else { 'Missing' }
            $facts.Add([pscustomobject]@{ Label = 'SRUM DB:'; Value = $sruText; Color = $sruColor })

            $sruLog = Join-Path $env:SystemRoot 'System32\sru\SRU.log'
            $sruLogExists = Test-Path -LiteralPath $sruLog
            $facts.Add([pscustomobject]@{
                Label = 'SRUM log:'
                Value = if ($sruLogExists) { 'Present' } else { 'Missing' }
                Color = if ($sruLogExists) { $successColor } else { $warnColor }
            })
        }
        'Appinfo' {
            $luaValue = $null
            try {
                $luaValue = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction Stop).EnableLUA
            } catch {}

            $uacEnabled = ($null -eq $luaValue) -or ([int]$luaValue -ne 0)
            $uacColor = if ($uacEnabled) { $successColor } else { $dangerColor }
            $uacText = if ($uacEnabled) { 'Enabled' } else { 'Disabled (EnableLUA=0)' }
            $facts.Add([pscustomobject]@{ Label = 'UAC:'; Value = $uacText; Color = $uacColor })
        }
        'DcomLaunch' {
            $children = 0
            if ($ProcessId -and $processSnapshot) {
                $children = @($processSnapshot | Where-Object { [int]$_.ParentProcessId -eq [int]$ProcessId }).Count
            }
            $facts.Add([pscustomobject]@{ Label = 'Child processes:'; Value = [string]$children; Color = $textColor })
        }
        'WSearch' {
            $edbPath = Join-Path $env:ProgramData 'Microsoft\Search\Data\Applications\Windows\Windows.edb'
            $edbExists = Test-Path -LiteralPath $edbPath
            $edbColor = if ($edbExists) { $successColor } else { $dangerColor }
            $edbText = if ($edbExists) { 'Present' } else { 'Missing' }
            $facts.Add([pscustomobject]@{ Label = 'Index DB:'; Value = $edbText; Color = $edbColor })
        }
        'BAM' {
            $bamState = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State'
            $bamExists = Test-Path -LiteralPath $bamState
            $bamColor = if ($bamExists) { $successColor } else { $dangerColor }
            $bamText = if ($bamExists) { 'Present' } else { 'Missing' }
            $facts.Add([pscustomobject]@{ Label = 'BAM state:'; Value = $bamText; Color = $bamColor })
        }
        'DPS' {
            $wdiKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI'
            $wdiExists = Test-Path -LiteralPath $wdiKey
            $wdiText = if ($wdiExists) { 'Present' } else { 'Default' }
            $facts.Add([pscustomobject]@{ Label = 'WDI policy:'; Value = $wdiText; Color = $textColor })
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

    foreach ($eventId in @(7036, 7040, 7045)) {
        $events = @()
        try {
            $events = @(Get-WinEvent -FilterHashtable @{
                LogName   = 'System'
                Id        = $eventId
                StartTime = $since
            } -ErrorAction Stop)
        } catch {
            continue
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
                            Restarts = [Collections.Generic.List[datetime]]::new()
                            Changes  = [Collections.Generic.List[object]]::new()
                            Installs = [Collections.Generic.List[datetime]]::new()
                        }
                    }

                    if ($eventId -eq 7036) {
                        if ([string]$data['param2'] -eq 'running') {
                            $facts[$key].Restarts.Add($event.TimeCreated)
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
            $argumentColor = $dangerColor
            if ($name -eq 'javaagent' -and $value -and $value -match '(?i)theseus\.jar') {
                $argumentColor = $successColor
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

    foreach ($line in @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
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
        Count  = 0
        Status = 'Unavailable'
    }

    $token   = [guid]::NewGuid().ToString('N')
    $outFile = Join-Path $env:TEMP ('psico_prefetch_usn_' + $token + '.txt')
    $errFile = Join-Path $env:TEMP ('psico_prefetch_usn_' + $token + '.err')
    $batFile = Join-Path $env:TEMP ('psico_prefetch_usn_' + $token + '.cmd')
    $letter  = $Volume.TrimEnd(':')

    try {
        $batch = '@echo off' + "`r`n" +
            'fsutil usn readjournal ' + $letter + ': csv 2> "' + $errFile + '" | findstr /I /C:"\Windows\Prefetch" /C:"Access is denied" > "' + $outFile + '"' + "`r`n"
        [IO.File]::WriteAllText($batFile, $batch, [Text.Encoding]::Default)

        $process = Start-Process -FilePath $batFile -WindowStyle Hidden -PassThru -ErrorAction Stop
        $finished = $process.WaitForExit(30000)
        if (-not $finished) {
            try { $process.Kill() } catch {}
        }

        if (Test-Path -LiteralPath $outFile) {
            $nameIndex       = 1
            $reasonIndex     = 3
            $reasonTextIndex = 4
            $headerSeen      = $false
            $errorSeen       = $false
            $deleted         = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

            foreach ($line in [IO.File]::ReadLines($outFile)) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }

                if ($line -match '(?i)access is denied') {
                    $errorSeen = $true
                    continue
                }

                if (-not $headerSeen -and $line -match '(?i)^Usn,') {
                    $header = $line.Split(',')
                    for ($i = 0; $i -lt $header.Count; $i++) {
                        $column = $header[$i].Trim()
                        if ($column -match '(?i)^file\s*name$') { $nameIndex = $i }
                        elseif ($column -match '(?i)^reason\s*#$') { $reasonIndex = $i }
                        elseif ($column -match '(?i)^reason$') { $reasonTextIndex = $i }
                    }
                    $headerSeen = $true
                    continue
                }

                $fields = $line.Split(',')
                $maxIndex = [Math]::Max($nameIndex, [Math]::Max($reasonIndex, $reasonTextIndex))
                if ($fields.Count -le $maxIndex) { continue }

                $name = $fields[$nameIndex]
                if ($name -notmatch '(?i)\\Windows\\Prefetch\\.+\.pf') { continue }

                $isDelete = $false
                $reasonText = $fields[$reasonIndex].Trim()

                if ($reasonText -match '^0x[0-9A-Fa-f]+$') {
                    $reason = [Convert]::ToInt64($reasonText.Substring(2), 16)
                    $isDelete = (($reason -band 0x200) -ne 0 -and ($reason -band 0x80000000) -ne 0)
                } elseif ($reasonText -match '^\d+$') {
                    $reason = [Convert]::ToInt64($reasonText)
                    $isDelete = (($reason -band 0x200) -ne 0 -and ($reason -band 0x80000000) -ne 0)
                }

                if (-not $isDelete -and $fields[$reasonTextIndex] -match '(?i)FILE_DELETE') {
                    $isDelete = $true
                }

                if ($isDelete) {
                    [void]$deleted.Add($name)
                }
            }

            if ($errorSeen) {
                $result.Count = 0
                $result.Status = 'Unavailable'
            } else {
                $result.Count = $deleted.Count
                $result.Status = if (-not $finished) { 'Partial (timeout)' } else { 'OK' }

                if (Test-Path -LiteralPath $errFile) {
                    $errText = [IO.File]::ReadAllText($errFile)
                    if ($errText -match '(?i)access is denied|error|failed|denied') {
                        $result.Count = 0
                        $result.Status = 'Unavailable'
                    }
                }
            }
        } else {
            $result.Status = 'No output'
        }
    } catch {
        $result.Status = 'Unavailable'
    } finally {
        Remove-Item -LiteralPath $outFile, $errFile, $batFile -Force -ErrorAction SilentlyContinue
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
    Write-Host ([string]$jarLaunches.Count) -ForegroundColor $warnColor

    $counter = 0
    foreach ($launch in $jarLaunches) {
        $counter++
        $launchDate = if ($launch.Created) { $launch.Created.ToString($formatDate) } else { 'Unknown' }
        $jarText = if ($launch.Jar) { $launch.Jar } else { 'Unknown' }

        Write-Host ($infoIndex + "  $counter. $launchDate  PID $($launch.ProcessId)  $($launch.Name)") -ForegroundColor $titleColor
        Write-Host ($infoIndex + '     |- Jar:        ') -ForegroundColor $subtColor -NoNewline
        Write-Host $jarText -ForegroundColor $warnColor
        Write-Host ($infoIndex + '     |- Parent:     ') -ForegroundColor $subtColor -NoNewline
        Write-Host ("$($launch.ParentName) ($($launch.ParentPid))") -ForegroundColor $textColor
        Write-Host ($infoIndex + '     |- DcomLaunch: ') -ForegroundColor $subtColor -NoNewline

        if ($launch.UnderDcomLaunch) {
            Write-Host 'Yes' -ForegroundColor $dangerColor
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
    $statusColor = if ($service.State -eq 'Running') { $successColor } else { $dangerColor }
    $startTimeText = if ($service.Start) {
        $service.Start.ToString($formatDate)
    } elseif ($service.State -eq 'Running') {
        'N/A (shared/hosted process)'
    } else {
        'N/A'
    }

    $eventInfo = $serviceEvents[$service.Name]
    $restartTimes = [Collections.Generic.List[datetime]]::new()
    $changes = @()
    $installs = @()

    if ($eventInfo) {
        $changes = @($eventInfo.Changes)
        $installs = @($eventInfo.Installs)

        foreach ($restartTime in @($eventInfo.Restarts)) {
            if ($bootTime -and $restartTime -gt $bootTime.AddMinutes(2)) {
                $restartTimes.Add($restartTime)
            }
        }
    }

    $processRestarted = ($service.Start -and $bootTime -and ($service.Start -gt $bootTime.AddMinutes(2)))

    if ($processRestarted) {
        $restartTimes.Add($service.Start)
    }

    $restartTimes = @($restartTimes | Sort-Object)
    $restarted = ($restartTimes.Count -gt 0)

    if ($restarted) {
        $lastRestart = $restartTimes[-1]
        $restartedText = 'Yes (' + $lastRestart.ToString($formatDate) + ')'
        $restartedColor = $dangerColor
    } else {
        $restartedText = 'No'
        $restartedColor = $successColor
    }

    if ($changes.Count -gt 0) {
        $lastChange = $changes[-1]
        $changeText = $lastChange.From + ' -> ' + $lastChange.To + ' (' + $lastChange.Time.ToString($formatDate) + ')'
        if ($changes.Count -gt 1) { $changeText += " +$($changes.Count - 1) more" }
        $changeColor = $dangerColor
    } else {
        $changeText = 'No'
        $changeColor = $successColor
    }

    if ($serviceNumber -gt 1) {
        Write-Host ''
    }

    Write-ThinSeparator
    Write-Host ($infoIndex + $service.Name.PadRight(16)) -ForegroundColor $titleColor -NoNewline
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
        Registry = "$eventLog\Application"
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
    $lastEventRecord = Get-WinEvent -LogName $event.LogName -FilterXPath "*[System[EventID=$($event.EventId)]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    $lastEventText = if ($lastEventRecord) {
        $lastEventRecord.TimeCreated.ToString($formatDate)
    } else {
        'No records found'
    }
    $eventColor = if ($lastEventRecord) { $successColor } else { $warnColor }

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

    foreach ($sidFolder in @(Get-ChildItem -LiteralPath $recyclePath -Force -Directory -ErrorAction SilentlyContinue)) {
        if ($sidFolder.LastWriteTime -gt $lastModified) { $lastModified = $sidFolder.LastWriteTime }

        foreach ($item in @(Get-ChildItem -LiteralPath $sidFolder.FullName -Force -ErrorAction SilentlyContinue)) {
            $totalItems++
            if ($null -eq $lastItem -or $item.LastWriteTime -ge $lastItem.LastWriteTime) {
                $lastItem = $item
            }
        }
    }

    $lastItemText = if ($lastItem) { $lastItem.Name } else { 'No items found' }

    Write-Field 'Total Items:' $totalItems $fieldWidth $textColor $subtColor
    Write-Field 'Last Deleted Item:' $lastItemText $fieldWidth $textColor $subtColor
    Write-Field 'Modified Time:' $lastModified.ToString($formatDate) $fieldWidth $textColor $subtColor
} else {
    Write-Host ($infoIndex + "$recyclePath not found.") -ForegroundColor $dangerColor
}

Write-Host ''
Write-SubSection 'Console Host History'
$consoleHistPath = $null
try { $consoleHistPath = (Get-PSReadLineOption).HistorySavePath } catch {}

if ($consoleHistPath -and (Test-Path -LiteralPath $consoleHistPath)) {
    $historyFile = Get-Item -LiteralPath $consoleHistPath -Force
    $lastLine = Get-Content -LiteralPath $consoleHistPath -Last 1 -ErrorAction SilentlyContinue
    $attributes = $historyFile.Attributes
    $lastModified = $historyFile.LastWriteTime

    $status = if ($attributes -ne [IO.FileAttributes]::Archive) { $attributes.ToString() } else { 'Normal' }
    $statusColor = if ($status -eq 'Normal') { $successColor } else { $dangerColor }
    $lastCommand = if ($lastLine -eq '}') { 'ScriptBlock' } elseif ($lastLine) { $lastLine } else { '(empty)' }

    Write-Field 'Last Command:' $lastCommand $fieldWidth $textColor $subtColor
    Write-Field 'File Attributes:' $status $fieldWidth $textColor $statusColor
    Write-Field 'Modified Time:' $lastModified.ToString($formatDate) $fieldWidth $textColor $subtColor
} else {
    Write-Host ($infoIndex + 'History file not found.') -ForegroundColor $warnColor
}

Write-Host ''
Write-SubSection 'Hosts'
$hostsPath = Join-Path $env:SystemRoot 'System32\Drivers\etc\hosts'

if (Test-Path -LiteralPath $hostsPath) {
    $hostsFile = Get-Item -LiteralPath $hostsPath -Force
    $attributes = $hostsFile.Attributes
    $attributeColor = if (Test-ArchiveAttribute $attributes) { $successColor } else { $dangerColor }
    $lastModified = $hostsFile.LastWriteTime
    $content = @(Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue)
    $suspiciousLines = [Collections.Generic.List[string]]::new()

    foreach ($line in $content) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.TrimStart().StartsWith('#')) { continue }
        $suspiciousLines.Add($line.Trim())
    }

    Write-Field 'File Attributes:' $attributes.ToString() $fieldWidth $textColor $attributeColor
    Write-Field 'Modified Time:' $lastModified.ToString($formatDate) $fieldWidth $textColor $subtColor
    Write-Host ($infoIndex + 'Suspicious Lines:'.PadRight($fieldWidth)) -ForegroundColor $textColor -NoNewline

    if ($suspiciousLines.Count -eq 0) {
        Write-Host 'No suspicious lines found' -ForegroundColor $successColor
    } else {
        Write-Host ("{0} found" -f $suspiciousLines.Count) -ForegroundColor $dangerColor
        $maxShow = 3

        for ($i = 0; $i -lt [Math]::Min($maxShow, $suspiciousLines.Count); $i++) {
            Write-Host ($infoIndex + '  |- ') -ForegroundColor $subtColor -NoNewline
            Write-Host $suspiciousLines[$i] -ForegroundColor $dangerColor
        }

        if ($suspiciousLines.Count -gt $maxShow) {
            Write-Host ($infoIndex + '  |- And ') -ForegroundColor $subtColor -NoNewline
            Write-Host ($suspiciousLines.Count - $maxShow) -ForegroundColor $dangerColor -NoNewline
            Write-Host ' more...' -ForegroundColor $subtColor
        }
    }
} else {
    Write-Host ($infoIndex + "Hosts not found in '$hostsPath'") -ForegroundColor $dangerColor
}

Write-Host ''
Write-SubSection 'USNJournal ($UsnJrnl:$J)'

$usnUrl      = 'https://github.com/Orbdiff/CheckDeletedUSN/releases/download/v0.2.1/CheckDeletedUSN.exe'
$usnExe      = Join-Path $env:TEMP 'CheckDeletedUSN.exe'
$usnHash     = '3CC655225C8F9B829AD446E4390C5C738F8E3DDB560493A52EE269AA00AADF42'
$usnInFile   = Join-Path $env:TEMP 'CheckDeletedUSN.input.txt'
$usnOutFile  = Join-Path $env:TEMP 'CheckDeletedUSN.output.txt'
$usnErrFile  = Join-Path $env:TEMP 'CheckDeletedUSN.error.txt'
$usnPath     = 'C:\$Extend\$UsnJrnl:$J'
$usnCreated  = $null
$usnState    = 'Unknown'
$usnError    = $null

try {
    $needDownload = $true
    if (Test-Path -LiteralPath $usnExe) {
        $existingHash = Get-FileHash -LiteralPath $usnExe -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($existingHash -and $existingHash.Hash -eq $usnHash) { $needDownload = $false }
    }

    if ($needDownload) {
        Invoke-WebRequest -Uri $usnUrl -UseBasicParsing -OutFile $usnExe -ErrorAction Stop
        $downloadedHash = Get-FileHash -LiteralPath $usnExe -Algorithm SHA256 -ErrorAction Stop
        if ($downloadedHash.Hash -ne $usnHash) {
            throw 'El archivo descargado no coincide con el hash esperado.'
        }
    }

    Remove-Item -LiteralPath $usnOutFile, $usnErrFile -Force -ErrorAction SilentlyContinue
    [IO.File]::WriteAllText($usnInFile, "`r`n")

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

    Remove-Item -LiteralPath $usnOutFile, $usnErrFile, $usnInFile -Force -ErrorAction SilentlyContinue
} catch {
    $usnError = $_.Exception.Message
    Remove-Item -LiteralPath $usnOutFile, $usnErrFile, $usnInFile -Force -ErrorAction SilentlyContinue
}

if ($usnError) {
    Write-Field 'Check:' 'Failed' $fieldWidth $textColor $dangerColor
    Write-Host ($infoIndex + '  ' + $usnError) -ForegroundColor $subtColor
} else {
    $stateColor = if ($usnState -eq 'Intact') {
        $successColor
    } elseif ($usnState -like 'Deleted*' -or $usnState -like 'Access denied*') {
        $dangerColor
    } else {
        $warnColor
    }

    $usnCreatedText = if ($usnCreated) { $usnCreated } else { 'Unknown' }
    Write-Field 'File Path:' $usnPath $fieldWidth $textColor $subtColor
    Write-Field 'Created:' $usnCreatedText $fieldWidth $textColor $subtColor
    Write-Field 'State:' $usnState $fieldWidth $textColor $stateColor
}

Write-Host ''
Write-SubSection 'TEMP'
$tmp = $env:TEMP

if (Test-Path -LiteralPath $tmp) {
    $javaLauncherPath = Join-Path $tmp 'JavaLauncher.log'
    $javaLauncher = Get-Item -LiteralPath $javaLauncherPath -Force -ErrorAction SilentlyContinue

    Write-Host ($infoIndex + 'JavaLauncher:'.PadRight($fieldWidth)) -ForegroundColor $textColor -NoNewline
    if ($javaLauncher) {
        Write-Host 'JavaLauncher.log found' -ForegroundColor $subtColor

        $attributes = $javaLauncher.Attributes
        $attributeColor = if (Test-ArchiveAttribute $attributes) { $successColor } else { $dangerColor }
        Write-Field 'File Attributes:' $attributes.ToString() $fieldWidth $textColor $attributeColor

        $executions = @(Get-JavaLauncherExecutions -Path $javaLauncher.FullName)
        if ($executions.Count -gt 0) {
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
                Write-Host $execution.Jar -ForegroundColor $warnColor
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
    $jnativeHook = @(Get-ChildItem -LiteralPath $tmp -Filter 'JNativeHook*' -Force -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)
    Write-Host ($infoIndex + 'JNativeHook:'.PadRight($fieldWidth)) -ForegroundColor $textColor -NoNewline

    if ($jnativeHook.Count -gt 0) {
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
    Write-Host ($infoIndex + "$tmp not found.") -ForegroundColor $dangerColor
}

# --- PREFETCH INTEGRITY -------------------------------------------------------
Write-SectionHeader 'PREFETCH INTEGRITY'

$prefetchPath = Join-Path $env:SystemRoot 'Prefetch'
$prefetchFindings = [Collections.Generic.List[object]]::new()
$duplicatedHashes = @()
$prefetchStatus = 'Not found'
$prefetchColor = $dangerColor
$prefetchCount = 0
$loggedCount = 0
$readOnlyCount = 0
$deletedPrefetch = $null

if (Test-Path -LiteralPath $prefetchPath) {
    $prefetchFiles = @(Get-ChildItem -LiteralPath $prefetchPath -Filter '*.pf' -Force -File -ErrorAction SilentlyContinue)
    $prefetchCount = $prefetchFiles.Count
    $hashTable = @{}

    foreach ($file in $prefetchFiles) {
        $isHidden = (($file.Attributes -band [IO.FileAttributes]::Hidden) -eq [IO.FileAttributes]::Hidden)
        $isReadOnly = $file.IsReadOnly

        if ($isReadOnly) { $readOnlyCount++ }

        if ($isReadOnly -and $isHidden) {
            $prefetchFindings.Add([pscustomobject]@{ Type = 'Read-Only and Hidden file'; File = $file.Name })
        } elseif ($isReadOnly) {
            $prefetchFindings.Add([pscustomobject]@{ Type = 'Read-Only file'; File = $file.Name })
        } elseif ($isHidden) {
            $prefetchFindings.Add([pscustomobject]@{ Type = 'Hidden file'; File = $file.Name })
        } else {
            $readOk = $false
            $mam = ''

            try {
                $buffer = New-Object byte[] 3
                $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
                try {
                    $bytesRead = $stream.Read($buffer, 0, 3)
                } finally {
                    $stream.Dispose()
                }
                $readOk = $true
                $mam = [Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
            } catch {}

            if (-not $readOk) {
                $prefetchFindings.Add([pscustomobject]@{ Type = 'Could not read file'; File = $file.Name })
            } elseif ($mam -ne 'MAM') {
                $prefetchFindings.Add([pscustomobject]@{ Type = "Does not contain 'MAM'"; File = $file.Name })
            } else {
                $loggedCount++
            }
        }

        $hash = $null
        try {
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {}

        if (-not $hash) {
            $prefetchFindings.Add([pscustomobject]@{ Type = 'Could not calculate SHA256'; File = $file.Name })
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

    if ($prefetchFindings.Count -eq 0 -and $duplicatedHashes.Count -eq 0) {
        $prefetchStatus = 'Clean'
        $prefetchColor = $successColor
    } else {
        $prefetchStatus = 'Suspicious'
        $prefetchColor = $warnColor
    }

    $deletedPrefetch = Get-DeletedPrefetchCount -Volume $env:SystemDrive
}

Write-Host ($titleIndex + 'Prefetch status:'.PadRight($fieldWidth) + $prefetchStatus) -ForegroundColor $prefetchColor

if ($prefetchStatus -eq 'Not found') {
    Write-Host ($infoIndex + "Path: $prefetchPath") -ForegroundColor $subtColor
} else {
    $deletedText = 'N/A'
    $deletedColor = $subtColor

    if ($deletedPrefetch) {
        if ($deletedPrefetch.Status -eq 'OK') {
            $deletedText = [string]$deletedPrefetch.Count
            $deletedColor = if ($deletedPrefetch.Count -gt 0) { $warnColor } else { $successColor }
        } elseif ($deletedPrefetch.Status -eq 'Partial (timeout)') {
            $deletedText = [string]$deletedPrefetch.Count + ' (partial)'
            $deletedColor = $warnColor
        }
    }

    $readOnlyColor = if ($readOnlyCount -eq 0) { $successColor } else { $dangerColor }
    $loggedColor = if ($loggedCount -gt 0) { $successColor } else { $warnColor }

    Write-Field 'Prefetch files:' ([string]$prefetchCount) $fieldWidth $textColor $textColor
    Write-Field 'Logged (MAM valid):' ([string]$loggedCount) $fieldWidth $textColor $loggedColor
    Write-Field 'Read-only:' ([string]$readOnlyCount) $fieldWidth $textColor $readOnlyColor
    Write-Field 'Deleted (USN):' $deletedText $fieldWidth $textColor $deletedColor
    Write-Host ''

    foreach ($finding in $prefetchFindings) {
        Write-Int $infoIndex '-' $finding.Type
        Write-Host ($infoIndex + '  |- File: ') -ForegroundColor $subtColor -NoNewline
        Write-Host $finding.File -ForegroundColor $dangerColor
    }

    foreach ($group in $duplicatedHashes) {
        Write-Int $infoIndex '-' 'Duplicated hash'
        Write-Host ($infoIndex + '  |- Files: ') -ForegroundColor $subtColor -NoNewline

        $groupFiles = @($group.Value)
        for ($i = 0; $i -lt $groupFiles.Count; $i++) {
            if ($i -gt 0) { Write-Host ', ' -ForegroundColor $subtColor -NoNewline }
            Write-Host $groupFiles[$i] -ForegroundColor $dangerColor -NoNewline
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
    $itemProperty = Get-ItemProperty -LiteralPath $item.Path -Name $item.Key -ErrorAction SilentlyContinue
    $itemColor = $successColor

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

    $value = $itemProperty.$($item.Key)
    if ($null -ne $value -and $value -eq $item.Disabled) {
        $status = 'Disabled'
        $itemColor = $dangerColor
    } else {
        $status = if ($item.Name -ne 'Command Prompt') { 'Enabled' } else { 'Available' }
    }

    Write-Host ($infoIndex + $item.Name.PadRight($regNameWidth) + ' ') -ForegroundColor $textColor -NoNewline
    Write-Host ($status.PadRight(10)) -ForegroundColor $itemColor -NoNewline
    Write-Host $lastWriteText -ForegroundColor $subtColor
}

$ifeoPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$debuggers = [Collections.Generic.List[object]]::new()
$deniedKeys = [Collections.Generic.List[string]]::new()

if (Test-Path -LiteralPath $ifeoPath) {
    foreach ($key in @(Get-ChildItem -LiteralPath $ifeoPath -ErrorAction SilentlyContinue)) {
        try {
            $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            if ($properties.Debugger) {
                $debuggers.Add([pscustomobject]@{
                    Key      = $key.PSChildName
                    Debugger = $properties.Debugger
                })
            }
        } catch {
            $deniedKeys.Add($key.PSChildName)
        }
    }
} else {
    $deniedKeys.Add('Image File Execution Options (not found)')
}

Write-Host ($infoIndex + 'Debuggers (IFEO):'.PadRight($fieldWidth)) -ForegroundColor $textColor -NoNewline
if ($debuggers.Count -eq 0) {
    Write-Host 'Not found' -ForegroundColor $successColor
} else {
    Write-Host ("{0} found" -f $debuggers.Count) -ForegroundColor $dangerColor
    $counter = 0

    foreach ($debugger in $debuggers) {
        $counter++
        Write-Int $infoIndex $counter 'Debugger found'
        Write-Host ($infoIndex + '  |- Executable: ') -ForegroundColor $subtColor -NoNewline
        Write-Host $debugger.Key -ForegroundColor $warnColor
        Write-Host ($infoIndex + '  |- Debugger:   ') -ForegroundColor $subtColor -NoNewline
        Write-Host $debugger.Debugger -ForegroundColor $warnColor
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

function Get-BrowserRecorderFindings {
    $findings = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $browserNames = @(
        'chrome','firefox','msedge','opera','opera_gx','brave','vivaldi',
        'browser','waterfox','librewolf','palemoon','tor','torbrowser',
        'chromium','epicbrowser','slimjet','comodo','msedgewebview2','electron'
    )
    $recorderPattern = '(?i)(screen[\s_.-]?record|record(er|ing)?|captur|captura|grabaci[oó]n|screencast|desktopcapture|tabcapture|getdisplaymedia|obs[\s_.-]?(studio|project)?)'
    $strongRecorderPattern = '(?i)(screen[\s_.-]?record|screen[\s_.-]?captur|screencast|grabador|captura de pantalla|recorder|desktopcapture|tabcapture|getdisplaymedia)'

    foreach ($proc in @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)) {
        try {
            if (-not $proc.Name) { continue }

            $baseName = [IO.Path]::GetFileNameWithoutExtension([string]$proc.Name).ToLower()
            if ($browserNames -notcontains $baseName) { continue }

            $commandLine = [string]$proc.CommandLine
            $title = ''
            try {
                $liveProc = Get-Process -Id $proc.ProcessId -ErrorAction Stop
                $title = [string]$liveProc.MainWindowTitle
            } catch {}

            $url = ''
            $appMatch = [regex]::Match($commandLine, '(?i)--app(?:=|\s+)(?:"(?<u>[^"]+)"|''(?<u>[^'']+)''|(?<u>\S+))')
            if ($appMatch.Success) { $url = $appMatch.Groups['u'].Value.Trim() }

            if (-not $url) {
                $htmlMatch = [regex]::Match($commandLine, '(?i)(?<u>(?:[a-z]:\\|file:///|https?://)[^\s"'']+\.html?)')
                if ($htmlMatch.Success) { $url = $htmlMatch.Groups['u'].Value }
            }

            $hasHtml = ($commandLine -match '(?i)\.(html?|htm)($|["''\s?])') -or ($url -match '(?i)\.(html?|htm)($|\?|#)')
            $isHeadless = $commandLine -match '(?i)--headless'
            $isAppMode = $commandLine -match '(?i)--app(?:=|\s)' -or $commandLine -match '(?i)--kiosk'
            $keywordHit = ($url -match $strongRecorderPattern) -or
                ($title -match $strongRecorderPattern) -or
                (($isHeadless -or $isAppMode) -and $commandLine -match $strongRecorderPattern)

            if (-not ($hasHtml -or $keywordHit)) { continue }

            $kind = if ($hasHtml) {
                'HTML Recorder'
            } elseif ($isHeadless -or ($isAppMode -and [string]::IsNullOrWhiteSpace($title))) {
                'Hidden Browser Recorder'
            } else {
                'Browser Recorder'
            }

            $detail = if ($url) { $url } elseif ($title) { $title } else { 'Hidden browser instance (no window title)' }
            $key = "$kind|$baseName|$detail"
            if (-not $seen.Add($key)) { continue }

            $findings.Add([pscustomobject]@{
                Kind        = $kind
                Name        = "$($proc.Name) (PID $($proc.ProcessId))"
                Detail      = $detail
                ProcessName = $baseName
            })
        } catch {}
    }

    $extensionRoots = @(
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'),
        (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data'),
        (Join-Path $env:LOCALAPPDATA 'Vivaldi\User Data'),
        (Join-Path $env:LOCALAPPDATA 'Chromium\User Data')
    )

    foreach ($root in $extensionRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }

        foreach ($profileDir in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
            $extensionsRoot = Join-Path $profileDir.FullName 'Extensions'
            if (-not (Test-Path -LiteralPath $extensionsRoot)) { continue }

            $manifests = @(Get-ChildItem -LiteralPath $extensionsRoot -Filter 'manifest.json' -Recurse -Depth 3 -Force -File -ErrorAction SilentlyContinue |
                Select-Object -First 400)

            foreach ($manifest in $manifests) {
                try {
                    $json = Get-Content -LiteralPath $manifest.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
                    $name = [string]$json.name
                    $description = [string]$json.description
                    $permissions = @($json.permissions) + @($json.optional_permissions)
                    $capturePermission = @($permissions | Where-Object {
                        $_ -match '(?i)desktopCapture|tabCapture|videoCapture|audioCapture'
                    }).Count -gt 0

                    $nameHit = ($name -match $recorderPattern) -or ($description -match '(?i)(screen[\s_.-]?record|screen[\s_.-]?captur|screencast|grabador|captura de pantalla|desktop capture|tab capture)')
                    $permissionHit = $capturePermission -and (($name -match '(?i)record|capture|screen|grab|cast|rec)') -or ($description -match '(?i)record|capture|screen|grab|cast|rec'))

                    if (-not ($nameHit -or $permissionHit)) { continue }

                    $key = "Extension|$($manifest.FullName)"
                    if (-not $seen.Add($key)) { continue }

                    $findings.Add([pscustomobject]@{
                        Kind        = if ($capturePermission) { 'Browser Recorder Extension' } else { 'Recorder Extension' }
                        Name        = if ($name) { $name } else { $manifest.Directory.Parent.Name }
                        Detail      = $manifest.FullName
                        ProcessName = $null
                    })
                } catch {}
            }
        }
    }

    $firefoxProfiles = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
    if (Test-Path -LiteralPath $firefoxProfiles) {
        foreach ($profile in @(Get-ChildItem -LiteralPath $firefoxProfiles -Directory -ErrorAction SilentlyContinue)) {
            $extensionsFile = Join-Path $profile.FullName 'extensions.json'
            if (-not (Test-Path -LiteralPath $extensionsFile)) { continue }

            try {
                $extensions = Get-Content -LiteralPath $extensionsFile -Raw -ErrorAction Stop | ConvertFrom-Json
                foreach ($addon in @($extensions.addons)) {
                    $name = [string]$addon.defaultLocale.name
                    $description = [string]$addon.defaultLocale.description
                    if (($name -notmatch $recorderPattern) -and ($description -notmatch $recorderPattern)) { continue }

                    $key = "FirefoxExtension|$([string]$addon.id)"
                    if (-not $seen.Add($key)) { continue }

                    $findings.Add([pscustomobject]@{
                        Kind        = 'Recorder Extension'
                        Name        = if ($name) { $name } else { [string]$addon.id }
                        Detail      = "Firefox profile: $($profile.Name)"
                        ProcessName = $null
                    })
                }
            } catch {}
        }
    }

    return $findings.ToArray()
}

function Get-HtmlRecorderFindings {
    $findings = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $recorderApiPattern = '(?i)(getDisplayMedia|MediaRecorder|desktopCapturer|RecordRTC|screen[\s_.-]?record|navigator\.mediaDevices|tabCapture|getUserMedia|grabador|grabaci[oó]n de pantalla|captura de pantalla|screencast)'

    $roots = @(
        [Environment]::GetFolderPath('Desktop'),
        (Join-Path $env:USERPROFILE 'Downloads'),
        [Environment]::GetFolderPath('MyDocuments'),
        $env:TEMP
    )

    foreach ($root in $roots) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root)) { continue }

        $files = @(Get-ChildItem -LiteralPath $root -Recurse -Depth 3 -Force -File -Filter '*.htm*' -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 -and $_.Length -le 5MB } |
            Select-Object -First 500)

        foreach ($file in $files) {
            if (-not $seen.Add($file.FullName)) { continue }

            $text = ''
            $stream = $null
            try {
                $buffer = New-Object byte[] 262144
                $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
                $read = $stream.Read($buffer, 0, $buffer.Length)
                if ($read -gt 0) { $text = [Text.Encoding]::UTF8.GetString($buffer, 0, $read) }
            } catch {
                continue
            } finally {
                if ($stream) { $stream.Dispose() }
            }

            if ([string]::IsNullOrWhiteSpace($text)) { continue }

            $match = [regex]::Match($text, $recorderApiPattern)
            if (-not $match.Success) { continue }

            $findings.Add([pscustomobject]@{
                Kind        = 'HTML Recorder File'
                Name        = $file.FullName
                Detail      = "Match: $($match.Value)"
                ProcessName = $null
            })
        }
    }

    return $findings.ToArray()
}

function Invoke-ScreenCaptureKiller {
    $forbiddenProcesses = @(
        'chrome','firefox','msedge','opera','opera_gx','brave','vivaldi',
        'browser','waterfox','librewolf','palemoon','tor','torbrowser',
        'chromium','ungoogled-chromium','epicbrowser','slimjet','comodo',

        'obs','obs32','obs64','streamlabs','camtasia','bandicam','xsplit',
        'fraps','action','dxtory','sharex','screenrec','flashback','bdcam',

        'gamebar','xboxgamebar','gamebarpresencewriter','broadcastdvr',
        'discord','discordcanary','discordptb','steam','steamwebhelper',
        'overwolf','teams','riotclientservices','epicgameslauncher',

        'nvcontainer','nvdisplay.container','nvidiashare','nvbackend',
        'nvsphelper64','nvstreamer','nvtray','nvtelemetry','nvfbc','nvifrex',

        'amdsoftware','radeonsoftware','amdxcapture','amdenc','amddvr'
    )

    $detected = @{}
    $recorderFindings = @()

    try {
        $recorderFindings = @(Get-BrowserRecorderFindings) + @(Get-HtmlRecorderFindings)
    } catch {}

    $allProcs = Get-Process -ErrorAction SilentlyContinue

    foreach ($proc in $allProcs) {
        try {
            $name = $proc.Name.ToLower()
            $isForbidden = $forbiddenProcesses -contains $name
            $isCapture = $false

            $modules = $proc.Modules.ModuleName
            if (
                $modules -contains 'Windows.Graphics.Capture.dll' -or
                $modules -match 'graphicscapture' -or
                $modules -match 'nvencodeapi' -or
                $modules -match 'amdenc|amf'
            ) {
                $isCapture = $true
            }

            if (($isForbidden -or $isCapture) -and -not $detected.ContainsKey($name)) {
                $detected[$name] = @{
                    Name = $proc.Name
                    Type = if ($isForbidden -and $isCapture) {
                        'Capture + Forbidden'
                    } elseif ($isCapture) {
                        'Screen Capture'
                    } else {
                        'Forbidden Process'
                    }
                }
            }
        } catch {}
    }

    if ($detected.Count -eq 0 -and $recorderFindings.Count -eq 0) {
        Write-Host ($infoIndex + 'No capture processes or HTML/browser recorders detected.') -ForegroundColor $successColor
        return
    }

    if ($detected.Count -gt 0) {
        Write-Host ($infoIndex + 'Detected processes:') -ForegroundColor $warnColor
        Write-Host ''

        foreach ($item in $detected.Values) {
            Write-Host ($infoIndex + ('  - {0}.exe [{1}]' -f $item.Name, $item.Type)) -ForegroundColor $titleColor
        }
    }

    if ($recorderFindings.Count -gt 0) {
        if ($detected.Count -gt 0) { Write-Host '' }

        Write-Host ($infoIndex + 'HTML / browser recorders:') -ForegroundColor $warnColor
        Write-Host ''

        foreach ($finding in $recorderFindings) {
            Write-Host ($infoIndex + ('  - [{0}] {1}' -f $finding.Kind, $finding.Name)) -ForegroundColor $titleColor
            Write-Host ($infoIndex + '      |- ') -ForegroundColor $subtColor -NoNewline
            Write-Host $finding.Detail -ForegroundColor $warnColor
        }
    }

    if ($detected.Count -eq 0) {
        Write-Host ''
        Write-Host ($infoIndex + 'No process to kill. Only HTML/browser recorder artifacts were found.') -ForegroundColor $warnColor
        return
    }

    Write-Host ''
    Write-Host ($infoIndex + '[A] Kill all detected processes.') -ForegroundColor $textColor
    Write-Host ($infoIndex + '[B] Kill 1 specific process.') -ForegroundColor $textColor
    Write-Host ($infoIndex + '[C] Kill all except 1 process.') -ForegroundColor $textColor
    Write-Host ''

    $choice = Read-Host '  Select option (A / B / C)'

    switch ($choice.ToUpper()) {
        'A' {
            foreach ($item in $detected.Values) {
                Get-Process -Name $item.Name -ErrorAction SilentlyContinue |
                    Stop-Process -Force
                Write-Host "[Terminated] $($item.Name).exe" -ForegroundColor $dangerColor
            }
        }
        'B' {
            $target = Read-Host '  Enter process name (example: chrome or chrome.exe)'
            $target = $target.ToLower().Replace('.exe', '')

            if ($detected.ContainsKey($target)) {
                Get-Process -Name $target -ErrorAction SilentlyContinue |
                    Stop-Process -Force
                Write-Host "[Terminated] $target.exe" -ForegroundColor $dangerColor
            } else {
                Write-Host '[Error] Process not found.' -ForegroundColor $dangerColor
            }
        }
        'C' {
            $exclude = Read-Host '  Enter process name to keep alive (example: chrome or chrome.exe)'
            $exclude = $exclude.ToLower().Replace('.exe', '')

            if (-not $detected.ContainsKey($exclude)) {
                Write-Host '[Error] Process not found.' -ForegroundColor $dangerColor
                return
            }

            foreach ($key in $detected.Keys) {
                if ($key -ne $exclude) {
                    Get-Process -Name $key -ErrorAction SilentlyContinue |
                        Stop-Process -Force
                    Write-Host "[Terminated] $key.exe" -ForegroundColor $dangerColor
                }
            }

            Write-Host "[+] Kept alive: $exclude.exe" -ForegroundColor $successColor
        }
    }
}

Invoke-ScreenCaptureKiller

# --- Footer -------------------------------------------------------------------
Write-Host ''
Write-GradientRow ('╔' + ('═' * $panelInner) + '╗') $frameFrom $frameTo
Write-GradientRow ('║' + (Center-Inner 'ESCANEO COMPLETADO' $panelInner) + '║') $frameFrom $frameTo
Write-GradientRow ('╚' + ('═' * $panelInner) + '╝') $frameFrom $frameTo
Write-Host ''
