$ErrorActionPreference = "Stop"

# Windows PowerShell 5.1 may default to TLS 1.0 on older .NET Framework
# installations, while GitHub's release endpoints require TLS 1.2.
if ($PSVersionTable.PSEdition -eq "Desktop") {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

$repository = "HUA503/mcprism"
$requestedVersion = $env:MC_PRISM_VERSION
if ([string]::IsNullOrWhiteSpace($requestedVersion) -or $requestedVersion -eq "latest") {
    $releaseBase = "https://github.com/$repository/releases/latest/download"
} else {
    if ($requestedVersion -cnotmatch '\Av?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?\z') {
        throw "Invalid MC_PRISM_VERSION '$requestedVersion'. Expected 'latest' or a version such as 'v0.35.0'."
    }
    if (-not $requestedVersion.StartsWith("v", [System.StringComparison]::Ordinal)) {
        $requestedVersion = "v$requestedVersion"
    }
    $releaseBase = "https://github.com/$repository/releases/download/$requestedVersion"
}
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
if ($architecture -eq "X86" -and [Environment]::Is64BitOperatingSystem) {
    $architecture = "X64"
}

switch ($architecture) {
    "X64" { $archiveArchitecture = "amd64" }
    "Arm64" { $archiveArchitecture = "arm64" }
    default {
        throw "Unsupported Windows architecture: $architecture. Download a compatible binary from https://github.com/$repository/releases"
    }
}

$archiveName = "mcprism_windows_$archiveArchitecture.zip"
$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("mcprism-" + [guid]::NewGuid().ToString("N"))
$installDirectory = Join-Path $env:LOCALAPPDATA "Programs\mcprism"
$archivePath = Join-Path $temporaryDirectory $archiveName
$checksumsPath = Join-Path $temporaryDirectory "checksums.txt"
$extractDirectory = Join-Path $temporaryDirectory "unpacked"
$binaryPath = Join-Path $extractDirectory "mcprism.exe"

try {
    New-Item -ItemType Directory -Path $extractDirectory -Force | Out-Null
    Invoke-WebRequest -Uri "$releaseBase/$archiveName" -OutFile $archivePath
    Invoke-WebRequest -Uri "$releaseBase/checksums.txt" -OutFile $checksumsPath

    $checksumLine = Get-Content -LiteralPath $checksumsPath |
        Where-Object { $_ -match ("^([a-fA-F0-9]{64})\s+\*?" + [regex]::Escape($archiveName) + "$") } |
        Select-Object -First 1
    if (-not $checksumLine) {
        throw "No SHA-256 checksum found for $archiveName."
    }

    $expectedHash = [regex]::Match($checksumLine, "^[a-fA-F0-9]{64}").Value.ToLowerInvariant()
    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "SHA-256 verification failed for $archiveName."
    }

    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDirectory -Force
    if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
        throw "The release archive does not contain mcprism.exe."
    }

    New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
    Copy-Item -LiteralPath $binaryPath -Destination (Join-Path $installDirectory "mcprism.exe") -Force

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $pathEntries = @($userPath -split ";" | Where-Object { $_ })
    if (-not ($pathEntries | Where-Object { $_.TrimEnd("\") -ieq $installDirectory.TrimEnd("\") })) {
        $updatedPath = (@($pathEntries) + $installDirectory) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $updatedPath, "User")
        $env:Path = "$installDirectory;$env:Path"
        Write-Output "Added $installDirectory to your user PATH. Open a new terminal to use it."
    }

    Write-Output "Installed mcprism to $installDirectory"
    & (Join-Path $installDirectory "mcprism.exe") version
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
