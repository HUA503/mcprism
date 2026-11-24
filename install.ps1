$ErrorActionPreference = "Stop"

$repository = "HUA503/mcprism"
$releaseBase = "https://github.com/$repository/releases/latest/download"
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture

switch ($architecture) {
    "X64" { $archiveArchitecture = "amd64" }
    default {
        throw "No Windows release is published for architecture $architecture. Download a compatible binary from https://github.com/$repository/releases"
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
