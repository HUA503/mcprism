$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    [Console]::Error.WriteLine("mcprism action: $Message")
    exit 2
}

$version = $env:MC_PRISM_VERSION
if ([string]::IsNullOrWhiteSpace($version)) {
    $version = $env:MC_PRISM_ACTION_REF -replace '^refs/tags/', ''
}
if ($version -notmatch '^v\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$') {
    Fail 'set version to a release tag such as v0.17.0, or pin this action to a release tag'
}

$inventoryTarget = $env:MC_PRISM_INVENTORY_TARGET
$inventoryBaseline = $env:MC_PRISM_INVENTORY_BASELINE
if ($inventoryTarget -and -not $inventoryBaseline) {
    Fail 'inventory-target requires inventory-baseline'
}
if (-not $inventoryTarget -and $inventoryBaseline) {
    Fail 'inventory-baseline requires inventory-target'
}

switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    'X64' { $arch = 'amd64' }
    'Arm64' { $arch = 'arm64' }
    default { Fail "unsupported Windows architecture: $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)" }
}

$archive = "mcprism_windows_${arch}.zip"
$base = "https://github.com/HUA503/mcprism/releases/download/$version"
$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($tmpDir)

try {
    $archivePath = Join-Path $tmpDir $archive
    $checksumsPath = Join-Path $tmpDir 'checksums.txt'
    foreach ($download in @(@{ Url = "$base/$archive"; Path = $archivePath }, @{ Url = "$base/checksums.txt"; Path = $checksumsPath })) {
        & curl.exe --fail --location --silent --show-error --retry 3 $download.Url --output $download.Path
        if ($LASTEXITCODE -ne 0) {
            Fail "download failed: $($download.Url)"
        }
    }

    $checksumLine = Get-Content -LiteralPath $checksumsPath | Where-Object {
        $columns = $_.Trim() -split '\s+'
        $filename = $columns[-1]
        if ($filename.StartsWith('*')) {
            $filename = $filename.Substring(1)
        }
        $columns.Count -ge 2 -and $filename -ceq $archive
    } | Select-Object -First 1
    if (-not $checksumLine) {
        Fail "no SHA-256 checksum found for $archive in release $version"
    }
    $expected = ($checksumLine -split '\s+')[0].ToLowerInvariant()
    if ($expected -notmatch '^[0-9a-f]{64}$') {
        Fail "no valid SHA-256 checksum found for $archive in release $version"
    }
    $actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $expected) {
        Fail "SHA-256 verification failed for $archive"
    }

    Expand-Archive -LiteralPath $archivePath -DestinationPath $tmpDir -Force
    $binary = Join-Path $tmpDir 'mcprism.exe'
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        Fail 'release archive does not contain mcprism.exe'
    }

    $workspace = $env:GITHUB_WORKSPACE
    if ([string]::IsNullOrWhiteSpace($workspace)) {
        $workspace = $PWD.Path
    }
    $sarifFile = $env:MC_PRISM_SARIF_FILE
    if ([string]::IsNullOrWhiteSpace($sarifFile)) {
        $sarifFile = 'mcprism.sarif'
    }
    if ([System.IO.Path]::IsPathRooted($sarifFile)) {
        Fail 'sarif-file must be a workspace-relative path'
    }
    $sarifPath = Join-Path $workspace $sarifFile
    $sarifParent = Split-Path -Parent $sarifPath
    if ($sarifParent) {
        [void][System.IO.Directory]::CreateDirectory($sarifParent)
    }

    $target = $env:MC_PRISM_TARGET
    if ([string]::IsNullOrWhiteSpace($target)) {
        $target = '.'
    }
    $scanArgs = @('scan', $target, '--format', 'sarif', '--output', $sarifPath)
    if ($env:MC_PRISM_PROFILE) { $scanArgs += @('--profile', $env:MC_PRISM_PROFILE) }
    if ($env:MC_PRISM_POLICY) { $scanArgs += @('--policy', $env:MC_PRISM_POLICY) }
    if ($env:MC_PRISM_SUPPRESSIONS) { $scanArgs += @('--suppressions', $env:MC_PRISM_SUPPRESSIONS) }
    if ($env:MC_PRISM_BASELINE) { $scanArgs += @('--baseline', $env:MC_PRISM_BASELINE) }
    if ($env:MC_PRISM_FAIL_ON) { $scanArgs += @('--fail-on', $env:MC_PRISM_FAIL_ON) }

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::AppendAllText($env:GITHUB_OUTPUT, "sarif-file=$sarifFile`nversion=$version`n", $utf8NoBom)

    & $binary @scanArgs
    $scanStatus = $LASTEXITCODE
    $inventoryStatus = 'skipped'
    $inventoryExit = 0
    if ($inventoryBaseline -and $scanStatus -ne 2) {
        & $binary inventory verify $inventoryTarget --baseline $inventoryBaseline
        $inventoryExit = $LASTEXITCODE
        switch ($inventoryExit) {
            0 { $inventoryStatus = 'passed' }
            1 { $inventoryStatus = 'drift' }
            default { $inventoryStatus = 'error' }
        }
    }
    [System.IO.File]::AppendAllText($env:GITHUB_OUTPUT, "inventory-status=$inventoryStatus`n", $utf8NoBom)

    if ($scanStatus -eq 2 -or $inventoryExit -eq 2) {
        exit 2
    }
    if ($scanStatus -ne 0 -or $inventoryExit -ne 0) {
        exit 1
    }
    exit 0
}
finally {
    if (Test-Path -LiteralPath $tmpDir) {
        Remove-Item -LiteralPath $tmpDir -Recurse -Force
    }
}
