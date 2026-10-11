# CT-01 T21b R3 — client side (PowerShell 5.1+ / 7). Run on YOUR machine. Ends by itself (max 300 s).
# Each line the SSH channel delivers is stamped on arrival: `RX <utc-iso> <client-monotonic-ms, invariant culture '.'> <line>` and appended (ASCII) to the file.
param([Parameter(Mandatory=$true)][string]$RunId, [string]$HostSpec = "dathq@192.168.177.128", [int]$MaxSeconds = 300)
$ErrorActionPreference = "Stop"
$file = Join-Path $env:USERPROFILE "Downloads\t21b-client-$RunId.log"
if (Test-Path $file) { throw "$file already exists: do not reuse a run id/log" }
$inv = [Globalization.CultureInfo]::InvariantCulture
$remote = "python3 -I -B /home/dathq/projects/ct01-t21b-r3/t21b_heartbeat.py $RunId /home/dathq/projects/ct01-t21b-run-$RunId --interval 1 --max-seconds $MaxSeconds"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
ssh -tt $HostSpec $remote | ForEach-Object {
    $ms = $sw.Elapsed.TotalMilliseconds.ToString('F3', $inv)
    $l = "RX $([DateTime]::UtcNow.ToString('o', $inv)) $ms $($_ -replace "`r", '')"
    $l
    Add-Content -Path $file -Value $l -Encoding ascii
}
"client log: $file"
