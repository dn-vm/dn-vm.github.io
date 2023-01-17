
$dnvmFeed = if ($env:DNVM_FEED) { $env:DNVM_FEED } else { "https://github.com/dn-vm/dnvm/releases/download" }
$latestVersion = "0.3.0" # To be replaced during publish

function Get-Arch {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        X64 { 'x64'; break; }
        default {
            throw 'Unsupported architecture: ' + $arch
        }
    }
}

$arch = Get-Arch
$url = "$dnvmFeed/v$latestVersion/dnvm-$latestVersion-win-$arch.zip"

Function New-TemporaryFolder {
    # Make a new folder based upon a TempFileName
    $T="$($Env:temp)\tmp$([convert]::tostring((get-random 65535),16).padleft(4,'0')).tmp"
    New-Item -ItemType Directory -Path $T
}

$dir = New-TemporaryFolder
$archiveFile = Join-Path "$dir" "dnvm.zip"
$archiveFolder = Join-Path "$dir" "dnvm"
$file = Join-Path "$archiveFolder" "dnvm.exe"

echo "Downloading dnvm"
Invoke-WebRequest -Uri $url -OutFile "$archiveFile"
Expand-Archive $archiveFile -DestinationPath $archiveFolder
ls $archiveFolder
. $file install --self

rm "$archiveFile"
rm "$file"
rmdir "$archiveFolder"
rmdir "$dir"
