<#
.SYNOPSIS
    Apply a dUP2-style Search-and-Replace patch table to a file (PowerShell port
    of the dup2_parser engine).

.DESCRIPTION
    Reads a patch table from a JSON file (as produced by dup2_parser.py --json),
    a raw resource blob (starts with 04 00 00 00), or a hex-dump text file, and
    applies each unit to a target file using the same rules as dUP2:
      * search skips positions whose find_mask byte is 01 (wildcard)
      * on a match, replace[] is written only where write_mask byte is 00
      * flags: 0xFFFFFFFF = replace ALL matches; 1 = first only; N = Nth only
    Non-destructive by default: writes <Target>.patched and leaves the original
    alone unless -InPlace (which first saves a .bak) is given. -DryRun reports
    only.

.PARAMETER PatchFile
    Path to the patch table (.json, raw .bin, or hex-dump .txt). Auto-detected.

.PARAMETER Target
    Path to the file to patch.

.PARAMETER OutFile
    Output path. Default: <Target>.patched.

.PARAMETER InPlace
    Overwrite Target in place (a <Target>.bak backup is written first).

.PARAMETER DryRun
    Report what would change; write nothing.

.PARAMETER Resource
    If the table holds several resources, choose this 0-based index.

.EXAMPLE
    . .\Invoke-Dup2Patch.ps1
    Invoke-Dup2Patch -PatchFile Res_2.json -Target .\app.bin -DryRun

.EXAMPLE
    Invoke-Dup2Patch -PatchFile Res_2.bin -Target .\app.bin -OutFile .\app.patched.bin
#>

function Resolve-FsPath {
    # Turn a (possibly relative) PowerShell path into an absolute filesystem
    # path based on PowerShell's current location. Works for files that don't
    # exist yet (e.g. -OutFile). .NET file APIs use the process CWD, which is
    # NOT PowerShell's $PWD, so every path handed to [System.IO.File] goes
    # through here first.
    param([string]$Path)
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Convert-HexToBytes {
    param([string]$Hex)
    $toks = $Hex -split '\s+' | Where-Object { $_ -ne '' }
    $b = New-Object byte[] $toks.Count
    for ($i = 0; $i -lt $toks.Count; $i++) { $b[$i] = [Convert]::ToByte($toks[$i], 16) }
    ,$b
}

function Get-Slice {
    param([byte[]]$Data, [int]$Start, [int]$Len)
    $out = New-Object byte[] $Len
    [Array]::Copy($Data, $Start, $out, 0, $Len)
    ,$out
}

function Get-FlagMeaning {
    param([uint32]$Flags)
    if ($Flags -eq [uint32]4294967295) { return 'replace ALL matches' }
    if ($Flags -eq 1)                  { return 'replace 1st match only' }
    return "replace match #$Flags only"
}

function ConvertFrom-Dup2Blob {
    # parse one raw resource blob (byte[]) -> resource hashtable
    param([byte[]]$D)
    $apu = [BitConverter]::ToUInt32($D, 0)
    if ($apu -lt 1 -or $apu -gt 16) { $apu = 4 }
    $ns = 0x22; $ne = $ns
    while ($ne -lt $D.Length -and $D[$ne] -ne 0) { $ne++ }
    $name = [Text.Encoding]::ASCII.GetString($D, $ns, $ne - $ns)
    $off = $ne + 1
    $units = New-Object System.Collections.ArrayList
    while ($off + 8 -le $D.Length) {
        $size  = [BitConverter]::ToUInt32($D, $off)
        $flags = [BitConverter]::ToUInt32($D, $off + 4)
        $stride = 8 + $apu * $size
        if ($size -eq 0 -or $size -gt 0x1000 -or ($off + $stride) -gt $D.Length) { break }
        $sz = [int]$size; $base = $off + 8
        $pat = New-Object byte[] $sz; [Array]::Copy($D, $base,            $pat, 0, $sz)
        $fm  = New-Object byte[] $sz; [Array]::Copy($D, $base + $sz,      $fm,  0, $sz)
        $rp  = New-Object byte[] $sz; [Array]::Copy($D, $base + 2 * $sz,  $rp,  0, $sz)
        $wm  = New-Object byte[] $sz; [Array]::Copy($D, $base + 3 * $sz,  $wm,  0, $sz)
        [void]$units.Add([pscustomobject]@{
            Offset = $off; Size = $sz; Flags = [uint32]$flags
            Pattern = $pat; FindMask = $fm; Replace = $rp; WriteMask = $wm
        })
        $off += $stride
    }
    [pscustomobject]@{ Target = $name; ArraysPerUnit = [int]$apu; Units = $units }
}

function Import-Dup2Table {
    # read a patch file -> array of resource objects
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hasNul = $false
    foreach ($b in $bytes) { if ($b -eq 0) { $hasNul = $true; break } }

    if (-not $hasNul) {
        $text = [Text.Encoding]::UTF8.GetString($bytes)
        $trim = $text.TrimStart()
        if ($trim.StartsWith('{') -or $trim.StartsWith('[')) {
            $j = $text | ConvertFrom-Json
            $res = @()
            foreach ($r in $j.resources) {
                $units = New-Object System.Collections.ArrayList
                foreach ($u in $r.units) {
                    [void]$units.Add([pscustomobject]@{
                        Offset = [int]$u.offset; Size = [int]$u.size; Flags = [uint32]$u.flags
                        Pattern   = [byte[]](Convert-HexToBytes $u.pattern)
                        FindMask  = [byte[]](Convert-HexToBytes $u.find_mask)
                        Replace   = [byte[]](Convert-HexToBytes $u.replace)
                        WriteMask = [byte[]](Convert-HexToBytes $u.write_mask)
                    })
                }
                $res += [pscustomobject]@{ Target = $r.target; ArraysPerUnit = 4; Units = $units }
            }
            return $res
        }
        # hex-dump text: gather hex-only lines into blobs (blank line separates)
        $blobs = @(); $cur = New-Object System.Collections.ArrayList
        foreach ($ln in ($text -split "`r?`n")) {
            $s = $ln.Trim()
            if ($s -ne '' -and $s -match '^([0-9A-Fa-f]{2}\s*)+$') {
                foreach ($t in ($s -split '\s+')) { if ($t) { [void]$cur.Add([Convert]::ToByte($t,16)) } }
            } elseif ($cur.Count) { $blobs += ,([byte[]]$cur.ToArray()); $cur.Clear() }
        }
        if ($cur.Count) { $blobs += ,([byte[]]$cur.ToArray()) }
        return @($blobs | ForEach-Object { ConvertFrom-Dup2Blob $_ })
    }
    return @((ConvertFrom-Dup2Blob $bytes))
}

function Find-Dup2Match {
    # offsets in $Bytes where pattern matches, ignoring find_mask wildcards
    param([byte[]]$Bytes, [string]$Text, [byte[]]$Pattern, [byte[]]$FindMask)
    $n = $Pattern.Length
    # longest run of significant (find_mask==0) bytes -> search anchor
    $bestS = 0; $bestE = -1; $curS = $null
    for ($i = 0; $i -le $n; $i++) {
        $sig = ($i -lt $n) -and ($FindMask[$i] -eq 0)
        if ($sig -and $null -eq $curS) { $curS = $i }
        if ((-not $sig) -and $null -ne $curS) {
            if (($i - 1 - $curS) -gt ($bestE - $bestS)) { $bestS = $curS; $bestE = $i - 1 }
            $curS = $null
        }
    }
    $enc = [Text.Encoding]::GetEncoding(28591)   # ISO-8859-1: 1:1 byte<->char
    $sigIdx = for ($i = 0; $i -lt $n; $i++) { if ($FindMask[$i] -eq 0) { $i } }
    $results = New-Object System.Collections.ArrayList
    if ($bestE -lt $bestS) { return @() }   # degenerate (all wildcard)
    $anchor = $enc.GetString((Get-Slice $Pattern $bestS ($bestE - $bestS + 1)))
    $a0 = $bestS
    $start = 0
    while ($true) {
        $j = $Text.IndexOf($anchor, $start, [StringComparison]::Ordinal)
        if ($j -lt 0) { break }
        $off = $j - $a0; $start = $j + 1
        if ($off -lt 0 -or ($off + $n) -gt $Bytes.Length) { continue }
        $ok = $true
        foreach ($i in $sigIdx) { if ($Bytes[$off + $i] -ne $Pattern[$i]) { $ok = $false; break } }
        if ($ok) { [void]$results.Add($off) }
    }
    return $results.ToArray()
}

function Invoke-Dup2Patch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PatchFile,
        [Parameter(Mandatory)][string]$Target,
        [string]$OutFile,
        [switch]$InPlace,
        [switch]$DryRun,
        [int]$Resource = -1
    )
    # Resolve to absolute filesystem paths (PowerShell location, not .NET CWD)
    $PatchFile = Resolve-FsPath $PatchFile
    $Target    = Resolve-FsPath $Target
    if ($OutFile) { $OutFile = Resolve-FsPath $OutFile }

    if (-not (Test-Path -LiteralPath $PatchFile)) { Write-Error "patch file not found: $PatchFile"; return }
    if (-not (Test-Path -LiteralPath $Target))    { Write-Error "target not found: $Target"; return }

    $resources = Import-Dup2Table -Path $PatchFile
    if (-not $resources -or $resources.Count -eq 0) { Write-Error "no patch data found"; return }

    # choose resource
    if ($Resource -ge 0) {
        if ($Resource -ge $resources.Count) { Write-Error "resource $Resource out of range (0..$($resources.Count-1))"; return }
        $r = $resources[$Resource]
    } elseif ($resources.Count -eq 1) {
        $r = $resources[0]
    } else {
        $base = [IO.Path]::GetFileName($Target).ToLower()
        $r = $resources | Where-Object { $_.Target.ToLower() -eq $base } | Select-Object -First 1
        if (-not $r) { $r = $resources[0]; Write-Host "note: $($resources.Count) resources; using #0 (use -Resource N)" -ForegroundColor Yellow }
    }

    $tname = [IO.Path]::GetFileName($Target)
    if ($r.Target -and $r.Target.ToLower() -ne $tname.ToLower()) {
        Write-Host "note: table targets '$($r.Target)', patching '$tname' anyway." -ForegroundColor Yellow
    }

    $buf = [System.IO.File]::ReadAllBytes($Target)
    $enc = [Text.Encoding]::GetEncoding(28591)
    $total = 0
    Write-Host ("patching {0} ({1:N0} bytes) with {2} unit(s):" -f $Target, $buf.Length, $r.Units.Count)

    for ($idx = 0; $idx -lt $r.Units.Count; $idx++) {
        $u = $r.Units[$idx]
        $text = $enc.GetString($buf)                       # rebuilt each unit: sees prior edits
        $matches = @(Find-Dup2Match -Bytes $buf -Text $text -Pattern $u.Pattern -FindMask $u.FindMask)

        if ($u.Flags -eq [uint32]4294967295) { $targets = $matches }
        elseif ($u.Flags -ge 1 -and $u.Flags -le $matches.Count) { $targets = @($matches[[int]$u.Flags - 1]) }
        else { $targets = @() }

        foreach ($off in $targets) {
            for ($i = 0; $i -lt $u.Size; $i++) {
                if ($u.WriteMask[$i] -ne 1) { $buf[$off + $i] = $u.Replace[$i] }
            }
            $total++
        }

        $at = if ($targets.Count) { ($targets | ForEach-Object { '0x{0:X}' -f $_ }) -join ' ' } else { '-' }
        $note = ''
        if ($matches.Count -eq 0) { $note = '  [PATTERN NOT FOUND]' }
        elseif ($u.Flags -ne [uint32]4294967295 -and -not ($u.Flags -ge 1 -and $u.Flags -le $matches.Count)) {
            $note = "  [wanted match #$($u.Flags), only $($matches.Count) found]"
        }
        Write-Host ("  unit {0,2} len={1,3} [{2}]: {3} match(es), {4} applied @ {5}{6}" -f `
            $idx, $u.Size, (Get-FlagMeaning $u.Flags), $matches.Count, $targets.Count, $at, $note)
    }

    if ($DryRun) {
        Write-Host "`n[dry-run] $total replacement(s) would be written; no file changed." -ForegroundColor Cyan
        return
    }
    if ($total -eq 0) { Write-Host "`nnothing matched; no output written." -ForegroundColor Yellow; return }

    if ($InPlace) {
        $bak = "$Target.bak"
        if (-not (Test-Path -LiteralPath $bak)) { [System.IO.File]::WriteAllBytes($bak, [System.IO.File]::ReadAllBytes($Target)) }
        [System.IO.File]::WriteAllBytes($Target, $buf)
        Write-Host "`nwrote $total replacement(s) in place: $Target  (backup: $bak)" -ForegroundColor Green
    } else {
        $dst = if ($OutFile) { $OutFile } else { "$Target.patched" }
        [System.IO.File]::WriteAllBytes($dst, $buf)
        Write-Host "`nwrote $total replacement(s) -> $dst  (original untouched)" -ForegroundColor Green
    }
}

# If run directly (not dot-sourced) with args, invoke with the passed parameters.
if ($MyInvocation.InvocationName -ne '.' -and $args.Count -gt 0) {
    Invoke-Dup2Patch @args
}
