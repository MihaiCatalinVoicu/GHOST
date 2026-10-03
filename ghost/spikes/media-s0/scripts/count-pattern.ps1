# V-M20 helper: counts, on a 4-pixel grid, the pixels of each image that match ViewerActivity's
# pattern colours (magenta 255,0,255; lime 0,255,0; cyan 0,255,255). A snapshot that holds the
# media shows thousands of them; a black, blank or placeholder snapshot shows none.
#   pwsh -File scripts/count-pattern.ps1 <file>...
param([Parameter(ValueFromRemainingArguments = $true)][string[]] $Files)
Add-Type -AssemblyName System.Drawing
foreach ($f in $Files) {
    try {
        $b = [System.Drawing.Bitmap]::FromFile((Resolve-Path $f))
    } catch {
        Write-Output "$f : not an image ($($_.Exception.Message))"
        continue
    }
    $m = 0; $g = 0; $c = 0; $n = 0; $black = 0
    for ($y = 0; $y -lt $b.Height; $y += 4) {
        for ($x = 0; $x -lt $b.Width; $x += 4) {
            $p = $b.GetPixel($x, $y); $n++
            if ($p.R -gt 200 -and $p.G -lt 70 -and $p.B -gt 200) { $m++ }
            elseif ($p.R -lt 70 -and $p.G -gt 200 -and $p.B -lt 70) { $g++ }
            elseif ($p.R -lt 70 -and $p.G -gt 200 -and $p.B -gt 200) { $c++ }
            elseif ($p.R -lt 16 -and $p.G -lt 16 -and $p.B -lt 16) { $black++ }
        }
    }
    Write-Output ("{0} : {1}x{2} sampled={3} magenta={4} lime={5} cyan={6} black={7}" -f $f, $b.Width, $b.Height, $n, $m, $g, $c, $black)
    $b.Dispose()
}
