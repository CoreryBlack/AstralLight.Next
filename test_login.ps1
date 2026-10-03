if ([string]::IsNullOrWhiteSpace($env:TEST_PASSWORD)) {
    throw "TEST_PASSWORD is required"
}

$testPhone = $env:TEST_PHONE ?? "13800000001"
$body = @{phone=$testPhone; password=$env:TEST_PASSWORD} | ConvertTo-Json -Compress
try {
    $r = Invoke-WebRequest -Uri "http://localhost:9001/api/v1/auth/login" -Method Post -ContentType "application/json" -Body $body -UseBasicParsing
    Write-Output "Login probe completed with HTTP $($r.StatusCode). Response content withheld."
    if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 300) {
        exit 1
    }
} catch {
    $statusCode = $null
    if ($_.Exception.Response) {
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { }
    }
    if ($null -ne $statusCode) {
        Write-Error "Login probe failed with HTTP $statusCode. Response content withheld."
    } else {
        Write-Error "Login probe failed before receiving an HTTP response. Details withheld."
    }
    exit 1
}
