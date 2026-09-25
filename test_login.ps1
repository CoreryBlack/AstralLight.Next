if ([string]::IsNullOrWhiteSpace($env:TEST_PASSWORD)) {
    throw "TEST_PASSWORD is required"
}

$testPhone = $env:TEST_PHONE ?? "13800000001"
$body = @{phone=$testPhone; password=$env:TEST_PASSWORD} | ConvertTo-Json
Write-Output "Request body: $body"
try {
    $r = Invoke-WebRequest -Uri "http://localhost:9001/api/v1/auth/login" -Method Post -ContentType "application/json" -Body $body -UseBasicParsing
    Write-Output "Status: $($r.StatusCode)"
    Write-Output "Response: $($r.Content)"
} catch {
    Write-Output "Error: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $content = $reader.ReadToEnd()
        Write-Output "Response body: $content"
    }
}
