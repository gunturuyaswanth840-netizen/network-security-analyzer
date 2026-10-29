# Define an array of standard real-world XSS payloads to test
$xss_payloads = @(
    "<script>alert(1)</script>",                  # Basic Script Tag
    '"><script>alert(1)</script>',                # Attribute Breakout
    "<img src=x onerror=alert(1)>",               # Alternative HTML Tag Breakout
    "<svg onload=alert(1)>",                      # Vector-based Injection
    "javascript:alert(1)"                         # URI Protocol Scheme Payload
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "   STARTING AUTOMATED XSS FUZZER LAB     " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

foreach ($payload in $xss_payloads) {
    Write-Host "`nTesting Payload Vector: [$payload]" -ForegroundColor Yellow
    
    # 1. Dynamically rewrite the injection variable line inside xss_injection_lab.py
    # Using single quotes to prevent PowerShell token parsing conflicts
    (Get-Content .\xss_injection_lab.py) -replace 'payload = .*', "payload = '$payload'" | Set-Content .\xss_injection_lab.py
    
    # 2. Execute the updated target rendering lab script
    $output = .\.venv\Scripts\python.exe .\xss_injection_lab.py 2>&1
    
    # 3. Parse output highlights
    foreach ($line in $output) {
        if ($line -like "*MATCH FOUND:*") {
            Write-Host "  [+] VULNERABLE RENDER DETECTED: $line" -ForegroundColor Green
        } elseif ($line -like "*NO MATCH:*") {
            Write-Host "  [-] NEUTRALIZED SANITIZATION: $line" -ForegroundColor DarkGray
        } else {
            Write-Host "      $line" -ForegroundColor White
        }
    }
}
