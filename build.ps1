$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

python -c "import PyInstaller" 2>$null
if (-not $?) {
    Write-Host "Installing PyInstaller..."
    python -m pip install --upgrade pyinstaller
}

python -m PyInstaller --noconfirm --clean --onefile --windowed `
    --name "php2shell_checker" `
    --icon "app.ico" `
    --add-data "app.ico;." `
    app.py

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "Build complete: $PSScriptRoot\dist\php2shell_checker.exe"
