# Trust-based Intrusion Detection System (tIDS) Run Script

Write-Host "Checking for Python Virtual Environment..." -ForegroundColor Cyan
if (-Not (Test-Path ".\.venv")) {
    Write-Host "Virtual environment not found. Creating one..." -ForegroundColor Yellow
    python -m venv .venv
}

Write-Host "Activating Virtual Environment..." -ForegroundColor Cyan
& ".\.venv\Scripts\Activate.ps1"

Write-Host "Installing/Updating Dependencies..." -ForegroundColor Cyan
pip install -r requirements.txt

Write-Host "Starting FastAPI Server..." -ForegroundColor Green
Write-Host "Note: If sniffing fails, ensure you are running this terminal as ADMINISTRATOR." -ForegroundColor Yellow
cd web
uvicorn main:app --reload --host 127.0.0.1 --port 8000
