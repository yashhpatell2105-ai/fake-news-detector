Write-Host "Installing dependencies..." -ForegroundColor Green
pip install -r requirements.txt
Write-Host ""
Write-Host "Starting Flask server..." -ForegroundColor Green
Write-Host "Server will be available at: http://127.0.0.1:5000" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""
python app.py

