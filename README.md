# SecureScan

A beginner-friendly passive web security assessment MVP.

## Stack
- Backend: Python + FastAPI + Requests
- Frontend: React + Vite
- UI: plain CSS + Lucide icons
- Scanner: passive HTTP response analysis

## Run backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload
```

Backend docs: http://127.0.0.1:8000/docs

## Run frontend

Open a second VS Code terminal:

```powershell
cd frontend
npm install
npm run dev
```

Frontend: http://127.0.0.1:5173

Only assess systems you own or are explicitly authorized to test.
