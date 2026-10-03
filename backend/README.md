# SecureScan backend

Passive, non-destructive web security assessment MVP.

Run from `backend`:

```powershell
pip install -r requirements.txt
uvicorn main:app --reload
```

API:
- `GET /`
- `POST /scan`

Swagger:
`http://127.0.0.1:8000/docs`

Only assess systems you own or are explicitly authorized to test.
