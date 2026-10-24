# Deployment

## Locale

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH="$PWD/src"
uvicorn api.app:app --host 0.0.0.0 --port 8919
```

## Docker

```bash
docker compose up --build
```

## Produzione

- Mettere API dietro reverse proxy TLS.
- Abilitare autenticazione.
- Loggare richieste e predizioni.
- Versionare modelli.
- Non esporre API pubblicamente senza auth.
