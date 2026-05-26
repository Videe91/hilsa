# Agentic Security MVP

## Run API

```bash
export AGENTIC_SECURITY_API_TOKEN=dev-token
python -c "from agentic_security.api import run; run()"
```

## API Auth

All API endpoints require:

```text
Authorization: Bearer <AGENTIC_SECURITY_API_TOKEN>
```

## Run tests

```bash
python -m unittest discover -s tests -v
```
