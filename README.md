# TOYOTA AI CTF — combined web app

Four beginner-to-intermediate **AI security** challenges served from a single
Flask app, ready to deploy on **Vercel**. Flag format: `TOYOTACTF{...}`.

| # | Path | Name | Category |
|---|------|------|----------|
| 1 | `/c1/` | SafeBot | Prompt injection (output-filter bypass) |
| 2 | `/c2/` | ToyotaGen | Cloud recon (leaky bucket) |
| 3 | `/c3/` | CalcBot Agent | Agent code execution (sandbox escape) |
| 4 | `/c4/` | DocSummarizer | Indirect prompt injection (RAG) |

The hub page (`/`) links to all four.

## Flags are set via environment variables

Real flags are **not** in the source (this is a public repo). Set them per
deployment — in Vercel: **Project → Settings → Environment Variables**:

| Key | Example value |
|-----|---------------|
| `FLAG_C1` | `TOYOTACTF{...}` |
| `FLAG_C2` | `TOYOTACTF{...}` |
| `FLAG_C3` | `TOYOTACTF{...}` |
| `FLAG_C4` | `TOYOTACTF{...}` |

Without them the app shows harmless placeholders. After reading them at startup
the app removes the flag vars from the OS environment, and Challenge 3 runs
player code in an isolated subprocess — so getting code-exec on C3 does **not**
leak the other challenges' flags.

## Deploy to Vercel

**Option A — Import the repo (recommended)**
1. Go to https://vercel.com/new and import `oattao123/ctf-ai-2`.
2. Framework preset: **Other** (the included `vercel.json` handles the build).
3. Add the `FLAG_C1..FLAG_C4` environment variables.
4. Deploy.

**Option B — CLI**
```bash
vercel login
vercel --prod
```
then add the env vars with `vercel env add FLAG_C1` (etc.) and redeploy.

## Run locally

```bash
pip install -r requirements.txt
FLAG_C1=TOYOTACTF{a} FLAG_C2=TOYOTACTF{b} FLAG_C3=TOYOTACTF{c} FLAG_C4=TOYOTACTF{d} \
  python api/index.py
# http://localhost:8000
```

## Tech
- Single Flask WSGI app (`api/index.py`), served by `@vercel/python`.
- Deterministic, offline "AI" logic — no external API keys required.
- Bilingual: each AI replies in the language it was asked in (Thai or English).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
