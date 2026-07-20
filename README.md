# neonai-hub

## Proof-of-Silence live demo

Run the local proxy and static demo with:

```bash
npm start
```

Then open <http://localhost:8787>.

### GPT-5.6 API configuration

The demo never stores an API key in browser code. Configure the local proxy with one of these options:

- `OPENAI_API_KEY=... npm start`
- `OPENAI_CONFIG_PATH=./config/openai.json npm start`

Copy `config/openai.example.json` to `config/openai.json` for local config-file use. The real local config file is ignored by git.

If no API key is present, the UI clearly switches to offline mode and lets the operator enter a manual answer. Manual answers are evaluated and signed into the chain with the same verdict rules.
