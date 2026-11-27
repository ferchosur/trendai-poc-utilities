# trendai-poc-utilities

Tools built during TrendAI Vision One PoCs, shared so the team and customers can reuse them.

> **Disclaimer:** community utilities, not an official TrendAI product and not covered by TrendAI support. Review and test before using them in your environment.

## Structure

One folder per category, one subfolder per tool. Each tool has its own `README.md` with usage, inputs/outputs and requirements.

| Category | Folder | Tools |
|---|---|---|
| AI Security | [`AISecurity/`](AISecurity/) | — |
| Cloud Security | [`CloudSecurity/`](CloudSecurity/) | — |
| Kubernetes Security | [`KubernetesSecurity/`](KubernetesSecurity/) | — |
| File Security | [`FileSecurity/`](FileSecurity/) | [`file-security-sdk-nodejs-demo`](FileSecurity/file-security-sdk-nodejs-demo/): web demo of the File Security SDK for Node.js |
| Code Security | [`CodeSecurity/`](CodeSecurity/) | [`tmas-json-to-sarif`](CodeSecurity/tmas-json-to-sarif/): convert a TMAS JSON report to SARIF 2.1.0 |

## Contributing a tool

1. Create `<Category>/<tool-name>/` (kebab-case).
2. Add a `README.md`: what it does, requirements, usage, inputs/outputs, tested versions.
3. Never commit credentials, customer data or real scan reports; use sanitized samples.
4. Add the tool to the table above.

---

**Español:** herramientas desarrolladas en PoCs de TrendAI Vision One para que el equipo y los clientes las reutilicen. Una carpeta por categoría (AI Security, Cloud Security, Kubernetes Security, File Security, Code Security) y una subcarpeta con su `README.md` por herramienta. No es un producto oficial ni tiene soporte de TrendAI.
