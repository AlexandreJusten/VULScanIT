# VULScanIT v2.0 — Developer Security Intelligence Platform

Plataforma gratuita e profissional de inteligência e segurança voltada para desenvolvedores.

## Principais Funcionalidades

- **Dependency Scanner**: Envie arquivos `package.json`, `package-lock.json` ou projetos compactados em `.zip` para análise estática, cálculo de Risk Score (0-100) e identificação de CVEs via OSV.dev (com proteção anti ZIP-Slip).
- **Threat Intelligence Center**: Monitoramento em tempo real do catálogo CISA KEV, advisories OSV.dev e NVD.
- **Ferramentas para Desenvolvedores**:
  1. CVE Lookup
  2. Package Checker (OSV.dev)
  3. Security Headers Checker
  4. Secrets Scanner (detecção estática de chaves e tokens)
  5. JWT Decoder (local)
  6. Hash Analyzer (MD5, SHA-1, SHA-256)
- **Projetos & Histórico**: Gerenciamento de análises de segurança e auditorias anteriores.
- **Internacionalização (i18n)**: Suporte completo a Português (PT-BR) e Inglês (EN) com alternância instantânea.

## Requisitos

- Node.js 18.18+ (recomendado Node 20 LTS)
- npm

## Executar localmente

1. Instale as dependências:
   ```bash
   npm install
   ```
2. Inicie o ambiente de desenvolvimento (frontend e backend simultaneamente):
   ```bash
   npm run dev
   ```
3. Acesse no navegador:
   `http://localhost:5173` (Frontend) e `http://localhost:4000` (API).

## Executar em produção

```bash
npm install
npm run build
npm start
```
