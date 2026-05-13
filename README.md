# Honeypot SSH Log Analyzer

Analisador de logs escrito em Rust que processa eventos do honeypot SSH,
detecta padroes de ataque e exporta metricas estruturadas com
mapeamento MITRE ATT&CK.

## Pipeline

Honeypot SSH (Python) -> auth_attempts.json -> Analyzer (Rust) -> analise.json -> SOC Report (Python)

## Deteccoes implementadas

| Tecnica             | MITRE ID   | Descricao                      |
|---------------------|------------|--------------------------------|
| Dictionary Attack   | T1110.001  | Senhas variadas, hashes unicos |
| Credential Stuffing | T1110.004  | Mesmo hash repetido            |
| Brute Force         | T1110      | Volume alto de tentativas      |
| Reconhecimento      | T1110      | Poucas tentativas, sondagem    |

## Como usar

cargo run -- /tmp/.honeypot_auth_attempts.json

cargo run -- samples/sample_events.json

## Output

JSON estruturado em output/analise.json com metricas temporais,
classificacao de severidade e recomendacoes de mitigacao.

## Stack

- Rust 1.95.0 (edition 2024)
- serde + serde_json
- chrono

## Parte do ecossistema Blue Team

1. honeypot-ssh - captura ataques SSH reais (Python)
2. honeypot-analyzer - processa e classifica (Rust)
3. soc-lab-report - exibe metricas no dashboard (Python/GitHub Pages)
