use std::fs::File;
use std::io::{BufRead, BufReader};
use crate::modelos::EventoAuth;

pub const CAMINHO_PADRAO: &str = "/tmp/.honeypot_events.json";
pub const CAMINHO_AMOSTRA: &str = "samples/sample_events.json";

pub fn ler_eventos(caminho: &str) -> Result<Vec<EventoAuth>, String> {
    let arquivo = File::open(caminho).map_err(|err| {
        format!("Falha ao abrir o arquivo em '{}': {}", caminho, err)
    })?;

    let leitor = BufReader::new(arquivo);

    let lista_de_eventos: Vec<EventoAuth> = leitor
        .lines()
        .filter_map(|linha_result| {
            let linha = linha_result.ok()?;
            let linha_limpa = linha.trim().to_string();
            if linha_limpa.is_empty() {
                return None;
            }
            serde_json::from_str::<EventoAuth>(&linha_limpa).ok()
        })
        .filter(|evento| validar_evento(evento))
        .collect();

    Ok(lista_de_eventos)
}

pub fn ler_amostra() -> Result<Vec<EventoAuth>, String> {
    ler_eventos(CAMINHO_AMOSTRA)
}

pub fn validar_evento(evento: &EventoAuth) -> bool {
    if evento.ip.is_empty() { return false; }
    if evento.username.is_empty() { return false; }
    if evento.timestamp.is_empty() { return false; }
    true
}
