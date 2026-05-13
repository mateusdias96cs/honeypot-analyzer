use chrono::NaiveDateTime;
use crate::modelos::{EventoAuth, LinhaDoTempo};

const FORMATO_TIMESTAMP: &str = "%Y-%m-%dT%H:%M:%S%.f";

pub fn parsear_timestamp(ts: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(ts, FORMATO_TIMESTAMP).ok()
}

pub fn ordenar_por_timestamp(mut eventos: Vec<EventoAuth>) -> Vec<EventoAuth> {
    eventos.sort_by(|a, b| {
        let ts_a = parsear_timestamp(&a.timestamp).unwrap_or(NaiveDateTime::MIN);
        let ts_b = parsear_timestamp(&b.timestamp).unwrap_or(NaiveDateTime::MIN);
        ts_a.cmp(&ts_b)
    });
    eventos
}

fn calcular_intervalo_medio(timestamps: &[NaiveDateTime]) -> f64 {
    if timestamps.len() < 2 {
        return 0.0;
    }
    let diferencas: Vec<i64> = timestamps
        .windows(2)
        .map(|par| (par[1] - par[0]).num_seconds())
        .collect();
    let soma: i64 = diferencas.iter().sum();
    soma as f64 / diferencas.len() as f64
}

pub fn calcular_linha_do_tempo(eventos: &[EventoAuth]) -> LinhaDoTempo {
    if eventos.is_empty() {
        return LinhaDoTempo {
            primeiro_evento: String::new(),
            ultimo_evento: String::new(),
            duracao_ataque_segundos: 0,
            intervalo_medio_entre_tentativas_segundos: 0.0,
        };
    }

    let ordenados = ordenar_por_timestamp(eventos.to_vec());
    let primeiro = &ordenados[0];
    let ultimo = &ordenados[ordenados.len() - 1];

    let duracao = match (
        parsear_timestamp(&primeiro.timestamp),
        parsear_timestamp(&ultimo.timestamp),
    ) {
        (Some(ts_inicio), Some(ts_fim)) => (ts_fim - ts_inicio).num_seconds(),
        _ => 0,
    };

    let timestamps: Vec<NaiveDateTime> = ordenados
        .iter()
        .filter_map(|e| parsear_timestamp(&e.timestamp))
        .collect();

    let intervalo_medio = calcular_intervalo_medio(&timestamps);

    LinhaDoTempo {
        primeiro_evento: primeiro.timestamp.clone(),
        ultimo_evento: ultimo.timestamp.clone(),
        duracao_ataque_segundos: duracao,
        intervalo_medio_entre_tentativas_segundos: intervalo_medio,
    }
}
