use std::collections::{HashMap, HashSet};
use crate::modelos::{EventoAuth, SeveridadeAtaque, PadraoAtaque, AnaliseSenhas};

pub const THRESHOLD_BRUTE_FORCE: usize = 5;

pub fn contar_tentativas_por_ip(eventos: &[EventoAuth]) -> HashMap<String, usize> {
    let mut contagem: HashMap<String, usize> = HashMap::new();
    for evento in eventos {
        let contador = contagem.entry(evento.ip.clone()).or_insert(0);
        *contador += 1;
    }
    contagem
}

pub fn detectar_brute_force(contagem: &HashMap<String, usize>) -> bool {
    contagem.values().any(|&total| total >= THRESHOLD_BRUTE_FORCE)
}

pub fn identificar_ips_suspeitos(contagem: &HashMap<String, usize>) -> Vec<String> {
    let mut suspeitos: Vec<String> = Vec::new();
    for (ip, total) in contagem {
        if *total >= THRESHOLD_BRUTE_FORCE {
            suspeitos.push(ip.clone());
        }
    }
    suspeitos
}

pub fn classificar_severidade(contagem: &HashMap<String, usize>) -> SeveridadeAtaque {
    let maximo = contagem.values().max();
    match maximo {
        None => SeveridadeAtaque::Baixa,
        Some(max) => match max {
            n if *n >= 10 => SeveridadeAtaque::Critica,
            n if *n >= 5  => SeveridadeAtaque::Alta,
            n if *n >= 3  => SeveridadeAtaque::Media,
            _             => SeveridadeAtaque::Baixa,
        },
    }
}

pub fn analisar_senhas(eventos: &[EventoAuth]) -> AnaliseSenhas {
    let hashes_unicos: HashSet<&str> = eventos
        .iter()
        .map(|evento| evento.password_hash.as_str())
        .collect();

    let total_unicos = hashes_unicos.len();
    let total_eventos = eventos.len();

    let padrao = if total_eventos <= 2 {
        PadraoAtaque::Reconhecimento
    } else if total_unicos == total_eventos {
        PadraoAtaque::DictionaryAttack
    } else {
        PadraoAtaque::CredentialStuffing
    };

    AnaliseSenhas {
        total_senhas_unicas: total_unicos,
        padrao_detectado: padrao.para_string().to_string(),
        hashes_unicos: total_unicos == total_eventos,
    }
}
pub fn classificar_ataque(
    eventos: &[EventoAuth],
    contagem: &HashMap<String, usize>,
) -> crate::modelos::Classificacao {
    let severidade = classificar_severidade(contagem);
    let analise = analisar_senhas(eventos);

    let padrao = if analise.padrao_detectado == "dictionary_attack" {
        PadraoAtaque::DictionaryAttack
    } else if analise.padrao_detectado == "credential_stuffing" {
        PadraoAtaque::CredentialStuffing
    } else if analise.padrao_detectado == "reconhecimento" {
        PadraoAtaque::Reconhecimento
    } else {
        PadraoAtaque::BruteForce
    };

    let ip_principal = contagem
        .iter()
        .max_by_key(|(_, total)| *total)
        .map(|(ip, _)| ip.as_str())
        .unwrap_or("desconhecido");

    let total_principal = contagem.values().max().copied().unwrap_or(0);

    crate::modelos::Classificacao {
        nivel: severidade.para_string().to_string(),
        justificativa: format!(
            "{} tentativas do IP {} - padrao consistente com ferramenta automatizada",
            total_principal, ip_principal
        ),
        mitre_attack: padrao.mitre_id().to_string(),
        recomendacao: format!(
            "Bloquear IP {} via firewall. Investigar outros alvos na rede.",
            ip_principal
        ),
    }
}