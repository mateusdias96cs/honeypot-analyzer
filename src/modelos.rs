use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Deserialize, Clone)]
pub struct EventoAuth {
    pub timestamp: String,
    #[serde(rename = "type")]
    pub tipo: String,
    pub username: String,
    pub password_hash: String,
    pub ip: String,
    pub success: bool,
}

#[derive(Debug, Serialize, Clone)]
pub enum SeveridadeAtaque {
    Baixa,
    Media,
    Alta,
    Critica,
}

impl SeveridadeAtaque {
    pub fn para_string(&self) -> &str {
        match self {
            SeveridadeAtaque::Baixa => "BAIXA",
            SeveridadeAtaque::Media => "MEDIA",
            SeveridadeAtaque::Alta => "ALTA",
            SeveridadeAtaque::Critica => "CRITICA",
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub enum PadraoAtaque {
    BruteForce,
    DictionaryAttack,
    CredentialStuffing,
    Reconhecimento,
}

impl PadraoAtaque {
    pub fn para_string(&self) -> &str {
        match self {
            PadraoAtaque::BruteForce => "brute_force",
            PadraoAtaque::DictionaryAttack => "dictionary_attack",
            PadraoAtaque::CredentialStuffing => "credential_stuffing",
            PadraoAtaque::Reconhecimento => "reconhecimento",
        }
    }

    pub fn mitre_id(&self) -> &str {
        match self {
            PadraoAtaque::BruteForce => "T1110",
            PadraoAtaque::DictionaryAttack => "T1110.001",
            PadraoAtaque::CredentialStuffing => "T1110.004",
            PadraoAtaque::Reconhecimento => "T1110",
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct LinhaDoTempo {
    pub primeiro_evento: String,
    pub ultimo_evento: String,
    pub duracao_ataque_segundos: i64,
    pub intervalo_medio_entre_tentativas_segundos: f64,
}

#[derive(Debug, Serialize, Clone)]
pub struct Classificacao {
    pub nivel: String,
    pub justificativa: String,
    pub mitre_attack: String,
    pub recomendacao: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct AnaliseSenhas {
    pub total_senhas_unicas: usize,
    pub padrao_detectado: String,
    pub hashes_unicos: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct ResultadoAnalise {
    pub periodo: String,
    pub total_eventos: usize,
    pub tentativas_por_ip: HashMap<String, usize>,
    pub brute_force_detectado: bool,
    pub ips_suspeitos: Vec<String>,
    pub severidade_maxima: String,
    pub linha_do_tempo: LinhaDoTempo,
    pub classificacao: Classificacao,
    pub analise_senhas: AnaliseSenhas,
}
