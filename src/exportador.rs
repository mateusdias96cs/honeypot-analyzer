use std::fs;
use std::path::Path;
use crate::modelos::ResultadoAnalise;

pub const CAMINHO_OUTPUT: &str = "output/analise.json";

pub fn garantir_diretorio(caminho: &str) -> Result<(), String> {
    if let Some(dir) = Path::new(caminho).parent() {
        fs::create_dir_all(dir)
            .map_err(|e| format!("Falha ao criar diretorio: {}", e))?;
    }
    Ok(())
}

pub fn exportar_json(resultado: &ResultadoAnalise, caminho: &str) -> Result<(), String> {
    garantir_diretorio(caminho)?;

    let json = serde_json::to_string_pretty(resultado)
        .map_err(|e| format!("Falha ao serializar: {}", e))?;

    fs::write(caminho, json)
        .map_err(|e| format!("Falha ao escrever {}: {}", caminho, e))?;

    Ok(())
}

pub fn imprimir_resumo(resultado: &ResultadoAnalise) {
    println!("==================================================");
    println!("ANALISE DO HONEYPOT SSH");
    println!("==================================================");
    println!("Periodo:          {}", resultado.periodo);
    println!("Total de eventos: {}", resultado.total_eventos);
    println!("IPs suspeitos:    {:?}", resultado.ips_suspeitos);
    println!("Brute force:      {}", resultado.brute_force_detectado);
    println!("Severidade:       {}", resultado.severidade_maxima);
    println!("MITRE ATT&CK:     {}", resultado.classificacao.mitre_attack);
    println!("Justificativa:    {}", resultado.classificacao.justificativa);
    println!("Recomendacao:     {}", resultado.classificacao.recomendacao);
    println!("Duracao:          {}s", resultado.linha_do_tempo.duracao_ataque_segundos);
    println!("Intervalo medio:  {:.1}s", resultado.linha_do_tempo.intervalo_medio_entre_tentativas_segundos);
    println!("Padrao detectado: {}", resultado.analise_senhas.padrao_detectado);
    println!("Hashes unicos:    {}", resultado.analise_senhas.total_senhas_unicas);
    println!("==================================================");
    println!("Relatorio gerado: {}", CAMINHO_OUTPUT);
}