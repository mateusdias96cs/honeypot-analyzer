mod modelos;
mod leitor;
mod detector;
mod metricas;
mod exportador;

use modelos::ResultadoAnalise;
use leitor::CAMINHO_PADRAO;
use exportador::CAMINHO_OUTPUT;

fn determinar_caminho(args: &[String]) -> &str {
    if args.len() > 1 {
        &args[1]
    } else {
        CAMINHO_PADRAO
    }
}

fn construir_resultado(eventos: Vec<modelos::EventoAuth>) -> ResultadoAnalise {
    let contagem_por_ip = detector::contar_tentativas_por_ip(&eventos);
    let brute_force = detector::detectar_brute_force(&contagem_por_ip);
    let ips_suspeitos = detector::identificar_ips_suspeitos(&contagem_por_ip);
    let severidade = detector::classificar_severidade(&contagem_por_ip);
    let linha_do_tempo = metricas::calcular_linha_do_tempo(&eventos);
    let classificacao = detector::classificar_ataque(&eventos, &contagem_por_ip);
    let analise_senhas = detector::analisar_senhas(&eventos);

    let periodo = if !eventos.is_empty() {
        eventos[0].timestamp[..10].to_string()
    } else {
        "desconhecido".to_string()
    };

    ResultadoAnalise {
        periodo,
        total_eventos: eventos.len(),
        tentativas_por_ip: contagem_por_ip,
        brute_force_detectado: brute_force,
        ips_suspeitos,
        severidade_maxima: severidade.para_string().to_string(),
        linha_do_tempo,
        classificacao,
        analise_senhas,
    }
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let caminho = determinar_caminho(&args);

    println!("Analisando eventos de: {}", caminho);

    let eventos = leitor::ler_eventos(caminho)?;

    if eventos.is_empty() {
        return Err(format!("Nenhum evento encontrado em {}", caminho));
    }

    println!("{} eventos carregados", eventos.len());

    let resultado = construir_resultado(eventos);

    exportador::exportar_json(&resultado, CAMINHO_OUTPUT)?;

    exportador::imprimir_resumo(&resultado);

    Ok(())
}