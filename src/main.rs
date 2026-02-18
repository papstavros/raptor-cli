use anyhow::{Context, anyhow};
use base32::Alphabet;
use clap::{Parser, Subcommand};
use dirs::config_dir;
use keyring::Entry;
use std::io::{self};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::PathBuf,
};
use totp_rs::{Algorithm, TOTP};

#[derive(Parser)]
#[command(name = "raptor-cli", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Store a new Base32-encoded secret (length ≥128 bits)
    Add {
        account: String,
        secret: String,
        #[arg(long)]
        custom: bool,
    },
    /// Delete a stored secret
    Remove { account: String },
    /// List stored accounts
    List,
    /// Generate the current TOTP code for an account
    Code {
        account: String,
        #[arg(long)]
        uri: Option<String>,
    },
}

fn parse_algo(s: &str) -> Result<Algorithm, anyhow::Error> {
    match s.to_ascii_lowercase().as_str() {
        "sha1" => Ok(Algorithm::SHA1),
        "sha256" => Ok(Algorithm::SHA256),
        "sha512" => Ok(Algorithm::SHA512),
        _ => Err(anyhow!(
            "unsupported algorithm: '{}'. Supported algorithms: sha1, sha256, sha512",
            s
        )),
    }
}

/// Helper to read a line from stdin
fn read_line_input(prompt: &str, default_val: &str) -> anyhow::Result<String> {
    print!("{}: ", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default_val.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

/// Try Base32 decode with padding=true, then padding=false.
fn decode_secret(s: &str) -> Result<Vec<u8>, anyhow::Error> {
    // Remove spaces and convert to uppercase
    let cleaned = s.replace(' ', "").to_uppercase();
    base32::decode(Alphabet::Rfc4648 { padding: true }, &cleaned)
        .or_else(|| base32::decode(Alphabet::Rfc4648 { padding: false }, &cleaned))
        .ok_or_else(|| anyhow!("invalid Base32 secret"))
}

fn accounts_file() -> anyhow::Result<PathBuf> {
    let mut dir = config_dir().ok_or_else(|| anyhow!("could not find config dir"))?;
    dir.push("raptor");
    fs::create_dir_all(&dir)?;
    dir.push("accounts");
    Ok(dir)
}

fn index_add(account: &str) -> anyhow::Result<()> {
    let path = accounts_file()?;
    let mut seen = false;
    if path.exists() {
        for line in BufReader::new(fs::File::open(&path)?).lines() {
            if line?.trim() == account {
                seen = true;
                break;
            }
        }
    }
    if !seen {
        let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
        writeln!(f, "{}", account)?;
    }
    Ok(())
}

fn index_remove(account: &str) -> anyhow::Result<()> {
    let path = accounts_file()?;
    if !path.exists() {
        return Ok(());
    }
    let lines: Vec<_> = BufReader::new(fs::File::open(&path)?)
        .lines()
        .map_while(Result::ok)
        .filter(|l| l.trim() != account)
        .collect();
    fs::write(&path, lines.join("\n") + "\n")?;
    Ok(())
}

fn list_accounts() -> anyhow::Result<()> {
    let path = accounts_file()?;
    if !path.exists() {
        println!("(no accounts)");
        return Ok(());
    }
    for line in BufReader::new(fs::File::open(&path)?).lines() {
        println!("{}", line?);
    }
    Ok(())
}

fn warn_about_algorithm(algorithm: Algorithm) {
    match algorithm {
        Algorithm::SHA256 | Algorithm::SHA512 => {
            let algo_name = match algorithm {
                Algorithm::SHA256 => "SHA256",
                Algorithm::SHA512 => "SHA512",
                _ => unreachable!(),
            };
            eprintln!(
                "Warning: Using {}. Some authenticators may silently fall back to SHA1.",
                algo_name
            );
        }
        _ => {}
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let service = "raptor";
    match cli.command {
        Commands::Add {
            account,
            secret,
            custom,
        } => {
            // Validate Base32 + length ≥128 bits
            let key = decode_secret(&secret).context("invalid Base32 secret")?;
            if key.len() < 8 {
                anyhow::bail!(
                    "secret too short: got {} bytes ({} bits), need ≥16 bytes (128 bits)\n\
                     Are you sure this is a valid Base32-encoded TOTP secret?",
                    key.len(),
                    key.len() * 8
                );
            }
            let mut digits = 6;
            let mut period = 30;
            let mut skew = 1;
            let mut algorithm_str = "sha1".to_string();
            if custom {
                println!();
                println!("Configuring TOTP for {} (custom)", account);
                println!("-------------------------------------");
                println!(
                    "Make sure your platform matches the chosen settings.\nIf you are unsure, press ENTER to use the default values.\n"
                );
                // Digits
                loop {
                    let input = read_line_input(
                        &format!("Digits (6/8, default {})", digits),
                        &digits.to_string(),
                    )?;
                    match input.parse::<usize>() {
                        Ok(d) if d == 6 || d == 8 => {
                            digits = d;
                            break;
                        }
                        _ => println!(" [!] Invalid digits. Please enter 6 or 8."),
                    }
                }
                // Period
                loop {
                    let input = read_line_input(
                        &format!("Period (sec, default {})", period),
                        &period.to_string(),
                    )?;
                    match input.parse::<u64>() {
                        Ok(p) if p > 0 => {
                            period = p;
                            break;
                        }
                        _ => println!(" [!] Invalid period. Please enter a positive number."),
                    }
                }
                // Skew
                loop {
                    let input = read_line_input(
                        &format!("Skew (periods, default {})", skew),
                        &skew.to_string(),
                    )?;
                    match input.parse::<u8>() {
                        Ok(s) => {
                            skew = s;
                            break;
                        }
                        _ => println!(" [!] Invalid skew. Please enter a number."),
                    }
                }
                // Algorithm
                loop {
                    let input = read_line_input(
                        &format!("Algorithm (sha1/sha256/sha512, default {})", algorithm_str),
                        &algorithm_str,
                    )?;
                    match parse_algo(&input) {
                        Ok(_) => {
                            algorithm_str = input;
                            break;
                        }
                        Err(e) => println!(" [!] {}", e),
                    }
                }
                println!();
            }
            // Store the secret and all parameters in a single string in the keyring
            // Format: "secret_base32:algo_name:digits:period:skew"
            let stored_value = format!(
                "{}:{}:{}:{}:{}",
                secret, algorithm_str, digits, period, skew
            );
            Entry::new(service, &account)?
                .set_password(&stored_value)
                .context("writing secret to keyring")?;
            index_add(&account).context("updating account index")?;
            println!("TOTP set for {}:", account);
            println!("- Digits: {}", digits);
            println!("- Period: {} sec", period);
            println!("- Skew: {}", skew);
            println!("- Algo: {}", algorithm_str);
            println!();
            println!("Next: `raptor-cli code {}` for your code.", account);
        }
        Commands::Remove { account } => {
            Entry::new(service, &account)?
                .delete_password()
                .context("deleting secret from keyring")?;
            index_remove(&account).context("updating account index")?;
            println!("Removed secret for \"{}\"", account);
        }
        Commands::List => {
            list_accounts().context("listing accounts")?;
        }
        Commands::Code { account, uri } => {
            if let Some(uri_str) = uri {
                // If --uri is provided, use it directly (all parameters are derived from URI)
                let totp = TOTP::from_url(&uri_str)
                    .with_context(|| format!("parsing otpauth:// URI for account '{}'", account))?;
                warn_about_algorithm(totp.algorithm);
                let code = totp
                    .generate_current()
                    .context("generating code from URI")?;
                println!("Code for {}: {}", account, code);
            } else {
                // Otherwise, use stored secret with ALL its associated parameters
                let stored_value = Entry::new(service, &account)?
                    .get_password()
                    .context("no secret found for that account. Add it first, or use --uri.")?;
                // Parse the stored value back into secret and parameters
                let parts: Vec<&str> = stored_value.split(':').collect();
                if parts.len() != 5 {
                    anyhow::bail!(
                        "Malformed stored secret for '{}'. Try removing and re-adding it with `raptor-cli add {} <secret> [--custom]`",
                        account,
                        account
                    );
                }
                let s_secret_str = parts[0];
                let algorithm_str = parts[1].to_string();
                let digits: usize = parts[2].parse().context("invalid stored digits")?;
                let period: u64 = parts[3].parse().context("invalid stored period")?;
                let skew: u8 = parts[4].parse().context("invalid stored skew")?;
                // Decode the secret bytes
                let secret_bytes =
                    decode_secret(s_secret_str).context("invalid Base32 secret in keyring")?;
                // Validate parameters (should be valid if added correctly, but good for defensive programming)
                if digits != 6 && digits != 8 {
                    anyhow::bail!("Invalid stored digits: {}. Must be 6 or 8.", digits);
                }
                if period == 0 {
                    anyhow::bail!("Invalid stored period: {}. Must be greater than 0.", period);
                }
                let algo = parse_algo(&algorithm_str)?; // Validate algorithm string
                warn_about_algorithm(algo); // Warn for loaded algo
                let totp = TOTP::new_unchecked(
                    algo,
                    digits,
                    skew,
                    period,
                    secret_bytes,
                    Some(account.clone()),
                    "Raptor".to_string(),
                );
                let code = totp.generate_current().context("generating code")?;
                println!("Code for {}: {}", account, code);
            }
        }
    }
    Ok(())
}
