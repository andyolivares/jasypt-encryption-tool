use std::{fs::File, io::{stdin, BufRead, BufReader, BufWriter, Read, Write}, path::PathBuf};
use clap::Parser;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use base64::{alphabet::STANDARD, engine::GeneralPurposeConfig, Engine};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

#[cfg(windows)]
const NL: &'static str = "\r\n";

#[cfg(not(windows))]
const NL: &'static str = "\n";

/// Simple CLI to encrypt data using a Jasypt (http://www.jasypt.org) compatible format.
/// 
/// It reads lines from multiple sources or STDIN if no source is specified.
/// Encrypted lines are written back to a file (if specified) or STDOUT.
/// 
/// Jasypt format used is:
///   algorithm: PBEWITHHMACSHA256ANDAES_256
///   saltGeneratorClassName: org.jasypt.salt.RandomSaltGenerator
///   ivGeneratorClassName: org.jasypt.iv.RandomIvGenerator
#[derive(Debug, Parser)]
#[command(version, verbatim_doc_comment, about, long_about, author = "Andres Olivares")]
struct Args {
    /// Data to encrypt
    #[arg(long, short = 'd', value_name = "STRING")]
    data: Option<String>,

    /// Input file with data lines to encrypt
    #[arg(long, short = 'i', value_name = "FILE")]
    input: Option<PathBuf>,

    /// Output file where to write encrypted data to
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    /// String that will be prefixed to each encrypted line
    #[arg(long)]
    prefix: Option<String>,

    /// String that will be postfixed to each encrypted line
    #[arg(long)]
    postfix: Option<String>,

    /// The password used to encrypt data
    #[arg(long, short = 'p')]
    password: String
}

fn main() {
    let args = Args::parse();
    let prefix = args.prefix.unwrap_or(String::from(""));
    let postfix = args.postfix.unwrap_or(String::from(""));
    let mut lines = Vec::new();

    // If data parameter specified, add data line
    if let Some(line) = args.data {
        lines.push(line);
    }

    // If input file specified, add all its lines
    if let Some(input) = args.input {
        if input.exists() {
            let file = File::open(input).expect("Unable to open input file!");
            
            read_lines(Box::new(file), &mut lines);
        }
    }

    // If no lines to this point, read lines from STDIN
    if lines.len() == 0 {
        read_lines(Box::new(stdin()), &mut lines);
    }

    // If output file specified, write to it. Write to STDOUT otherwise.
    let w: Box<dyn Write> = match args.output {
        Some(file) => Box::new(File::create(file).unwrap()),
        None => Box::new(std::io::stdout())
    };

    let mut writer = BufWriter::new(w);

    // Encrypt and write back all lines
    for line in lines {
        let line = format!("{}{}{}{}", prefix, encrypt(&line, &args.password), postfix, NL);

        writer.write_all(line.as_bytes()).unwrap_or_default();
    }
}

fn read_lines(stream: Box<dyn Read>, lines: &mut Vec<String>) {
    let reader = BufReader::new(stream);

    for line in reader.lines() {
        if let Ok(line) = line {
            lines.push(line);
        }
    }
}

fn encrypt(input: &String, password: &String) -> String {
    const ITERATIONS: u32 = 1_000;
    const IV_SIZE_BYTES: usize = 16;
    const SALT_SIZE_BYTES: usize = 16;
    const KEY_SIZE_BYTES: usize = 32;

    let mut rng = ChaCha20Rng::from_entropy();
    let mut salt = [0u8; SALT_SIZE_BYTES];
    let mut iv = [0u8; IV_SIZE_BYTES];

    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    let key = pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, KEY_SIZE_BYTES>(password.as_bytes(), &salt, ITERATIONS);
    let data_arr = input.as_bytes();
    
    let enc = Aes256CbcEnc::new(&key.into(), &iv.into());
    let ed = enc.encrypt_padded_vec_mut::<Pkcs7>(data_arr);
    let b64e = base64::engine::GeneralPurpose::new(&STANDARD, GeneralPurposeConfig::default());
    let mut buf = Vec::with_capacity(IV_SIZE_BYTES + SALT_SIZE_BYTES + ed.len());

    buf.append(Vec::from(salt).as_mut());
    buf.append(Vec::from(iv).as_mut());
    buf.append(Vec::from(ed).as_mut());

    b64e.encode(buf)
}