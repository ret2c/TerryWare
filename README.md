# TerryWare 🦀
Ransomware I wrote in Rust to demo for a future blog post about reverse engineering binaries.<br>
I'm not a great programmer, I only have experience with scripting, so apologies for the sloppy code
<br><br>
TerryWare Demo:<br>
<img src="https://i.ibb.co/xsV267m/vmware-SHZRS87t4a-ezgif-com-video-to-gif-converter.gif">
<br>
Ransomware is designed to only trigger for Windows users named 'Terry', and it will only encrypt files under (C:\Users\Terry\*)<br>
The key for decryption is: **e558e84dba2de0209ce8d1ec73db5d3b** - the first 16 bytes in the AES key used to encrypt the files defined here:<br>
```rust
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
```
