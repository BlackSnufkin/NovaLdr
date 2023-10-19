# NovaLdr :snowflake:
> NovaLdr is a shellcode loader written in Rust, designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities. This project is not intended to be a complete or polished product but rather a journey into the technical aspects of malware, showcasing various techniques and features.


# Features Overview :bulb:
 * **Idirect Sycalls**
 * **String encryption**
 * **Shellcode encryption**: simplae XOR and converting the Shellcode bytes into MAC address 
 * **Threadless Execution**
    * Threadless inject: Writes a trampoline into a specified function within a given DLL and redirects it to load another DLL.
    * JMPThreadHijack: Hijack a thread without calling SetThreadContext. Still needs improvement because I'm lazy and haven't implement the whole thing well enough to maintain the original functionality of the thread. Just a quick and dirty PoC (Be ware of payload execution control. Browsers tend to execute the payload multiple times)
 * **Module Unlink**
   * Overwrites the DOS header magic bytes.
   * Clears the DLL base addresses from the target process.
   * Eliminates DLL name strings from the target process.
   * Unlinks a module from the module list  
 * **Spawning Process**: spawning suspended process with **NtCreateUserProcess** and Spoofing the PPID and Seting the process to Block DLL
 * **Ntdll Unhooking**: Remote and local Ntdll Unhooking using Parun's Fart technique
 * **No GetModuleHandleA & GetProcAddress**: Custome Function that using NT functions

