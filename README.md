# NovaLdr :fleur_de_lis:
> NovaLdr is a Threadless Module Stomping written in Rust, designed as a learning project while exploring the world of malware development. It uses advanced techniques like indirect syscalls and string encryption to achieve its functionalities. This project is not intended to be a complete or polished product but rather a journey into the technical aspects of malware, showcasing various techniques and features.

# Features Overview :bulb:
   * **Idirect Sycalls**
   * **String encryption**
   * **Shellcode encryption**: simple XOR and converting the Shellcode bytes into MAC address
   * **Threadless Execution**
      * Threadless inject: Writes a trampoline into a specified function within a given DLL and redirects it to load another DLL.
      * JMPThreadHijack: Hijack a thread without calling SetThreadContext. Still needs improvement because I'm lazy and haven't implemented the whole thing well enough to maintain the original functionality of the thread. Just a quick and dirty PoC (Beware of payload execution control. Browsers tend to execute the payload multiple times)
   * **Module Unlink**
      * Overwrites the DOS header magic bytes.
      * Clears the DLL base addresses from the target process.
      * Eliminates DLL name strings from the target process.
      * Unlinks a module from the module list
   * **Spawning Process**: spawning suspended process with **NtCreateUserProcess** and Spoofing the PPID and Setting the process to Block DLL
   * **Ntdll Unhooking**: Remote and local Ntdll Unhooking using Parun's Fart technique
   * **No GetModuleHandleA & GetProcAddress**: Custome Function that using NT functions
   * **Sleep Encrypt**: custom sleep function that encrypts the stack during its sleep duration using a separate thread.
   * **HWBP**: In process Patchless AMSI + ETW Bypass with HWBP on all threads. 

# Usage: :hammer_and_wrench:
   * Generate Shellcode file: `msfvenom -p windows/x64/messagebox TITLE=NovaLdr TEXT='In memory of all those murdered in the Nova party massacre 7.10.2023' ICON=WARNING EXITFUNC=thread -b '\xff\x00\x0b' -f raw -e none -o Nova_MSG.bin`
   * Encrypt the shellcode file and convert it to MAC address format `python bin2mac.py Nova_MSG.bin > nova_msg.txt`
   * Copy the content of the output file and paste it to the main.rs file
   * Compile the program just run the file `compile.bat`

# Disclaimer :loudspeaker:
NovaLdr is intended for educational and research purposes only. The author is not responsible for any misuse or damage caused by this program. Always seek permission before testing it against any target.

# Contributing :chart_with_upwards_trend:
As this project is a learning journey, contributions, suggestions, and enhancements are welcome to make NovaLdr a valuable resource for learning malware development in Rust.

# Resources & Credit :round_pushpin:

- [masking-malicious-memory-artifacts-part-ii-insights-from-moneta](https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-ii-insights-from-moneta)
- [masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners](https://www.cyberark.com/resources/threat-research-blog/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners)
- [alternative-process-injection](https://www.netero1010-securitylab.com/evasion/alternative-process-injection)
- [custom_getmodulehandle_getprocaddress](https://blog.atsika.ninja/posts/custom_getmodulehandle_getprocaddress)
- [nim-noload-dll-hollowing](https://tishina.in/execution/nim-noload-dll-hollowing)
- [Malwear-Sweet](https://github.com/0prrr/Malwear-Sweet)
- [dll-unlinking](https://blog.christophetd.fr/dll-unlinking/)
- [operating-into-EDRs-blindspot](https://www.naksyn.com/edr%20evasion/2022/09/01/operating-into-EDRs-blindspot.html)
- [Hidding Module from the HashTable](http://www.ivanlef0u.tuxfamily.org/?p=365)
- [module-pebldr-hiding-all-4-methods](http://www.rohitab.com/discuss/topic/41944-module-pebldr-hiding-all-4-methods/)
- [NtCreateUserProcess](https://offensivedefence.co.uk/posts/ntcreateuserprocess/)
- [Defcon31](https://github.com/OtterHacker/Conferences/tree/main/Defcon31)
- [process-injection-evading-edr-in-2023](https://vanmieghem.io/process-injection-evading-edr-in-2023/)
- [StackMask](https://github.com/WKL-Sec/StackMask)
- [Patchless Amsi Bypass](https://gist.github.com/CCob/fe3b63d80890fafeca982f76c8a3efdf)
- [PatchlessHook](https://github.com/ScriptIdiot/sleepmask_PatchlessHook)
- [import_dll_injection](https://www.x86matthew.com/view_post?id=import_dll_injection) :pushpin: (will be added later)

# POC
![Screenshot 2023-10-19 142856](https://github.com/BlackSnufkin/NovaLdr/assets/61916899/39e7176b-eed3-4891-a322-d119064eabfe)




# PE-SIEVE
![Screenshot 2023-10-19 142029](https://github.com/BlackSnufkin/NovaLdr/assets/61916899/1bfc6dbd-db2d-4254-a467-643aac6744a9)



