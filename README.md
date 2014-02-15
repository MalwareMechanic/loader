loader
======

Resident Http(s) Command Execution Bot


Small Bot prototype
knocks to a webserver every X seconds
POST system information
and in turn retrieves commands from server

[*] commands can be filtered in Commands()

[*] 5 worker threads for separate execution (Yet to be implemented)

    -> Anti Debugging
    
    -> Anti VirtualMachine
    
    -> Anti SandBoxing
    
    -> Rootkit Capabilities
    
    -> Plugin Thread

[*] HKEY_CURRENT_USER startup (hidden by rootkit)

[*] Copies to %appdata%

[*] Global chunk initiative for faster memory handling

[*] dynamically called API's for faster working

[*] usage of ntdll api's whereever possible instead of junk wrappers

[*] no imports

[*] basing properly done, so .text section can be called as a shellcode
