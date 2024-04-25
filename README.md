# CrushFTP SSTI & LFI PoC (CVE-2024-4040)

This is a proof of concept for a Server Side Template Injection (SSTI) vulnerability in CrushFTP. 

## Developer

@stuub

## Features

### Auth Bypass

### SSTI

### LFI

## Documentation

This vulnerability is a VFS sandbox escape in the CrushFTP managed file transfer service that allows remote attackers with low privileges to read files from the filesystem outside of VFS Sandbox

Server-Side Template Injection (SSTI) in CrushFTP allows an attacker to execute arbitrary code on the server by abusing the "zip" function in the WebInterface.

Affecting CrushFTP versions below 10.7.1 and 11.1.0 (as well as legacy 9.x versions)

## Shodan Dork:

http.favicon.hash:-1022206565

## References

https://attackerkb.com/topics/20oYjlmfXa/cve-2024-4040/rapid7-analysis

## Disclaimer

This tool is purely for ethical and educational purposes only. Use responsibly.
