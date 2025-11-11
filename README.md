# LSA Secrets Dumper 🔓

A professional security research tool for extracting LSA secrets from Windows systems, designed for penetration testers and security researchers.

## ⚡ Features

- **Token Stealing**: Leverages winlogon.exe token duplication for SYSTEM privileges
- **LSA Secrets Extraction**: Dumps DPAPI_SYSTEM, NL$KM, and other secrets
- **Mimikatz Alternative**: Pure C implementation with no external dependencies
- **EDR Evasion**: Uses legitimate Windows APIs with minimal footprint
- **Memory Operations**: Fileless execution capabilities

## 🛠️ Installation

# Compile with MinGW
gcc -o lsa_dumper.exe lsa_dumper.c -ladvapi32 -lcrypt32
