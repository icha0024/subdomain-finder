# Subdomain Finder

A multi-threaded Python tool for discovering subdomains using DNS brute force, certificate transparency, and other reconnaissance techniques.

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is for educational purposes and authorized security testing only. Only use on domains you own or have explicit written permission to test. Unauthorized subdomain enumeration may be illegal in your jurisdiction and could violate terms of service.

## Features

- **DNS Brute Force**: High-speed subdomain discovery using custom wordlists
- **Multi-threading**: Concurrent scanning for maximum performance
- **Certificate Transparency**: Query public SSL certificate logs
- **Multiple Output Formats**: Export results to TXT, CSV, or JSON
- **Interactive & CLI Modes**: User-friendly interface or automation-ready
- **Custom Wordlists**: Use built-in or custom subdomain lists
- **Real-time Progress**: Live scanning feedback with progress tracking

## Reconnaissance Techniques

1. **DNS Brute Force** - Test common subdomain names against target domain
2. **Certificate Transparency Logs** - Search public certificate databases
3. **DNS Zone Walking** - Attempt zone transfers (if misconfigured)
4. **Wildcard Detection** - Identify and handle wildcard DNS responses

## Requirements

- Python 3.6+
- See `requirements.txt` for dependencies
