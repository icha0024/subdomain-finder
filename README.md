# Subdomain Finder

A multi-threaded Python tool for discovering subdomains using DNS brute force, certificate transparency, and other reconnaissance techniques.

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is for educational purposes and authorized security testing only. Only use on domains you own or have explicit written permission to test. Unauthorized subdomain enumeration may be illegal in your jurisdiction and could violate terms of service.

## Features

- **DNS Brute Force**: High-speed subdomain discovery using custom wordlists
- **Multi-threading**: Concurrent scanning for maximum performance (1000x+ faster)
- **Certificate Transparency**: Query CertSpotter API for SSL certificate data
- **Interactive Mode**: Guided prompts with validation and examples
- **Command-line Interface**: Professional CLI for automation and scripting
- **Custom Wordlists**: Support for custom subdomain wordlist files
- **Real-time Progress**: Live scanning feedback with completion percentage
- **Source Tracking**: Shows discovery method (DNS, CT_LOG, or both)

## Requirements

- Python 3.6+
- See `requirements.txt` for dependencies
