#!/usr/bin/env python3

import dns.resolver
import requests
import json
import socket
import time
import os
import threading
from concurrent.futures import ThreadPoolExecutor

class SubdomainFinder:
    def __init__(self, domain, timeout=3, max_threads=50):
        self.domain = domain.lower().strip()
        self.timeout = timeout
        self.max_threads = max_threads
        self.found_subdomains = []
        self.scanned_count = 0
        self.total_count = 0
        self.lock = threading.Lock()  # For thread-safe operations
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
    def check_subdomain(self, subdomain):
        """
        Check if a subdomain exists using DNS resolution
        
        Args:
            subdomain (str): Subdomain to check (without domain)
            
        Returns:
            dict: Result with subdomain info or None if not found
        """
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            # Try A record resolution
            answers = self.resolver.resolve(full_domain, 'A')
            
            # Get IP addresses
            ip_addresses = [str(answer) for answer in answers]
            
            result = {
                'subdomain': subdomain,
                'full_domain': full_domain,
                'ip_addresses': ip_addresses,
                'record_type': 'A',
                'source': 'DNS'
            }
            
            # Thread-safe operations
            with self.lock:
                self.found_subdomains.append(result)
                self.scanned_count += 1
                progress = (self.scanned_count / self.total_count) * 100
            
            print(f"[{self.scanned_count:3d}/{self.total_count}] {full_domain:30} ✅ FOUND ({', '.join(ip_addresses)}) ({progress:5.1f}%)")
            return result
            
        except dns.resolver.NXDOMAIN:
            # Subdomain doesn't exist
            with self.lock:
                self.scanned_count += 1
                progress = (self.scanned_count / self.total_count) * 100
            print(f"[{self.scanned_count:3d}/{self.total_count}] {full_domain:30} ❌ NOT FOUND ({progress:5.1f}%)")
            return None
            
        except dns.resolver.Timeout:
            with self.lock:
                self.scanned_count += 1
                progress = (self.scanned_count / self.total_count) * 100
            print(f"[{self.scanned_count:3d}/{self.total_count}] {full_domain:30} ⏱️  TIMEOUT ({progress:5.1f}%)")
            return None
            
        except dns.resolver.NoAnswer:
            # Domain exists but no A record, try CNAME
            try:
                cname_answers = self.resolver.resolve(full_domain, 'CNAME')
                cname_targets = [str(answer) for answer in cname_answers]
                
                result = {
                    'subdomain': subdomain,
                    'full_domain': full_domain,
                    'cname_targets': cname_targets,
                    'record_type': 'CNAME',
                    'source': 'DNS'
                }
                
                with self.lock:
                    self.found_subdomains.append(result)
                    self.scanned_count += 1
                    progress = (self.scanned_count / self.total_count) * 100
                
                print(f"[{self.scanned_count:3d}/{self.total_count}] {full_domain:30} ✅ FOUND (CNAME: {', '.join(cname_targets)}) ({progress:5.1f}%)")
                return result
                
            except:
                with self.lock:
                    self.scanned_count += 1
                    progress = (self.scanned_count / self.total_count) * 100
                print(f"[{self.scanned_count:3d}/{self.total_count}] {full_domain:30} ❌ NO RECORD ({progress:5.1f}%)")
                return None
                
        except Exception as e:
            with self.lock:
                self.scanned_count += 1
                progress = (self.scanned_count / self.total_count) * 100
            print(f"[{self.scanned_count:3d}/{self.total_count}] {full_domain:30} ❌ ERROR: {str(e)} ({progress:5.1f}%)")
            return None
    
    def certificate_transparency_search(self):
        """
        Search certificate transparency logs using CertSpotter API
        
        Returns:
            list: List of discovered subdomains from CT logs
        """
        print(f"\n🔍 Searching Certificate Transparency logs for: {self.domain}")
        ct_subdomains = []
        
        # Use CertSpotter API (the one that works)
        url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        
        # Better headers to avoid blocking
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        
        try:
            print(f"📡 Querying CertSpotter API...")
            
            response = requests.get(
                url, 
                headers=headers,
                timeout=15,
                verify=True
            )
            
            if response.status_code == 200:
                print(f"✅ CertSpotter responded successfully!")
                
                try:
                    data = response.json()
                    ct_subdomains = self._parse_certspotter_response(data)
                    
                    if ct_subdomains:
                        print(f"✅ Found {len(ct_subdomains)} unique subdomains from Certificate Transparency")
                        print("📋 CT Log subdomains:", ', '.join(sorted(ct_subdomains)[:10]) + 
                              ('...' if len(ct_subdomains) > 10 else ''))
                    else:
                        print(f"⚠️  CertSpotter returned no subdomains")
                        
                except json.JSONDecodeError:
                    print(f"❌ CertSpotter returned invalid JSON")
                    
            elif response.status_code == 503:
                print(f"⚠️  CertSpotter is overloaded (503)")
            elif response.status_code == 429:
                print(f"⚠️  CertSpotter rate limited (429)")
            else:
                print(f"❌ CertSpotter failed (status: {response.status_code})")
                
        except requests.exceptions.Timeout:
            print(f"⏱️  CertSpotter timed out")
        except requests.exceptions.ConnectionError:
            print(f"❌ CertSpotter connection failed")
        except requests.exceptions.RequestException as e:
            print(f"❌ CertSpotter error: {e}")
        except Exception as e:
            print(f"❌ CertSpotter unexpected error: {e}")
        
        return ct_subdomains
    
    def _parse_certspotter_response(self, data):
        """Parse CertSpotter JSON response"""
        domains_found = set()
        
        if not isinstance(data, list):
            return []
        
        for cert in data:
            if not isinstance(cert, dict):
                continue
                
            dns_names = cert.get('dns_names', [])
            if not isinstance(dns_names, list):
                continue
            
            for domain in dns_names:
                if not isinstance(domain, str):
                    continue
                    
                domain = domain.strip().lower()
                
                # Remove wildcards
                if domain.startswith('*.'):
                    domain = domain[2:]
                
                # Must end with our target domain
                if domain.endswith(f'.{self.domain}') and domain != self.domain:
                    # Extract subdomain part
                    subdomain = domain.replace(f'.{self.domain}', '')
                    if subdomain and '.' not in subdomain and subdomain.replace('-', '').replace('_', '').isalnum():
                        domains_found.add(subdomain)
        
        return list(domains_found)
    
    def load_wordlist(self, wordlist_path):
        """
        Load subdomain wordlist from file
        
        Args:
            wordlist_path (str): Path to wordlist file
            
        Returns:
            list: List of subdomain words
        """
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                words = [line.strip().lower() for line in f if line.strip()]
                
            # Remove duplicates and empty lines
            words = list(set(word for word in words if word and word.isalnum()))
            
            print(f"📋 Loaded {len(words)} subdomains from {wordlist_path}")
            return words
            
        except FileNotFoundError:
            print(f"❌ Wordlist file not found: {wordlist_path}")
            return []
        except Exception as e:
            print(f"❌ Error loading wordlist: {e}")
            return []
    
    def brute_force_scan(self, wordlist_path="wordlists/common.txt"):
        """
        Perform multi-threaded DNS brute force scan using wordlist
        
        Args:
            wordlist_path (str): Path to wordlist file
            
        Returns:
            list: List of found subdomains
        """
        # Load wordlist
        subdomains = self.load_wordlist(wordlist_path)
        
        if not subdomains:
            print("❌ No subdomains to scan")
            return []
        
        print(f"\n🔍 Starting DNS brute force for: {self.domain}")
        print(f"📊 Scanning {len(subdomains)} subdomains with {self.max_threads} threads")
        print(f"⏱️  Timeout: {self.timeout} seconds per request")
        print("-" * 80)
        
        # Initialize counters
        dns_results = []
        self.scanned_count = 0
        self.total_count = len(subdomains)
        
        start_time = time.time()
        
        # Use ThreadPoolExecutor for concurrent DNS queries
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all subdomain check tasks
            futures = [executor.submit(self.check_subdomain, subdomain) for subdomain in subdomains]
            
            # Wait for all tasks to complete
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        dns_results.append(result)
                except Exception as e:
                    print(f"❌ Thread error: {e}")
        
        end_time = time.time()
        
        # Results summary
        print(f"\n" + "=" * 80)
        print(f"🎯 DNS BRUTE FORCE COMPLETE")
        print(f"⏱️  Time taken: {end_time - start_time:.2f} seconds")
        print(f"📈 Subdomains scanned: {self.scanned_count}/{self.total_count}")
        print(f"🚀 Threads used: {self.max_threads}")
        print(f"✅ Subdomains found via DNS: {len(dns_results)}")
        
        # Calculate speed improvement
        sequential_time = self.total_count * self.timeout
        actual_time = end_time - start_time
        if actual_time > 0:
            speedup = sequential_time / actual_time
            print(f"⚡ Speed improvement: {speedup:.1f}x faster than sequential")
        
        return dns_results
    
    def comprehensive_scan(self, wordlist_path="wordlists/common.txt", use_ct_logs=True):
        """
        Perform comprehensive subdomain discovery using multiple methods
        
        Args:
            wordlist_path (str): Path to wordlist file
            use_ct_logs (bool): Whether to use certificate transparency logs
            
        Returns:
            list: List of all found subdomains
        """
        all_results = []
        
        # Method 1: Certificate Transparency Logs
        if use_ct_logs:
            ct_subdomains = self.certificate_transparency_search()
            
            if ct_subdomains:
                print(f"\n🔍 Validating {len(ct_subdomains)} CT log subdomains via DNS...")
                
                # Reset counters for CT validation
                self.found_subdomains = []
                self.scanned_count = 0
                self.total_count = len(ct_subdomains)
                
                # Validate CT subdomains via DNS
                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    futures = [executor.submit(self.check_subdomain, sub) for sub in ct_subdomains]
                    for future in futures:
                        try:
                            result = future.result()
                            if result:
                                result['source'] = 'CT_LOG'
                                all_results.append(result)
                        except Exception as e:
                            print(f"❌ CT validation error: {e}")
        
        # Method 2: DNS Brute Force
        self.found_subdomains = []  # Reset for brute force
        dns_results = self.brute_force_scan(wordlist_path)
        all_results.extend(dns_results)
        
        # Remove duplicates (same subdomain found via different methods)
        unique_results = {}
        for result in all_results:
            full_domain = result['full_domain']
            if full_domain not in unique_results:
                unique_results[full_domain] = result
            else:
                # Merge sources
                existing = unique_results[full_domain]
                if 'sources' not in existing:
                    existing['sources'] = [existing.get('source', 'DNS')]
                if result.get('source') not in existing['sources']:
                    existing['sources'].append(result.get('source'))
        
        final_results = list(unique_results.values())
        
        # Final summary
        print(f"\n" + "=" * 80)
        print(f"🎯 COMPREHENSIVE SCAN COMPLETE")
        print(f"✅ Total unique subdomains found: {len(final_results)}")
        
        ct_count = len([r for r in all_results if r.get('source') == 'CT_LOG'])
        dns_count = len([r for r in all_results if r.get('source') == 'DNS'])
        
        print(f"📊 Discovery breakdown:")
        print(f"   • Certificate Transparency: {ct_count}")
        print(f"   • DNS Brute Force: {dns_count}")
        print("=" * 80)
        
        if final_results:
            print(f"\n🌐 DISCOVERED SUBDOMAINS:")
            for result in sorted(final_results, key=lambda x: x['full_domain']):
                if result['record_type'] == 'A':
                    ips = ', '.join(result['ip_addresses'])
                    sources = result.get('sources', [result.get('source', 'DNS')])
                    source_str = '+'.join(sources) if len(sources) > 1 else sources[0]
                    print(f"   • {result['full_domain']:35} ({ips}) [{source_str}]")
                else:
                    targets = ', '.join(result['cname_targets'])
                    sources = result.get('sources', [result.get('source', 'DNS')])
                    source_str = '+'.join(sources) if len(sources) > 1 else sources[0]
                    print(f"   • {result['full_domain']:35} (CNAME: {targets}) [{source_str}]")
        else:
            print(f"\n❌ No subdomains found for {self.domain}")
        
        return final_results

def validate_domain(domain):
    """
    Validate if domain format is correct
    
    Args:
        domain (str): Domain to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not domain or len(domain) < 3:
        return False
    
    # Basic domain validation
    if not all(c.isalnum() or c in '.-' for c in domain):
        return False
    
    if domain.startswith('.') or domain.endswith('.'):
        return False
    
    if '..' in domain:
        return False
    
    # Must contain at least one dot
    if '.' not in domain:
        return False
    
    return True

def test_dns_connectivity():
    """Test if DNS resolution is working"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.resolve('google.com', 'A')
        return True
    except:
        return False

def get_domain_input():
    """Get domain from user with validation and examples"""
    print("🌐 DOMAIN SELECTION:")
    print("   • Enter a domain you own or have permission to scan")
    print("   • Examples: example.com, github.com, your-company.com")
    print("   • Do NOT include 'www' or 'http://' - just the domain name")
    print()
    
    while True:
        domain = input("Enter domain to scan: ").strip()
        
        if not domain:
            print("❌ Please enter a domain")
            continue
        
        # Clean up common user mistakes
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.replace('www.', '')
        
        if not validate_domain(domain):
            print("❌ Invalid domain format. Please enter a valid domain (e.g., example.com)")
            print("💡 Make sure it contains a dot and no special characters except hyphens")
            continue
        
        # Show what will be scanned
        print(f"✅ Will scan subdomains of: {domain}")
        confirm = input("Is this correct? (y/n) [y]: ").strip().lower()
        if confirm in ['', 'y', 'yes']:
            return domain
        
def get_scan_method():
    """Get scanning method from user"""
    print("\n🔍 SCANNING METHODS:")
    print("   1. DNS Brute Force only")
    print("      • Fast and reliable")
    print("      • Uses common subdomain wordlist")
    print("      • Finds actively responding subdomains")
    print()
    print("   2. Certificate Transparency + DNS Brute Force (recommended)")
    print("      • More comprehensive discovery")
    print("      • Finds subdomains from SSL certificates")
    print("      • May discover hidden/forgotten subdomains")
    print()
    
    while True:
        choice = input("Choose scanning method (1/2) [2]: ").strip()
        
        if choice == '1':
            return False  # DNS only
        elif choice in ['', '2']:
            return True   # CT + DNS
        else:
            print("❌ Please choose 1 or 2")

def get_timeout_setting():
    """Get timeout setting from user with validation"""
    print("\n⏱️  TIMEOUT CONFIGURATION:")
    print("   • Faster timeout: 1-2 seconds (may miss slow devices)")
    print("   • Balanced timeout: 3 seconds (recommended for most networks)")
    print("   • Thorough timeout: 5+ seconds (catches very slow devices)")
    print()
    
    while True:
        timeout_input = input("Enter DNS timeout in seconds [3]: ").strip()
        
        if not timeout_input:
            return 3  # Default
        
        try:
            timeout = int(timeout_input)
            if timeout < 1:
                print("❌ Timeout must be at least 1 second")
                continue
            elif timeout > 30:
                print("❌ Timeout cannot exceed 30 seconds (too slow)")
                continue
            elif timeout > 10:
                print(f"⚠️  Warning: {timeout} seconds is quite slow. This will take a long time.")
                confirm = input("Continue with this timeout? (y/n): ").strip().lower()
                if confirm not in ['y', 'yes']:
                    continue
            
            return timeout
            
        except ValueError:
            print("❌ Please enter a valid number")

def get_thread_count():
    """Get thread count from user with validation"""
    print("\n🧵 THREADING CONFIGURATION:")
    print("   • Conservative: 10-25 threads (safe for all systems)")
    print("   • Balanced: 50 threads (recommended)")
    print("   • Aggressive: 100+ threads (may overwhelm network/DNS)")
    print()
    
    while True:
        threads_input = input("Enter number of threads [50]: ").strip()
        
        if not threads_input:
            return 50  # Default
        
        try:
            threads = int(threads_input)
            if threads < 1:
                print("❌ Thread count must be at least 1")
                continue
            elif threads > 500:
                print("❌ Maximum 500 threads allowed to prevent system overload")
                continue
            elif threads > 100:
                print(f"⚠️  Warning: {threads} threads may overwhelm your network or DNS servers")
                confirm = input("Continue with this many threads? (y/n): ").strip().lower()
                if confirm not in ['y', 'yes']:
                    continue
            
            return threads
            
        except ValueError:
            print("❌ Please enter a valid number")

def get_wordlist_setting():
    """Get wordlist setting from user"""
    print("\n📋 WORDLIST CONFIGURATION:")
    
    default_wordlist = "wordlists/common.txt"
    
    if os.path.exists(default_wordlist):
        with open(default_wordlist, 'r') as f:
            word_count = sum(1 for line in f if line.strip())
        print(f"   • Default wordlist: {default_wordlist} ({word_count} subdomains)")
    else:
        print(f"   • Default wordlist: {default_wordlist} (not found)")
    
    print("   • Custom wordlist: Specify your own file path")
    print()
    
    while True:
        choice = input("Use default wordlist or specify custom path? (default/custom) [default]: ").strip().lower()
        
        if choice in ['', 'default', 'd']:
            if os.path.exists(default_wordlist):
                return default_wordlist
            else:
                print(f"❌ Default wordlist not found: {default_wordlist}")
                print("💡 Make sure the wordlists/common.txt file exists")
                return None
        
        elif choice in ['custom', 'c']:
            custom_path = input("Enter custom wordlist path: ").strip()
            if not custom_path:
                print("❌ Please enter a file path")
                continue
            
            if os.path.exists(custom_path):
                return custom_path
            else:
                print(f"❌ File not found: {custom_path}")
                continue
        else:
            print("❌ Please choose 'default' or 'custom'")

def run_interactive_mode():
    """Run the tool in interactive mode with guided prompts"""
    print("🔍 Subdomain Finder v0.5.0")
    print("=" * 60)
    print("⚠️  IMPORTANT: Only use on domains you own or have explicit permission to scan!")
    print("   Unauthorized subdomain enumeration may be illegal in your jurisdiction.")
    print("=" * 60)
    
    try:
        # Get all settings from user with validation
        domain = get_domain_input()
        use_ct_logs = get_scan_method()
        timeout = get_timeout_setting()
        threads = get_thread_count()
        wordlist_path = get_wordlist_setting()
        
        if not wordlist_path:
            print("❌ Cannot proceed without a valid wordlist")
            return
        
        # Show final configuration
        print(f"\n📋 SCAN CONFIGURATION:")
        print(f"   Domain: {domain}")
        print(f"   Method: {'Certificate Transparency + DNS Brute Force' if use_ct_logs else 'DNS Brute Force only'}")
        print(f"   Timeout: {timeout} seconds")
        print(f"   Threads: {threads}")
        print(f"   Wordlist: {wordlist_path}")
        print()
        
        confirm = input("Start scan with these settings? (y/n) [y]: ").strip().lower()
        if confirm not in ['', 'y', 'yes']:
            print("👋 Scan cancelled by user")
            return
        
        # Create scanner and run
        scanner = SubdomainFinder(domain, timeout, threads)
        results = scanner.comprehensive_scan(wordlist_path, use_ct_logs)
        
        print(f"\n🏁 Scan finished. Found {len(results)} subdomains for {domain}.")
        
    except KeyboardInterrupt:
        print(f"\n\n👋 Scan cancelled by user. Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

def main():
    """Main entry point for the subdomain finder"""
    # Test DNS connectivity first
    if not test_dns_connectivity():
        print("❌ DNS resolution not working. Check your internet connection.")
        return
    
    # Run interactive mode
    run_interactive_mode()

if __name__ == "__main__":
    main()