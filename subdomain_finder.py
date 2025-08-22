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

def main():
    """Main entry point for the subdomain finder"""
    print("🔍 Subdomain Finder v0.4.0")
    print("⚠️  WARNING: Only use on domains you own or have permission to scan!")
    print()
    
    # Test DNS connectivity
    if not test_dns_connectivity():
        print("❌ DNS resolution not working. Check your internet connection.")
        return
    
    # Get domain from user
    while True:
        domain = input("🌐 Enter domain to scan (e.g., example.com): ").strip()
        
        if not domain:
            print("❌ Please enter a domain")
            continue
        
        if not validate_domain(domain):
            print("❌ Invalid domain format. Please enter a valid domain (e.g., example.com)")
            continue
        
        break
    
    # Get scan method
    print("\n🔍 SCAN METHODS:")
    print("   1. DNS Brute Force only")
    print("   2. Certificate Transparency + DNS Brute Force (recommended)")
    
    method_choice = input("Choose scanning method (1/2) [2]: ").strip()
    use_ct_logs = method_choice != '1'
    
    # Get timeout setting
    try:
        timeout_input = input("⏱️  DNS timeout in seconds [3]: ").strip()
        timeout = int(timeout_input) if timeout_input else 3
        if timeout < 1 or timeout > 10:
            print("⚠️  Invalid timeout, using default: 3 seconds")
            timeout = 3
    except ValueError:
        timeout = 3
        print("⚠️  Invalid timeout, using default: 3 seconds")
    
    # Get thread count setting
    try:
        threads_input = input("🧵 Number of threads [50]: ").strip()
        threads = int(threads_input) if threads_input else 50
        if threads > 200:
            print("⚠️  Warning: Too many threads may overwhelm DNS servers")
            threads = 200
        elif threads < 1:
            threads = 1
    except ValueError:
        threads = 50
        print("⚠️  Invalid thread count, using default: 50")
    
    # Check if wordlist exists
    wordlist_path = "wordlists/common.txt"
    if not os.path.exists(wordlist_path):
        print(f"❌ Wordlist not found: {wordlist_path}")
        print("💡 Make sure the wordlists/common.txt file exists")
        return
    
    # Create scanner and run
    scanner = SubdomainFinder(domain, timeout, threads)
    
    try:
        results = scanner.comprehensive_scan(wordlist_path, use_ct_logs)
        print(f"\n🏁 Scan finished. Found {len(results)} subdomains.")
        
    except KeyboardInterrupt:
        print(f"\n\n⚠️  Scan interrupted by user")
        if scanner.found_subdomains:
            print(f"✅ Subdomains found so far: {len(scanner.found_subdomains)}")
            for result in scanner.found_subdomains:
                print(f"   • {result['full_domain']}")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()