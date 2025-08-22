#!/usr/bin/env python3

import dns.resolver
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
                'record_type': 'A'
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
                    'record_type': 'CNAME'
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
        self.found_subdomains = []
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
                    future.result()  # This will raise any exceptions that occurred
                except Exception as e:
                    print(f"❌ Thread error: {e}")
        
        end_time = time.time()
        
        # Results summary
        print(f"\n" + "=" * 80)
        print(f"🎯 SCAN COMPLETE")
        print(f"⏱️  Time taken: {end_time - start_time:.2f} seconds")
        print(f"📈 Subdomains scanned: {self.scanned_count}/{self.total_count}")
        print(f"🚀 Threads used: {self.max_threads}")
        print(f"✅ Subdomains found: {len(self.found_subdomains)}")
        
        # Calculate speed improvement
        sequential_time = self.total_count * self.timeout
        actual_time = end_time - start_time
        if actual_time > 0:
            speedup = sequential_time / actual_time
            print(f"⚡ Speed improvement: {speedup:.1f}x faster than sequential")
        
        print("=" * 80)
        
        if self.found_subdomains:
            print(f"\n🌐 DISCOVERED SUBDOMAINS:")
            for result in sorted(self.found_subdomains, key=lambda x: x['full_domain']):
                if result['record_type'] == 'A':
                    ips = ', '.join(result['ip_addresses'])
                    print(f"   • {result['full_domain']:35} ({ips})")
                else:
                    targets = ', '.join(result['cname_targets'])
                    print(f"   • {result['full_domain']:35} (CNAME: {targets})")
        else:
            print(f"\n❌ No subdomains found for {self.domain}")
        
        return self.found_subdomains

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
    print("🔍 Subdomain Finder v0.3.0")
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
        results = scanner.brute_force_scan(wordlist_path)
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