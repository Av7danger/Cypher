import socket
import dns.resolver
import ipaddress
import re
import time


class DNSLookup:
    """Utility for DNS lookups and domain name resolution."""
    
    def __init__(self):
        # Set default DNS servers (Google's public DNS)
        self.dns_servers = ['8.8.8.8', '8.8.4.4']
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.dns_servers
        
        # Common DNS record types
        self.common_record_types = [
            'A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR'
        ]
    
    def set_dns_servers(self, servers):
        """
        Set custom DNS servers to use for lookups.
        
        Args:
            servers: List of DNS server IP addresses
        """
        # Validate each IP address
        valid_servers = []
        for server in servers:
            try:
                ipaddress.ip_address(server)
                valid_servers.append(server)
            except ValueError:
                pass
        
        if valid_servers:
            self.dns_servers = valid_servers
            self.resolver.nameservers = valid_servers
            return True
        return False
    
    def resolve_hostname(self, hostname):
        """
        Resolve a hostname to its IP address(es).
        
        Args:
            hostname: The hostname to resolve
            
        Returns:
            Dictionary with IP addresses or error
        """
        try:
            # Validate the hostname format
            if not self._is_valid_hostname(hostname):
                return {'error': f'Invalid hostname format: {hostname}'}
            
            # Try to get IPv4 addresses
            ipv4_addresses = []
            try:
                answers = self.resolver.resolve(hostname, 'A')
                for rdata in answers:
                    ipv4_addresses.append(str(rdata))
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                return {'error': f'Domain {hostname} does not exist'}
            except Exception as e:
                return {'error': f'Error resolving IPv4 address: {str(e)}'}
            
            # Try to get IPv6 addresses
            ipv6_addresses = []
            try:
                answers = self.resolver.resolve(hostname, 'AAAA')
                for rdata in answers:
                    ipv6_addresses.append(str(rdata))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
                pass
            
            if not ipv4_addresses and not ipv6_addresses:
                return {'error': f'No IP addresses found for {hostname}'}
            
            # Try to get canonical name (if it's an alias)
            canonical_name = None
            try:
                answers = self.resolver.resolve(hostname, 'CNAME')
                for rdata in answers:
                    canonical_name = str(rdata)
                    break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
                pass
            
            return {
                'hostname': hostname,
                'ipv4_addresses': ipv4_addresses,
                'ipv6_addresses': ipv6_addresses,
                'canonical_name': canonical_name
            }
            
        except Exception as e:
            return {'error': f'Error resolving hostname: {str(e)}'}
    
    def reverse_lookup(self, ip_address):
        """
        Perform a reverse DNS lookup to find the hostname for an IP address.
        
        Args:
            ip_address: The IP address to lookup
            
        Returns:
            Dictionary with hostname(s) or error
        """
        try:
            # Validate the IP address
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                return {'error': f'Invalid IP address: {ip_address}'}
            
            # For IPv4, create the reverse lookup domain
            if '.' in ip_address:  # IPv4
                # Prepare the reversed IP address for PTR lookup
                ip_parts = ip_address.split('.')
                reversed_ip = '.'.join(reversed(ip_parts)) + '.in-addr.arpa'
            else:  # IPv6
                # Convert IPv6 to expanded form and prepare for PTR
                try:
                    full_ipv6 = ipaddress.IPv6Address(ip_address).exploded
                    reversed_chars = ''.join(reversed(full_ipv6.replace(':', '')))
                    reversed_ip = '.'.join(reversed_chars) + '.ip6.arpa'
                except Exception:
                    return {'error': f'Error formatting IPv6 address for reverse lookup: {ip_address}'}
            
            # Perform the PTR lookup
            try:
                answers = self.resolver.resolve(reversed_ip, 'PTR')
                hostnames = [str(rdata) for rdata in answers]
                
                return {
                    'ip_address': ip_address,
                    'hostnames': hostnames
                }
            except dns.resolver.NoAnswer:
                return {'error': f'No reverse DNS records found for {ip_address}'}
            except dns.resolver.NXDOMAIN:
                return {'error': f'No reverse DNS entry exists for {ip_address}'}
            except Exception as e:
                return {'error': f'Error during reverse lookup: {str(e)}'}
            
        except Exception as e:
            return {'error': f'Error performing reverse lookup: {str(e)}'}
    
    def get_dns_records(self, domain, record_types=None):
        """
        Get all DNS records for a domain.
        
        Args:
            domain: The domain to query
            record_types: List of record types to query (default: all common types)
            
        Returns:
            Dictionary with DNS records organized by type
        """
        if not record_types:
            record_types = self.common_record_types
            
        # Validate the domain format
        if not self._is_valid_hostname(domain):
            return {'error': f'Invalid domain format: {domain}'}
            
        results = {}
        errors = []
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                results[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                results[record_type] = []
            except dns.resolver.NXDOMAIN:
                errors.append(f'Domain {domain} does not exist')
                break
            except Exception as e:
                errors.append(f'Error querying {record_type} records: {str(e)}')
        
        return {
            'domain': domain,
            'records': results,
            'errors': errors if errors else None
        }
    
    def trace_dns_propagation(self, domain, record_type='A'):
        """
        Check DNS propagation across multiple nameservers.
        
        Args:
            domain: The domain to check
            record_type: The DNS record type to check
            
        Returns:
            Dictionary with results from different nameservers
        """
        # Common public DNS servers (name: IP)
        public_dns = {
            'Google': ['8.8.8.8', '8.8.4.4'],
            'Cloudflare': ['1.1.1.1', '1.0.0.1'],
            'Quad9': ['9.9.9.9', '149.112.112.112'],
            'OpenDNS': ['208.67.222.222', '208.67.220.220'],
            'Level3': ['4.2.2.1', '4.2.2.2']
        }
        
        results = {}
        
        for provider, servers in public_dns.items():
            try:
                # Create a new resolver for this provider
                resolver = dns.resolver.Resolver()
                resolver.nameservers = servers
                resolver.timeout = 3
                resolver.lifetime = 5
                
                try:
                    start_time = time.time()
                    answers = resolver.resolve(domain, record_type)
                    response_time = time.time() - start_time
                    
                    results[provider] = {
                        'status': 'success',
                        'data': [str(rdata) for rdata in answers],
                        'response_time': round(response_time * 1000, 2)  # ms
                    }
                except dns.resolver.NoAnswer:
                    results[provider] = {
                        'status': 'no_records',
                        'data': [],
                        'error': f'No {record_type} records found'
                    }
                except dns.resolver.NXDOMAIN:
                    results[provider] = {
                        'status': 'not_found',
                        'data': [],
                        'error': f'Domain {domain} not found'
                    }
                except Exception as e:
                    results[provider] = {
                        'status': 'error',
                        'data': [],
                        'error': str(e)
                    }
            except Exception as e:
                results[provider] = {
                    'status': 'error',
                    'data': [],
                    'error': f'Failed to query DNS: {str(e)}'
                }
        
        # Check for inconsistency among DNS providers
        values_seen = {}
        for provider, result in results.items():
            if result['status'] == 'success':
                for value in result['data']:
                    if value not in values_seen:
                        values_seen[value] = []
                    values_seen[value].append(provider)
        
        # Calculate propagation status
        all_providers = list(public_dns.keys())
        propagation_status = {}
        for value, providers in values_seen.items():
            propagation_status[value] = {
                'propagated_to': providers,
                'not_propagated_to': [p for p in all_providers if p not in providers],
                'propagation_percentage': round(len(providers) / len(all_providers) * 100, 1)
            }
        
        return {
            'domain': domain,
            'record_type': record_type,
            'provider_results': results,
            'propagation_status': propagation_status
        }
    
    def _is_valid_hostname(self, hostname):
        """Check if a string is a valid hostname."""
        if not hostname or len(hostname) > 255:
            return False
            
        # Check for valid hostname pattern
        if hostname[-1] == '.':
            hostname = hostname[:-1]
            
        allowed = re.compile(r'^([a-z0-9]|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9])(\.[a-z0-9]|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9])*$', re.IGNORECASE)
        return bool(allowed.match(hostname))