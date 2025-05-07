import socket
import ipaddress
import re
import json
import datetime
import requests
from concurrent.futures import ThreadPoolExecutor


class WhoisLookup:
    """Tool for performing WHOIS lookups on domains and IP addresses."""
    
    def __init__(self):
        # WHOIS servers for different TLDs
        self.whois_servers = {
            # Generic TLDs
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'info': 'whois.afilias.net',
            'biz': 'whois.neulevel.biz',
            'io': 'whois.nic.io',
            'me': 'whois.nic.me',
            'co': 'whois.nic.co',
            'ai': 'whois.nic.ai',
            'dev': 'whois.nic.google',
            'app': 'whois.nic.google',
            
            # Country TLDs
            'us': 'whois.nic.us',
            'uk': 'whois.nic.uk',
            'ca': 'whois.cira.ca',
            'au': 'whois.auda.org.au',
            'de': 'whois.denic.de',
            'fr': 'whois.nic.fr',
            'nl': 'whois.domain-registry.nl',
            'ru': 'whois.tcinet.ru',
            'cn': 'whois.cnnic.cn',
            'jp': 'whois.jprs.jp',
            'br': 'whois.registro.br',
            'in': 'whois.registry.in',
            
            # Default WHOIS server for generic queries
            'default': 'whois.iana.org'
        }
        
        # WHOIS server for IP address lookups
        self.ip_whois_servers = {
            'arin': 'whois.arin.net',      # North America
            'ripe': 'whois.ripe.net',      # Europe
            'apnic': 'whois.apnic.net',    # Asia/Pacific
            'lacnic': 'whois.lacnic.net',  # Latin America and Caribbean
            'afrinic': 'whois.afrinic.net' # Africa
        }
        
        # Default timeout for socket connections
        self.timeout = 10
        
        # Parser patterns for WHOIS data fields
        self.field_patterns = {
            'domain_name': [
                r'Domain Name: *(.+)',
                r'domain: *(.+)'
            ],
            'registrar': [
                r'Registrar: *(.+)',
                r'registrar: *(.+)'
            ],
            'whois_server': [
                r'Whois Server: *(.+)',
                r'Registrar WHOIS Server: *(.+)'
            ],
            'referral_url': [
                r'Referral URL: *(.+)',
                r'URL: *(.+)'
            ],
            'name_servers': [
                r'Name Server: *(.+)',
                r'nserver: *(.+)'
            ],
            'status': [
                r'Status: *(.+)',
                r'Domain status: *(.+)'
            ],
            'creation_date': [
                r'Creation Date: *(.+)',
                r'Created: *(.+)',
                r'created: *(.+)'
            ],
            'updated_date': [
                r'Updated Date: *(.+)',
                r'Last Updated: *(.+)',
                r'changed: *(.+)'
            ],
            'expiration_date': [
                r'Expiration Date: *(.+)',
                r'Registry Expiry Date: *(.+)',
                r'expires: *(.+)'
            ],
            'registrant_name': [
                r'Registrant Name: *(.+)',
                r'registrant: *(.+)'
            ],
            'registrant_organization': [
                r'Registrant Organization: *(.+)',
                r'Registrant: *(.+)'
            ],
            'registrant_country': [
                r'Registrant Country: *(.+)'
            ],
            'admin_name': [
                r'Admin Name: *(.+)'
            ],
            'admin_email': [
                r'Admin Email: *(.+)'
            ],
            'tech_name': [
                r'Tech Name: *(.+)'
            ],
            'tech_email': [
                r'Tech Email: *(.+)'
            ],
            # IP specific fields
            'ip_range': [
                r'inetnum: *(.+)',
                r'NetRange: *(.+)'
            ],
            'netname': [
                r'netname: *(.+)',
                r'NetName: *(.+)'
            ],
            'organization': [
                r'organization: *(.+)',
                r'Organization: *(.+)'
            ],
            'country': [
                r'country: *(.+)',
                r'Country: *(.+)'
            ],
            'cidr': [
                r'CIDR: *(.+)'
            ],
            'abuse_contact': [
                r'abuse-mailbox: *(.+)',
                r'OrgAbuseEmail: *(.+)'
            ]
        }
    
    def lookup(self, query, use_cache=True):
        """
        Perform a WHOIS lookup on a domain or IP address.
        
        Args:
            query: Domain name or IP address to look up
            use_cache: Whether to use cached results if available
            
        Returns:
            Dictionary with WHOIS information
        """
        # Clean and validate the query
        query = query.strip().lower()
        
        # Remove protocol prefixes if present
        query = re.sub(r'^https?://', '', query)
        
        # Remove path, query string, and fragment if present
        query = query.split('/', 1)[0]
        
        # Remove port if present
        query = query.split(':', 1)[0]
        
        # Remove www. prefix if present
        query = re.sub(r'^www\.', '', query)
        
        try:
            # Check if it's an IP address
            ipaddress.ip_address(query)
            return self._lookup_ip(query)
        except ValueError:
            # If not an IP address, treat as domain name
            return self._lookup_domain(query)
    
    def _lookup_domain(self, domain):
        """
        Perform a WHOIS lookup on a domain name.
        
        Args:
            domain: Domain name to look up
            
        Returns:
            Dictionary with WHOIS information
        """
        # Extract the TLD
        tld = domain.split('.')[-1]
        
        # Get the appropriate WHOIS server
        whois_server = self.whois_servers.get(tld, self.whois_servers['default'])
        
        try:
            # Initial query to get the authoritative WHOIS server
            raw_data = self._query_whois_server(whois_server, domain)
            
            # Extract the authoritative WHOIS server from the response
            for pattern in self.field_patterns['whois_server']:
                matches = re.search(pattern, raw_data, re.IGNORECASE)
                if matches:
                    auth_whois_server = matches.group(1).strip()
                    # Query the authoritative WHOIS server
                    raw_data = self._query_whois_server(auth_whois_server, domain)
                    break
            
            # Parse the WHOIS data
            parsed_data = self._parse_whois_data(raw_data, is_domain=True)
            
            # Add the raw data for reference
            parsed_data['raw_data'] = raw_data
            
            # Format dates if present
            parsed_data = self._format_dates(parsed_data)
            
            # Add query time
            parsed_data['query_time'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            return {
                'status': 'success',
                'query': domain,
                'type': 'domain',
                'data': parsed_data
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'query': domain,
                'type': 'domain',
                'error': str(e)
            }
    
    def _lookup_ip(self, ip):
        """
        Perform a WHOIS lookup on an IP address.
        
        Args:
            ip: IP address to look up
            
        Returns:
            Dictionary with WHOIS information
        """
        try:
            # First, determine the appropriate RIR (Regional Internet Registry)
            # For simplicity, we'll start with ARIN, which will refer us to the correct RIR
            whois_server = self.ip_whois_servers['arin']
            
            # Query the initial WHOIS server
            raw_data = self._query_whois_server(whois_server, ip)
            
            # Check if we need to query a different RIR
            for rir, server in self.ip_whois_servers.items():
                if f"refer: {server}" in raw_data.lower():
                    # Query the correct RIR
                    raw_data = self._query_whois_server(server, ip)
                    break
            
            # Parse the WHOIS data
            parsed_data = self._parse_whois_data(raw_data, is_domain=False)
            
            # Add the raw data for reference
            parsed_data['raw_data'] = raw_data
            
            # Add query time
            parsed_data['query_time'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Try to get geolocation data
            try:
                geo_data = self._get_geolocation(ip)
                if geo_data and geo_data.get('status') == 'success':
                    parsed_data['geolocation'] = geo_data.get('data', {})
            except Exception:
                # Ignore geolocation errors
                pass
            
            return {
                'status': 'success',
                'query': ip,
                'type': 'ip',
                'data': parsed_data
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'query': ip,
                'type': 'ip',
                'error': str(e)
            }
    
    def _query_whois_server(self, server, query):
        """
        Query a WHOIS server for information.
        
        Args:
            server: WHOIS server to query
            query: Domain or IP to look up
            
        Returns:
            Raw WHOIS response as a string
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            # Connect to the WHOIS server
            sock.connect((server, 43))
            
            # Send the query (with newline)
            sock.send(f"{query}\r\n".encode('utf-8'))
            
            # Receive the response
            response = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            # Convert the response to a string
            try:
                return response.decode('utf-8')
            except UnicodeDecodeError:
                # Some WHOIS servers might use different encodings
                try:
                    return response.decode('latin-1')
                except UnicodeDecodeError:
                    return response.decode('utf-8', errors='replace')
        
        finally:
            sock.close()
    
    def _parse_whois_data(self, raw_data, is_domain):
        """
        Parse the raw WHOIS data into a structured format.
        
        Args:
            raw_data: Raw WHOIS response text
            is_domain: Whether this is domain data (vs IP data)
            
        Returns:
            Dictionary with parsed WHOIS data
        """
        result = {
            'raw_text_sample': raw_data[:1000] if len(raw_data) > 1000 else raw_data
        }
        
        # Select which fields to parse based on query type
        fields_to_parse = self.field_patterns.items()
        
        # Extract values for each field
        for field, patterns in fields_to_parse:
            values = []
            
            for pattern in patterns:
                matches = re.finditer(pattern, raw_data, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    value = match.group(1).strip()
                    if value and value not in values:
                        values.append(value)
            
            if values:
                # Fields that can have multiple values
                if field in ['name_servers', 'status']:
                    result[field] = values
                else:
                    result[field] = values[0]
        
        # For domains, extract privacy status
        if is_domain:
            result['privacy_protected'] = self._is_privacy_protected(raw_data)
        
        return result
    
    def _is_privacy_protected(self, raw_data):
        """
        Check if a domain has privacy protection enabled.
        
        Args:
            raw_data: Raw WHOIS response text
            
        Returns:
            Boolean indicating if privacy protection is detected
        """
        privacy_indicators = [
            'privacy', 'redacted', 'private', 
            'proxy', 'protected', 'withheld',
            'identity shield', 'id protect'
        ]
        
        # If any of the privacy indicators appear in the WHOIS data
        for indicator in privacy_indicators:
            if re.search(r'\b' + re.escape(indicator) + r'\b', raw_data, re.IGNORECASE):
                return True
        
        # Check for typical privacy service names
        privacy_services = [
            'privatewhois', 'domainsbyproxy', 'privacyguardian', 
            'privacyprotect', 'whoisguard', 'privacy service',
            'redacted for privacy', 'contact privacy'
        ]
        
        for service in privacy_services:
            if re.search(r'\b' + re.escape(service) + r'\b', raw_data, re.IGNORECASE):
                return True
        
        return False
    
    def _format_dates(self, data):
        """
        Format dates in the WHOIS data for better readability.
        
        Args:
            data: Parsed WHOIS data dictionary
            
        Returns:
            WHOIS data with formatted dates
        """
        date_fields = ['creation_date', 'updated_date', 'expiration_date']
        
        for field in date_fields:
            if field in data:
                raw_date = data[field]
                
                # Try several date formats
                formatted_date = self._parse_date(raw_date)
                
                if formatted_date:
                    # Replace the raw date with the formatted one
                    data[field] = formatted_date
                    
                    # Add a relative time description
                    if field == 'creation_date':
                        data['domain_age'] = self._get_relative_time(formatted_date)
                    elif field == 'expiration_date':
                        data['expires_in'] = self._get_relative_time(formatted_date, from_now=True)
        
        return data
    
    def _parse_date(self, date_string):
        """
        Parse a date string into a standard format.
        
        Args:
            date_string: Date string from WHOIS data
            
        Returns:
            Formatted date string or None if parsing fails
        """
        # Common date formats in WHOIS data
        date_formats = [
            '%Y-%m-%d',
            '%d-%b-%Y',
            '%d-%B-%Y',
            '%d %b %Y',
            '%d %B %Y',
            '%b %d %Y',
            '%B %d %Y',
            '%Y.%m.%d',
            '%d.%m.%Y',
            '%Y/%m/%d',
            '%d/%m/%Y',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%d %H:%M:%S',
            '%d-%b-%Y %H:%M:%S %Z',
            '%a %b %d %H:%M:%S %Z %Y'
        ]
        
        # Clean the date string
        date_string = date_string.strip()
        
        # Try each format
        for fmt in date_formats:
            try:
                date_obj = datetime.datetime.strptime(date_string, fmt)
                return date_obj.strftime('%Y-%m-%d')
            except ValueError:
                continue
        
        # Some WHOIS servers return dates with timezone names like "UTC"
        # Try to handle these cases
        try:
            # Remove timezone name and try again
            cleaned_date = re.sub(r'\([A-Z]+\)', '', date_string).strip()
            cleaned_date = re.sub(r'[A-Z]{3,}$', '', cleaned_date).strip()
            
            for fmt in date_formats:
                try:
                    date_obj = datetime.datetime.strptime(cleaned_date, fmt)
                    return date_obj.strftime('%Y-%m-%d')
                except ValueError:
                    continue
        except Exception:
            pass
        
        # Return original if all parsing attempts fail
        return date_string
    
    def _get_relative_time(self, date_string, from_now=False):
        """
        Get a human-readable string describing relative time.
        
        Args:
            date_string: Date string in YYYY-MM-DD format
            from_now: Whether to calculate time from now to date (True),
                     or from date to now (False)
            
        Returns:
            Human-readable string describing the time span
        """
        try:
            date_obj = datetime.datetime.strptime(date_string, '%Y-%m-%d')
            now = datetime.datetime.now()
            
            if from_now:
                # Time from now until the date
                delta = date_obj - now
                if delta.days < 0:
                    return "Expired"
            else:
                # Time from the date until now
                delta = now - date_obj
            
            years, remainder = divmod(delta.days, 365)
            months, days = divmod(remainder, 30)
            
            if years > 0:
                if months > 0:
                    return f"{years} year{'s' if years != 1 else ''}, {months} month{'s' if months != 1 else ''}"
                return f"{years} year{'s' if years != 1 else ''}"
            elif months > 0:
                if days > 0:
                    return f"{months} month{'s' if months != 1 else ''}, {days} day{'s' if days != 1 else ''}"
                return f"{months} month{'s' if months != 1 else ''}"
            else:
                return f"{delta.days} day{'s' if delta.days != 1 else ''}"
        
        except Exception:
            return "Unknown"
    
    def _get_geolocation(self, ip):
        """
        Get geolocation information for an IP address.
        
        Args:
            ip: IP address to locate
            
        Returns:
            Dictionary with geolocation data
        """
        try:
            # Use a free IP geolocation API
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                # Filter the relevant fields
                geo_data = {
                    'ip': data.get('ip'),
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country_name'),
                    'country_code': data.get('country_code'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'timezone': data.get('timezone'),
                    'org': data.get('org'),
                    'asn': data.get('asn')
                }
                
                return {
                    'status': 'success',
                    'data': geo_data
                }
            
            return {
                'status': 'error',
                'error': f"API returned status code {response.status_code}"
            }
        
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def batch_lookup(self, queries, max_workers=5):
        """
        Perform WHOIS lookups on multiple domains or IPs in parallel.
        
        Args:
            queries: List of domains or IPs to look up
            max_workers: Maximum number of concurrent workers
            
        Returns:
            Dictionary with results for each query
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all queries
            future_to_query = {executor.submit(self.lookup, query): query for query in queries}
            
            # Process results as they complete
            for future in future_to_query:
                query = future_to_query[future]
                try:
                    results[query] = future.result()
                except Exception as e:
                    results[query] = {
                        'status': 'error',
                        'query': query,
                        'error': str(e)
                    }
        
        return {
            'status': 'completed',
            'total': len(queries),
            'successful': sum(1 for query, result in results.items() if result.get('status') == 'success'),
            'results': results
        }
    
    def get_domain_expiry(self, domain):
        """
        Get the expiration date of a domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with expiration information
        """
        result = self.lookup(domain)
        
        if result.get('status') == 'success':
            data = result.get('data', {})
            
            expiration_date = data.get('expiration_date')
            expires_in = data.get('expires_in')
            
            if expiration_date:
                return {
                    'status': 'success',
                    'domain': domain,
                    'expiration_date': expiration_date,
                    'expires_in': expires_in or "Unknown"
                }
        
        return {
            'status': 'error',
            'domain': domain,
            'error': "Could not retrieve expiration date"
        }
    
    def get_registrar_info(self, domain):
        """
        Get information about the registrar of a domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with registrar information
        """
        result = self.lookup(domain)
        
        if result.get('status') == 'success':
            data = result.get('data', {})
            
            return {
                'status': 'success',
                'domain': domain,
                'registrar': data.get('registrar', "Unknown"),
                'whois_server': data.get('whois_server', "Unknown"),
                'referral_url': data.get('referral_url', "Unknown")
            }
        
        return {
            'status': 'error',
            'domain': domain,
            'error': "Could not retrieve registrar information"
        }
    
    def is_domain_available(self, domain):
        """
        Check if a domain is available for registration.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary indicating if the domain is available
        """
        result = self.lookup(domain)
        
        # Domain is likely available if WHOIS lookup fails or returns no data
        if result.get('status') == 'error' or not result.get('data', {}).get('domain_name'):
            return {
                'status': 'success',
                'domain': domain,
                'available': True
            }
        
        # Check for common phrases indicating domain availability
        raw_data = result.get('data', {}).get('raw_data', '').lower()
        
        availability_phrases = [
            'no match', 'not found', 'no entries found',
            'no data found', 'domain not found',
            'domain is available', 'available for registration'
        ]
        
        if any(phrase in raw_data for phrase in availability_phrases):
            return {
                'status': 'success',
                'domain': domain,
                'available': True
            }
        
        return {
            'status': 'success',
            'domain': domain,
            'available': False
        }