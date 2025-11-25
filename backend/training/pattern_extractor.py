import re
from typing import List, Dict, Any

class PatternExtractor:
    """Extract and generalize attack patterns from datasets"""
    
    def __init__(self):
        self.sql_patterns = []
        self.xss_patterns = []
        self.command_injection_patterns = []
        self.path_traversal_patterns = []
    
    def extract_sql_patterns(self, examples: List[str]) -> List[str]:
        """Extract SQL injection regex patterns from examples"""
        patterns = [
            # Classic SQL injection
            r"'\s*[Oo][Rr]\s*'?\d+'?\s*=\s*'?\d+",
            r"'\s*[Oo][Rr]\s*'?1'?\s*=\s*'?1",
            r"'?\s*[Oo][Rr]\s+[Tt][Rr][Uu][Ee]\s*--",
            
            # Union-based
            r"[Uu][Nn][Ii][Oo][Nn]\s+[Aa][Ll][Ll]?\s+[Ss][Ee][Ll][Ee][Cc][Tt]",
            r"'\s+[Uu][Nn][Ii][Oo][Nn]\s+[Ss][Ee][Ll][Ee][Cc][Tt]",
            
            # Comment-based
            r"'?\s*;?\s*--",
            r"/\*.*?\*/",
            r"#.*$",
            
            # Time-based
            r"[Ss][Ll][Ee][Ee][Pp]\s*\(",
            r"[Ww][Aa][Ii][Tt][Ff][Oo][Rr]\s+[Dd][Ee][Ll][Aa][Yy]",
            r"[Bb][Ee][Nn][Cc][Hh][Mm][Aa][Rr][Kk]\s*\(",
            
            # Stacked queries
            r";\s*[Dd][Rr][Oo][Pp]\s+[Tt][Aa][Bb][Ll][Ee]",
            r";\s*[Ee][Xx][Ee][Cc]\s*\(",
            r";\s*[Dd][Ee][Ll][Ee][Tt][Ee]\s+[Ff][Rr][Oo][Mm]",
            
            # Boolean-based
            r"[Aa][Nn][Dd]\s+\d+\s*=\s*\d+",
            r"[Aa][Nn][Dd]\s+'[^']*'\s*=\s*'[^']*'",
            
            # Generalized patterns from examples
        ]
        
        # Add generalized patterns from actual examples
        for example in examples:
            generalized = self.generalize_pattern(example)
            if generalized and generalized not in patterns:
                patterns.append(generalized)
        
        self.sql_patterns = patterns
        return patterns
    
    def extract_xss_patterns(self, examples: List[str]) -> List[str]:
        """Extract XSS attack regex patterns"""
        patterns = [
            # Script tags
            r"<script[^>]*>.*?</script>",
            r"<script[^>]*>",
            r"</script>",
            
            # Event handlers
            r"on\w+\s*=\s*['\"]?[^'\">\s]+",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            
            # JavaScript protocol
            r"javascript\s*:",
            r"vbscript\s*:",
            
            # Iframe injection
            r"<iframe[^>]*>",
            r"<embed[^>]*>",
            r"<object[^>]*>",
            
            # IMG tag XSS
            r"<img[^>]*onerror",
            r"<img[^>]*src\s*=\s*['\"]?javascript:",
            
            # SVG XSS
            r"<svg[^>]*onload",
            r"<svg[^>]*onerror",
            
            # Data URIs
            r"data:text/html[^>]*base64",
            
            # Alert/prompt/confirm
            r"alert\s*\(",
            r"prompt\s*\(",
            r"confirm\s*\(",
            r"eval\s*\(",
            
            # DOM manipulation
            r"document\.(cookie|location|write|writeln)",
            r"window\.(location|open)",
        ]
        
        for example in examples:
            generalized = self.generalize_pattern(example)
            if generalized and generalized not in patterns:
                patterns.append(generalized)
        
        self.xss_patterns = patterns
        return patterns
    
    def extract_command_injection_patterns(self, examples: List[str]) -> List[str]:
        """Extract command injection patterns"""
        patterns = [
            # Command separators
            r"[;|&]\s*(cat|ls|wget|curl|nc|bash|sh|cmd)",
            r"[;|&]\s*\w+",
            
            # Backticks and command substitution
            r"`[^`]+`",
            r"\$\([^)]+\)",
            
            # Common commands
            r"\b(cat|ls|pwd|whoami|id|uname)\b",
            r"\b(wget|curl)\s+https?://",
            r"\b(nc|netcat)\s+",
            r"\b(bash|sh|cmd|powershell)\b",
            
            # File operations
            r"\b(rm|mv|cp|chmod|chown)\s+",
            r"\b(echo|printf)\s+.*>\s*",
            
            # Redirection
            r">\s*/",
            r">>\s*/",
            r"<\s*/",
            
            # Pipe chains
            r"\|\s*\w+",
            
            # Windows commands
            r"\b(dir|type|del|copy|move)\b",
            r"\.bat\b",
            r"\.ps1\b",
        ]
        
        for example in examples:
            generalized = self.generalize_pattern(example)
            if generalized and generalized not in patterns:
                patterns.append(generalized)
        
        self.command_injection_patterns = patterns
        return patterns
    
    def extract_path_traversal_patterns(self, examples: List[str]) -> List[str]:
        """Extract path traversal patterns"""
        patterns = [
            r"\.\./",
            r"\.\.\\",
            r"\.\./+",
            r"\.\.\\+",
            r"(%2e%2e[/\\])+",
            r"(..%2f)+",
            r"(..%5c)+",
            r"/etc/passwd",
            r"c:\\windows\\",
            r"/var/www/",
            r"\.\.%252f",
        ]
        
        self.path_traversal_patterns = patterns
        return patterns
    
    def generalize_pattern(self, payload: str) -> str:
        """Convert specific payload to generalized regex pattern"""
        if not payload:
            return ""
        
        # Escape special regex characters
        escaped = re.escape(payload)
        
        # Generalize common variations
        # Numbers -> \d+
        generalized = re.sub(r'\\\d+', r'\\d+', escaped)
        
        # Specific strings -> \w+
        # Be careful not to over-generalize keywords
        
        # Case-insensitive keywords
        keywords = ['union', 'select', 'insert', 'update', 'delete', 'from', 'where', 
                   'script', 'alert', 'onerror', 'onload']
        
        for keyword in keywords:
            # Make keyword case-insensitive
            pattern = ''.join([f'[{c.upper()}{c.lower()}]' if c.isalpha() else c for c in keyword])
            generalized = generalized.replace(re.escape(keyword), pattern)
        
        # Whitespace variations
        generalized = re.sub(r'\\ +', r'\\s+', generalized)
        
        return generalized
    
    def match_patterns(self, text: str, pattern_type: str = 'all') -> List[Dict[str, Any]]:
        """Match text against stored patterns"""
        matches = []
        
        if pattern_type in ['all', 'sql']:
            for pattern in self.sql_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append({
                        'type': 'sql_injection',
                        'pattern': pattern,
                        'match': re.search(pattern, text, re.IGNORECASE).group(0)
                    })
        
        if pattern_type in ['all', 'xss']:
            for pattern in self.xss_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append({
                        'type': 'xss',
                        'pattern': pattern,
                        'match': re.search(pattern, text, re.IGNORECASE).group(0)
                    })
        
        if pattern_type in ['all', 'command']:
            for pattern in self.command_injection_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append({
                        'type': 'command_injection',
                        'pattern': pattern,
                        'match': re.search(pattern, text, re.IGNORECASE).group(0)
                    })
        
        if pattern_type in ['all', 'path']:
            for pattern in self.path_traversal_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append({
                        'type': 'path_traversal',
                        'pattern': pattern,
                        'match': re.search(pattern, text, re.IGNORECASE).group(0)
                    })
        
        return matches
    
    def get_all_patterns(self) -> Dict[str, List[str]]:
        """Get all extracted patterns"""
        return {
            'sql': self.sql_patterns,
            'xss': self.xss_patterns,
            'command_injection': self.command_injection_patterns,
            'path_traversal': self.path_traversal_patterns
        }
