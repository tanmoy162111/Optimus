"""
Enhanced State Encoder - 128-dimensional state representation
Provides rich context for RL agent decision making

Dimensions breakdown:
- Phase encoding: 5
- Target context: 25  
- Vulnerability context: 30
- Tool history: 40
- Progress metrics: 15
- Intelligence features: 13
Total: 128
"""

import numpy as np
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class EnhancedStateEncoder:
    """
    Encodes scan context into 128-dimensional state vector.
    
    This rich representation allows the RL agent to make informed decisions
    based on comprehensive scan context including target characteristics,
    vulnerability findings, tool history, and progress metrics.
    """
    
    def __init__(self):
        # Phase definitions
        self.phases = [
            'reconnaissance', 'enumeration', 'vulnerability_analysis', 
            'exploitation', 'post_exploitation'
        ]
        
        # Vulnerability types to track (12 types)
        self.vuln_types = [
            'sql_injection', 'xss', 'rce', 'lfi', 'rfi', 
            'ssrf', 'xxe', 'open_port', 'misconfiguration', 
            'info_disclosure', 'auth_bypass', 'command_injection'
        ]
        
        # Services to track (12 services)
        self.services = [
            'http', 'https', 'ssh', 'ftp', 'smtp', 'mysql', 
            'mssql', 'postgres', 'smb', 'rdp', 'dns', 'telnet'
        ]
        
        # Common ports (12 ports)
        self.common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080]
        
        # Tools to track - ordered by common usage (35 tools for history encoding)
        self.tools_list = [
            'nmap', 'nikto', 'nuclei', 'sqlmap', 'dalfox', 'commix',
            'gobuster', 'ffuf', 'dirb', 'wpscan', 'hydra', 'metasploit',
            'burpsuite', 'sublist3r', 'amass', 'whatweb', 'fierce',
            'dnsenum', 'sslscan', 'enum4linux', 'xsser', 'testssl',
            'wfuzz', 'arjun', 'paramspider', 'waybackurls', 'gau',
            'httpx', 'katana', 'subfinder', 'masscan', 'nessus',
            'openvas', 'zap', 'arachni'
        ]
        
        self.state_dim = 128
        
        # Pre-compute indices for performance
        self._tool_index = {tool: idx for idx, tool in enumerate(self.tools_list)}
        self._vuln_index = {v: idx for idx, v in enumerate(self.vuln_types)}
        self._service_index = {s: idx for idx, s in enumerate(self.services)}
        
        logger.info(f"[EnhancedStateEncoder] Initialized with {self.state_dim} dimensions")
    
    def encode(self, scan_state: Dict[str, Any]) -> np.ndarray:
        """
        Encode scan state to 128-dimensional vector.
        
        Args:
            scan_state: Current scan state dictionary containing:
                - phase: Current pentesting phase
                - findings: List of vulnerability findings
                - tools_executed: List of executed tools
                - discovered_services: List of discovered services
                - coverage: Scan coverage percentage
                - And other scan metadata
            
        Returns:
            np.ndarray of shape (128,) with float32 values in [0, 1] range
        """
        # Handle numpy array input (convert back to dict)
        if isinstance(scan_state, np.ndarray):
            logger.warning("[EnhancedStateEncoder] Received numpy array instead of dict, returning zeros")
            return np.zeros(self.state_dim, dtype=np.float32)
        
        vector = []
        
        try:
            # === Section 1: Phase Encoding (5 dims) ===
            phase_vec = self._encode_phase(scan_state)
            vector.extend(phase_vec)
            
            # === Section 2: Target Context (25 dims) ===
            target_vec = self._encode_target_context(scan_state)
            vector.extend(target_vec)
            
            # === Section 3: Vulnerability Context (30 dims) ===
            vuln_vec = self._encode_vulnerability_context(scan_state)
            vector.extend(vuln_vec)
            
            # === Section 4: Tool History (40 dims) ===
            tool_vec = self._encode_tool_history(scan_state)
            vector.extend(tool_vec)
            
            # === Section 5: Progress Metrics (15 dims) ===
            progress_vec = self._encode_progress_metrics(scan_state)
            vector.extend(progress_vec)
            
            # === Section 6: Intelligence Features (13 dims) ===
            intel_vec = self._encode_intelligence_features(scan_state)
            vector.extend(intel_vec)
            
        except Exception as e:
            logger.error(f"[EnhancedStateEncoder] Encoding error: {e}")
            import traceback
            traceback.print_exc()
            return np.zeros(self.state_dim, dtype=np.float32)
        
        # Ensure exactly 128 dimensions
        vector = vector[:self.state_dim]
        while len(vector) < self.state_dim:
            vector.append(0.0)
        
        # Clip values to [0, 1] range
        result = np.array(vector, dtype=np.float32)
        result = np.clip(result, 0.0, 1.0)
        
        return result
    
    def _encode_phase(self, scan_state: Dict) -> List[float]:
        """
        Encode current phase as one-hot vector (5 dims).
        
        Returns: [recon, scan, exploit, post_exploit, covering]
        """
        current_phase = scan_state.get('phase', 'reconnaissance').lower()
        return [1.0 if current_phase == phase else 0.0 for phase in self.phases]
    
    def _encode_target_context(self, scan_state: Dict) -> List[float]:
        """
        Encode target context (25 dims).
        
        - Port presence: 12 dims (common ports)
        - Service types: 12 dims (detected services)
        - Target complexity: 1 dim
        """
        features = []
        
        # Get services from scan state (try multiple keys for compatibility)
        services = scan_state.get('discovered_services', [])
        if not services:
            services = scan_state.get('services', [])
        if not services:
            # Try to extract from findings
            for finding in scan_state.get('findings', []):
                if finding.get('port'):
                    services.append({'port': finding['port'], 'service': finding.get('service', '')})
        
        # Extract port numbers from services
        service_ports = set()
        detected_services = set()
        
        for svc in services:
            if isinstance(svc, dict):
                port = svc.get('port')
                if port:
                    try:
                        service_ports.add(int(port))
                    except (ValueError, TypeError):
                        pass
                svc_name = str(svc.get('service', '')).lower()
                if svc_name:
                    detected_services.add(svc_name)
            elif isinstance(svc, (int, str)):
                try:
                    service_ports.add(int(svc))
                except (ValueError, TypeError):
                    pass
        
        # Port presence encoding (12 dims)
        for port in self.common_ports:
            features.append(1.0 if port in service_ports else 0.0)
        
        # Service type encoding (12 dims)
        for svc in self.services:
            # Check if service name contains the target service
            found = any(svc in ds for ds in detected_services)
            features.append(1.0 if found else 0.0)
        
        # Target complexity (1 dim) - based on number of services/ports
        complexity = min((len(service_ports) + len(detected_services)) / 20.0, 1.0)
        features.append(complexity)
        
        return features  # 25 dims total
    
    def _encode_vulnerability_context(self, scan_state: Dict) -> List[float]:
        """
        Encode vulnerability context (30 dims).
        
        - Severity distribution: 4 dims
        - Vulnerability types: 12 dims
        - Exploitability metrics: 6 dims
        - CVE tracking: 4 dims
        - Severity statistics: 4 dims
        """
        features = []
        findings = scan_state.get('findings', [])
        
        # === Severity distribution (4 dims) ===
        severity_counts = [0, 0, 0, 0]  # [critical, high, medium, low]
        for f in findings:
            sev = f.get('severity', 0)
            if isinstance(sev, str):
                sev_map = {'critical': 9.5, 'high': 7.5, 'medium': 5.0, 'low': 2.5, 'info': 1.0}
                sev = sev_map.get(sev.lower(), 5.0)
            try:
                sev = float(sev)
            except (ValueError, TypeError):
                sev = 5.0
            
            if sev >= 9:
                severity_counts[0] += 1
            elif sev >= 7:
                severity_counts[1] += 1
            elif sev >= 4:
                severity_counts[2] += 1
            else:
                severity_counts[3] += 1
        
        # Normalize counts (cap at 10 each for reasonable scaling)
        for count in severity_counts:
            features.append(min(count / 10.0, 1.0))
        
        # === Vulnerability types (12 dims) ===
        detected_types = set()
        for f in findings:
            vtype = str(f.get('type', '')).lower().replace(' ', '_').replace('-', '_')
            detected_types.add(vtype)
            # Also add variations
            if 'sql' in vtype:
                detected_types.add('sql_injection')
            if 'xss' in vtype or 'cross' in vtype:
                detected_types.add('xss')
            if 'command' in vtype or 'rce' in vtype:
                detected_types.add('command_injection')
                detected_types.add('rce')
        
        for vtype in self.vuln_types:
            features.append(1.0 if vtype in detected_types else 0.0)
        
        # === Exploitability metrics (6 dims) ===
        exploitable = [f for f in findings if f.get('exploitable', False)]
        features.append(min(len(exploitable) / 10.0, 1.0))  # Exploitable count
        
        # Critical exploitable
        critical_exploit = any(
            f.get('severity', 0) >= 9 and f.get('exploitable', False) 
            for f in findings
        )
        features.append(1.0 if critical_exploit else 0.0)
        
        features.append(min(len(findings) / 50.0, 1.0))  # Total findings normalized
        
        # High severity exploitable count
        high_exploit = sum(1 for f in findings 
                          if f.get('severity', 0) >= 7 and f.get('exploitable', False))
        features.append(min(high_exploit / 5.0, 1.0))
        
        # Unique vulnerability types
        features.append(min(len(detected_types) / 10.0, 1.0))
        
        # Has any findings flag
        features.append(1.0 if findings else 0.0)
        
        # === CVE tracking (4 dims) ===
        cves = [f.get('cve', '') for f in findings if f.get('cve')]
        cves = [c for c in cves if c and c != 'null' and c != 'None']
        
        features.append(min(len(cves) / 10.0, 1.0))  # CVE count
        
        # Recent CVEs (2023, 2024, 2025)
        recent_cves = any('2023' in str(cve) or '2024' in str(cve) or '2025' in str(cve) 
                         for cve in cves)
        features.append(1.0 if recent_cves else 0.0)
        
        # Critical CVEs (just check if we have high severity with CVE)
        critical_cve = any(f.get('severity', 0) >= 9 and f.get('cve') for f in findings)
        features.append(1.0 if critical_cve else 0.0)
        
        # Exploitable CVEs
        exploit_cve = any(f.get('exploitable', False) and f.get('cve') for f in findings)
        features.append(1.0 if exploit_cve else 0.0)
        
        # === Severity statistics (4 dims) ===
        if findings:
            severities = []
            for f in findings:
                sev = f.get('severity', 0)
                if isinstance(sev, str):
                    sev_map = {'critical': 9.5, 'high': 7.5, 'medium': 5.0, 'low': 2.5}
                    sev = sev_map.get(sev.lower(), 5.0)
                try:
                    severities.append(float(sev))
                except:
                    severities.append(5.0)
            
            features.append(np.mean(severities) / 10.0)  # Average severity
            features.append(max(severities) / 10.0)  # Max severity
            features.append(np.std(severities) / 5.0 if len(severities) > 1 else 0.0)  # Spread
            features.append(min(sum(1 for s in severities if s >= 7) / 5.0, 1.0))  # High+ count
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])
        
        return features[:30]  # Ensure exactly 30 dims
    
    def _encode_tool_history(self, scan_state: Dict) -> List[float]:
        """
        Encode tool execution history (40 dims).
        
        - Tool execution flags: 35 dims (one per tracked tool)
        - Execution statistics: 5 dims
        """
        features = []
        
        # Extract tool names from execution history
        tools_executed = scan_state.get('tools_executed', [])
        tool_names = []
        for t in tools_executed:
            if isinstance(t, dict):
                tool_names.append(str(t.get('tool', '')).lower())
            else:
                tool_names.append(str(t).lower())
        
        executed_set = set(tool_names)
        
        # === Tool execution flags (35 dims) ===
        for tool in self.tools_list[:35]:
            features.append(1.0 if tool in executed_set else 0.0)
        
        # === Execution statistics (5 dims) ===
        # Total execution count normalized
        features.append(min(len(tools_executed) / 30.0, 1.0))
        
        # Unique tools ratio
        unique_count = len(executed_set)
        total_count = max(len(tools_executed), 1)
        features.append(unique_count / total_count if total_count > 0 else 0.0)
        
        # Recent tools pattern (last 3 tools encoded as normalized indices)
        recent_tools = tool_names[-3:] if tool_names else []
        for i in range(3):
            if i < len(recent_tools):
                tool = recent_tools[-(i+1)]  # Most recent first
                idx = self._tool_index.get(tool, -1)
                features.append((idx + 1) / len(self.tools_list) if idx >= 0 else 0.0)
            else:
                features.append(0.0)
        
        return features[:40]  # Ensure exactly 40 dims
    
    def _encode_progress_metrics(self, scan_state: Dict) -> List[float]:
        """
        Encode progress metrics (15 dims).
        
        - Time metrics: 4 dims
        - Coverage and iteration: 4 dims
        - Stall detection: 3 dims
        - Phase progress: 4 dims
        """
        features = []
        
        # === Time metrics (4 dims) ===
        time_elapsed = scan_state.get('time_elapsed', 0)
        time_budget = scan_state.get('config', {}).get('max_time', 3600)
        
        # Try to calculate from start_time if time_elapsed not set
        if time_elapsed == 0 and scan_state.get('start_time'):
            try:
                start = datetime.fromisoformat(scan_state['start_time'].replace('Z', '+00:00'))
                now = datetime.now(start.tzinfo) if start.tzinfo else datetime.now()
                time_elapsed = (now - start).total_seconds()
            except Exception:
                pass
        
        features.append(min(time_elapsed / 3600.0, 1.0))  # Hours elapsed (cap at 1)
        
        # Time remaining ratio
        if time_budget > 0:
            remaining_ratio = max(0, (time_budget - time_elapsed)) / time_budget
        else:
            remaining_ratio = 0.5
        features.append(remaining_ratio)
        
        # Time in current phase
        phase_start = scan_state.get('phase_start_time')
        if phase_start:
            try:
                phase_start_dt = datetime.fromisoformat(phase_start.replace('Z', '+00:00'))
                now = datetime.now(phase_start_dt.tzinfo) if phase_start_dt.tzinfo else datetime.now()
                time_in_phase = (now - phase_start_dt).total_seconds()
                features.append(min(time_in_phase / 600.0, 1.0))  # Normalized to 10 min
            except Exception:
                features.append(0.0)
        else:
            features.append(0.0)
        
        # Strategy changes count
        features.append(min(scan_state.get('strategy_changes', 0) / 5.0, 1.0))
        
        # === Coverage and iteration (4 dims) ===
        features.append(float(scan_state.get('coverage', 0.0)))
        
        tools_executed = scan_state.get('tools_executed', [])
        features.append(min(len(tools_executed) / 50.0, 1.0))  # Iteration count proxy
        
        # Findings per tool ratio
        findings_count = len(scan_state.get('findings', []))
        tools_count = max(len(tools_executed), 1)
        features.append(min(findings_count / tools_count, 1.0))
        
        # Discovery rate (findings in recent tools)
        recent_findings = scan_state.get('recent_findings_count', findings_count)
        features.append(min(recent_findings / 10.0, 1.0))
        
        # === Stall detection (3 dims) ===
        last_finding_iter = scan_state.get('last_finding_iteration', 0)
        current_iter = len(tools_executed)
        stall_count = current_iter - last_finding_iter
        
        features.append(min(stall_count / 10.0, 1.0))  # Stall counter
        features.append(1.0 if stall_count >= 5 else 0.0)  # Stalled flag
        features.append(1.0 if stall_count >= 10 else 0.0)  # Severely stalled
        
        # === Phase progress (4 dims) ===
        # Tools executed in current phase
        phase_tools = scan_state.get('phase_tools_executed', 0)
        features.append(min(phase_tools / 10.0, 1.0))
        
        # Blacklist size
        blacklisted = scan_state.get('blacklisted_tools', [])
        features.append(min(len(blacklisted) / 10.0, 1.0))
        
        # Phase completion estimate
        phase = scan_state.get('phase', 'reconnaissance')
        phase_idx = self.phases.index(phase) if phase in self.phases else 0
        features.append(phase_idx / (len(self.phases) - 1))
        
        # Scan completion estimate
        completion = min(
            scan_state.get('coverage', 0) * 0.5 + 
            (phase_idx / len(self.phases)) * 0.3 +
            min(len(tools_executed) / 30.0, 1.0) * 0.2,
            1.0
        )
        features.append(completion)
        
        return features[:15]  # Ensure exactly 15 dims
    
    def _encode_intelligence_features(self, scan_state: Dict) -> List[float]:
        """
        Encode intelligence features (13 dims).
        
        - Technology stack: 6 dims
        - Intelligence data: 4 dims
        - Target profile: 3 dims
        """
        features = []
        
        # === Technology stack detection (6 dims) ===
        tech_stack = scan_state.get('technologies_detected', [])
        tech_str = ' '.join(str(t).lower() for t in tech_stack)
        
        tech_indicators = ['wordpress', 'php', 'java', 'node', 'python', 'apache']
        for tech in tech_indicators:
            features.append(1.0 if tech in tech_str else 0.0)
        
        # === Intelligence data (4 dims) ===
        intel = scan_state.get('intelligence', {})
        
        # Known CVEs from intelligence
        known_cves = intel.get('known_cves', [])
        features.append(min(len(known_cves) / 10.0, 1.0))
        
        # Exploit availability score
        features.append(float(intel.get('exploit_availability', 0.0)))
        
        # Has public exploits flag
        features.append(1.0 if intel.get('has_public_exploits', False) else 0.0)
        
        # Reputation/threat score
        features.append(float(intel.get('reputation_score', 0.5)))
        
        # === Target profile (3 dims) ===
        target_profile = scan_state.get('target_profile', {})
        
        # WAF detected
        features.append(1.0 if target_profile.get('has_waf', False) else 0.0)
        
        # Is API target
        features.append(1.0 if target_profile.get('is_api', False) else 0.0)
        
        # Target complexity score
        features.append(float(target_profile.get('complexity_score', 0.5)))
        
        return features[:13]  # Ensure exactly 13 dims
    
    def get_state_dim(self) -> int:
        """Return state vector dimensions"""
        return self.state_dim
    
    def get_feature_names(self) -> List[str]:
        """Get human-readable feature names for debugging/visualization"""
        names = []
        
        # Phase (5)
        names.extend([f"phase_{p}" for p in self.phases])
        
        # Target context (25)
        names.extend([f"port_{p}" for p in self.common_ports])
        names.extend([f"service_{s}" for s in self.services])
        names.append("target_complexity")
        
        # Vulnerability context (30)
        names.extend(["sev_critical", "sev_high", "sev_medium", "sev_low"])
        names.extend([f"vuln_{v}" for v in self.vuln_types])
        names.extend([
            "exploitable_count", "critical_exploitable", "total_findings",
            "high_exploitable", "unique_vuln_types", "has_findings",
            "cve_count", "recent_cves", "critical_cve", "exploitable_cve",
            "avg_severity", "max_severity", "severity_spread", "high_plus_count"
        ])
        
        # Tool history (40)
        names.extend([f"tool_{t}" for t in self.tools_list[:35]])
        names.extend(["exec_count", "unique_ratio", "recent_1", "recent_2", "recent_3"])
        
        # Progress metrics (15)
        names.extend([
            "time_elapsed", "time_remaining", "time_in_phase", "strategy_changes",
            "coverage", "iteration", "findings_per_tool", "discovery_rate",
            "stall_count", "stalled", "severely_stalled",
            "phase_tools", "blacklist_size", "phase_progress", "completion"
        ])
        
        # Intelligence (13)
        names.extend([
            "tech_wordpress", "tech_php", "tech_java", "tech_node", "tech_python", "tech_apache",
            "known_cves", "exploit_avail", "public_exploits", "reputation",
            "has_waf", "is_api", "complexity"
        ])
        
        return names[:self.state_dim]
    
    def decode_state(self, state_vector: np.ndarray) -> Dict[str, Any]:
        """
        Decode state vector back to human-readable format (for debugging).
        
        Args:
            state_vector: 128-dim numpy array
            
        Returns:
            Dictionary with decoded features
        """
        names = self.get_feature_names()
        decoded = {}
        
        for i, (name, value) in enumerate(zip(names, state_vector)):
            if value > 0.01:  # Only include non-zero features
                decoded[name] = float(value)
        
        return decoded


# Singleton instance for performance
_encoder_instance = None

def get_state_encoder() -> EnhancedStateEncoder:
    """Get or create singleton state encoder"""
    global _encoder_instance
    if _encoder_instance is None:
        _encoder_instance = EnhancedStateEncoder()
    return _encoder_instance
