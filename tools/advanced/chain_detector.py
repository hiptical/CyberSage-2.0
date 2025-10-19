# tools/advanced/chain_detector.py
class VulnerabilityChainDetector:
    """
    Detects multi-step attack chains that single tools miss
    """
    
    ATTACK_CHAINS = {
        'ssrf_to_rce': {
            'steps': [
                ('ssrf', 'Internal service access'),
                ('port_scan', 'Internal service enumeration'),
                ('exploit', 'RCE on internal service')
            ],
            'severity': 'critical',
            'impact': 'Full system compromise via internal network'
        },
        'idor_to_privilege_escalation': {
            'steps': [
                ('idor', 'Access other user data'),
                ('parameter_pollution', 'Modify admin flag'),
                ('auth_bypass', 'Gain admin access')
            ],
            'severity': 'critical',
            'impact': 'Complete account takeover with privilege escalation'
        },
        'xss_to_session_hijack': {
            'steps': [
                ('stored_xss', 'Inject persistent payload'),
                ('cookie_theft', 'Steal session tokens'),
                ('csrf', 'Perform privileged actions')
            ],
            'severity': 'high',
            'impact': 'Account takeover of any user'
        },
        'open_redirect_to_oauth_bypass': {
            'steps': [
                ('open_redirect', 'Redirect to attacker domain'),
                ('oauth_misconfig', 'Steal OAuth tokens'),
                ('token_replay', 'Account access')
            ],
            'severity': 'high',
            'impact': 'OAuth flow compromise'
        }
    }
    
    def detect_chains(self, scan_id, findings_db):
        """
        Analyze all findings to detect multi-step attack chains
        """
        chains_detected = []
        
        for chain_name, chain_config in self.ATTACK_CHAINS.items():
            if self._can_execute_chain(scan_id, chain_config['steps'], findings_db):
                chain_poc = self._generate_chain_poc(chain_config)
                chains_detected.append({
                    'name': chain_name,
                    'severity': chain_config['severity'],
                    'impact': chain_config['impact'],
                    'steps': chain_config['steps'],
                    'poc': chain_poc,
                    'confidence': self._calculate_chain_confidence(chain_config['steps'], findings_db)
                })
        
        return chains_detected
    
    def _can_execute_chain(self, scan_id, required_steps, findings_db):
        """Check if all prerequisite vulnerabilities exist"""
        found_steps = set()
        
        for vuln_type, description in required_steps:
            if self._vulnerability_exists(scan_id, vuln_type, findings_db):
                found_steps.add(vuln_type)
        
        return len(found_steps) >= len(required_steps) * 0.8  # 80% match threshold