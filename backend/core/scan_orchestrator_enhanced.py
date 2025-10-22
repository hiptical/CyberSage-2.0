# backend/core/scan_orchestrator_enhanced.py
"""
Enhanced Scan Orchestrator
Integrates custom scanners with professional security tools
"""

import time
from tools.recon import ReconEngine
from tools.vuln_scanner import VulnerabilityScanner
from tools.advanced.chain_detector import ChainDetector
from tools.advanced.business_logic import BusinessLogicScanner
from tools.advanced.api_security import APISecurityScanner
from tools.advanced.ai_analyzer import AIAnalyzer
from tools.ajax_spider import AjaxSpider
from tools.professional_tools import ProfessionalToolsIntegration

class EnhancedScanOrchestrator:
    """
    Orchestrates comprehensive security scans using both custom and professional tools
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
        
        # Initialize custom scan engines
        self.recon = ReconEngine(database, broadcaster)
        self.vuln_scanner = VulnerabilityScanner(database, broadcaster)
        self.chain_detector = ChainDetector(database, broadcaster)
        self.business_logic = BusinessLogicScanner(database, broadcaster)
        self.api_security = APISecurityScanner(database, broadcaster)
        self.ai_analyzer = AIAnalyzer(database, broadcaster)
        self.ajax_spider = AjaxSpider(database, broadcaster)
        
        # Initialize professional tools integration
        self.pro_tools = ProfessionalToolsIntegration(database, broadcaster)
    
    def execute_comprehensive_scan(self, scan_id, target, scan_mode='comprehensive', options=None):
        """
        Execute comprehensive elite-level security scan with professional tools
        """
        print(f"\n{'='*80}")
        print(f"🧠 Starting Comprehensive Professional Scan: {scan_id}")
        print(f"🎯 Target: {target}")
        print(f"⚙️  Mode: {scan_mode}")
        print(f"{'='*80}\n")
        
        start_time = time.time()
        all_vulnerabilities = []
        all_chains = []
        
        options = options or {}
        tools_config = options.get('tools', {})
        
        try:
            # ========================================================================
            # PHASE 3: VULNERABILITY SCANNING (35-65%)
            # ========================================================================
            self.broadcaster.broadcast_scan_progress(scan_id, 37, "⚠️ Phase 3: Vulnerability Detection")
            
            # Custom Vulnerability Scanners
            self.broadcaster.broadcast_scan_progress(scan_id, 40, "🔥 Custom Vulnerability Scanning")
            custom_vulns = self.vuln_scanner.comprehensive_scan(scan_id, recon_data)
            all_vulnerabilities.extend(custom_vulns)
            
            # Professional Vulnerability Tools
            self.broadcaster.broadcast_scan_progress(scan_id, 45, "💉 Running SQLMap")
            if tools_config.get('sqlmap', True):
                sqlmap_findings = self.pro_tools.run_sqlmap(scan_id, target)
                all_vulnerabilities.extend(sqlmap_findings)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 50, "🕸️ Running Nikto")
            if tools_config.get('nikto', True):
                nikto_findings = self.pro_tools.run_nikto(scan_id, target)
                all_vulnerabilities.extend(nikto_findings)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 55, "🔌 Running WPScan")
            if tools_config.get('wpscan', True):
                wpscan_findings = self.pro_tools.run_wpscan(scan_id, target)
                all_vulnerabilities.extend(wpscan_findings)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 60, "🎯 Running Nuclei")
            if tools_config.get('nuclei', True):
                nuclei_findings = self.pro_tools.run_nuclei(scan_id, target)
                all_vulnerabilities.extend(nuclei_findings)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 65, "✓ Phase 3 Complete")
            self.broadcaster.broadcast_phase_complete(scan_id, "Vulnerability Scanning", {
                'vulnerabilities_found': len(all_vulnerabilities),
                'critical': len([v for v in all_vulnerabilities if v.get('severity') == 'critical']),
                'high': len([v for v in all_vulnerabilities if v.get('severity') == 'high'])
            })
            
            # ========================================================================
            # PHASE 4: ADVANCED DETECTION (65-80%)
            # ========================================================================
            self.broadcaster.broadcast_scan_progress(scan_id, 67, "🧩 Phase 4: Advanced Analysis")
            
            # Business Logic Testing
            self.broadcaster.broadcast_scan_progress(scan_id, 70, "💼 Business Logic Analysis")
            business_vulns = self.business_logic.scan(scan_id, recon_data)
            all_vulnerabilities.extend(business_vulns)
            
            # API Security Testing
            if recon_data.get('has_api'):
                self.broadcaster.broadcast_scan_progress(scan_id, 73, "🔌 API Security Testing")
                api_vulns = self.api_security.scan(scan_id, recon_data)
                all_vulnerabilities.extend(api_vulns)
            
            # Attack Chain Detection
            self.broadcaster.broadcast_scan_progress(scan_id, 76, "⛓️ Detecting Attack Chains")
            chains = self.chain_detector.detect_chains(scan_id, all_vulnerabilities, recon_data)
            all_chains.extend(chains)
            
            for chain in chains:
                self.broadcaster.broadcast_chain_detected(scan_id, chain)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 80, "✓ Phase 4 Complete")
            self.broadcaster.broadcast_phase_complete(scan_id, "Advanced Detection", {
                'business_logic_issues': len(business_vulns),
                'attack_chains': len(chains)
            })
            
            # ========================================================================
            # PHASE 5: AI ANALYSIS (80-95%)
            # ========================================================================
            if scan_mode in ['comprehensive', 'elite']:
                self.broadcaster.broadcast_scan_progress(scan_id, 85, "🤖 Phase 5: AI Analysis")
                
                ai_insights = self.ai_analyzer.analyze(scan_id, {
                    'vulnerabilities': all_vulnerabilities,
                    'chains': all_chains,
                    'recon_data': recon_data
                })
                
                for insight in ai_insights:
                    self.broadcaster.broadcast_ai_insight(scan_id, insight)
                
                self.broadcaster.broadcast_scan_progress(scan_id, 95, "✓ Phase 5 Complete")
            
            # ========================================================================
            # PHASE 6: FINALIZATION (95-100%)
            # ========================================================================
            self.broadcaster.broadcast_scan_progress(scan_id, 97, "📊 Generating Final Report")
            
            # Broadcast all findings
            for vuln in all_vulnerabilities:
                self.broadcaster.broadcast_vulnerability_found(scan_id, vuln)
                self.db.add_vulnerability(scan_id, vuln)
            
            # Calculate statistics
            stats = self._calculate_comprehensive_stats(all_vulnerabilities, all_chains)
            self.db.update_scan_statistics(scan_id, **stats)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 100, "✅ Scan Complete")
            
            elapsed_time = time.time() - start_time
            
            print(f"\n{'='*80}")
            print(f"✅ Comprehensive Scan Complete: {scan_id}")
            print(f"⏱️  Duration: {elapsed_time:.2f}s")
            print(f"🔍 Total Vulnerabilities: {len(all_vulnerabilities)}")
            print(f"   - Critical: {stats['critical']}")
            print(f"   - High: {stats['high']}")
            print(f"   - Medium: {stats['medium']}")
            print(f"   - Low: {stats['low']}")
            print(f"⛓️  Attack Chains: {len(all_chains)}")
            print(f"🛠️  Professional Tools Used: {sum(tools_config.values())}")
            print(f"{'='*80}\n")
            
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'duration': elapsed_time,
                'vulnerabilities_count': len(all_vulnerabilities),
                'chains_count': len(all_chains),
                'stats': stats,
                'tools_used': [k for k, v in tools_config.items() if v]
            }
            
        except Exception as e:
            print(f"[ERROR] Scan failed: {str(e)}")
            import traceback
            traceback.print_exc()
            
            self.db.update_scan_status(scan_id, 'failed', str(e))
            self.broadcaster.broadcast_event('scan_error', {
                'scan_id': scan_id,
                'error': str(e)
            })
            raise e
    
    def _calculate_comprehensive_stats(self, vulnerabilities, chains):
        """Calculate comprehensive scan statistics"""
        stats = {
            'total': len(vulnerabilities),
            'critical': len([v for v in vulnerabilities if v.get('severity') == 'critical']),
            'high': len([v for v in vulnerabilities if v.get('severity') == 'high']),
            'medium': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
            'low': len([v for v in vulnerabilities if v.get('severity') == 'low']),
            'chains': len(chains),
            'avg_confidence': sum([v.get('confidence', 50) for v in vulnerabilities]) / len(vulnerabilities) if vulnerabilities else 0,
            'vulnerabilities_found': len(vulnerabilities),
            'endpoints_discovered': 0,  # Will be updated by recon
            'parameters_tested': 0,  # Will be updated by scanners
            'payloads_sent': 0  # Will be updated by scanners
        }
        
        # Count tools used
        tools_used = set([v.get('tool') for v in vulnerabilities if v.get('tool')])
        stats['tools_used'] = len(tools_used)
        
        # Calculate risk score (0-100)
        risk_score = 0
        risk_score += stats['critical'] * 10
        risk_score += stats['high'] * 7
        risk_score += stats['medium'] * 4
        risk_score += stats['low'] * 1
        risk_score += len(chains) * 15
        stats['risk_score'] = min(100, risk_score)
        
        return stats PHASE 1: RECONNAISSANCE (0-15%)
            # ========================================================================
            self.broadcaster.broadcast_scan_progress(scan_id, 2, "🔍 Phase 1: Reconnaissance")
            
            # Professional Recon Tools
            self.broadcaster.broadcast_scan_progress(scan_id, 5, "🌐 Running Nmap Discovery")
            if tools_config.get('nmap', True):
                nmap_findings = self.pro_tools.run_nmap_comprehensive(scan_id, target)
                all_vulnerabilities.extend(nmap_findings)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 7, "📧 Running theHarvester")
            if tools_config.get('theHarvester', True):
                harvest_findings = self.pro_tools.run_theharvester(scan_id, target)
                all_vulnerabilities.extend(harvest_findings)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 9, "🔎 Running Amass")
            if tools_config.get('amass', True):
                amass_findings = self.pro_tools.run_amass(scan_id, target)
                all_vulnerabilities.extend(amass_findings)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 11, "📋 Running WHOIS Lookup")
            if tools_config.get('whois', True):
                whois_findings = self.pro_tools.run_whois(scan_id, target)
                all_vulnerabilities.extend(whois_findings)
            
            # Custom Recon
            self.broadcaster.broadcast_scan_progress(scan_id, 13, "🎯 Deep Reconnaissance")
            recon_data = self.recon.deep_reconnaissance(scan_id, target)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 15, "✓ Phase 1 Complete")
            self.broadcaster.broadcast_phase_complete(scan_id, "Reconnaissance", {
                'subdomains': len(recon_data.get('subdomains', [])),
                'technologies': len(recon_data.get('technologies', [])),
                'nmap_findings': len([v for v in all_vulnerabilities if v.get('tool') == 'nmap'])
            })
            
            # ========================================================================
            # PHASE 2: ENUMERATION (15-35%)
            # ========================================================================
            self.broadcaster.broadcast_scan_progress(scan_id, 17, "🔢 Phase 2: Enumeration")
            
            # Professional Enumeration Tools
            self.broadcaster.broadcast_scan_progress(scan_id, 20, "🔍 Running Ffuf Directory Fuzzing")
            if tools_config.get('ffuf', True):
                ffuf_findings = self.pro_tools.run_ffuf(scan_id, target)
                all_vulnerabilities.extend(ffuf_findings)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 25, "📂 Running Gobuster")
            if tools_config.get('gobuster', True):
                gobuster_findings = self.pro_tools.run_gobuster(scan_id, target)
                all_vulnerabilities.extend(gobuster_findings)
            
            # AJAX Spider for JavaScript Apps
            self.broadcaster.broadcast_scan_progress(scan_id, 30, "🤖 AJAX Spider Crawling")
            ajax_endpoints = self.ajax_spider.crawl_ajax_aware(scan_id, target, max_depth=2, max_pages=30)
            recon_data['endpoints'].extend(ajax_endpoints)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 35, "✓ Phase 2 Complete")
            self.broadcaster.broadcast_phase_complete(scan_id, "Enumeration", {
                'endpoints_discovered': len(recon_data.get('endpoints', [])),
                'directories_found': len([v for v in all_vulnerabilities if 'Enumeration' in v.get('type', '')])
            })
            
            # ========================================================================
            #