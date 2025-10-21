import time
from tools.recon import ReconEngine
from tools.vuln_scanner import VulnerabilityScanner
from tools.advanced.chain_detector import ChainDetector
from tools.advanced.business_logic import BusinessLogicScanner
from tools.advanced.api_security import APISecurityScanner
from tools.advanced.ai_analyzer import AIAnalyzer
from tools.nmap_scanner import NmapScanner

class ScanOrchestrator:
    """
    Orchestrates the complete security scan workflow
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
        
        # Initialize scan engines
        self.recon = ReconEngine(database, broadcaster)
        self.vuln_scanner = VulnerabilityScanner(database, broadcaster)
        self.chain_detector = ChainDetector(database, broadcaster)
        self.business_logic = BusinessLogicScanner(database, broadcaster)
        self.api_security = APISecurityScanner(database, broadcaster)
        self.ai_analyzer = AIAnalyzer(database, broadcaster)
        self.nmap = NmapScanner(database, broadcaster)
    
    def execute_elite_scan(self, scan_id, target, scan_mode='elite'):
        """
        Execute comprehensive elite-level security scan
        """
        print(f"\n{'='*60}")
        print(f"🧠 Starting Elite Scan: {scan_id}")
        print(f"🎯 Target: {target}")
        print(f"⚙️  Mode: {scan_mode}")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        all_vulnerabilities = []
        all_chains = []
        
        try:
            # Phase 1: Deep Reconnaissance & Blueprinting (0-20%)
            self.broadcaster.broadcast_scan_progress(scan_id, 3, "🔍 Initiating Recon & Blueprinting")
            recon_data = self.recon.deep_reconnaissance(scan_id, target)
            try:
                # Persist blueprint and OSINT
                osint = {
                    'subdomains': recon_data.get('subdomains', []),
                    'live_hosts': recon_data.get('live_hosts', []),
                    'technologies': recon_data.get('technologies', []),
                    'api_definitions': recon_data.get('api_definitions', [])
                }
                self.db.set_recon_blueprint(scan_id, recon_data.get('blueprint', {}), osint)
            except Exception:
                pass

            # Run Nmap discovery (low impact network mapping)
            self.broadcaster.broadcast_scan_progress(scan_id, 12, "🌐 Network Discovery (Nmap)")
            nmap_findings = self.nmap.scan_target(scan_id, target, intensity='normal')
            for nf in nmap_findings:
                self.broadcaster.broadcast_vulnerability_found(scan_id, nf)
                self.db.add_vulnerability(scan_id, nf)

            self.broadcaster.broadcast_scan_progress(scan_id, 20, "✓ Reconnaissance Complete")
            self.broadcaster.broadcast_phase_complete(scan_id, "Reconnaissance", {
                'subdomains': len(recon_data.get('subdomains', [])),
                'live_hosts': len(recon_data.get('live_hosts', [])),
                'technologies': len(recon_data.get('technologies', []))
            })
            
            # Phase 2: Vulnerability Scanning (20-50%)
            self.broadcaster.broadcast_scan_progress(scan_id, 25, "🔥 Initiating Vulnerability Scans")
            vulns = self.vuln_scanner.comprehensive_scan(scan_id, recon_data)
            all_vulnerabilities.extend(vulns)
            self.broadcaster.broadcast_scan_progress(scan_id, 50, "✓ Vulnerability Scanning Complete")
            
            # Phase 3: Advanced Detection (50-70%)
            if scan_mode == 'elite':
                # Business Logic Testing
                self.broadcaster.broadcast_scan_progress(scan_id, 55, "🧩 Analyzing Business Logic")
                business_vulns = self.business_logic.scan(scan_id, recon_data)
                all_vulnerabilities.extend(business_vulns)
                
                # API Security Testing
                if recon_data.get('has_api'):
                    self.broadcaster.broadcast_scan_progress(scan_id, 60, "🔌 Testing API Security")
                    api_vulns = self.api_security.scan(scan_id, recon_data)
                    all_vulnerabilities.extend(api_vulns)
                
                self.broadcaster.broadcast_scan_progress(scan_id, 70, "✓ Advanced Detection Complete")
            
            # Phase 4: Chain Detection (70-85%)
            self.broadcaster.broadcast_scan_progress(scan_id, 75, "⛓️  Detecting Attack Chains")
            chains = self.chain_detector.detect_chains(scan_id, all_vulnerabilities, recon_data)
            all_chains.extend(chains)
            
            for chain in chains:
                self.broadcaster.broadcast_chain_detected(scan_id, chain)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 85, "✓ Chain Analysis Complete")
            
            # Phase 5: AI Analysis (85-95%)
            if scan_mode == 'elite':
                self.broadcaster.broadcast_scan_progress(scan_id, 90, "🤖 AI Deep Analysis")
                ai_insights = self.ai_analyzer.analyze(scan_id, {
                    'vulnerabilities': all_vulnerabilities,
                    'chains': all_chains,
                    'recon_data': recon_data
                })
                
                for insight in ai_insights:
                    self.broadcaster.broadcast_ai_insight(scan_id, insight)
                
                self.broadcaster.broadcast_scan_progress(scan_id, 95, "✓ AI Analysis Complete")
            
            # Phase 6: Finalization (95-100%)
            self.broadcaster.broadcast_scan_progress(scan_id, 98, "📊 Generating Final Report")
            
            # Calculate final statistics
            stats = self._calculate_final_stats(all_vulnerabilities, all_chains)
            
            self.broadcaster.broadcast_scan_progress(scan_id, 100, "✅ Scan Complete")
            
            elapsed_time = time.time() - start_time
            
            print(f"\n{'='*60}")
            print(f"✅ Scan Complete: {scan_id}")
            print(f"⏱️  Duration: {elapsed_time:.2f}s")
            print(f"🔍 Vulnerabilities Found: {len(all_vulnerabilities)}")
            print(f"⛓️  Attack Chains: {len(all_chains)}")
            print(f"{'='*60}\n")
            
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'duration': elapsed_time,
                'vulnerabilities_count': len(all_vulnerabilities),
                'chains_count': len(all_chains),
                'stats': stats
            }
            
        except Exception as e:
            print(f"[ERROR] Scan failed: {str(e)}")
            import traceback
            traceback.print_exc()
            raise e
    
    def _calculate_final_stats(self, vulnerabilities, chains):
        """Calculate final scan statistics"""
        stats = {
            'total': len(vulnerabilities),
            'critical': len([v for v in vulnerabilities if v.get('severity') == 'critical']),
            'high': len([v for v in vulnerabilities if v.get('severity') == 'high']),
            'medium': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
            'low': len([v for v in vulnerabilities if v.get('severity') == 'low']),
            'chains': len(chains),
            'avg_confidence': sum([v.get('confidence', 50) for v in vulnerabilities]) / len(vulnerabilities) if vulnerabilities else 0
        }
        return stats