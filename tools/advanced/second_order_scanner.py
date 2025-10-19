# tools/advanced/second_order_scanner.py
class SecondOrderScanner:
    """
    Detect vulnerabilities that trigger in different contexts
    """
    
    def scan_second_order(self, target_info, db_conn):
        findings = []
        
        # 1. Store payloads in all input points
        payload_map = self._inject_tracking_payloads(target_info)
        
        # 2. Navigate application to trigger payloads
        triggered_payloads = self._crawl_and_detect_triggers(target_info, payload_map)
        
        # 3. Analyze where payloads executed
        for payload_id, trigger_location in triggered_payloads.items():
            original_injection = payload_map[payload_id]
            
            findings.append({
                'type': 'second_order_vulnerability',
                'severity': self._calculate_second_order_severity(original_injection, trigger_location),
                'injection_point': original_injection['endpoint'],
                'trigger_point': trigger_location['endpoint'],
                'payload': original_injection['payload'],
                'description': f"Payload injected at {original_injection['endpoint']} executed at {trigger_location['endpoint']}",
                'poc': self._generate_second_order_poc(original_injection, trigger_location)
            })
        
        return findings
    
    def _inject_tracking_payloads(self, target_info):
        """
        Inject unique tracking payloads across the application
        """
        payload_map = {}
        
        # Generate unique payloads for different contexts
        contexts = {
            'xss': lambda id: f'<img src=x onerror=alert("CS2-{id}")>',
            'sqli': lambda id: f"' OR '1'='1' -- CS2-{id}",
            'ssti': lambda id: f"{{{{7*7}}}}-CS2-{id}",
            'command': lambda id: f"; whoami # CS2-{id}"
        }
        
        for endpoint in target_info.get('input_endpoints', []):
            for ctx_name, payload_gen in contexts.items():
                payload_id = f"{ctx_name}_{endpoint['id']}_{random_id()}"
                payload = payload_gen(payload_id)
                
                # Inject payload
                self._inject_payload(endpoint, payload)
                
                payload_map[payload_id] = {
                    'endpoint': endpoint['url'],
                    'parameter': endpoint['parameter'],
                    'payload': payload,
                    'context': ctx_name
                }
        
        return payload_map