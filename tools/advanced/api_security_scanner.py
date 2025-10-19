# tools/advanced/api_security_scanner.py
class AdvancedAPIScanner:
    """
    Deep API security testing beyond basic fuzzing
    """
    
    def scan_api_vulnerabilities(self, api_endpoints):
        findings = []
        
        # 1. BOLA/IDOR at scale
        findings.extend(self._test_bola_advanced(api_endpoints))
        
        # 2. Mass Assignment
        findings.extend(self._test_mass_assignment(api_endpoints))
        
        # 3. GraphQL specific (if detected)
        if self._is_graphql_api(api_endpoints):
            findings.extend(self._test_graphql_vulnerabilities(api_endpoints))
        
        # 4. API Rate Limit Bypass
        findings.extend(self._test_rate_limit_bypass(api_endpoints))
        
        # 5. JWT/Token Vulnerabilities
        findings.extend(self._test_token_vulnerabilities(api_endpoints))
        
        # 6. API Versioning Issues
        findings.extend(self._test_api_versioning_bypass(api_endpoints))
        
        return findings
    
    def _test_bola_advanced(self, endpoints):
        """
        Advanced BOLA testing:
        - Test with different auth contexts
        - Test predictable vs unpredictable IDs
        - Test with modified IDs (base64, hex, UUID)
        """
        findings = []
        
        # Find endpoints with ID parameters
        id_endpoints = [ep for ep in endpoints if self._has_id_parameter(ep)]
        
        for endpoint in id_endpoints:
            # Create two test accounts
            user1_token = self._create_test_account()
            user2_token = self._create_test_account()
            
            # Get user1's resources
            user1_resources = self._fetch_resources(endpoint, user1_token)
            
            # Try accessing user1's resources with user2's token
            for resource_id in user1_resources:
                response = self._access_resource(endpoint, resource_id, user2_token)
                
                if response.status_code == 200:
                    findings.append({
                        'type': 'bola_idor',
                        'severity': 'critical',
                        'endpoint': endpoint,
                        'description': 'Broken Object Level Authorization - users can access other users\' data',
                        'poc': self._generate_bola_poc(endpoint, resource_id, user1_token, user2_token)
                    })
        
        return findings
    
    def _test_mass_assignment(self, endpoints):
        """
        Test for mass assignment vulnerabilities:
        - Add admin/role parameters
        - Modify price/credit parameters
        - Add hidden fields
        """
        findings = []
        
        for endpoint in endpoints:
            if endpoint['method'] in ['POST', 'PUT', 'PATCH']:
                # Get legitimate parameters
                legit_params = endpoint.get('parameters', {})
                
                # Test with additional privilege escalation parameters
                test_params = {
                    **legit_params,
                    'isAdmin': True,
                    'role': 'admin',
                    'is_verified': True,
                    'credits': 999999,
                    'price': 0.01,
                    'discount': 100
                }
                
                response = self._send_request(endpoint, test_params)
                
                # Check if parameters were accepted
                if self._verify_mass_assignment_success(response, test_params):
                    findings.append({
                        'type': 'mass_assignment',
                        'severity': 'critical',
                        'endpoint': endpoint['url'],
                        'affected_parameters': self._get_accepted_params(response, test_params),
                        'poc': self._generate_mass_assignment_poc(endpoint, test_params)
                    })
        
        return findings
    
    def _test_graphql_vulnerabilities(self, endpoints):
        """
        GraphQL-specific vulnerabilities:
        - Introspection enabled
        - Batch query attacks
        - Circular query DoS
        - Authorization bypass via aliases
        """
        findings = []
        graphql_endpoint = self._find_graphql_endpoint(endpoints)
        
        if not graphql_endpoint:
            return findings
        
        # Test introspection
        introspection_data = self._test_graphql_introspection(graphql_endpoint)
        if introspection_data:
            findings.append({
                'type': 'graphql_introspection',
                'severity': 'medium',
                'description': 'GraphQL introspection is enabled, exposing full schema',
                'schema_queries': len(introspection_data.get('queries', [])),
                'schema_mutations': len(introspection_data.get('mutations', []))
            })
            
            # Use schema to test authorization on each field
            findings.extend(self._test_graphql_field_authorization(graphql_endpoint, introspection_data))
        
        # Test batch attacks
        findings.extend(self._test_graphql_batch_attacks(graphql_endpoint))
        
        return findings