import time
import json
import re
from urllib.parse import urlparse, urljoin, urlunparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service

class AjaxSpider:
    """
    AJAX-aware spider for JavaScript-heavy applications
    Uses headless Chrome to render and interact with dynamic content
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
        self.driver = None
        self.visited_urls = set()
        self.discovered_endpoints = set()
        self.ajax_calls = set()
        
    def setup_driver(self, headless=True):
        """Initialize headless Chrome WebDriver"""
        try:
            chrome_options = Options()
            if headless:
                chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-images')
            chrome_options.add_argument('--disable-javascript')  # We'll enable it selectively
            chrome_options.add_argument('--user-agent=CyberSage/2.0 (Security Scanner)')
            
            # Enable network monitoring
            chrome_options.add_argument('--enable-logging')
            chrome_options.add_argument('--log-level=0')
            
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Enable JavaScript for dynamic content
            self.driver.execute_script("return navigator.userAgent")
            
            # Set up network monitoring
            self.driver.execute_cdp_cmd('Network.enable', {})
            self.driver.execute_cdp_cmd('Runtime.enable', {})
            
            return True
        except Exception as e:
            print(f"[AjaxSpider] Failed to setup driver: {str(e)}")
            return False
    
    def crawl_ajax_aware(self, scan_id, target, max_depth=3, max_pages=50):
        """
        AJAX-aware crawling with DOM interaction
        """
        if not self.setup_driver():
            return []
        
        try:
            self.broadcaster.broadcast_tool_started(scan_id, 'AJAX Spider', target)
            
            # Start with target URL
            self._crawl_page(scan_id, target, depth=0, max_depth=max_depth)
            
            # Process discovered endpoints
            endpoints = list(self.discovered_endpoints)
            
            # Log findings
            self.db.log_tool_run(
                scan_id, 'AJAX Spider', target, 'completed', 
                f"Discovered {len(endpoints)} endpoints", '', len(endpoints)
            )
            
            self.broadcaster.broadcast_tool_completed(scan_id, 'AJAX Spider', 'success', len(endpoints))
            
            return endpoints[:200]  # Limit to 200 endpoints
            
        except Exception as e:
            print(f"[AjaxSpider] Error during crawling: {str(e)}")
            self.broadcaster.broadcast_tool_completed(scan_id, 'AJAX Spider', 'error', 0)
            return []
        finally:
            if self.driver:
                self.driver.quit()
    
    def _crawl_page(self, scan_id, url, depth=0, max_depth=3):
        """Crawl a single page with AJAX awareness"""
        if depth > max_depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            print(f"[AjaxSpider] Crawling: {url} (depth: {depth})")
            
            # Navigate to page
            self.driver.get(url)
            
            # Wait for initial page load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Wait for AJAX calls to complete
            self._wait_for_ajax_completion()
            
            # Extract static links
            static_links = self._extract_static_links(url)
            self.discovered_endpoints.update(static_links)
            
            # Extract dynamic links from JavaScript
            dynamic_links = self._extract_dynamic_links()
            self.discovered_endpoints.update(dynamic_links)
            
            # Interact with forms and buttons
            self._interact_with_forms()
            self._interact_with_buttons()
            
            # Monitor for new AJAX calls
            self._monitor_ajax_calls()
            
            # Extract API endpoints from network traffic
            api_endpoints = self._extract_api_endpoints()
            self.discovered_endpoints.update(api_endpoints)
            
            # Recursively crawl discovered links
            for link in list(static_links)[:10]:  # Limit recursion
                if depth < max_depth:
                    self._crawl_page(scan_id, link, depth + 1, max_depth)
                    
        except Exception as e:
            print(f"[AjaxSpider] Error crawling {url}: {str(e)}")
    
    def _wait_for_ajax_completion(self, timeout=10):
        """Wait for AJAX calls to complete"""
        try:
            # Wait for jQuery AJAX to complete
            WebDriverWait(self.driver, timeout).until(
                lambda driver: driver.execute_script("return jQuery.active == 0")
            )
        except TimeoutException:
            pass
        
        # Additional wait for other AJAX frameworks
        time.sleep(2)
    
    def _extract_static_links(self, base_url):
        """Extract links from static HTML"""
        links = set()
        
        try:
            # Find all href attributes
            elements = self.driver.find_elements(By.XPATH, "//a[@href]")
            for element in elements:
                href = element.get_attribute('href')
                if href:
                    full_url = self._normalize_url(base_url, href)
                    if full_url:
                        links.add(full_url)
            
            # Find form actions
            forms = self.driver.find_elements(By.XPATH, "//form[@action]")
            for form in forms:
                action = form.get_attribute('action')
                if action:
                    full_url = self._normalize_url(base_url, action)
                    if full_url:
                        links.add(full_url)
                        
        except Exception as e:
            print(f"[AjaxSpider] Error extracting static links: {str(e)}")
        
        return links
    
    def _extract_dynamic_links(self):
        """Extract links from JavaScript execution"""
        links = set()
        
        try:
            # Execute JavaScript to find dynamically generated links
            js_code = """
            var links = [];
            var elements = document.querySelectorAll('a[href], form[action]');
            for (var i = 0; i < elements.length; i++) {
                var href = elements[i].href || elements[i].action;
                if (href) links.push(href);
            }
            return links;
            """
            
            dynamic_links = self.driver.execute_script(js_code)
            for link in dynamic_links:
                if link and isinstance(link, str):
                    links.add(link)
                    
        except Exception as e:
            print(f"[AjaxSpider] Error extracting dynamic links: {str(e)}")
        
        return links
    
    def _interact_with_forms(self):
        """Interact with forms to trigger AJAX calls"""
        try:
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            
            for form in forms:
                try:
                    # Find input fields
                    inputs = form.find_elements(By.XPATH, ".//input[@type='text'], .//input[@type='email'], .//input[@type='search']")
                    
                    # Fill form with benign data
                    for input_field in inputs[:3]:  # Limit to first 3 inputs
                        try:
                            input_field.clear()
                            input_field.send_keys("test")
                        except:
                            pass
                    
                    # Find and click submit buttons
                    submit_buttons = form.find_elements(By.XPATH, ".//input[@type='submit'], .//button[@type='submit']")
                    for button in submit_buttons[:1]:  # Only click first submit button
                        try:
                            button.click()
                            time.sleep(2)  # Wait for AJAX response
                        except:
                            pass
                            
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"[AjaxSpider] Error interacting with forms: {str(e)}")
    
    def _interact_with_buttons(self):
        """Interact with buttons that might trigger AJAX calls"""
        try:
            # Find clickable buttons and links
            buttons = self.driver.find_elements(By.XPATH, "//button[contains(@class, 'ajax') or contains(@onclick, 'ajax') or contains(@onclick, 'fetch')]")
            links = self.driver.find_elements(By.XPATH, "//a[contains(@class, 'ajax') or contains(@onclick, 'ajax')]")
            
            clickable_elements = buttons + links
            
            for element in clickable_elements[:5]:  # Limit to first 5 elements
                try:
                    # Scroll element into view
                    self.driver.execute_script("arguments[0].scrollIntoView(true);", element)
                    time.sleep(0.5)
                    
                    # Click element
                    element.click()
                    time.sleep(2)  # Wait for AJAX response
                    
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"[AjaxSpider] Error interacting with buttons: {str(e)}")
    
    def _monitor_ajax_calls(self):
        """Monitor network traffic for AJAX calls"""
        try:
            # Get network logs
            logs = self.driver.get_log('performance')
            
            for log in logs:
                message = json.loads(log['message'])
                
                if message['message']['method'] == 'Network.responseReceived':
                    response = message['message']['params']['response']
                    url = response.get('url', '')
                    
                    if url and self._is_ajax_endpoint(url):
                        self.ajax_calls.add(url)
                        
        except Exception as e:
            print(f"[AjaxSpider] Error monitoring AJAX calls: {str(e)}")
    
    def _extract_api_endpoints(self):
        """Extract API endpoints from network traffic"""
        endpoints = set()
        
        try:
            # Get all network requests
            logs = self.driver.get_log('performance')
            
            for log in logs:
                message = json.loads(log['message'])
                
                if message['message']['method'] == 'Network.requestWillBeSent':
                    request = message['message']['params']['request']
                    url = request.get('url', '')
                    method = request.get('method', '')
                    
                    if self._is_api_endpoint(url, method):
                        endpoints.add(url)
                        
        except Exception as e:
            print(f"[AjaxSpider] Error extracting API endpoints: {str(e)}")
        
        return endpoints
    
    def _is_ajax_endpoint(self, url):
        """Check if URL is likely an AJAX endpoint"""
        ajax_indicators = [
            'ajax', 'api', 'json', 'xml', 'fetch', 'xhr',
            '.php', '.asp', '.jsp', '.aspx'
        ]
        
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in ajax_indicators)
    
    def _is_api_endpoint(self, url, method):
        """Check if URL is an API endpoint"""
        api_indicators = [
            '/api/', '/rest/', '/graphql', '/v1/', '/v2/',
            'application/json', 'application/xml'
        ]
        
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in api_indicators)
    
    def _normalize_url(self, base_url, url):
        """Normalize URL to absolute form"""
        try:
            if url.startswith('http'):
                return url
            elif url.startswith('/'):
                parsed_base = urlparse(base_url)
                return f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
            else:
                return urljoin(base_url, url)
        except:
            return None

