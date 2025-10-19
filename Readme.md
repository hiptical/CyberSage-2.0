# 🧠 CyberSage v2.0 - Elite Vulnerability Intelligence Platform

> **Advanced Security Scanning with AI-Powered Analysis**  


---

## 🎯 Features

### Core Capabilities
- ✅ **Real-Time Web Dashboard** - Live vulnerability feed with WebSocket updates
- ✅ **Advanced Vulnerability Detection** - XSS, SQLi, IDOR, SSRF, and more
- ✅ **Attack Chain Detection** - Identifies multi-step exploitation paths
- ✅ **Business Logic Scanner** - Race conditions, price manipulation, auth bypass
- ✅ **API Security Testing** - REST, GraphQL, rate limiting, mass assignment
- ✅ **AI-Powered Analysis** - Smart insights and recommendations
- ✅ **Elite Scanning Modes** - Quick, Standard, and Elite (with AI)

### Technical Highlights
- 🔥 **WebSocket-Based Real-Time Updates**
- 🧩 **Modular Architecture** - Easy to extend with new scanners
- 🎨 **Beautiful UI** - Smooth animations and modern design
- 📊 **Comprehensive Reporting** - Severity analysis, confidence scoring
- 🤖 **AI Integration** - OpenRouter API for advanced analysis

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 14+
- pip & npm

### Installation

```bash
# Clone or extract the project
cd CyberSage-2.0

# Run setup script (Linux/Mac)
chmod +x setup.sh
./setup.sh
```

# Or manual setup:

```
# Backend
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install
```

### Running

**Option 1: Use the start script (recommended)**
```bash
./start.sh
```

**Option 2: Start components separately**

Terminal 1 (Backend):
```bash
cd backend
source venv/bin/activate
python app.py
```

Terminal 2 (Frontend):
```bash
cd frontend
npm start
```

**Access the application:**
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000

---

## 📖 Usage Guide

### 1. Starting a Scan

1. Enter target URL or domain (e.g., `https://example.com` or `example.com`)
2. Select scan mode:
   - **⚡ Quick**: ~5 mins - Basic vulnerabilities
   - **🔍 Standard**: ~15 mins - Comprehensive scan
   - **🧠 Elite**: ~30 mins - Advanced + AI analysis
3. Click "🚀 Start Elite Scan"

### 2. Monitoring Progress

Watch real-time updates:
- **Progress Bar**: Current phase and percentage
- **Tool Activity**: Which scanners are running
- **Vulnerability Feed**: Live findings as they're discovered
- **Attack Chains**: Critical multi-step vulnerabilities

### 3. Understanding Results

**Severity Levels:**
- 🔴 **Critical**: Immediate action required (RCE, SQLi, Auth bypass)
- 🟠 **High**: Serious vulnerabilities (XSS, IDOR, sensitive data exposure)
- 🟡 **Medium**: Important issues (Missing headers, CORS misconfig)
- 🟢 **Low**: Minor issues (Info disclosure, best practices)

**Confidence Score:**
- 90-100%: Very high confidence, verified
- 70-89%: High confidence, likely true
- 50-69%: Medium confidence, needs review
- <50%: Low confidence, possible false positive

---

## 🏗️ Architecture

```
CyberSage-2.0/
├── backend/
│   ├── app.py                 # Main Flask + SocketIO server
│   ├── core/
│   │   ├── database.py        # SQLite database operations
│   │   ├── scan_orchestrator.py  # Main scan coordinator
│   │   └── realtime_broadcaster.py  # WebSocket events
│   ├── tools/
│   │   ├── recon.py          # Reconnaissance engine
│   │   ├── vuln_scanner.py   # Core vulnerability scanner
│   │   └── advanced/
│   │       ├── chain_detector.py     # Attack chain detection
│   │       ├── business_logic.py     # Business logic scanner
│   │       ├── api_security.py       # API security testing
│   │       └── ai_analyzer.py        # AI-powered analysis
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── ScanControl.jsx
│   │   │   ├── VulnerabilityFeed.jsx
│   │   │   └── ... (other components)
│   │   └── styles/
│   │       └── globals.css
│   └── package.json
└── README.md
```

---

## 🔧 Configuration

### API Key Setup (Optional but Recommended)

For AI analysis, add your OpenRouter API key:

```bash
# backend/.env
OPENROUTER_API_KEY=your_api_key_here
```

Get a free API key at: https://openrouter.ai

### Customizing Scans

Edit `backend/tools/vuln_scanner.py` to:
- Add custom payloads
- Adjust timeout values
- Enable/disable specific checks

---

## 🎯 For Competition Day (October 30)

### Pre-Competition Checklist

1. ✅ Test all features thoroughly
2. ✅ Prepare demo targets (use intentionally vulnerable apps)
3. ✅ Practice explaining each feature
4. ✅ Have backup of the entire project
5. ✅ Test on competition network/machine

### Recommended Demo Flow

1. **Introduction** (1 min)
   - Show the dashboard
   - Explain the real-time capabilities

2. **Quick Scan Demo** (3 mins)
   - Scan a vulnerable target
   - Show live vulnerability detection
   - Highlight the UI animations

3. **Advanced Features** (3 mins)
   - Demonstrate attack chain detection
   - Show AI-powered insights
   - Explain confidence scoring

4. **Technical Deep Dive** (2 mins)
   - Show the architecture
   - Explain the modular design
   - Highlight unique features

5. **Q&A** (1 min)

### Demo Targets

Use these safe, intentionally vulnerable applications:
- https://testphp.vulnweb.com
- http://testhtml5.vulnweb.com
- DVWA (Damn Vulnerable Web Application)
- WebGoat

---

## 🛠️ Troubleshooting

### Backend won't start
```bash
# Check Python version
python3 --version  # Should be 3.8+

# Reinstall dependencies
cd backend
pip install -r requirements.txt --force-reinstall
```

### Frontend won't start
```bash
# Clear cache and reinstall
cd frontend
rm -rf node_modules package-lock.json
npm install
npm start
```

### WebSocket connection fails
- Check if backend is running on port 5000
- Check firewall settings
- Try accessing http://localhost:5000/api/health

### No vulnerabilities detected
- Ensure target is accessible
- Check if target has protections (WAF, rate limiting)
- Try a known vulnerable target first

---

## 🎓 Learning Resources

### Understanding Vulnerabilities

**XSS (Cross-Site Scripting)**
- Injecting malicious scripts into web pages
- Can steal cookies, session tokens, credentials

**SQL Injection**
- Manipulating database queries
- Can lead to data breach, authentication bypass

**IDOR (Insecure Direct Object Reference)**
- Accessing other users' data by changing IDs
- Common in APIs and web applications

**Business Logic Flaws**
- Race conditions, price manipulation
- Requires understanding application flow

### Further Reading
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- PortSwigger Web Security Academy: https://portswigger.net/web-security

---

## 🔒 Legal & Ethical Use

⚠️ **IMPORTANT**: Only scan targets you own or have explicit permission to test.

**Authorized Use Cases:**
- Your own applications
- Bug bounty programs
- Penetration testing engagements with contracts
- Educational labs (DVWA, WebGoat, etc.)

**Unauthorized scanning is illegal and may result in:**
- Criminal charges
- Civil lawsuits
- Network bans

**Always get written permission before scanning!**

---

## 🚀 Advanced Features Explained

### Attack Chain Detection

CyberSage identifies combinations of vulnerabilities that create critical attack paths:

**Example Chain: XSS → Session Hijack**
1. Stored XSS vulnerability found
2. Missing HTTPOnly flag on cookies
3. **Result**: Attacker can steal session tokens and impersonate users

**Why This Matters:**
- Single vulnerabilities might be rated Medium
- Combined, they create Critical risk
- Prioritizes remediation efforts

### Business Logic Scanner

Tests for flaws automated scanners miss:

**Race Conditions**
- Sends 50 parallel requests to payment endpoints
- Detects if multiple transactions succeed
- Example: Redeeming same voucher multiple times

**Price Manipulation**
- Tests negative values, zero prices
- Checks if server validates amounts
- Example: Buying items for $0.00

**Authentication Bypass**
- Tests direct access to protected pages
- Tries header manipulation techniques
- Example: Accessing /admin without login

### AI Analysis

Uses OpenRouter API for intelligent insights:

**Severity Prioritization**
- Analyzes distribution of findings
- Recommends immediate actions
- Provides context-aware guidance

**Risk Assessment**
- Calculates overall security posture score
- Considers confidence levels
- Factors in attack chains

**Smart Recommendations**
- Tailored to your specific findings
- Prioritizes quick wins
- Suggests long-term improvements

---

## 📊 API Reference

### REST Endpoints

**Health Check**
```http
GET /api/health
```

**Get All Scans**
```http
GET /api/scans
```

**Get Scan Details**
```http
GET /api/scan/{scan_id}
```

**Export Scan Results**
```http
GET /api/scan/{scan_id}/export
```

### WebSocket Events

**Client → Server**

```javascript
// Start a scan
socket.emit('start_scan', {
  target: 'https://example.com',
  mode: 'elite'
});

// Stop a scan
socket.emit('stop_scan', {
  scan_id: 'scan_123'
});
```

**Server → Client**

```javascript
// Connected
socket.on('connected', (data) => {
  console.log('Ready:', data.status);
});

// Scan started
socket.on('scan_started', (data) => {
  console.log('Scan ID:', data.scan_id);
});

// Progress update
socket.on('scan_progress', (data) => {
  console.log(`${data.progress}% - ${data.phase}`);
});

// Vulnerability found
socket.on('vulnerability_found', (data) => {
  console.log('Vuln:', data.type, data.severity);
});

// Chain detected
socket.on('chain_detected', (data) => {
  console.log('Chain:', data.name, data.impact);
});

// Scan completed
socket.on('scan_completed', (data) => {
  console.log('Results:', data.results_summary);
});
```

---

## 🎨 Customization Guide

### Adding a New Scanner

1. Create scanner module:
```python
# backend/tools/custom_scanner.py
class CustomScanner:
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
    
    def scan(self, scan_id, target):
        vulnerabilities = []
        
        # Your scanning logic here
        
        # Broadcast findings
        for vuln in vulnerabilities:
            self.broadcaster.broadcast_vulnerability_found(scan_id, vuln)
            self.db.add_vulnerability(scan_id, vuln)
        
        return vulnerabilities
```

2. Integrate in orchestrator:
```python
# backend/core/scan_orchestrator.py
from tools.custom_scanner import CustomScanner

class ScanOrchestrator:
    def __init__(self, database, broadcaster):
        # ... existing code ...
        self.custom_scanner = CustomScanner(database, broadcaster)
    
    def execute_elite_scan(self, scan_id, target, scan_mode):
        # ... existing code ...
        
        # Add your scanner
        custom_vulns = self.custom_scanner.scan(scan_id, target)
        all_vulnerabilities.extend(custom_vulns)
```

### Adding UI Components

Create new component:
```jsx
// frontend/src/components/CustomComponent.jsx
import React from 'react';

export const CustomComponent = ({ data }) => {
  return (
    <div className="bg-gray-800 rounded-lg p-6">
      <h2 className="text-xl font-bold text-white mb-4">
        Custom Feature
      </h2>
      {/* Your component JSX */}
    </div>
  );
};
```

Add to Dashboard:
```jsx
// frontend/src/components/Dashboard.jsx
import { CustomComponent } from './CustomComponent';

// In render:
<CustomComponent data={yourData} />
```

---

## 🐛 Known Issues & Limitations

### Current Limitations

1. **No Authentication**
   - Single user mode
   - No login system
   - Plan: Add JWT authentication in future

2. **Limited Concurrent Scans**
   - One scan at a time per instance
   - Plan: Add scan queue system

3. **No Scan History UI**
   - Database stores history
   - Not exposed in current UI
   - Plan: Add history viewer

4. **Basic SQLi Detection**
   - Uses error-based detection
   - May miss blind SQLi
   - Plan: Add time-based detection

### Workarounds

**For multiple scans:**
- Wait for current scan to complete
- Or run multiple backend instances on different ports

**For scan history:**
- Access database directly: `sqlite3 cybersage_v2.db`
- Or use API: `GET /api/scans`

---

## 🤝 Contributing

Want to improve CyberSage? Here are some ideas:

### Easy Wins
- [ ] Add more vulnerability payloads
- [ ] Improve error messages
- [ ] Add dark/light theme toggle
- [ ] Create PDF export for reports

### Medium Difficulty
- [ ] Implement scan queue system
- [ ] Add user authentication
- [ ] Create scan history viewer
- [ ] Add screenshot capture for findings

### Advanced
- [ ] Machine learning for false positive detection
- [ ] Distributed scanning across multiple workers
- [ ] Integration with bug bounty platforms
- [ ] Custom vulnerability signatures

---

### Anticipate Questions

**Q: How is this different from Burp Suite/OWASP ZAP?**
A: Focus on real-time UI, AI analysis, and attack chain detection. Built for modern web apps with API-first approach.

**Q: How do you handle false positives?**
A: Confidence scoring system, multi-tool correlation, and AI validation layer.

**Q: Can this scale to enterprise use?**
A: Modular architecture allows easy integration of new scanners. Database design supports multiple users and concurrent scans.

**Q: What's the performance like?**
A: Elite scan completes in ~30 minutes. Async architecture ensures non-blocking operations.

**Q: Security of the tool itself?**
A: Currently localhost only. Production deployment would add authentication, rate limiting, and input validation.

---
