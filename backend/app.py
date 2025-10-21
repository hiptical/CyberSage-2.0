from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
import os
from datetime import datetime
import requests

from core.database import Database
from core.scan_orchestrator import ScanOrchestrator
from core.realtime_broadcaster import RealTimeBroadcaster
from core.pdf_generator import PDFReportGenerator
from tools.integrations import ThirdPartyScannerIntegration

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cybersage_v2_elite_secret_2024')
CORS(app, resources={r"/*": {"origins": "*"}})

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', ping_timeout=60, ping_interval=25)

# Initialize components
db = Database()
broadcaster = RealTimeBroadcaster(socketio)
scan_orchestrator = ScanOrchestrator(db, broadcaster)
pdf_generator = PDFReportGenerator()
scanner_integration = ThirdPartyScannerIntegration(db, broadcaster)

# Store active scans
active_scans = {}

@app.route('/')
def index():
    return jsonify({
        "status": "online",
        "version": "2.0",
        "name": "CyberSage Elite",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/health')
def health():
    return jsonify({
        "status": "healthy",
        "active_scans": len(active_scans),
        "database": "connected"
    })

@app.route('/api/scans', methods=['GET'])
def get_scans():
    """Get all scan history"""
    scans = db.get_all_scans()
    return jsonify({"scans": scans})

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    """Get detailed scan results"""
    scan_data = db.get_scan_by_id(scan_id)
    vulnerabilities = db.get_vulnerabilities_by_scan(scan_id)
    chains = db.get_chains_by_scan(scan_id)
    
    return jsonify({
        "scan": scan_data,
        "vulnerabilities": vulnerabilities,
        "chains": chains,
        "stats": db.get_scan_stats(scan_id)
    })

@app.route('/api/scan/<scan_id>/export', methods=['GET'])
def export_scan(scan_id):
    """Export scan results as JSON"""
    scan_data = db.get_scan_by_id(scan_id)
    vulnerabilities = db.get_vulnerabilities_by_scan(scan_id)
    chains = db.get_chains_by_scan(scan_id)
    
    export_data = {
        "scan_info": scan_data,
        "vulnerabilities": vulnerabilities,
        "attack_chains": chains,
        "generated_at": datetime.now().isoformat(),
        "platform": "CyberSage v2.0"
    }
    
    return jsonify(export_data)

@app.route('/api/scan/<scan_id>/export/pdf', methods=['GET'])
def export_scan_pdf(scan_id):
    """Export scan results as PDF report"""
    try:
        # Get scan data
        scan_data = db.get_scan_by_id(scan_id)
        vulnerabilities = db.get_vulnerabilities_by_scan(scan_id)
        chains = db.get_chains_by_scan(scan_id)
        statistics = db.get_scan_statistics(scan_id)
        
        if not scan_data:
            return jsonify({"error": "Scan not found"}), 404
        
        # Create temporary PDF file
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
            pdf_path = tmp_file.name
        
        # Generate PDF
        pdf_generator.generate_scan_report(
            scan_data, 
            vulnerabilities, 
            chains, 
            statistics, 
            pdf_path
        )
        
        # Return PDF file
        from flask import send_file
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f'cybersage-scan-{scan_id}.pdf',
            mimetype='application/pdf'
        )
        
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500
@app.route('/api/scan/<scan_id>/history', methods=['GET'])
def get_scan_history(scan_id):
    """Get HTTP request/response history (like Burp Repeater)"""
    history = db.get_http_history(scan_id)
    return jsonify({"history": history})

@app.route('/api/scan/<scan_id>/statistics', methods=['GET'])
def get_scan_statistics(scan_id):
    """Get detailed scan statistics"""
    stats = db.get_scan_statistics(scan_id)
    return jsonify({"statistics": stats})

@app.route('/api/scan/<scan_id>/blueprint', methods=['GET'])
def get_scan_blueprint(scan_id):
    """Get recon blueprint and OSINT details for a scan"""
    data = db.get_recon_blueprint(scan_id)
    return jsonify(data)

@app.route('/api/vulnerability/<int:vuln_id>', methods=['GET'])
def get_vulnerability_details(vuln_id):
    """Get full vulnerability details with HTTP history"""
    vuln = db.get_vulnerability_details(vuln_id)
    return jsonify({"vulnerability": vuln})

@app.route('/api/repeater/send', methods=['POST'])
def repeater_send():
    """Manually send an HTTP request (Repeater-like) and record history"""
    try:
        payload = request.get_json(force=True) or {}
        method = (payload.get('method') or 'GET').upper()
        url = payload.get('url')
        headers = payload.get('headers') or {}
        body = payload.get('body') or ''
        timeout = int(payload.get('timeout') or 20)
        scan_id = payload.get('scan_id') or f"manual_{int(time.time())}"

        if not url:
            return jsonify({"error": "url is required"}), 400

        session = requests.Session()
        session.verify = False

        start = time.time()
        resp = session.request(method, url, headers=headers, data=body, timeout=timeout, allow_redirects=True)
        elapsed_ms = int((time.time() - start) * 1000)

        req_headers_raw = "\n".join([f"{k}: {v}" for k, v in (headers or {}).items()])
        resp_headers_raw = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])

        db.add_http_request(
            scan_id=scan_id,
            method=method,
            url=url,
            req_headers=req_headers_raw,
            req_body=str(body)[:10000],
            resp_code=resp.status_code,
            resp_headers=resp_headers_raw[:10000],
            resp_body=resp.text[:50000],
            resp_time_ms=elapsed_ms,
            vuln_id=None
        )

        return jsonify({
            "scan_id": scan_id,
            "status": "ok",
            "response": {
                "code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text,
                "time_ms": elapsed_ms
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Third-Party Scanner Integration Endpoints

@app.route('/api/integration/nmap', methods=['POST'])
def integrate_nmap():
    """Integrate Nmap scan results"""
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        nmap_output = data.get('nmap_output', '')
        
        if not scan_id:
            return jsonify({"error": "scan_id is required"}), 400
        
        vulnerabilities = scanner_integration.integrate_nmap_results(scan_id, nmap_output)
        
        return jsonify({
            "status": "success",
            "vulnerabilities_added": len(vulnerabilities),
            "message": f"Integrated {len(vulnerabilities)} findings from Nmap"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/integration/nessus', methods=['POST'])
def integrate_nessus():
    """Integrate Nessus scan results"""
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        nessus_data = data.get('nessus_data', {})
        
        if not scan_id:
            return jsonify({"error": "scan_id is required"}), 400
        
        vulnerabilities = scanner_integration.integrate_nessus_results(scan_id, nessus_data)
        
        return jsonify({
            "status": "success",
            "vulnerabilities_added": len(vulnerabilities),
            "message": f"Integrated {len(vulnerabilities)} findings from Nessus"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/integration/owasp-zap', methods=['POST'])
def integrate_owasp_zap():
    """Integrate OWASP ZAP scan results"""
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        zap_data = data.get('zap_data', {})
        
        if not scan_id:
            return jsonify({"error": "scan_id is required"}), 400
        
        vulnerabilities = scanner_integration.integrate_owasp_zap_results(scan_id, zap_data)
        
        return jsonify({
            "status": "success",
            "vulnerabilities_added": len(vulnerabilities),
            "message": f"Integrated {len(vulnerabilities)} findings from OWASP ZAP"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/integration/burp', methods=['POST'])
def integrate_burp():
    """Integrate Burp Suite scan results"""
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        burp_data = data.get('burp_data', {})
        
        if not scan_id:
            return jsonify({"error": "scan_id is required"}), 400
        
        vulnerabilities = scanner_integration.integrate_burp_results(scan_id, burp_data)
        
        return jsonify({
            "status": "success",
            "vulnerabilities_added": len(vulnerabilities),
            "message": f"Integrated {len(vulnerabilities)} findings from Burp Suite"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/integration/custom', methods=['POST'])
def integrate_custom():
    """Integrate custom scanner results"""
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        scanner_name = data.get('scanner_name', 'custom')
        results = data.get('results', {})
        
        if not scan_id:
            return jsonify({"error": "scan_id is required"}), 400
        
        vulnerabilities = scanner_integration.integrate_custom_scanner(scan_id, scanner_name, results)
        
        return jsonify({
            "status": "success",
            "vulnerabilities_added": len(vulnerabilities),
            "message": f"Integrated {len(vulnerabilities)} findings from {scanner_name}"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# WebSocket Events
@socketio.on('connect', namespace='/scan')
def handle_connect():
    print(f'[WebSocket] Client connected: {request.sid}')
    emit('connected', {
        'status': 'ready',
        'message': 'Connected to CyberSage v2.0',
        'timestamp': time.time()
    })

@socketio.on('disconnect', namespace='/scan')
def handle_disconnect():
    print(f'[WebSocket] Client disconnected: {request.sid}')

@socketio.on('start_scan', namespace='/scan')
def handle_start_scan(data):
    """Start a new security scan"""
    target = data.get('target')
    scan_mode = data.get('mode', 'elite')
    options = {
        'intensity': data.get('intensity', 'normal'),
        'auth': data.get('auth', {}),
        'policy': data.get('policy', {})
    }
    
    if not target:
        emit('error', {'message': 'Target is required'})
        return
    
    # Generate scan ID
    scan_id = f"scan_{int(time.time())}_{target.replace('://', '_').replace('/', '_')[:30]}"
    
    # Create scan record
    db.create_scan(scan_id, target, scan_mode)
    
    # Emit scan started
    emit('scan_started', {
        'scan_id': scan_id,
        'target': target,
        'mode': scan_mode,
        'timestamp': time.time()
    })
    
    # Start scan in background thread
    scan_thread = threading.Thread(
        target=execute_scan_async,
        args=(scan_id, target, scan_mode, options),
        daemon=True
    )
    scan_thread.start()
    
    active_scans[scan_id] = {
        'target': target,
        'mode': scan_mode,
        'thread': scan_thread,
        'started_at': time.time()
    }

def execute_scan_async(scan_id, target, scan_mode, options=None):
    """Execute scan asynchronously"""
    try:
        broadcaster.broadcast_event('scan_status', {
            'scan_id': scan_id,
            'status': 'running',
            'message': 'Initializing CyberSage Elite Scanner...'
        })
        
        # Execute the scan
        results = scan_orchestrator.execute_elite_scan(scan_id, target, scan_mode)
        
        # Update scan status
        db.update_scan_status(scan_id, 'completed')
        
        broadcaster.broadcast_event('scan_completed', {
            'scan_id': scan_id,
            'status': 'completed',
            'results_summary': results,
            'timestamp': time.time()
        })
        
    except Exception as e:
        print(f"[ERROR] Scan failed: {str(e)}")
        db.update_scan_status(scan_id, 'failed', str(e))
        
        broadcaster.broadcast_event('scan_error', {
            'scan_id': scan_id,
            'error': str(e),
            'timestamp': time.time()
        })
    
    finally:
        if scan_id in active_scans:
            del active_scans[scan_id]

@socketio.on('stop_scan', namespace='/scan')
def handle_stop_scan(data):
    """Stop an active scan"""
    scan_id = data.get('scan_id')
    
    if scan_id in active_scans:
        db.update_scan_status(scan_id, 'stopped')
        emit('scan_stopped', {'scan_id': scan_id})
    else:
        emit('error', {'message': 'Scan not found or already completed'})

if __name__ == '__main__':
    print("=" * 60)
    print("🧠 CyberSage v2.0 - Elite Vulnerability Intelligence Platform")
    print("=" * 60)
    print(f"[+] Starting server...")
    print(f"[+] WebSocket endpoint: /scan")
    print(f"[+] Ready for connections!")
    print("=" * 60)
    
    socketio.run(app, 
                 host='0.0.0.0', 
                 port=5000, 
                 debug=True,
                 use_reloader=False,
                 allow_unsafe_werkzeug=True)