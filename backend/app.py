from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
import os
from datetime import datetime

from core.database import Database
from core.scan_orchestrator import ScanOrchestrator
from core.realtime_broadcaster import RealTimeBroadcaster

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cybersage_v2_elite_secret_2024')
CORS(app, resources={r"/*": {"origins": "*"}})

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', ping_timeout=60, ping_interval=25)

# Initialize components
db = Database()
broadcaster = RealTimeBroadcaster(socketio)
scan_orchestrator = ScanOrchestrator(db, broadcaster)

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
        args=(scan_id, target, scan_mode),
        daemon=True
    )
    scan_thread.start()
    
    active_scans[scan_id] = {
        'target': target,
        'mode': scan_mode,
        'thread': scan_thread,
        'started_at': time.time()
    }

def execute_scan_async(scan_id, target, scan_mode):
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