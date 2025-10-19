# app.py - Enhanced with WebSockets
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cybersage_v2_secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

class RealTimeScanBroadcaster:
    """
    Broadcasts scan progress to all connected clients in real-time
    """
    
    @staticmethod
    def broadcast_event(event_type, data):
        """Send event to all connected clients"""
        socketio.emit(event_type, data, namespace='/scan')
    
    @staticmethod
    def broadcast_tool_start(tool_name, target):
        socketio.emit('tool_started', {
            'tool': tool_name,
            'target': target,
            'timestamp': time.time()
        }, namespace='/scan')
    
    @staticmethod
    def broadcast_vulnerability_found(vuln_data):
        socketio.emit('vulnerability_found', {
            'type': vuln_data['type'],
            'severity': vuln_data['severity'],
            'title': vuln_data['title'],
            'confidence': vuln_data.get('confidence', 50),
            'timestamp': time.time(),
            'preview': vuln_data.get('description', '')[:100]
        }, namespace='/scan')
    
    @staticmethod
    def broadcast_scan_progress(scan_id, progress_percentage, current_phase):
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'progress': progress_percentage,
            'phase': current_phase,
            'timestamp': time.time()
        }, namespace='/scan')
    
    @staticmethod
    def broadcast_chain_detected(chain_data):
        """Special notification for vulnerability chains"""
        socketio.emit('chain_detected', {
            'name': chain_data['name'],
            'severity': 'critical',
            'steps': chain_data['steps'],
            'impact': chain_data['impact'],
            'animation': 'pulse'  # Trigger special UI animation
        }, namespace='/scan')

@socketio.on('connect', namespace='/scan')
def handle_connect():
    print(f'Client connected: {request.sid}')
    emit('connected', {'status': 'ready'})

@socketio.on('start_scan', namespace='/scan')
def handle_start_scan(data):
    target = data['target']
    scan_mode = data.get('mode', 'precision')
    
    # Start scan in background thread
    scan_thread = threading.Thread(
        target=execute_scan_with_broadcast,
        args=(target, scan_mode)
    )
    scan_thread.daemon = True
    scan_thread.start()