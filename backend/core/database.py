import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager

class Database:
    def __init__(self, db_path='cybersage_v2.db'):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    scan_mode TEXT,
                    status TEXT DEFAULT 'pending',
                    error_message TEXT,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    duration_seconds INTEGER
                )
            ''')
            
            # Vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    vuln_type TEXT,
                    severity TEXT,
                    title TEXT,
                    description TEXT,
                    confidence_score INTEGER,
                    detection_tool TEXT,
                    affected_url TEXT,
                    proof_of_concept TEXT,
                    remediation TEXT,
                    raw_data TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            ''')
            
            # Attack chains table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_chains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    chain_name TEXT,
                    severity TEXT,
                    impact TEXT,
                    steps TEXT,
                    confidence_score INTEGER,
                    proof_of_concept TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            ''')
            
            # Tool logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tool_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    tool_name TEXT,
                    target TEXT,
                    status TEXT,
                    stdout TEXT,
                    stderr TEXT,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            ''')
            
            print("[Database] Initialized successfully")
    
    def create_scan(self, scan_id, target, scan_mode):
        """Create a new scan record"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scans (scan_id, target, scan_mode, status)
                VALUES (?, ?, ?, 'running')
            ''', (scan_id, target, scan_mode))
            print(f"[Database] Created scan: {scan_id}")
    
    def update_scan_status(self, scan_id, status, error_message=None):
        """Update scan status"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if status == 'completed':
                cursor.execute('''
                    UPDATE scans 
                    SET status = ?, 
                        completed_at = CURRENT_TIMESTAMP,
                        duration_seconds = (strftime('%s', 'now') - strftime('%s', started_at))
                    WHERE scan_id = ?
                ''', (status, scan_id))
            else:
                cursor.execute('''
                    UPDATE scans 
                    SET status = ?, error_message = ?
                    WHERE scan_id = ?
                ''', (status, error_message, scan_id))
    
    def add_vulnerability(self, scan_id, vuln_data):
        """Add a vulnerability finding"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO vulnerabilities 
                (scan_id, vuln_type, severity, title, description, confidence_score, 
                 detection_tool, affected_url, proof_of_concept, remediation, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                vuln_data.get('type'),
                vuln_data.get('severity'),
                vuln_data.get('title'),
                vuln_data.get('description'),
                vuln_data.get('confidence', 50),
                vuln_data.get('tool'),
                vuln_data.get('url'),
                vuln_data.get('poc'),
                vuln_data.get('remediation'),
                json.dumps(vuln_data.get('raw_data', {}))
            ))
            return cursor.lastrowid
    
    def add_attack_chain(self, scan_id, chain_data):
        """Add an attack chain finding"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO attack_chains 
                (scan_id, chain_name, severity, impact, steps, confidence_score, proof_of_concept)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                chain_data.get('name'),
                chain_data.get('severity'),
                chain_data.get('impact'),
                json.dumps(chain_data.get('steps', [])),
                chain_data.get('confidence', 50),
                chain_data.get('poc')
            ))
            return cursor.lastrowid
    
    def log_tool_run(self, scan_id, tool_name, target, status, stdout='', stderr=''):
        """Log tool execution"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO tool_logs 
                (scan_id, tool_name, target, status, stdout, stderr, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (scan_id, tool_name, target, status, stdout[:5000], stderr[:5000]))
    
    def get_all_scans(self, limit=50):
        """Get all scans"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM scans 
                ORDER BY started_at DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_scan_by_id(self, scan_id):
        """Get scan details"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_vulnerabilities_by_scan(self, scan_id):
        """Get all vulnerabilities for a scan"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM vulnerabilities 
                WHERE scan_id = ? 
                ORDER BY 
                    CASE severity 
                        WHEN 'critical' THEN 1 
                        WHEN 'high' THEN 2 
                        WHEN 'medium' THEN 3 
                        WHEN 'low' THEN 4 
                        ELSE 5 
                    END,
                    confidence_score DESC
            ''', (scan_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_chains_by_scan(self, scan_id):
        """Get all attack chains for a scan"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM attack_chains 
                WHERE scan_id = ? 
                ORDER BY detected_at DESC
            ''', (scan_id,))
            
            chains = []
            for row in cursor.fetchall():
                chain = dict(row)
                chain['steps'] = json.loads(chain['steps'])
                chains.append(chain)
            return chains
    
    def get_scan_stats(self, scan_id):
        """Get vulnerability statistics for a scan"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
                    AVG(confidence_score) as avg_confidence
                FROM vulnerabilities
                WHERE scan_id = ?
            ''', (scan_id,))
            
            row = cursor.fetchone()
            stats = dict(row) if row else {}
            
            # Get chain count
            cursor.execute('SELECT COUNT(*) as chain_count FROM attack_chains WHERE scan_id = ?', (scan_id,))
            stats['attack_chains'] = cursor.fetchone()['chain_count']
            
            return stats