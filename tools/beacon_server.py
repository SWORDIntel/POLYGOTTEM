#!/usr/bin/env python3
"""
POLYGOTTEM GUARANTEE Network Beacon Test Server
================================================
Test callback server for receiving GUARANTEE chain beacons
from articbastion.duckdns.org

Setup Instructions:
1. pip install flask requests
2. python3 beacon_server.py
3. Configure reverse proxy on articbastion.duckdns.org to forward /beacon to localhost:5000
"""

from flask import Flask, request, jsonify
import json
from datetime import datetime
from pathlib import Path
import os

app = Flask(__name__)

# Log file for callbacks
LOG_FILE = 'guarantee_beacons.log'

@app.route('/beacon', methods=['POST'])
def receive_beacon():
    """
    Receive beacon callback from GUARANTEE chain

    Expected payload:
    {
        "timestamp": "2025-11-15T10:30:45.123456",
        "chain_id": "CHAIN_1234_5678",
        "method_id": "pdf_autoexec",
        "hostname": "target-machine",
        "framework": "POLYGOTTEM",
        "mode": "GUARANTEE_CASCADE"
    }
    """
    try:
        data = request.get_json()

        # Validate beacon data
        required_fields = ['chain_id', 'method_id', 'timestamp']
        if not all(field in data for field in required_fields):
            return jsonify({
                'status': 'error',
                'message': f'Missing required fields. Required: {required_fields}'
            }), 400

        # Log callback
        callback_record = {
            'received_at': datetime.now().isoformat(),
            'source_ip': request.remote_addr,
            'data': data
        }

        # Write to log file
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(callback_record) + '\n')

        print(f"[+] Beacon received from {request.remote_addr}")
        print(f"    Chain ID: {data.get('chain_id')}")
        print(f"    Method: {data.get('method_id')}")

        # Return success response
        return jsonify({
            'status': 'received',
            'message': f'Beacon from chain {data.get("chain_id")} recorded',
            'timestamp': datetime.now().isoformat(),
            'beacon_count': count_beacons()
        }), 200

    except Exception as e:
        print(f"[-] Beacon error: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'POLYGOTTEM Guarantee Beacon Server',
        'timestamp': datetime.now().isoformat(),
        'uptime': 'N/A',
        'total_beacons': count_beacons()
    }), 200


@app.route('/stats', methods=['GET'])
def get_stats():
    """Get beacon statistics"""
    total = count_beacons()

    if not Path(LOG_FILE).exists():
        return jsonify({
            'total_beacons': 0,
            'log_file': LOG_FILE,
            'message': 'No beacons received yet'
        }), 200

    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()

        # Parse recent beacons
        recent = []
        for line in lines[-10:]:
            try:
                beacon = json.loads(line)
                recent.append(beacon)
            except:
                pass

        # Count by method
        methods_count = {}
        for line in lines:
            try:
                beacon = json.loads(line)
                method = beacon['data'].get('method_id', 'unknown')
                methods_count[method] = methods_count.get(method, 0) + 1
            except:
                pass

        return jsonify({
            'total_beacons': total,
            'log_file': LOG_FILE,
            'methods_executed': methods_count,
            'recent_beacons': recent,
            'last_beacon': lines[-1] if lines else None
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/clear', methods=['POST'])
def clear_logs():
    """Clear beacon logs (for testing)"""
    try:
        if Path(LOG_FILE).exists():
            os.remove(LOG_FILE)
        return jsonify({
            'status': 'cleared',
            'message': 'Beacon logs cleared'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


def count_beacons():
    """Count total beacons logged"""
    if not Path(LOG_FILE).exists():
        return 0
    try:
        with open(LOG_FILE, 'r') as f:
            return len(f.readlines())
    except:
        return 0


@app.route('/', methods=['GET'])
def root():
    """Root endpoint with documentation"""
    return jsonify({
        'service': 'POLYGOTTEM Guarantee Network Beacon Server',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            'POST /beacon': 'Receive beacon callback from GUARANTEE chain',
            'GET /health': 'Health check',
            'GET /stats': 'View beacon statistics',
            'POST /clear': 'Clear beacon logs (testing only)',
            'GET /': 'This documentation'
        },
        'documentation': 'See https://github.com/SWORDIntel/POLYGOTTEM for setup instructions'
    }), 200


if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║  POLYGOTTEM GUARANTEE Network Beacon Test Server                         ║
║  Version 1.0.0                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

[+] Starting test beacon server...
[+] Listening on: 0.0.0.0:5000
[+] Log file: {log}

Endpoints:
    POST /beacon  - Receive beacon callbacks
    GET /health   - Health check
    GET /stats    - Beacon statistics
    POST /clear   - Clear logs (testing)
    GET /         - Documentation

Setup:
1. Configure articbastion.duckdns.org to forward /beacon to localhost:5000
2. Example nginx config:
   location /beacon {{
       proxy_pass http://localhost:5000/beacon;
       proxy_set_header Content-Type application/json;
   }}

3. Test connectivity:
   curl https://articbastion.duckdns.org/health

[*] Press Ctrl+C to stop the server
""".format(log=LOG_FILE))

    app.run(host='0.0.0.0', port=5000, debug=False)
