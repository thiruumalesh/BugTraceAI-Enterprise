from flask import Flask, jsonify, request
from flask_cors import CORS

from bugtrace.schemas.db_models import ScanTable, ScanStatus
from bugtrace.core.event_bus import EventBus

app = Flask(__name__)
CORS(app)


event_bus = EventBus()
@app.route('/api/scans', methods=['GET'])
def get_scans():
    scans = Scan.query.all()
    return jsonify([{
        'id': scan.id,
        'name': scan.name,
        'status': scan.status.value,
        'created_at': scan.created_at.isoformat(),
        'updated_at': scan.updated_at.isoformat()
    } for scan in scans])

@app.route('/api/scans/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
        scan = Scan.query.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        return jsonify({
            'status': scan.status.value,
        'phase': scan.phase,
            'progress': scan.progress,
            'active_agent': scan.active_agent,
            'current_url': scan.current_url,
            'findings_count': len(scan.findings)
        })

@app.route('/api/scans/<scan_id>/exploit', methods=['POST'])
def run_exploit(scan_id):
        scan = Scan.query.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        if scan.status != ScanStatus.RUNNING:
            return jsonify({'error': 'Scan is not running'}), 400

        # Run exploit
        result = mcp_tools.bugtraceai_exploit(scan_id)

        return jsonify(result)

@app.route('/api/scans/<scan_id>/stop', methods=['POST'])
def stop_scan(scan_id):
        scan = Scan.query.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        if scan.status != ScanStatus.RUNNING:
            return jsonify({'error': 'Scan is not running'}), 400

        # Stop the scan
        scan.status = ScanStatus.STOPPED
        scan.progress = 100
        scan.phase = 'STOPPED'
        scan.active_agent = None
        scan.current_url = None

        db.session.commit()

        return jsonify({'success': True})

@app.route('/api/scans/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
        scan = Scan.query.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        return jsonify({
            'successful_exploits': scan.successful_exploits,
            'failed_exploits': scan.failed_exploits
        })

@app.route('/api/scans/<scan_id>/events', methods=['GET'])
def get_scan_events(scan_id):
        events = event_bus.get_events(scan_id)
        return jsonify(events)

if __name__ == '__main__':
        app.run(host='0.0.0.0', port=5000)

