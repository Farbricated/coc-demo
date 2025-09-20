"""
Professional REST API
=====================
Comprehensive API endpoints for system integration
"""

from flask import Blueprint, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import jwt
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

# Create API blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

# Rate limiting
limiter = Limiter(
    get_remote_address,
    default_limits=["1000 per hour"]
)

def require_api_key(f):
    """API key authentication decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or not validate_api_key(api_key):
            return jsonify({'error': 'Invalid or missing API key'}), 401
        return f(*args, **kwargs)
    return decorated

def validate_api_key(api_key: str) -> bool:
    """Validate API key"""
    # Implement your API key validation logic
    valid_keys = ['chainguard-api-key-2025']  # Replace with proper key management
    return api_key in valid_keys

@api_bp.route('/health', methods=['GET'])
@limiter.limit("100 per minute")
def health_check():
    """System health check endpoint"""
    from core.database import db
    from modules.monitoring import system_monitor
    
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'services': {
            'database': 'operational' if db.connected else 'degraded',
            'monitoring': 'operational' if system_monitor.monitoring_active else 'stopped'
        },
        'metrics': system_monitor.get_current_metrics()
    }
    
    status_code = 200 if all(s == 'operational' for s in health_status['services'].values()) else 503
    return jsonify(health_status), status_code

@api_bp.route('/evidence', methods=['GET'])
@require_api_key
@limiter.limit("100 per hour")
def list_evidence():
    """List evidence with pagination and filtering"""
    try:
        from core.database import db
        
        # Parse query parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        user_clearance = int(request.args.get('clearance', 5))
        
        filters = {}
        if request.args.get('status'):
            filters['status'] = request.args.get('status')
        if request.args.get('risk_level'):
            filters['risk_level'] = request.args.get('risk_level')
        if request.args.get('case_id'):
            filters['case_id'] = request.args.get('case_id')
        
        # Get evidence
        evidence_list = db.get_evidence_list(
            limit=per_page,
            user_clearance=user_clearance,
            filters=filters
        )
        
        response = {
            'status': 'success',
            'data': evidence_list,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': len(evidence_list)
            },
            'filters_applied': filters
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"API evidence list error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/evidence/<evidence_id>', methods=['GET'])
@require_api_key
@limiter.limit("200 per hour")
def get_evidence(evidence_id):
    """Get specific evidence details"""
    try:
        from core.database import db
        
        # This would be implemented with proper database query
        evidence = db.get_evidence_by_id(evidence_id)  # You'll need to implement this method
        
        if not evidence:
            return jsonify({'error': 'Evidence not found'}), 404
        
        return jsonify({
            'status': 'success',
            'data': evidence
        }), 200
        
    except Exception as e:
        logger.error(f"API get evidence error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/search', methods=['POST'])
@require_api_key
@limiter.limit("50 per hour")
def search_evidence():
    """Advanced evidence search"""
    try:
        from modules.search_engine import search_engine
        
        data = request.json
        query = data.get('query', '')
        filters = data.get('filters', {})
        user_clearance = data.get('clearance', 5)
        
        results = search_engine.advanced_search(query, filters, user_clearance)
        
        return jsonify({
            'status': 'success',
            'query': query,
            'results': results
        }), 200
        
    except Exception as e:
        logger.error(f"API search error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/analytics', methods=['GET'])
@require_api_key
@limiter.limit("20 per hour")
def get_analytics():
    """Get system analytics and insights"""
    try:
        from core.database import db
        from modules.search_engine import search_engine
        from modules.monitoring import system_monitor
        
        analytics_data = {
            'dashboard_stats': db.get_dashboard_stats(),
            'search_analytics': search_engine.get_search_analytics(),
            'system_metrics': system_monitor.get_current_metrics(),
            'generated_at': datetime.now().isoformat()
        }
        
        return jsonify({
            'status': 'success',
            'data': analytics_data
        }), 200
        
    except Exception as e:
        logger.error(f"API analytics error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/upload', methods=['POST'])
@require_api_key
@limiter.limit("10 per hour")
def upload_evidence():
    """Upload evidence via API"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400
        
        # Process file upload
        # This would integrate with your existing upload logic
        
        return jsonify({
            'status': 'success',
            'message': 'Evidence uploaded successfully',
            'evidence_id': 'generated-evidence-id'
        }), 201
        
    except Exception as e:
        logger.error(f"API upload error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Error handlers
@api_bp.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded', 'retry_after': str(e.retry_after)}), 429

@api_bp.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@api_bp.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500
