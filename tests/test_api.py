"""
Modern test suite for CHN Server API endpoints
"""
import pytest
import json
from unittest.mock import patch, MagicMock
from flask import url_for

from mhn import create_app, db
from mhn.auth.models import User, Role
from mhn.api.models import Sensor


@pytest.fixture
def app():
    """Create application for testing"""
    app = create_app('testing')
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'SECRET_KEY': 'test-secret-key',
        'STRUCTURED_LOGGING': False,
    })
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def auth_headers():
    """Mock authentication headers"""
    return {'Authorization': 'Bearer test-token'}


class TestSensorAPI:
    """Test sensor management API endpoints"""
    
    def test_create_sensor_success(self, client, auth_headers):
        """Test successful sensor creation"""
        sensor_data = {
            'name': 'test-sensor',
            'hostname': 'test.example.com',
            'honeypot': 'dionaea'
        }
        
        with patch('mhn.api.views.Clio') as mock_clio:
            mock_clio.return_value.authkey.new.return_value.post.return_value = None
            
            response = client.post(
                '/api/sensor/',
                data=json.dumps(sensor_data),
                headers={**auth_headers, 'Content-Type': 'application/json'}
            )
            
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['name'] == 'test-sensor'
        assert 'uuid' in data
    
    def test_create_sensor_missing_fields(self, client, auth_headers):
        """Test sensor creation with missing required fields"""
        sensor_data = {
            'name': 'test-sensor'
            # Missing hostname and honeypot
        }
        
        response = client.post(
            '/api/sensor/',
            data=json.dumps(sensor_data),
            headers={**auth_headers, 'Content-Type': 'application/json'}
        )
        
        assert response.status_code == 400
    
    def test_rate_limiting(self, client, auth_headers):
        """Test rate limiting on sensor creation"""
        sensor_data = {
            'name': 'test-sensor',
            'hostname': 'test.example.com',
            'honeypot': 'dionaea'
        }
        
        with patch('mhn.api.views.Clio') as mock_clio:
            mock_clio.return_value.authkey.new.return_value.post.return_value = None
            
            # Make requests up to the rate limit
            for i in range(11):  # Rate limit is 10 per minute
                response = client.post(
                    '/api/sensor/',
                    data=json.dumps({**sensor_data, 'name': f'sensor-{i}'}),
                    headers={**auth_headers, 'Content-Type': 'application/json'}
                )
                
                if i < 10:
                    assert response.status_code == 200
                else:
                    assert response.status_code == 429  # Too Many Requests


class TestSecurityHeaders:
    """Test security headers and CSRF protection"""
    
    def test_security_headers_present(self, client):
        """Test that security headers are present"""
        response = client.get('/')
        
        # Check for common security headers
        assert 'X-Content-Type-Options' in response.headers
        assert 'X-Frame-Options' in response.headers
    
    def test_csrf_protection(self, client):
        """Test CSRF protection on forms"""
        response = client.post('/ui/login/', data={
            'email': 'test@example.com',
            'password': 'password'
        })
        
        # Should fail without CSRF token
        assert response.status_code in [400, 403]


class TestHealthCheck:
    """Test application health and monitoring endpoints"""
    
    def test_app_runs(self, client):
        """Test that the application starts and responds"""
        response = client.get('/')
        assert response.status_code in [200, 302, 404]  # Any response means it's running
    
    def test_database_connection(self, app):
        """Test database connectivity"""
        with app.app_context():
            # Try to query the database
            users = User.query.all()
            assert isinstance(users, list)