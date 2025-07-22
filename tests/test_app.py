import unittest
import os
import sys

# Add the parent directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import app, init_db

class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        # Set up a temporary database for testing
        self.test_db_path = 'test_devices.db'
        app.config['DATABASE'] = self.test_db_path

        # Initialize the database with test data
        with app.app_context():
            init_db()

    def tearDown(self):
        # Clean up the test database
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

    def test_login_logout(self):
        # Test login with valid credentials
        response = self.app.post('/login', data=dict(
            username='admin',
            password='StrongPassword123'
        ), follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Dashboard', response.data)

        # Test logout
        response = self.app.get('/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Sign in', response.data)

    def test_invalid_login(self):
        # Test login with invalid credentials
        response = self.app.post('/login', data=dict(
            username='admin',
            password='wrongpassword'
        ), follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid credentials', response.data)

    def test_dashboard_access(self):
        # Test accessing dashboard without logging in
        response = self.app.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Sign in', response.data)

        # Test accessing dashboard after logging in
        self.app.post('/login', data=dict(
            username='admin',
            password='StrongPassword123'
        ), follow_redirects=True)
        response = self.app.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Dashboard', response.data)

if __name__ == '__main__':
    unittest.main()
