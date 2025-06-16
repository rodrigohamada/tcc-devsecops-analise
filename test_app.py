import unittest
from app import app

class BasicTestCase(unittest.TestCase):

    def test_home(self):
        """Testa se a página inicial carrega corretamente."""
        tester = app.test_client(self)
        response = tester.get('/', content_type='html/text')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'Ola' in response.data)

if __name__ == '__main__':
    unittest.main()
