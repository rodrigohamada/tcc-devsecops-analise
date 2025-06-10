# test_app.py (COM CÓDIGO DE DEPURAÇÃO)
import unittest
from app import app

class BasicTestCase(unittest.TestCase):

    def test_home(self):
        """Testa se a página inicial carrega corretamente."""
        tester = app.test_client(self)
        response = tester.get('/', content_type='html/text')
        
        # --- INÍCIO DO BLOCO DE DEPURAÇÃO ---
        # As linhas a seguir vão imprimir o conteúdo exato da resposta no log do pipeline
        # para que possamos ver o que realmente está lá.
        print("\n\n--- INÍCIO DO DEBUG DA RESPOSTA DO PIPELINE ---")
        print(f"Tipo do dado recebido (response.data): {type(response.data)}")
        print(f"Conteúdo exato do dado (response.data): {response.data}")
        print("--- FIM DO DEBUG DA RESPOSTA DO PIPELINE ---\n\n")
        # --- FIM DO BLOCO DE DEPURAÇÃO ---

        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'Ola' in response.data)

if __name__ == '__main__':
    unittest.main()