import unittest
from unittest.mock import patch, MagicMock
from app import app  # Substitua pelo nome correto do módulo onde seu código principal está.

class TestChatAPI(unittest.TestCase):

    def setUp(self):
        """Configuração inicial para os testes."""
        self.app = app.test_client()
        self.app.testing = True

    @patch('app.chat.send_message')  # Mock da função `send_message` da API Gemini.
    def test_chat_endpoint_success(self, mock_send_message):
        """Testa se a API responde corretamente ao enviar uma mensagem."""
        # Configurando o mock para simular uma resposta do Gemini
        mock_response = MagicMock()
        mock_response.text = "Olá, como posso ajudar?"
        mock_send_message.return_value = mock_response

        # Dados de entrada
        data = {'message': 'Oi!'}
        
        # Enviar a requisição POST para a rota `/chat`
        response = self.app.post('/chat', json=data)

        # Verificar o status e a resposta
        self.assertEqual(response.status_code, 200)
        self.assertIn('response', response.json)
        self.assertEqual(response.json['response'], "Olá, como posso ajudar?")

    @patch('app.chat.send_message')
    def test_chat_endpoint_error(self, mock_send_message):
        """Testa o comportamento da API quando ocorre um erro interno."""
        # Configurando o mock para simular uma exceção
        mock_send_message.side_effect = Exception("Erro na API do Gemini")

        # Dados de entrada
        data = {'message': 'Oi!'}
        
        # Enviar a requisição POST para a rota `/chat`
        response = self.app.post('/chat', json=data)

        # Verificar o status e a resposta
        self.assertEqual(response.status_code, 500)
        self.assertIn('error', response.json)
        self.assertIn("Erro na API do Gemini", response.json['error'])

    def test_chat_endpoint_missing_message(self):
        """Testa a API quando a mensagem não é fornecida."""
        # Dados de entrada sem a chave `message`
        data = {}
        
        # Enviar a requisição POST para a rota `/chat`
        response = self.app.post('/chat', json=data)

        # Verificar o status e a resposta
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.json)
        self.assertEqual(response.json['error'], "Mensagem não fornecida.")

if __name__ == '__main__':
    unittest.main()
