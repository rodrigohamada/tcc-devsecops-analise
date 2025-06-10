# app.py
from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

# VULNERABILIDADE 2: Segredo hardcoded no código.
API_KEY = "sk-live-12345abcdefg67890hijklmn12345"

# Função para inicializar o banco de dados
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL
        )
    ''')
    # Inserir um usuário de teste
    cursor.execute("INSERT OR IGNORE INTO users (id, username) VALUES (1, 'admin')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    name = request.args.get('name', 'Visitante')
    return f'<h1>Olá, {name}!</h1><p>API Key usada (exemplo): {API_KEY}</p>'

@app.route('/user/<username>')
def get_user(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # VULNERABILIDADE 1: Injeção de SQL. A entrada do usuário é concatenada diretamente.
    # Um invasor pode usar: ' OR 1=1 --
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        if user:
            return jsonify({"id": user[0], "username": user[1]})
        else:
            return jsonify({"error": "Usuário não encontrado"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)