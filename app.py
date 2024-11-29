import os
import base64
from io import BytesIO
import requests
from flask import Flask, render_template, redirect, url_for, flash, session, abort, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
import onetimepass
import pyqrcode
from datetime import datetime
import re
import language_tool_python  # Biblioteca para correção gramatical
import google.generativeai as lua  # Biblioteca para Google Gemini
from functools import lru_cache  # Biblioteca para caching


# Criação da aplicação
app = Flask(__name__)

# Configuração do banco de dados e chave secreta
app.config['SECRET_KEY'] = 'top-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///C:/Users/mirso/OneDrive/Ambiente de Trabalho/HEART/heart7/db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuração do Google Gemini
GOOGLE_GEMINI_API_KEY = 'INSIRA SUA CHAVE DE API AQUI'
if not GOOGLE_GEMINI_API_KEY:
    raise ValueError("A chave API não está definida. Defina 'GOOGLE_GEMINI_API_KEY' corretamente.")
lua.configure(api_key=GOOGLE_GEMINI_API_KEY)
model = lua.GenerativeModel('gemini-1.5-pro-latest')
chat = model.start_chat(history=[])

# Inicializando o LanguageTool
tool = language_tool_python.LanguageTool('pt-BR')

# Utilitários
def limpar_resposta(resposta):
    return re.sub(r'[^\w\s+\-=\!?@#,.()*$%]', '', resposta)

def corrigir_gramatica(resposta):
    matches = tool.check(resposta)
    return language_tool_python.utils.correct(resposta, matches)

# Função com caching para melhorar a performance da API
@lru_cache(maxsize=100)
def get_gemini_response(user_message):
    try:
        response = chat.send_message(user_message)
        resposta_limpa = limpar_resposta(response.text)
        resposta_corrigida = corrigir_gramatica(resposta_limpa)
        return resposta_corrigida
    except Exception as e:
        return f"Erro: {str(e)}"

@app.route('/chat', methods=['POST'])
def chat_endpoint():
    data = request.get_json()
    user_message = data.get('message')
    if not user_message:
        return jsonify({'error': 'Mensagem não fornecida.'}), 400

    resposta_corrigida = get_gemini_response(user_message)
    return jsonify({'response': resposta_corrigida})

# Inicialização das extensões
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)

# Modelo de Usuário
class User(UserMixin, db.Model):
    """Modelo do Usuário"""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # Gerar um segredo aleatório
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

# Modelo de Auditoria
class Audit(db.Model):
    """Modelo de Logs de Auditoria"""
    __tablename__ = 'audits'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(64), nullable=False)
    action = db.Column(db.String(128), nullable=False)
    username = db.Column(db.String(64), nullable=False)

    def __init__(self, timestamp, action, username):
        self.timestamp = timestamp
        self.action = action
        self.username = username

# Inicialização do LoginManager
@lm.user_loader
def load_user(user_id):
    """Carregar usuário pelo ID"""
    return User.query.get(int(user_id))

# Formulário de Registro
class RegisterForm(FlaskForm):
    """Formulário de Registro"""
    username = StringField('Nome', validators=[DataRequired(), Length(1, 64)])
    password = PasswordField('Senha', validators=[DataRequired()])
    password_again = PasswordField('Senha, novamente',
                                   validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

# Formulário de Login
class LoginForm(FlaskForm):
    """Formulário de Login"""
    username = StringField('Nome', validators=[DataRequired(), Length(1, 64)])
    password = PasswordField('Senha', validators=[DataRequired()])
    token = StringField('Codigo de verificacao', validators=[DataRequired(), Length(6, 6)])
    submit = SubmitField('Entrar')

# Rota Principal
@app.route('/')
def index():
    return render_template('index.html')

# Rota de Registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Rota de Registro de Usuário"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('register'))
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

        session['username'] = user.username
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html', form=form)

# Rota de Setup do 2FA
@app.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('index'))
    return render_template('two-factor-setup.html')

# Gerar QR Code
@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    del session['username']

    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

# Rota de Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Rota de Login do Usuário"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data) or \
                not user.verify_totp(form.token.data):
            flash('A sua senha, nome de usuário ou codigo de verificação estao incorretos.')
            return redirect(url_for('Entrar'))

        login_user(user)

        # Registrar ação de login na auditoria
        audit = Audit(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M"), action="Login", username=user.username)
        db.session.add(audit)
        db.session.commit()

        flash('Voce esta logado!')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

# Rota de Logout
@app.route('/logout')
def logout():
    """Rota de Logout do Usuário"""
    if current_user.is_authenticated:
        # Registrar ação de logout na auditoria
        audit = Audit(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M"), action="Logout", username=current_user.username)
        db.session.add(audit)
        db.session.commit()

        logout_user()
    return redirect(url_for('index'))

# Rota de Auditoria
@app.route('/audits')
def audits():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    audits = Audit.query.order_by(Audit.timestamp.desc()).all()
    
    return render_template('audits.html', audits=audits)

# Rota de Perguntas e Respostas com a API Wit.ai
@app.route('/ask', methods=['GET', 'POST'])
def ask():
    answer = ''
    if request.method == 'POST':
        question = request.form['question']
        answer = get_gemini_response(question)

    return render_template('ask.html', answer=answer)

if __name__ == '__main__':
    app.run(debug=True)
