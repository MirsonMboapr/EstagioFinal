import os

SECRET_KEY = 'top-secret'
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///C:/Users/mirso/OneDrive/Ambiente de Trabalho/HEART/heart7/db.sqlite')
SQLALCHEMY_TRACK_MODIFICATIONS = False
