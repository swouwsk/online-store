from flask import Flask, render_template, request, url_for, redirect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from kodland_db import db
import bcrypt
app = Flask(__name__)

app.config.update(
    SECRET_KEY = 'WOW SUCH SECRET'
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

def hashed_password(plain_text_password):
    #Мы добавляем "соль" к нашему паролю, чтобы сделать его декодирование невозможным
    return bcrypt.hashpw(plain_text_password.encode('utf-8'), bcrypt.gensalt())

def check_password(plain_text_password, hashed_password):
    return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed_password)


class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(login):
        return User(login)



@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/products')
@login_required
def products():
    return render_template('products.html')

@app.route('/cart')
@login_required
def cart():
    return render_template('cart.html')

@app.route('/contacts')
@login_required
def contacts():
    return render_template('contacts.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/product1')
@login_required
def product1():
    return render_template('product1.html')

@app.route('/product2')
@login_required
def product2():
    return render_template('product2.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        row = db.users.get('login', request.form['login'])
        if not row:
            return render_template('login.html', error = 'такого логина не существует')
        if check_password(request.form['password'],row.password):
            user = User(login) # Создаем пользователя
            login_user(user) # Логинем пользователя
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error = 'вы неправильно ввели логин или пароль')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        for key in request.form:
            if request.form[key] == '':
                return render_template('register.html', message='Все поля должны быть заполнены!')

        row = db.users.get('login', request.form['login'])
        if row:
            return render_template('register.html', message='Такой пользователь уже существует!')
            
        if request.form['password'] != request.form['password_check']:
            return render_template('register.html', message='Пороли не совпадают')
        data = dict(request.form)
        data['password'] = hashed_password(data['password'])
        data.pop('password_check')
        db.users.put(data=data)
        return render_template('register.html', message='Регистрация прошла успешно')
    return render_template('register.html')
            

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'пока-пока'


if __name__ == "__main__":
    app.run()

