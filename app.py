from flask import Flask, render_template,request,flash,redirect,url_for,session, logging
from flask_bootstrap import Bootstrap
#from data import Articles
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, PasswordField, TextAreaField,validators,BooleanField
from passlib.hash import sha256_crypt
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import datetime
app=Flask(__name__)
bootstrap = Bootstrap(app)
#Articles=Articles()

#app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+mysqlconnector://ogedegbemaurice:Damilola@ogedegbemaurice.mysql.pythonanywhere-services.com/ogedegbemaurice$lozenge_training"

#app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
#app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


app.config['SECRET_KEY'] = 'secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:''@localhost:3307/Lozenge_training'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app) # this brings about the connection

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unathorized, Please login','danger')
            return redirect(url_for('login'))
    return wrap

def is_admin(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unathorized, Please login as admin','danger')
            return redirect(url_for('admin_login'))
    return wrap

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/articles')
@is_logged_in
def articles():
    article= articles.query.all()
    if article:
        return render_template('articles.html',article=article) #updates the articles table with the available article instnatiated
    else:
        msg = 'No Articles Found'
    return render_template('articles.html',msg=msg)
    #return render_template('articles.html', articles=Articles) # the paremeter passed in is the result from data.py

@app.route('/article/<string:id>/')
def article(id):
    article = articles.query.get(id)
    return render_template('article.html', article=article)

class users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(15), unique=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    confirm = db.Column(db.String(80))


    def __init__(self, fname,username, email, password,confirm):
        self.fname = fname
        self.username = username
        self.email = email
        self.password = password
        self.confirm = confirm

class RegisterForm(Form):
    fname = StringField('fname', [validators.Length(min=1,max=50)])
    username = StringField('username', [validators.Length(min=4,max=25)])
    email = StringField('email', [validators.Length(min=6,max=50)])
    password = PasswordField('password', [
        validators.DataRequired(),
        validators.EqualTo('confirm',message='Passwords do not match')
        ])
    confirm = PasswordField('Confirm Password')

@app.route('/signup', methods=['GET', 'POST']) # GET is by default for all routes but bcos we need POST, hence specific need to state it
def signup():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        hashed_password = generate_password_hash(form.password.data, method='sha256')


        new_user = users(fname=form.fname.data,username=form.username.data, email=form.email.data, password=hashed_password, confirm=hashed_password)
        db.session.add(new_user)
        db.session.commit()


        flash('you are now registered and can log in', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


class LoginForm(Form):
    username = StringField('username', [validators.Length(min=4,max=25)])
    password = PasswordField('password', [validators.DataRequired()])
    remember = BooleanField('remember me')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        user = users.query.filter_by(username=form.username.data).first()

        if user:
            if check_password_hash(user.password, form.password.data):
                session['logged_in'] = True
                session['username'] = form.username.data
                flash('you are now logged in','success')
                return redirect(url_for('articles'))
            error = 'invalid password'
            return render_template('login.html',form=form,error=error)
        error ='Invalid username'
        return render_template('login.html',form=form,error=error)
    return render_template('login.html', form=form)


class admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(15), unique=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


    def __init__(self, fname,username, email, password):
        self.fname = fname
        self.username = username
        self.email = email
        self.password = password


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        admin_1 = admin.query.filter_by(username=form.username.data).first()

        if admin_1:
            if admin_1.password== form.password.data:
                session['admin_logged_in'] = True
                session['username'] = form.username.data
                flash('you are now logged in as admin','success')
                return redirect(url_for('dashboard'))
            error = 'You do not have admin right'
            return render_template('admin_login.html',form=form,error=error)
        error ='Invalid admin username'
        return render_template('admin_login.html',form=form,error=error)
    return render_template('admin_login.html', form=form)


@app.route('/dashboard')
@is_admin
def dashboard():
    article= articles.query.all()
    if article:
        return render_template('dashboard.html',article=article, date=datetime.datetime.now()) #updates the articles table with the available article instnatiated
    else:
        msg = 'No Articles Found'
    return render_template('dashboard.html',msg=msg)

class articles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), unique=True)
    author = db.Column(db.String(50), unique=True)
    body = db.Column(db.Text(1000), unique=True)
    create_date = db.Column(db.DateTime, default=datetime)

    def __init__(self, title,author,body,create_date):
        self.title = title
        self.author = author
        self.body = body
        self.create_date = create_date


class ArticleForm(Form):
    title = StringField('title', [validators.Length(min=1,max=50)])
    author = StringField('title', [validators.Length(min=1,max=50)])
    body = TextAreaField('body', [validators.Length(min=30)])

@app.route('/add_article',methods=['GET','POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        author = form.author.data
        body = form.body.data

        new_article = articles(title=form.title.data,author=form.author.data, body=form.body.data,create_date=datetime.datetime.now())
        db.session.add(new_article)
        db.session.commit()

        flash('Article created','success')
        return redirect(url_for('dashboard'))
    return render_template('add_article.html',form=form)



@app.route('/edit_article/<string:id>',methods=['GET','POST'])
@is_logged_in
def edit_article(id):
    article = articles.query.get(id)
    form = ArticleForm(request.form)

    form.title.data = article.title
    form.author.data = article.author
    form.body.data = article.body

    if request.method == 'POST' and form.validate():
        article.title = request.form['title']
        article.author = request.form['author']
        article.body = request.form['body']

        article = articles(title=article.title,author=article.author, body=article.body,create_date=datetime.datetime.now())
        db.session.commit()

        flash('Article updated','success')
        return redirect(url_for('dashboard'))
    return render_template('edit_article.html',form=form)

@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    article = articles.query.get(id)
    db.session.delete(article)
    db.session.commit()

    flash('Article deleted', 'success')
    return redirect(url_for('dashboard'))



@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('you are now logged out','success')
    return redirect(url_for('login'))

@app.route('/logout_admin')
@is_admin
def logout_admin():
    session.clear()
    flash('you are now logged out as admin','success')
    return redirect(url_for('admin_login'))



if __name__ == '__main__':
    app.run(debug=True)