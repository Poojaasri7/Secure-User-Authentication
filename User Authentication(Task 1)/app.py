from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = "Helloworld"  # Replace with a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_details.db'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Set session duration
app.config['SESSION_COOKIE_SECURE'] = False  # Should be True in production with HTTPS
app.config['SESSION_USE_SIGNER'] = True

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'
login_manager.session_protection = "strong"  

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)              
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/index', methods=["POST", "GET"])
def index():
    if request.method == "POST":
        username = request.form['username1']
        password = request.form['password1']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            if user.role == "admin":
                return render_template('redirect.html', target='admin_dashboard')
            else:
                return render_template('redirect.html', target='dashboard')
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    return render_template("index.html", name="LOGIN")
@app.route('/logout', methods=["POST"])
def logout():
    logout_user()  # Clear session data on server-side
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('index')) 

@app.route('/signup', methods=["POST", "GET"])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        user_by_email = User.query.filter_by(email=email).first()
        user_by_username = User.query.filter_by(username=username).first()
        if user_by_email or user_by_username:
            flash('Username or email is already registered. Please use a different username or email or log in.', 'danger')
            return redirect(url_for('signup'))

        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$', password):
            flash('Password must contain at least 8 characters, including an uppercase letter, a lowercase letter, a number, and a special symbol.', 'danger')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('index'))

    return render_template('index.html', name="signup")

@app.route('/admin_dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    if current_user.is_authenticated:
        users = User.query.all()
        return render_template('admin_dashboard.html', users=users)
    else:
        flash('You are not authenticated!')
        return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    if current_user.is_authenticated:
        return render_template('dashboard.html', user1=current_user.username, email=current_user.email)
    else:
        flash('You are not authenticated!')
        return redirect(url_for('index')) 
@app.route('/js_logout', methods=['POST'])
@login_required
def js_logout():
    if current_user.is_authenticated:
        logout_user()
        session.pop('_flashes', None)  # Clear flash messages
    return '', 204     

@app.route('/delete/<int:user_id>', methods=["POST"])
@login_required
def delete(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/update_role/<int:user_id>', methods=["POST"])
@login_required
def update_role(user_id):
    user = User.query.get(user_id)
    if user:
        new_role = request.form['role']
        user.role = new_role
        db.session.commit()
        flash(f'Role updated to {new_role} for user {user.username}.', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin_dashboard'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
