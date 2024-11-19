from flask import Flask, render_template, request, redirect, url_for, session,flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os,uuid
from functools import wraps
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.secret_key = 'your_secret_key'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    room_number = db.Column(db.String(20), nullable=True) 
    reset_token = db.Column(db.String(36), unique=True, nullable=True) 


    approved = db.Column(db.Boolean, default=False)
class UserSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='sessions')

User.sessions = db.relationship('UserSession', back_populates='user', cascade='all, delete')

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
class Warning(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(256), nullable=False)
    requires_response = db.Column(db.Boolean, default=False)  
class WarningResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    warning_id = db.Column(db.Integer, db.ForeignKey('warning.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    response = db.Column(db.Text, nullable=True)
    
    warning = db.relationship('Warning', backref=db.backref('responses', lazy=True))
    user = db.relationship('User', backref=db.backref('responses', lazy=True))

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    image_url = db.Column(db.String(255), nullable=True) 

    def __init__(self, title, description, image_url=None):
        self.title = title
        self.description = description
        self.image_url = image_url

with app.app_context():
    db.create_all()

    if not Admin.query.filter_by(username='admin').first():
        admin = Admin(username='admin', password=generate_password_hash('admin'))
        db.session.add(admin)
        db.session.commit()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/warnings', methods=['GET', 'POST'])
def user_warnings():
    if 'user_id' in session:
        warnings = Warning.query.all()
        if request.method == 'POST':
            warning_id = request.form['warning_id']
            response = request.form['response']
            user_id = session['user_id']
            
            new_response = WarningResponse(warning_id=warning_id, user_id=user_id, response=response)
            db.session.add(new_response)
            db.session.commit()
            flash('Cavabınız uğurla göndərildi.', 'success')
            return redirect(url_for('user_warnings'))

        return render_template('user_warnings.html', warnings=warnings)
    return redirect(url_for('login'))
@app.route('/admin/warning_responses')
@admin_required
def warning_responses():
    responses = WarningResponse.query.all()
    return render_template('admin/warning_responses.html', responses=responses)

@app.route('/submit_complaint', methods=['POST'])
def submit_complaint():
    complaint_message = request.form['complaint']
    room_number = request.form['room_number']
    
    new_complaint = Complaint(room_number=room_number, message=complaint_message)
    db.session.add(new_complaint)
    db.session.commit()
    
    return redirect(url_for('user_room_management'))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/admin/events', methods=['GET', 'POST'])
@admin_required
def admin_events():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        image = request.files.get('image')
        image_url = None

        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        new_event = Event(title=title, description=description, image_url=image_url)
        db.session.add(new_event)
        db.session.commit()

        flash("Etkinlik başarıyla eklendi.", 'success')
        return redirect(url_for('admin_events')) 

    events = Event.query.order_by(Event.timestamp.desc()).all()
    
    return render_template('admin/admin_events.html', events=events)
@app.route('/admin/complaints')
@admin_required
def view_complaints():
    complaints = Complaint.query.all()
    return render_template('view_complaints.html', complaints=complaints)

@app.route('/admin/delete_all_warnings', methods=['POST'])
@admin_required
def delete_all_warnings():
    db.session.query(Warning).delete()
    db.session.commit()
    return redirect(url_for('add_warning'))  

@app.route('/admin/warnings', methods=['GET', 'POST'])
@admin_required
def add_warning():
    if 'admin_logged_in' in session:
        if request.method == 'POST':
            message = request.form['message']
            requires_response = 'requires_response' in request.form  
            
            new_warning = Warning(message=message, requires_response=requires_response)
            db.session.add(new_warning)
            db.session.commit()
            return redirect(url_for('add_warning')) 

        warnings = Warning.query.all()
        return render_template('admin/announcements.html', warnings=warnings)
    return redirect(url_for('admin_login'))


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('index'))
    
class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<LoginLog {self.ip_address} at {self.timestamp}>'
    
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password, password):
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
            
            new_log = LoginLog(ip_address=ip_address)
            db.session.add(new_log)
            db.session.commit()
            
            session['admin_logged_in'] = True
            return redirect(url_for('admin_home'))
    
    return render_template('admin/admin_login.html')

@app.route('/admin/home')
def admin_home():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(10).all()
    
    return render_template('admin/admin_home.html', logs=logs)


@app.route('/admin/delete_event/<int:event_id>', methods=['POST'])
@admin_required
def delete_event(event_id):
    event = Event.query.get(event_id)
    if event:
        db.session.delete(event)
        db.session.commit()
    return redirect(url_for('admin_events'))


@app.route('/admin/user_management')
@admin_required
def user_management():
    users = User.query.all()
    return render_template('admin/user_management.html', users=users)


@app.route('/admin/approve_user/<int:user_id>', methods=['POST'])
@admin_required
def approve_user(user_id):
    user = User.query.get(user_id)
    if user:
        room_number = request.form['room_number']
        user.room_number = room_number
        user.approved = True
        db.session.commit()
    return redirect(url_for('user_management'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        uuid = request.form.get('uuid')
        
        user = User.query.filter_by(reset_token=uuid).first()

        if user:
            return redirect(url_for('reset_password_confirm', token=uuid))
        else:
            flash("Token Səhvdir!", 'error')
            return redirect(url_for('reset_password'))
    
    return render_template('reset_password.html')


@app.route('/reset_password_confirm/<token>', methods=['GET', 'POST'])
def reset_password_confirm(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user:
        flash("Geçersiz token", 'error')
        return redirect(url_for('reset_password'))

    if request.method == 'POST':
        new_password = request.form['password']

        if len(new_password) < 8:
            flash("Şifrə ən az 8 simvol olmalıdır.", 'error')
            return redirect(url_for('reset_password_confirm', token=token))

        user.password = generate_password_hash(new_password)
        user.reset_token = None 

        db.session.commit()

        flash("Şifrəniz Uğurla Dəyişdirildi.", 'success')
        return redirect(url_for('login'))

    return render_template('reset_password_confirm.html', token=token)

@app.route('/admin/room_management')
@admin_required
def admin_room_management():
    complaints = Complaint.query.all() 
    return render_template('admin/admin_room_management.html', complaints=complaints)

@app.route('/admin/announcements', methods=['GET', 'POST'])
@admin_required
def announcements():
    if 'admin_logged_in' in session:
        if request.method == 'POST':
            message = request.form['message']
            new_warning = Warning(message=message)
            db.session.add(new_warning)
            db.session.commit()
            return redirect(url_for('announcements')) 

        warnings = Warning.query.all() 
        return render_template('admin/announcements.html', warnings=warnings)
    return redirect(url_for('admin_login'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if len(password) < 8:
            flash("Şifrəniz Ən Azı 8 Simvoldan İbarət Olmalıdır !", 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)

        if not email.endswith('@karabakh.edu.az'):
            flash("Sadəcə Sizə Verilmiş Korporativ Mail(karabakh.edu.az) İstifadə Edin", 'error')
            return redirect(url_for('register'))
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Bu mail ilə artıq hesab yaradılıb", 'error')
            return redirect(url_for('register'))
        
        reset_token = str(uuid.uuid4())  

        new_user = User(
            email=email,
            password=hashed_password,
            room_number=None,
            approved=False,
            reset_token=reset_token 
        )

        db.session.add(new_user)
        db.session.commit()

        return render_template('registration_pending.html') 

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            if user.approved: 
                session['user_id'] = user.id
                return redirect(url_for('user_interface'))  
            else:
                flash('Təsdiq üçün gözlənilir .')  
        else:
            flash('Məlumatlar düzgün deyil !') 

    return render_template('login.html')
@app.route('/user_interface')
def user_interface():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.approved:
            return render_template('user_interface.html', user=user)
        else:
            flash("İstifadəçi tapılmadı ","error")
            return redirect(url_for('login'))  

    return redirect(url_for('login'))  

@app.route('/profile')
def profile():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.approved:
            return render_template('profile.html', user=user)
        else:
            return redirect(url_for('home'))  
    return redirect(url_for('home'))

@app.route('/user/room_management', methods=['GET'])
def user_room_management():
    if 'user_id' in session:
        room_number = User.query.filter_by(id=session['user_id']).first().room_number

        return render_template('user_room_management.html', room_number=room_number)
    return redirect(url_for('login'))

@app.route('/events')
def events():
    if 'user_id' in session:
        events = Event.query.order_by(Event.timestamp.desc()).all()
        return render_template('events.html', events=events)
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True)
