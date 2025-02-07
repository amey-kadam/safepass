from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import qrcode
from io import BytesIO
import base64
import uuid
import random
from datetime import datetime, timezone
from flask import jsonify
import os
from pathlib import Path

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///emergency_contact.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key' 
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

upload_folder = Path(app.config['UPLOAD_FOLDER'])
upload_folder.mkdir(parents=True, exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'auth'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Emergency Contact model
class EmergencyContact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    contact = db.Column(db.String(20), nullable=False)
    document_path = db.Column(db.String(255), nullable=True)
    qr_code_path = db.Column(db.String(255), nullable=True)
    unique_id = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_accessed = db.Column(db.DateTime)
    user = db.relationship('User', backref=db.backref('contacts', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_login = datetime.utcnow()
        db.session.commit()

@app.route('/')
def home():
    return render_template('landing.html')

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        action = request.form.get('action')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required', 'error')
            return redirect(url_for('auth'))

        if action == 'login':
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                login_user(user)
                user.last_login = datetime.utcnow()
                db.session.commit()
                return redirect(url_for('dashboard'))
            flash('Invalid email or password', 'error')
        
        elif action == 'signup':
            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'error')
                return redirect(url_for('auth'))
            
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'error')
                return redirect(url_for('auth'))
            
            new_user = User(email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('dashboard'))

    return render_template('auth.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('home.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home')) 


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('dashboard'))
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    new_contact = EmergencyContact(name=request.form['name'], contact=request.form['contact'], document_path=file_path, user_id=current_user.id)
    db.session.add(new_contact)
    db.session.commit()
    
    flash('File uploaded successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/scan/<unique_id>')
def scan_result(unique_id):
    contact = EmergencyContact.query.filter_by(unique_id=unique_id).first_or_404()
    return render_template('opt_pg.html', 
                         unique_id=unique_id)

@app.route('/authorize/<unique_id>')
def authorize(unique_id):
    contact = EmergencyContact.query.filter_by(unique_id=unique_id).first_or_404()
    return render_template('authorize.html',
                         name=contact.name,
                         contact=contact.contact,
                         document_filename=contact.document_path)

@app.route('/emergency/<unique_id>')
def emergency(unique_id):
    contact = EmergencyContact.query.filter_by(unique_id=unique_id).first_or_404()
    contact.last_accessed = datetime.utcnow()
    db.session.commit()
    return render_template('emergency.html',
                         name=contact.name,
                         contact=contact.contact,
                         document_filename=contact.document_path)

@app.route('/info/<int:user_id>/options')
def options_page(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('opt_pg.html', user_id=user_id)

@app.route('/generate_qr', methods=['GET', 'POST'])
@login_required
def generate_qr():
    if request.method == 'POST':
        name = request.form.get('name')
        contact = request.form.get('contact')
        
        if not name or not contact:
            flash('Name and contact are required', 'error')
            return redirect(url_for('dashboard'))
        
        if 'document' not in request.files:
            flash('No document file uploaded', 'error')
            return redirect(url_for('dashboard'))
        
        file = request.files['document']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('dashboard'))
        
        if not allowed_file(file.filename):
            flash('Invalid file type', 'error')
            return redirect(url_for('dashboard'))
        
        try:
            # Generate unique ID
            unique_id = str(uuid.uuid4())
            
            # Save the document file
            filename = secure_filename(file.filename)
            document_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(document_path)
            
            # Create new contact record
            new_contact = EmergencyContact(
                name=name,
                contact=contact,
                document_path=filename,
                unique_id=unique_id,
                user_id=current_user.id
            )
            db.session.add(new_contact)
            db.session.commit()
            
            # Generate QR code with the scan_result URL
            try:
                qr_data = url_for('scan_result', unique_id=unique_id, _external=True)
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
                qr.add_data(qr_data)
                qr.make(fit=True)
                
                img = qr.make_image(fill_color="black", back_color="white")
                qr_filename = f"qr_code_{unique_id}.png"
                qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)
                img.save(qr_path)
                
                new_contact.qr_code_path = qr_filename
                db.session.commit()
                
                # Generate base64 QR code image
                buffer = BytesIO()
                img.save(buffer, format="PNG")
                buffer.seek(0)
                img_str = base64.b64encode(buffer.getvalue()).decode()
                qr_code_url = f"data:image/png;base64,{img_str}"
                
                return render_template('qr_code.html', 
                                    qr_code_url=qr_code_url,
                                    contact_name=name,
                                    contact_number=contact)
            
            except Exception as qr_error:
                print(f"QR Code Generation Error: {str(qr_error)}")
                if os.path.exists(document_path):
                    os.remove(document_path)
                db.session.delete(new_contact)
                db.session.commit()
                flash(f'Error generating QR code: {str(qr_error)}', 'error')
                return redirect(url_for('dashboard'))
                
        except Exception as e:
            print(f"General Error: {str(e)}")
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('dashboard'))
    
    return render_template('home.html')



@app.route('/send_location', methods=['POST'])
def send_location():
    return jsonify({"status": "success", "message": "Location sent successfully"})

@app.route('/my-qrcodes')
@login_required
def my_qrcodes():
    contacts = EmergencyContact.query.filter_by(user_id=current_user.id).order_by(EmergencyContact.created_at.desc()).all()
    return render_template('my_qrcodes.html', contacts=contacts)


@app.route('/delete-contact/<int:contact_id>')
@login_required
def delete_contact(contact_id):
    contact = EmergencyContact.query.get_or_404(contact_id)
    
    # Verify that the contact belongs to the current user
    if contact.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('my_qrcodes'))
    
    try:
        # Delete the QR code file if it exists
        if contact.qr_code_path:
            qr_file_path = os.path.join(app.config['UPLOAD_FOLDER'], contact.qr_code_path)
            if os.path.exists(qr_file_path):
                os.remove(qr_file_path)
        
        # Delete the document file if it exists
        if contact.document_path:
            doc_file_path = os.path.join(app.config['UPLOAD_FOLDER'], contact.document_path)
            if os.path.exists(doc_file_path):
                os.remove(doc_file_path)
        
        # Delete the database record
        db.session.delete(contact)
        db.session.commit()
        flash('Contact and associated files deleted successfully', 'success')
    except Exception as e:
        flash('Error deleting contact', 'error')
    
    return redirect(url_for('my_qrcodes'))



@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)