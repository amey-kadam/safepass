from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
import os, uuid, qrcode
from pathlib import Path
from PIL import Image, ImageDraw
from io import BytesIO
from flask import send_file
from models import db, User, EmergencyContact, Admin

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///emergency_contact.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}


# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'auth'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
# Update these routes in app.py

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # If user is already logged in and is admin, redirect to dashboard
    if current_user.is_authenticated and hasattr(current_user, 'is_admin') and current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # First try User model with is_admin=True
        admin = User.query.filter_by(email=email, is_admin=True).first()
        
        if admin and admin.check_password(password):
            login_user(admin)
            # Add a flash message for successful login
            flash('Successfully logged in as admin', 'success')
            return redirect(url_for('admin_dashboard'))
        
        # If no admin user found or password incorrect
        flash('Invalid email or password', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    # Add print statements for debugging
    print(f"Current user: {current_user}")
    print(f"Is authenticated: {current_user.is_authenticated}")
    print(f"Is admin: {getattr(current_user, 'is_admin', False)}")
    
    # Check if user is admin
    if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
        flash('Unauthorized access. Admin privileges required.', 'error')
        return redirect(url_for('home'))
    
    # Fetch pending contacts for admin review
    pending_contacts = EmergencyContact.query.filter_by(status='pending').all()
    return render_template('admin.html', contacts=pending_contacts)

# Add a route to create an admin user
@app.route('/create-admin', methods=['GET', 'POST'])
def create_admin():
    try:
        # Check if admin already exists
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin = User(
                email='admin@example.com',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            return 'Admin user created successfully'
        return 'Admin user already exists'
    except Exception as e:
        db.session.rollback()
        return f'Error creating admin: {str(e)}'

@app.route('/api/placeholder/<int:width>/<int:height>')
def placeholder(width, height):
    # Create a new image with a light gray background
    img = Image.new('RGB', (width, height), color='#CCCCCC')
    draw = ImageDraw.Draw(img)
    
    # Draw the dimensions as text
    text = f'{width}x{height}'
    # Get text size
    text_bbox = draw.textbbox((0, 0), text)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]
    
    # Calculate text position to center it
    x = (width - text_width) // 2
    y = (height - text_height) // 2
    
    # Draw the text in dark gray
    draw.text((x, y), text, fill='#666666')
    
    # Save the image to a bytes buffer
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png')


# Update the approve_contact route
@app.route('/admin/approve/<int:contact_id>')
@login_required
def approve_contact(contact_id):
    if not (isinstance(current_user, Admin) or 
            (isinstance(current_user, User) and current_user.is_administrator())):
        return jsonify({'error': 'Unauthorized'}), 403
    
    contact = EmergencyContact.query.get_or_404(contact_id)
    contact.status = 'approved'
    db.session.commit()
    
    # Generate QR code here
    try:
        qr_data = url_for('scan_result', unique_id=contact.unique_id, _external=True)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        qr_filename = f"qr_code_{contact.unique_id}.png"
        qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)
        img.save(qr_path)
        
        contact.qr_code_path = qr_filename
        db.session.commit()
    except Exception as e:
        flash(f'Error generating QR code: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/deny/<int:contact_id>', methods=['POST'])
@login_required
def deny_contact(contact_id):
    if not isinstance(current_user, Admin):
        return jsonify({'error': 'Unauthorized'}), 403
    
    contact = EmergencyContact.query.get_or_404(contact_id)
    contact.status = 'denied'
    contact.admin_comment = request.form.get('comment', '')
    db.session.commit()
    
    return redirect(url_for('admin_dashboard'))

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


@app.route('/view-document/<filename>', methods=['GET', 'POST'])
def view_document(filename):
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            # If login is successful, redirect to download
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
        else:
            flash('Invalid email or password', 'error')
            return render_template('view.html', filename=filename)
    
    return render_template('view.html', filename=filename)

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
            
            # Create new contact record with pending status
            new_contact = EmergencyContact(
                name=name,
                contact=contact,
                document_path=filename,
                unique_id=unique_id,
                user_id=current_user.id,
                status='pending'
            )
            db.session.add(new_contact)
            db.session.commit()
            
            flash('Your QR code request has been submitted for approval', 'success')
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
    return render_template('error.html', 
                         error_code=404,
                         error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html',
                         error_code=500,
                         error_message="Internal server error"), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)