from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
import os, uuid, qrcode
from pathlib import Path
from PIL import Image, ImageDraw
from functools import wraps
from flask import session
from io import BytesIO
from flask import send_file
from models import db, User, EmergencyContact, Admin, Police
from flask_mail import Mail, Message
import random
import string
from models import db, User, EmergencyContact, Admin, Police
from sqlalchemy import inspect


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

app.config['ADMIN_SESSION_KEY'] = 'admin_id'
app.config['USER_SESSION_KEY'] = 'user_id'

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'auth'

def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in as admin', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def user_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in', 'error')
            return redirect(url_for('auth'))
        return f(*args, **kwargs)
    return decorated_function

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

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        admin = User.query.filter_by(email=email, is_admin=True).first()
        
        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            flash('Successfully logged in as admin', 'success')
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid email or password', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_login_required
def admin_dashboard():
    pending_contacts = EmergencyContact.query.filter_by(status='pending').all()
    return render_template('admin.html', pending_contacts=pending_contacts)

@app.route('/dashboard')
@user_login_required
def dashboard():
    user = User.query.get(session.get('user_id'))
    return render_template('home.html', user=user)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None) 
    flash('Logged out from admin successfully', 'success')
    return redirect(url_for('admin_login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)  
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))


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


@app.route('/admin/approve/<int:contact_id>')
@admin_login_required  
def approve_contact(contact_id):
    contact = EmergencyContact.query.get_or_404(contact_id)
    
    try:
        # Generate unique QR code filename
        qr_filename = f"qr_{contact.unique_id}.png"
        qr_path = os.path.join(app.config['UPLOAD_FOLDER'], qr_filename)
        
        # Create QR code URL
        qr_data = url_for('scan_result', unique_id=contact.unique_id, _external=True)
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        # Create and save QR code image
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img.save(qr_path)
        
        # Update contact status and QR code path
        contact.status = 'approved'
        contact.qr_code_path = qr_filename
        db.session.commit()
        
        flash('Contact approved and QR code generated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error generating QR code: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/deny/<int:contact_id>', methods=['POST'])
@admin_login_required  

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
    if 'user_id' in session:
        return redirect(url_for('choice'))

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
                session['user_id'] = user.id
                user.last_login = datetime.utcnow()
                db.session.commit()
                return redirect(url_for('choice'))
            flash('Invalid email or password', 'error')
        
        elif action == 'signup':
            # Check password length - added validation here
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'error')
                return redirect(url_for('auth'))
                
            # Check if passwords match
            confirm_password = request.form.get('confirm_password')
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return redirect(url_for('auth'))
                
            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'error')
                return redirect(url_for('auth'))
            
            new_user = User(email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            return redirect(url_for('choice'))

    return render_template('auth.html')

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('No account found with this email', 'error')
            return redirect(url_for('auth'))

        # Generate and store OTP
        otp = generate_otp()
        otp_store[email] = otp

        # Debugging: Print OTP and email
        print(f"Generated OTP: {otp} for email: {email}")

        # Send OTP via email
        try:
            msg = Message('Password Reset OTP',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            msg.body = f'Your OTP is: {otp} (valid for 3 minutes)'
            mail.send(msg)
            flash('OTP sent to your email', 'success')
        except Exception as e:
            flash('Failed to send OTP. Try again.', 'error')
            print(f"Email error: {str(e)}")

        return redirect(url_for('auth', show_otp=True, email=email))

@app.route('/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    if request.method == 'POST':
        email = request.form.get('email')
        otp1 = request.form.get('otp1')
        otp2 = request.form.get('otp2')
        otp3 = request.form.get('otp3')
        otp4 = request.form.get('otp4')
        otp5 = request.form.get('otp5')
        otp6 = request.form.get('otp6')
        
        # Combine the OTP digits
        submitted_otp = otp1 + otp2 + otp3 + otp4 + otp5 + otp6
        
        # Check if the OTP matches
        if email in otp_store and otp_store[email] == submitted_otp:
            new_password = request.form.get('new_password')
            
            # Update the user's password
            user = User.query.filter_by(email=email).first()
            if user:
                user.set_password(new_password)
                db.session.commit()
                
                # Clear the OTP
                del otp_store[email]
                
                flash('Password reset successfully', 'success')
                return redirect(url_for('auth'))
        
        flash('Invalid OTP. Please try again', 'error')
        return redirect(url_for('auth'))
    
    return redirect(url_for('auth'))


@app.route('/police/login/<unique_id>', methods=['GET', 'POST'])
def police_login(unique_id):
    if request.method == 'POST':
        badge_number = request.form.get('badge_number')
        password = request.form.get('password')
        
        police = Police.query.filter_by(badge_number=badge_number).first()
        
        if police and police.check_password(password):
            police.last_login = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('authorize', unique_id=unique_id))
        
        flash('Invalid badge number or password', 'error')
    
    return render_template('police_login.html')

# Add this route to create a test police account
@app.route('/create-police', methods=['GET'])
def create_police():
    try:
        # Check if test police account already exists
        police = Police.query.filter_by(badge_number='P001').first()
        if not police:
            police = Police(
                badge_number='P001',
                email='police@example.com',
                station='Central Police Station'
            )
            police.set_password('police123')
            db.session.add(police)
            db.session.commit()
            return 'Police account created successfully'
        return 'Police account already exists'
    except Exception as e:
        db.session.rollback()
        return f'Error creating police account: {str(e)}'

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/upload', methods=['POST'])
@user_login_required 
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
@user_login_required  
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
    
    
    contact_data = {
        'personal': {},
        'vehicle': {},
        'license': {},
        'documents': {}
    }
    
    try:
        if contact.additional_data:
            import json
            contact_data = json.loads(contact.additional_data)
    except Exception as e:
        print(f"Error parsing contact data: {str(e)}")


    personal = contact_data.get('personal', {})
    vehicle = contact_data.get('vehicle', {})
    license_info = contact_data.get('license', {})
    documents = contact_data.get('documents', {})

    
    license_doc = documents.get('driving_license') 
    insurance_doc = documents.get('insurance_policy')  
    puc_doc = documents.get('puc_certificate') 

    return render_template('authorize.html',
                         name=personal.get('name', contact.name),
                         contact=personal.get('mobile', contact.contact),
                         email=personal.get('email', ''),
                         blood_group=personal.get('blood_group', ''),
                         gender=personal.get('gender', ''),
                         vehicle_number=vehicle.get('number', ''),
                         vehicle_model=vehicle.get('model', ''),
                         license_number=license_info.get('number', ''),
                         license_expiry=license_info.get('expiry', ''),
                         profile_pic=documents.get('profile_picture'),
                         license_doc=license_doc,  
                         insurance_doc=insurance_doc, 
                         puc_doc=puc_doc 
                         )


@app.route('/emergency/<unique_id>')
def emergency(unique_id):
    contact = EmergencyContact.query.filter_by(unique_id=unique_id).first_or_404()
    contact.last_accessed = datetime.utcnow()
    db.session.commit()
    
    contact_data = {}
    documents = {}
    
    try:
        if contact.additional_data:
            import json
            data = json.loads(contact.additional_data)
            
            # Extract personal details
            personal = data.get('personal', {})
            vehicle = data.get('vehicle', {})
            license_info = data.get('license', {})
            documents = data.get('documents', {})
            
            profile_pic = documents.get('profile_picture', None)
            
            return render_template('emergency.html',
                               unique_id=unique_id,
                               name=personal.get('name', contact.name),
                               contact=personal.get('mobile', contact.contact),
                               blood_group=personal.get('blood_group', ''),
                               gender=personal.get('gender', ''),
                               profile_pic=profile_pic,
                               contact_data=True)
    except Exception as e:
        print(f"Error parsing contact data: {str(e)}")
    
    return render_template('emergency.html',
                         name=contact.name,
                         contact=contact.contact,
                         document_filename=contact.document_path,
                         contact_data=False)


@app.route('/info/<int:user_id>/options')
def options_page(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('opt_pg.html', user_id=user_id)

@app.route('/generate_qr', methods=['GET', 'POST'])
@user_login_required
def generate_qr():
    if request.method == 'POST':
        try:

            name = request.form.get('full_name')
            dob = request.form.get('date_of_birth')
            gender = request.form.get('gender')
            blood_group = request.form.get('blood_group')
            email = request.form.get('email')
            
            country_code = request.form.get('country_code')
            mobile_number = request.form.get('mobile')
            mobile = f"{country_code}{mobile_number}"
            
            aadhaar_number = request.form.get('aadhaar_number')
            pan_number = request.form.get('pan_number', '')  
            permanent_address = request.form.get('permanent_address')
            current_address = request.form.get('current_address')
            
            # Vehicle Details
            vehicle_number = request.form.get('vehicle_number')
            vehicle_model = request.form.get('vehicle_model')
            vehicle_type = request.form.get('vehicle_type')
            insurance_policy = request.form.get('insurance_policy')
            puc_number = request.form.get('puc_number')
            
            # License Details
            license_number = request.form.get('license_number')
            license_expiry = request.form.get('license_expiry')
            
            # Validate required fields
            required_fields = [name, dob, gender, blood_group, email, mobile, 
                              aadhaar_number, permanent_address, vehicle_number, 
                              license_number, license_expiry]
            
            if not all(required_fields):
                flash('Please fill all required fields', 'error')
                return redirect(url_for('dashboard'))
            
            # Process uploaded documents
            document_paths = {}
            required_documents = ['aadhaar_card', 'driving_license', 'insurance_policy', 'puc_certificate']
            optional_documents = ['pan_card', 'profile_picture']
            
            # Check required documents
            for doc_name in required_documents:
                if doc_name not in request.files or request.files[doc_name].filename == '':
                    flash(f'{doc_name.replace("_", " ").title()} is required', 'error')
                    return redirect(url_for('dashboard'))
                
                file = request.files[doc_name]
                if not allowed_file(file.filename):
                    flash(f'Invalid file type for {doc_name.replace("_", " ").title()}', 'error')
                    return redirect(url_for('dashboard'))
                
                # Save file with unique name
                filename = f"{doc_name}_{uuid.uuid4()}_{secure_filename(file.filename)}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                document_paths[doc_name] = filename
            
            # Process optional documents
            for doc_name in optional_documents:
                if doc_name in request.files and request.files[doc_name].filename != '':
                    file = request.files[doc_name]
                    if allowed_file(file.filename):
                        filename = f"{doc_name}_{uuid.uuid4()}_{secure_filename(file.filename)}"
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(file_path)
                        document_paths[doc_name] = filename
            
            # Create JSON data for all fields
            contact_data = {
                "personal": {
                    "name": name,
                    "dob": dob,
                    "gender": gender,
                    "blood_group": blood_group,
                    "email": email,
                    "country_code": country_code,  
                    "mobile_number": mobile_number,  
                    "mobile": mobile,  
                    "aadhaar_number": aadhaar_number,
                    "pan_number": pan_number,
                    "permanent_address": permanent_address,
                    "current_address": current_address
                },
                "vehicle": {
                    "number": vehicle_number,
                    "model": vehicle_model,
                    "type": vehicle_type,
                    "insurance_policy": insurance_policy,
                    "puc_number": puc_number
                },
                "license": {
                    "number": license_number,
                    "expiry": license_expiry
                },
                "documents": document_paths
            }
            
            # Generate unique ID for the emergency contact
            unique_id = str(uuid.uuid4())
            
            # Store main document as the emergency document (driving license)
            main_document = document_paths.get('driving_license')
            
            # Create new contact record
            user_id = session.get('user_id')
            if not user_id:
                flash('User not logged in', 'error')
                return redirect(url_for('auth'))
            
            import json
            new_contact = EmergencyContact(
                name=name,
                contact=mobile,  # Using mobile as primary contact
                document_path=main_document,
                unique_id=unique_id,
                user_id=user_id,
                status='pending',
                created_at=datetime.utcnow(),
                admin_comment="",
                additional_data=json.dumps(contact_data)  # Store all data as JSON
            )
            
            db.session.add(new_contact)
            db.session.commit()
            
            flash('Your QR code request has been submitted for approval', 'success')
            return redirect(url_for('my_qrcodes'))
            
        except Exception as e:
            print(f"Error in generate_qr: {str(e)}")
            db.session.rollback()
            flash(f'Error generating QR code: {str(e)}', 'error')
            return redirect(url_for('dashboard'))
    
    # GET request - render the form
    blood_groups = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']
    vehicle_types = ['Two Wheeler', 'Car', 'Truck', 'Bus', 'Other']
    return render_template('generate_qr.html', blood_groups=blood_groups, vehicle_types=vehicle_types)



@app.route('/send_location', methods=['POST'])
def send_location():
    return jsonify({"status": "success", "message": "Location sent successfully"})

@app.route('/choice')
def choice():
    return render_template('choice.html')

@app.route('/my-qrcodes')
@user_login_required
def my_qrcodes():
    user = User.query.get(session.get('user_id'))
    contacts = EmergencyContact.query.filter_by(user_id=user.id).order_by(EmergencyContact.created_at.desc()).all()
    return render_template('my_qrcodes.html', contacts=contacts)


@app.route('/delete-contact/<int:contact_id>')
@user_login_required
def delete_contact(contact_id):
    user_id = session.get('user_id')
    contact = EmergencyContact.query.get_or_404(contact_id)
    
    # Verify that the contact belongs to the current user
    if contact.user_id != user_id:
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

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kamey2312@gmail.com'  
app.config['MAIL_PASSWORD'] = 'pmkd stcj wowf vbcc'     
mail = Mail(app)

# Store OTPs temporarily (in production, use Redis or similar)
otp_store = {}

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

@app.route('/send-otp/<unique_id>', methods=['POST'])
def send_otp(unique_id):
    try:
        # Get contact info from database
        contact = EmergencyContact.query.filter_by(unique_id=unique_id).first_or_404()
        
        # Get email from contact's additional data
        try:
            import json
            data = json.loads(contact.additional_data)
            email = data.get('personal', {}).get('email')
            
            if not email:
                return jsonify({'success': False, 'message': 'Email not found'}), 400
            
            otp = generate_otp()
            otp_store[unique_id] = otp
            
            # Send email
            msg = Message('Document Access OTP',
                         sender=app.config['MAIL_USERNAME'],
                         recipients=[email])
            msg.body = f'Your OTP for accessing documents is: {otp}\nThis OTP will expire in 3 minutes.'
            mail.send(msg)
            
            return jsonify({'success': True, 'message': 'OTP sent successfully'})
        except Exception as e:
            return jsonify({'success': False, 'message': f'Error processing contact data: {str(e)}'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/verify-otp/<unique_id>', methods=['POST'])
def verify_otp(unique_id):
    try:
        data = request.get_json()
        otp = data.get('otp')
        
        if not otp:
            return jsonify({'success': False, 'message': 'OTP is required'}), 400
        
        stored_otp = otp_store.get(unique_id)
        
        if not stored_otp:
            return jsonify({'success': False, 'message': 'OTP expired'}), 400
        
        if otp == stored_otp:
            # Clear the OTP after successful verification
            del otp_store[unique_id]
            return jsonify({'success': True, 'message': 'OTP verified successfully'})
        
        return jsonify({'success': False, 'message': 'Invalid OTP'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500




with app.app_context():
    if not inspect(db.engine).get_table_names(): 
        db.create_all()


if __name__ == '__main__':
    app.run(debug=True)