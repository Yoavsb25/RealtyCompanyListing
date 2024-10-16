# app.py
from dotenv import load_dotenv
import os
import uuid
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_from_directory, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FloatField, IntegerField, BooleanField, SubmitField, FileField, PasswordField, MultipleFileField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer

load_dotenv()

email = os.getenv("EMAIL")
password = os.getenv("PASSWORD")
mail_server = os.getenv("MAIL_SERVER")
# Application Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///properties.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = mail_server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = email
app.config['MAIL_PASSWORD'] = password
app.config['MAIL_DEFAULT_SENDER'] = email
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt'}



# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    bedrooms = db.Column(db.Integer, nullable=False)
    bathrooms = db.Column(db.Integer, nullable=False)
    square_footage = db.Column(db.Integer, nullable=False)
    images = db.Column(db.JSON, nullable=False, default=list)
    files = db.relationship('PropertyFile', backref='property', lazy=True, cascade="all, delete-orphan")
    tenants = db.Column(db.String(100))
    buying_price = db.Column(db.Float)
    year_bought = db.Column(db.Integer)
    current_value = db.Column(db.Float)


class PropertyFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

# Forms

class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    is_admin = BooleanField('Admin')
    submit = SubmitField('Save Changes')
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('New Password', validators=[EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField('Confirm New Password')
    submit = SubmitField('Update Profile')

class AddPropertyForm(FlaskForm):
    name = StringField('Property Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    bedrooms = IntegerField('Bedrooms', validators=[DataRequired()])
    bathrooms = IntegerField('Bathrooms', validators=[DataRequired()])
    square_footage = IntegerField('Square Footage', validators=[DataRequired()])
    images = FileField('Images (optional)')
    files = MultipleFileField('Additional Files')
    tenants = StringField('Tenants')
    buying_price = FloatField('Buying Price')
    year_bought = IntegerField('Year Bought')
    current_value = FloatField('Current Value')
    submit = SubmitField('Add Property')


# Utility functions
def allowed_file(filename, allowed_extensions=None):
    if allowed_extensions is None:
        allowed_extensions = app.config['ALLOWED_EXTENSIONS']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def generate_reset_token(email):
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return None
    return email


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check your credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        if form.email.data != current_user.email:
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash('Email already exists. Please choose another.', 'danger')
                return redirect(url_for('profile'))
        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.password.data:
            current_user.set_password(form.password.data)
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', title='Your Profile', form=form)

@app.route('/properties')
def properties():
    properties = Property.query.all()
    return render_template('our_properties.html', properties=properties, search_active=False)

@app.route('/under_construction')
def under_construction():
    return render_template('under_construction.html')

@app.route('/property/<int:property_id>/document/<int:document_id>')
def download_document(property_id, document_id):
    property_file = PropertyFile.query.filter_by(id=document_id, property_id=property_id).first_or_404()
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        property_file.filename,
        as_attachment=True,
        download_name=property_file.original_filename
    )
@app.route('/add_property', methods=['GET', 'POST'])
@login_required
def add_property():
    form = AddPropertyForm()
    if form.validate_on_submit():
        try:
            new_property = Property(
                name=form.name.data,
                description=form.description.data,
                price=form.price.data,
                location=form.location.data,
                bedrooms=form.bedrooms.data,
                bathrooms=form.bathrooms.data,
                square_footage=form.square_footage.data,
                tenants=form.tenants.data,
                buying_price=form.buying_price.data,
                year_bought=form.year_bought.data,
                current_value=form.current_value.data,
                images=[]
            )

            # Handle image uploads
            if 'images' in request.files:
                images = request.files.getlist('images')
                for image in images:
                    if image and allowed_file(image.filename, app.config['ALLOWED_EXTENSIONS']):
                        filename = secure_filename(image.filename)
                        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        new_property.images.append(filename)

            # Handle additional file uploads
            if 'files' in request.files:
                files = request.files.getlist('files')
                for file in files:
                    if file and allowed_file(file.filename, app.config['ALLOWED_EXTENSIONS']):
                        filename = secure_filename(file.filename)
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                        property_file = PropertyFile(
                            filename=filename,
                            original_filename=file.filename,
                            property=new_property
                        )
                        db.session.add(property_file)

            db.session.add(new_property)
            db.session.commit()

            return jsonify({
                'success': True,
                'redirect': url_for('property_detail', property_id=new_property.id)
            })

        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'message': str(e)
            }), 400

    if form.errors:
        return jsonify({
            'success': False,
            'message': 'Validation error',
            'errors': form.errors
        }), 400

    return render_template('add_property.html', form=form)

@app.route('/download_file/<int:file_id>')
def download_file(file_id):
    property_file = PropertyFile.query.get_or_404(file_id)
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        property_file.filename,
        as_attachment=True,
        download_name=property_file.original_filename
    )

@app.route('/property/<int:property_id>')
def property_detail(property_id):
    property = Property.query.get_or_404(property_id)
    return render_template('property_detail.html', property=property)

@app.route('/search', methods=['GET'])
def search_properties():
    query = request.args.get('query', '')
    min_price = request.args.get('min_price', type=int)
    max_price = request.args.get('max_price', type=int)
    bedrooms = request.args.get('bedrooms', type=int)

    if min_price is not None and max_price is not None and min_price > max_price:
        return "Minimum price cannot be greater than maximum price", 400

    filters = []
    if query:
        filters.append(Property.name.contains(query))
    if min_price is not None:
        filters.append(Property.price >= min_price)
    if max_price is not None:
        filters.append(Property.price <= max_price)
    if bedrooms is not None:
        filters.append(Property.bedrooms == bedrooms)

    properties = Property.query.filter(*filters).all()
    return render_template('our_properties.html', properties=properties, search_active=bool(filters))

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(user.email)
            msg = Message('Password Reset Request', recipients=[user.email])
            msg.body = f'Please click the link to reset your password: {url_for("reset_token", token=token, _external=True)}'
            mail.send(msg)
        flash('If that email is registered, you will receive a password reset email.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html')

@app.route('/reset_token/<token>', methods=['GET', 'POST'])
def reset_token(token):
    email = verify_reset_token(token)
    if email is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        user.set_password(request.form['password'])
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', token=token)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    properties = Property.query.all()
    return render_template('admin_dashboard.html', users=users, properties=properties)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    search_query = request.args.get('search')
    if search_query:
        users = User.query.filter(User.username.contains(search_query) | User.email.contains(search_query)).all()
    else:
        users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm(obj=user)

    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.is_admin = form.is_admin.data
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('profile'))

    return render_template('edit_user.html', user=user, form=form)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/property/delete/<int:property_id>', methods=['POST'])
@login_required
@admin_required
def delete_property(property_id):
    property = Property.query.get_or_404(property_id)

    # Delete associated images
    for image in property.images:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image)
        if os.path.exists(image_path):
            os.remove(image_path)

    # Delete associated files
    for file in property.files:
        # Replace 'file.filename' with the correct attribute that holds the file name
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)  # Adjust this line
        if os.path.exists(file_path):
            os.remove(file_path)

    # Delete the property from the database
    db.session.delete(property)
    db.session.commit()
    flash('Property deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/property/delete/image/<image_id>', methods=['POST'])
@login_required
@admin_required
def delete_image(image_id):
    # Assuming you have a method to get the property by image ID
    property_file = PropertyFile.query.filter_by(id=image_id).first_or_404()

    # Delete the image file from the filesystem
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], property_file.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    # Delete from the database
    db.session.delete(property_file)
    db.session.commit()

    return '', 204  # No content

@app.route('/edit_property/<int:property_id>', methods=['GET', 'POST'])
@login_required
def edit_property(property_id):
    property = Property.query.get_or_404(property_id)
    form = AddPropertyForm(obj=property)

    if form.validate_on_submit():
        # Update property fields
        property.name = form.name.data
        property.description = form.description.data
        property.price = float(form.price.data)
        property.location = form.location.data
        property.bedrooms = int(form.bedrooms.data)
        property.bathrooms = int(form.bathrooms.data)
        property.square_footage = int(form.square_footage.data)

        # Handle deleted images
        deleted_images = request.form.get('deleted_images')
        if deleted_images:
            deleted_image_ids = deleted_images.split(',')
            for image_id in deleted_image_ids:
                if image_id in property.images:
                    # Remove from the property images
                    property.images.remove(image_id)

                    # Remove the file from the file system
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_id)
                    if os.path.exists(image_path):
                        try:
                            os.remove(image_path)
                        except OSError as e:
                            flash(f"Error deleting image: {e}", 'danger')

        # Handle new images
        if 'new_images' in request.files:
            new_images = request.files.getlist('new_images')
            for new_image in new_images:
                # Generate a secure, unique filename to avoid overwriting files
                filename = secure_filename(new_image.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                # Ensure the filename is unique
                while os.path.exists(filepath):
                    filename = f"{uuid.uuid4()}_{filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                # Save the new image and add it to the property images
                new_image.save(filepath)
                property.images.append(filename)

        db.session.commit()
        flash('Property updated successfully!', 'success')
        return redirect(url_for('property_detail', property_id=property.id))

    return render_template('edit_property.html', form=form, property=property)


if __name__ == '__main__':
    app.run(debug=True)