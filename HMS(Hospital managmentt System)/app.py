from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file # type: ignore
from flask_sqlalchemy import SQLAlchemy # type: ignore
import pandas as pd # type: ignore
from io import BytesIO
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore

app = Flask(__name__)
app.secret_key = 'HMS2024CAREtAKER'  # Needed for session management

# Configure the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define the Patient model
class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(20), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    address = db.Column(db.String(200), nullable=False)
    causes = db.Column(db.String(200), nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    appointments = db.relationship('Appointment', backref='patient', lazy=True)

# define the staff model
class Staff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    contact = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=False)  # Field for email
    qualification = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.Integer, nullable=False)  # Field for experience
    dob = db.Column(db.Date, nullable=False)  # New field for Date of Birth
    role = db.Column(db.String(100), nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    age = db.Column(db.Integer, nullable=False)


# Define the Doctor model
class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)  # Unique email field
    address = db.Column(db.String(200), nullable=False)  # Address of the doctor
    qualification = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.String(100), nullable=False)  # Experience as a string (can be modified to Integer if needed)
    dob = db.Column(db.Date, nullable=False)  # Date of birth
    age = db.Column(db.Integer, nullable=False)  # Calculated age
    date_time = db.Column(db.DateTime, default=datetime.utcnow)  # Record creation date and time

    # Relationship to appointments
    appointments = db.relationship('Appointment', backref='doctor', lazy=True)


# Define the Appointment model
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)  # New doctor_id field
    date_time = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.String(200), nullable=False)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # e.g., 'admin', 'user'
    email = db.Column(db.String(150), unique=True, nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    address = db.Column(db.String(250), nullable=True)

# Initialize the database
with app.app_context():
    db.create_all()

    # Check if the admin user already exists        
    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            password_hash=generate_password_hash('adminpassword'),
            role='admin',
            email='admin@example.com',  # Email for admin user
            full_name='Admin User',      # Full name for admin user
            address='123 Admin St, Admin City'  # Address for admin user
        )
        db.session.add(admin_user)

    if not User.query.filter_by(username='user1').first():
        regular_user = User(
            username='user1',
            password_hash=generate_password_hash('userpassword'),
            role='user',
            email='user1@example.com',  # Email for regular user
            full_name='Regular User',    # Full name for regular user
            address='456 User Ave, User City'  # Address for regular user
        )
        db.session.add(regular_user)

    db.session.commit()

# New user route
@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    if 'username' in session and session['role'] == 'admin':  # Only allow admin to create users
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']
            email = request.form['email']  # Get the email from the form
            full_name = request.form['full_name']  # Get the full name from the form
            address = request.form['address']  # Get the address from the form

            if User.query.filter_by(username=username).first():  # Prevent duplicate usernames
                flash('Username already exists. Please choose a different one.')

            elif User.query.filter_by(email=email).first():  # Prevent duplicate emails
                flash('Email already exists. Please choose a different one.')

            else:
                # Hash the password and create a new User instance
                password_hash = generate_password_hash(password)
                new_user = User(
                    username=username,
                    password_hash=password_hash,
                    role=role,
                    email=email,
                    full_name=full_name,  # Include full name
                    address=address       # Include address
                )
                db.session.add(new_user)
                db.session.commit()
                flash('New user created successfully!')
                return redirect(url_for('all_users'))

        return render_template('new_user.html')
    return redirect(url_for('login'))

# All users route
@app.route('/all_users')
def all_users():
    if 'username' in session and session['role'] == 'admin':
        users = User.query.all()
        return render_template('all_users.html', users=users)
    return redirect(url_for('login'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'username' in session and session['role'] == 'admin':
        user = User.query.get(user_id)

        if user is None:
            flash('User not found.')
            return redirect(url_for('all_users'))

        if request.method == 'POST':
            new_username = request.form['username']
            new_email = request.form['email']
            new_password = request.form.get('new_password')
            new_full_name = request.form['full_name']  # Get new full name
            new_address = request.form['address']  # Get new address

            # Check for duplicate username
            if User.query.filter_by(username=new_username).first() and new_username != user.username:
                flash('Username already exists. Please choose a different one.')
            # Check for duplicate email
            elif User.query.filter_by(email=new_email).first() and new_email != user.email:
                flash('Email already exists. Please choose a different one.')
            else:
                user.username = new_username  # Update username
                user.email = new_email  # Update email
                user.full_name = new_full_name  # Update full name
                user.address = new_address  # Update address
                if new_password:  # Only update the password if a new one is provided
                    user.password_hash = generate_password_hash(new_password)  # Hash new password
                db.session.commit()
                flash('User updated successfully!')
                return redirect(url_for('all_users'))

        return render_template('edit_user.html', user=user)

    return redirect(url_for('login'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'username' in session and session['role'] == 'admin':
        user = User.query.get(user_id)

        if user is not None:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully!')
        else:
            flash('User not found.')

        return redirect(url_for('all_users'))

    return redirect(url_for('login'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        
        if request.method == 'POST':
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']

            # Check if current password is correct
            if not check_password_hash(user.password_hash, current_password):
                flash('Current password is incorrect.')
                return redirect(url_for('change_password'))

            # Check if new password and confirm password match
            if new_password != confirm_password:
                flash('New password and confirmation do not match.')
                return redirect(url_for('change_password'))

            try:
                user.password_hash = generate_password_hash(new_password)
                db.session.commit()
                flash('Password changed successfully!')
                return redirect(url_for('dashboard'))
            except Exception as e:
                flash('An error occurred while changing the password. Please try again.')
                # You might want to log the error
                app.logger.error(f"Error changing password: {e}")
                return redirect(url_for('change_password'))

        return render_template('change_password.html', user=user)
    return redirect(url_for('login'))

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find user in the database
        user = User.query.filter_by(username=username).first()

        print(f"Username: {username}, User Found: {user is not None}")  # Debug
        if user:
            print(f"Stored Password Hash: {user.password_hash}")  # Debug
            if check_password_hash(user.password_hash, password):
                session['username'] = username
                session['role'] = user.role
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid password. Please try again.'
        else:
            error = 'User does not exist.'

    return render_template('login.html', error=error)

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)  # Clear the role from session
    return redirect(url_for('login'))

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        role = session.get('role')
        if role == 'admin':
            return render_template('admin_dashboard.html')  # Admin dashboard template
        elif role == 'user':
            return render_template('user_dashboard.html')  # User dashboard template
    return redirect(url_for('login'))

# New Patient route
@app.route('/new_patient', methods=['GET', 'POST'])
def new_patient():
    if 'username' in session:
        if request.method == 'POST':
            name = request.form['name']
            contact = request.form['contact']
            age = int(request.form['age'])  # Convert to integer
            address = request.form['address']
            causes = request.form['causes']
            date_time_str = request.form['date_time']
            date_time = datetime.strptime(date_time_str, '%Y-%m-%dT%H:%M')  # Convert string to datetime object

            # Create a new Patient instance
            new_patient = Patient(
                name=name,
                contact=contact,
                age=age,
                address=address,
                causes=causes,
                date_time=date_time
            )

            # Add to the session and commit to the database
            db.session.add(new_patient)
            db.session.commit()

            # Get the auto-generated patient ID
            patient_id = new_patient.id

            # Flash a success message including the patient ID
            flash(f'New patient added successfully! Patient ID: {patient_id}')
            return redirect(url_for('all_patients'))

        return render_template('new_patient.html')
    return redirect(url_for('login'))

# All Patients route
@app.route('/all_patients')
def all_patients():
    if 'username' in session:
        patients = Patient.query.all()
        return render_template('all_patients.html', patients=patients)
    return redirect(url_for('login'))

# Route to download patients as Excel file
@app.route('/download_patients')
def download_patients():
    if 'username' in session:
        try:
            patients = Patient.query.all()
            df = pd.DataFrame([(p.name, p.contact, p.age, p.address, p.causes, p.date_time) for p in patients],
                              columns=['Name', 'Contact', 'Age', 'Address', 'Causes', 'Date and Time'])
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name='Patients')
            output.seek(0)
            return send_file(output, download_name='patients.xlsx', as_attachment=True)
        except Exception as e:
            flash(f'Error occurred: {e}')
            return redirect(url_for('all_patients'))
    return redirect(url_for('login'))

@app.route('/edit_patient/<int:patient_id>', methods=['GET', 'POST'])
def edit_patient(patient_id):
    if 'username' in session and session['role'] == 'admin':
        patient = Patient.query.get_or_404(patient_id)

        if request.method == 'POST':
            # Update patient information
            patient.name = request.form['name']
            patient.contact = request.form['contact']
            patient.age = int(request.form['age'])
            patient.address = request.form['address']
            patient.causes = request.form['causes']
            date_time_str = request.form['date_time']
            patient.date_time = datetime.strptime(date_time_str, '%Y-%m-%dT%H:%M')

            # Commit changes to the database
            db.session.commit()
            flash('Patient updated successfully!')
            return redirect(url_for('all_patients'))

        return render_template('edit_patient.html', patient=patient)
    
    return redirect(url_for('login'))

@app.route('/delete_patient/<int:patient_id>', methods=['POST'])
def delete_patient(patient_id):
    if 'username' in session and session['role'] == 'admin':
        patient = Patient.query.get_or_404(patient_id)
        db.session.delete(patient)
        db.session.commit()
        flash('Patient deleted successfully!')
        return redirect(url_for('all_patients'))

    return redirect(url_for('login'))
    
# New Staff route
@app.route('/new_staff', methods=['GET', 'POST'])
def new_staff():
    if 'username' in session and session['role'] == 'admin':  # Only allow admin to create staff
        if request.method == 'POST':
            name = request.form['name']
            address = request.form['address']
            contact = request.form['contact']
            email = request.form['email']  # Add email
            qualification = request.form['qualification']
            role = request.form['role']
            dob = request.form['dob']  # Get the DOB
            date_time_str = request.form['date_time']
            date_time = datetime.strptime(date_time_str, '%Y-%m-%dT%H:%M')  # Convert string to datetime object
            
            # Calculate age
            age = (datetime.now().date() - datetime.strptime(dob, '%Y-%m-%d').date()).days // 365

            # Create new staff instance
            new_staff = Staff(
                name=name,
                address=address,
                contact=contact,
                email=email,
                qualification=qualification,
                role=role,
                date_time=date_time,
                age=age,
                dob=datetime.strptime(dob, '%Y-%m-%d').date(),  # Store DOB as date
                experience=int(request.form['experience'])  # Add experience
            )
            db.session.add(new_staff)
            db.session.commit()
            flash('New staff added successfully!')
            return redirect(url_for('all_staff'))

        return render_template('new_staff.html')
    return redirect(url_for('login'))

# All Staff Details route
@app.route('/all_staff')
def all_staff():
    if 'username' in session and session['role'] == 'admin':
        staffs = Staff.query.all()
        return render_template('all_staff.html', staffs=staffs)
    return redirect(url_for('login'))

# Route to download staff as Excel file
@app.route('/download_staff')
def download_staff():
    if 'username' in session and session['role'] == 'admin':
        try:
            staffs = Staff.query.all()
            df = pd.DataFrame([(s.name, s.contact, s.age, s.dob, s.address, s.qualification, s.role, s.experience, s.date_time) for s in staffs],
                              columns=['Name', 'Contact', 'Age', 'DOB', 'Address', 'Qualification', 'Role', 'Experience', 'Date and Time'])
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name='Staff')
            output.seek(0)
            return send_file(output, download_name='staff.xlsx', as_attachment=True)
        except Exception as e:
            flash(f'Error occurred: {e}')
            return redirect(url_for('all_staff'))
    return redirect(url_for('login'))

# Edit Staff route
@app.route('/edit_staff/<int:staff_id>', methods=['GET', 'POST'])
def edit_staff(staff_id):
    if 'username' in session and session['role'] == 'admin':
        staff = Staff.query.get(staff_id)

        if staff is None:
            flash('Staff not found.')
            return redirect(url_for('all_staff'))

        if request.method == 'POST':
            # Update staff properties based on form input
            staff.name = request.form['name']
            staff.address = request.form['address']
            staff.contact = request.form['contact']
            staff.email = request.form['email']  # Update email
            staff.qualification = request.form['qualification']
            staff.role = request.form['role']

            # Convert the date of birth from string to a date object
            staff.dob = datetime.strptime(request.form['dob'], '%Y-%m-%d').date()  # Update DOB
            
            # Update the datetime field
            staff.date_time = datetime.strptime(request.form['date_time'], '%Y-%m-%dT%H:%M')  # Update datetime
            
            # Recalculate age based on the updated dob
            staff.age = (datetime.now().date() - staff.dob).days // 365
            
            staff.experience = int(request.form['experience'])  # Update experience

            db.session.commit()
            flash('Staff updated successfully!')
            return redirect(url_for('all_staff'))

        return render_template('edit_staff.html', staff=staff)

    return redirect(url_for('login'))

# Delete Staff route
@app.route('/delete_staff/<int:staff_id>', methods=['POST'])
def delete_staff(staff_id):
    if 'username' in session and session['role'] == 'admin':
        staff = Staff.query.get(staff_id)

        if staff is not None:
            db.session.delete(staff)
            db.session.commit()
            flash('Staff deleted successfully!')
        else:
            flash('Staff not found.')

        return redirect(url_for('all_staff'))

    return redirect(url_for('login'))

# New Doctor route
@app.route('/new_doctor', methods=['GET', 'POST'])
def new_doctor():
    if 'username' in session and session['role'] == 'admin':
        if request.method == 'POST':
            name = request.form['name']
            specialization = request.form['specialization']
            contact = request.form['contact']
            email = request.form['email']
            address = request.form['address']
            qualification = request.form['qualification']
            experience = request.form['experience']
            dob = datetime.strptime(request.form['dob'], '%Y-%m-%d').date()  # Convert to date object
            age = (datetime.now().date() - dob).days // 365  # Calculate age

            new_doctor = Doctor(
                name=name,
                specialization=specialization,
                contact=contact,
                email=email,
                address=address,
                qualification=qualification,
                experience=experience,
                dob=dob,
                age=age
            )
            db.session.add(new_doctor)
            db.session.commit()
            flash('New doctor added successfully!')
            return redirect(url_for('all_doctors'))

        return render_template('new_doctor.html')
    return redirect(url_for('login'))

# All Doctors route
@app.route('/all_doctors')
def all_doctors():
    if 'username' in session:
        doctors = Doctor.query.all()
        return render_template('all_doctors.html', doctors=doctors)
    return redirect(url_for('login'))

# Edit Doctor route
@app.route('/edit_doctor/<int:doctor_id>', methods=['GET', 'POST'])
def edit_doctor(doctor_id):
    if 'username' in session and session['role'] == 'admin':
        doctor = Doctor.query.get(doctor_id)

        if doctor is None:
            flash('Doctor not found.')
            return redirect(url_for('all_doctors'))

        if request.method == 'POST':
            doctor.name = request.form['name']
            doctor.specialization = request.form['specialization']
            doctor.contact = request.form['contact']
            doctor.email = request.form['email']
            doctor.address = request.form['address']
            doctor.qualification = request.form['qualification']
            doctor.experience = request.form['experience']
            doctor.dob = datetime.strptime(request.form['dob'], '%Y-%m-%d').date()  # Update DOB
            doctor.age = (datetime.now().date() - doctor.dob).days // 365  # Recalculate age

            db.session.commit()
            flash('Doctor updated successfully!')
            return redirect(url_for('all_doctors'))

        return render_template('edit_doctor.html', doctor=doctor)
    return redirect(url_for('login'))

# Delete Doctor route
@app.route('/delete_doctor/<int:doctor_id>', methods=['POST'])
def delete_doctor(doctor_id):
    if 'username' in session and session['role'] == 'admin':
        doctor = Doctor.query.get(doctor_id)

        if doctor is not None:
            db.session.delete(doctor)
            db.session.commit()
            flash('Doctor deleted successfully!')
        else:
            flash('Doctor not found.')

        return redirect(url_for('all_doctors'))
    return redirect(url_for('login'))

# Route to download doctors as an Excel file
@app.route('/download_doctors')
def download_doctors():
    if 'username' in session:
        try:
            doctors = Doctor.query.all()
            df = pd.DataFrame([(d.name, d.specialization, d.contact, d.email, d.address, d.qualification, d.experience, d.dob, d.age) for d in doctors],
                              columns=['Name', 'Specialization', 'Contact', 'Email', 'Address', 'Qualification', 'Experience', 'DOB', 'Age'])
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name='Doctors')
            output.seek(0)
            return send_file(output, download_name='doctors.xlsx', as_attachment=True)
        except Exception as e:
            flash(f'Error occurred: {e}')
            return redirect(url_for('all_doctors'))
    return redirect(url_for('login'))

# New Appointment route
@app.route('/new_appointment', methods=['GET', 'POST'])
def new_appointment():
    if 'username' in session:
        if request.method == 'POST':
            patient_id = request.form['patient_id']
            doctor_id = request.form['doctor_id']
            date_time_str = request.form['date_time']
            date_time = datetime.strptime(date_time_str, '%Y-%m-%dT%H:%M')  # Convert string to datetime object
            reason = request.form['reason']

            new_appointment = Appointment(
                patient_id=patient_id,
                doctor_id=doctor_id,
                date_time=date_time,
                reason=reason
            )
            db.session.add(new_appointment)
            db.session.commit()
            flash('New appointment created successfully!')
            return redirect(url_for('all_appointments'))

        patients = Patient.query.all()
        doctors = Doctor.query.all()
        return render_template('new_appointment.html', patients=patients, doctors=doctors)
    return redirect(url_for('login'))

# All Appointments route
@app.route('/all_appointments')
def all_appointments():
    if 'username' in session:
        appointments = Appointment.query.all()
        return render_template('all_appointments.html', appointments=appointments)
    return redirect(url_for('login'))

# Edit Appointment route
@app.route('/edit_appointment/<int:appointment_id>', methods=['GET', 'POST'])
def edit_appointment(appointment_id):
    if 'username' in session:
        appointment = Appointment.query.get_or_404(appointment_id)

        if request.method == 'POST':
            appointment.patient_id = request.form['patient_id']
            appointment.doctor_id = request.form['doctor_id']
            date_time_str = request.form['date_time']
            appointment.date_time = datetime.strptime(date_time_str, '%Y-%m-%dT%H:%M')  # Update the datetime
            appointment.reason = request.form['reason']

            db.session.commit()
            flash('Appointment updated successfully!')
            return redirect(url_for('all_appointments'))

        patients = Patient.query.all()
        doctors = Doctor.query.all()
        return render_template('edit_appointment.html', appointment=appointment, patients=patients, doctors=doctors)

    return redirect(url_for('login'))

# Delete Appointment route
@app.route('/delete_appointment/<int:appointment_id>', methods=['POST'])
def delete_appointment(appointment_id):
    if 'username' in session:
        appointment = Appointment.query.get_or_404(appointment_id)
        db.session.delete(appointment)
        db.session.commit()
        flash('Appointment deleted successfully!')
        return redirect(url_for('all_appointments'))

    return redirect(url_for('login'))

# Route to download appointments as Excel file
@app.route('/download_appointments')
def download_appointments():
    if 'username' in session:
        try:
            appointments = Appointment.query.all()
            df = pd.DataFrame([(a.patient.name, a.doctor.name, a.date_time, a.reason) for a in appointments],
                              columns=['Patient', 'Doctor', 'Date and Time', 'Reason'])
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name='Appointments')
            output.seek(0)
            return send_file(output, download_name='appointments.xlsx', as_attachment=True)
        except Exception as e:
            flash(f'Error occurred: {e}')
            return redirect(url_for('all_appointments'))
    return redirect(url_for('login'))

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html',privacy_policy=privacy_policy)

@app.route('/about')
def about():
    return render_template('about.html',about=about)

@app.route('/terms_of_service')
def terms_of_service():
    return render_template('terms_of_service.html',terms_of_service=terms_of_service)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        
        # Process the form data (e.g., send an email or store in a database)
        # For now, we'll just flash a message for demonstration
        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('contact'))  # Redirect back to the contact page

    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=False, host = '0.0.0.0')