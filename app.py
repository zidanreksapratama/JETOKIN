from flask import Flask, render_template, redirect, url_for, flash, request, session
from forms import RegistrationForm, LoginForm, SetNicknameForm
from models import db, User, Role
from flask_login import current_user, LoginManager
import pymysql
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import random
from flask import session
from werkzeug.utils import secure_filename
import os
from google_auth_oauthlib.flow import Flow


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@localhost/jejak tokoh indonesia"
app.config['SECRET_KEY'] = 'your_secret_key'
pymysql.install_as_MySQLdb()
bcrypt = Bcrypt(app)
db.init_app(app)

registered_data = {}

# Konfigurasi LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login.html" 

# Konfigurasi SMTP Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Gunakan port 465 jika menggunakan SSL
app.config['MAIL_USE_TLS'] = True  # Gunakan TLS untuk port 587
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'zidanreksa789@gmail.com'
app.config['MAIL_PASSWORD'] = 'zqqc tnba bcsy fzdh'  # Masukkan App Password
app.config['MAIL_DEFAULT_SENDER'] = ('Jetokin', 'zidanreksa789@gmail.com')
app.config['MAIL_DEBUG'] = True  # Aktifkan debug untuk melihat log


mail = Mail(app)

# Fungsi untuk mengirim OTP
def send_otp(email):
    otp = str(random.randint(100000, 999999))  # Generate OTP
    msg = Message("Your OTP Code", recipients=[email])
    msg.body = f"Your OTP code is {otp}. It is valid for 10 minutes."
    mail.send(msg)
    session['otp'] = otp  # Simpan OTP di session
    return otp


# Setup Google Blueprint
google_bp = make_google_blueprint(
    client_id='874747577446-2uumobogao7raislcih7ssgkvvrcddg8.apps.googleusercontent.com',
    client_secret='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',
    redirect_to='google_login'
)
app.register_blueprint(google_bp, url_prefix="/google")

# Setup Facebook Blueprint
facebook_bp = make_facebook_blueprint(
    client_id='1254130402691057',
    client_secret='a4249cec7e8a1d5b621364268716b2a4',
    redirect_to='facebook_login',
)
app.register_blueprint(facebook_bp, url_prefix="/facebook")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password == form.password.data:  # Cocokkan password langsung
            session['email'] = user.email  # Simpan email pengguna di session
            session['user_id'] = user.user_id  # Simpan user_id ke session
            if not user.nickname:  # Cek apakah nickname belum diisi
                return redirect(url_for('set_nickname'))  # Arahkan ke halaman set nickname
            return redirect(url_for('homepage'))
        else:
            flash('Email atau password salah', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Cek apakah email sudah ada di database
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email sudah digunakan. Silakan gunakan email lain.', 'danger')
            return redirect(url_for('register'))  # Kembali ke halaman register jika email sudah terdaftar

        # Jika email belum ada, lakukan pendaftaran
        user = User(
            fullname=form.fullname.data,
            email=form.email.data,
            password=form.password.data,
            gender=form.gender.data,  # Pastikan ini sesuai
            role=Role.user,
            profile_picture='default_profile_picture.png'
        )
        db.session.add(user)
        db.session.commit()
        flash('Akun berhasil dibuat!', 'success')  # Tambahkan flash message
        return redirect(url_for('register'))  # Redirect ke halaman login
    return render_template('register.html', form=form)

@app.route("/set_nickname", methods=['GET', 'POST'])
def set_nickname():
    form = SetNicknameForm()  # Membuat instance form
    if request.method == 'POST' and form.validate_on_submit():
        # Ambil user yang sesuai (misalnya dari session)
        user = User.query.filter_by(email=session.get('email')).first()
        if user:
            # Cek apakah nickname sudah ada di database
            existing_nickname = User.query.filter_by(nickname=form.nickname.data).first()
            if existing_nickname:
                flash('Nickname sudah digunakan, silakan pilih yang lain.', 'danger')
                return redirect(url_for('set_nickname'))  # Kembali ke halaman set nickname
            # Set nickname dari input form
            user.nickname = form.nickname.data
            db.session.commit()
            return redirect(url_for('homepage'))
        flash('Error setting nickname', 'danger')
    return render_template('set_nickname.html', form=form)  # Kirim form ke template

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = request.args.get('email')
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        # Mengupdate password di database tanpa bcrypt
        user = User.query.filter_by(email=email).first()  # Ambil pengguna berdasarkan email
        if user:
            user.password = new_password  # Simpan password baru tanpa hashing
            db.session.commit()  # Simpan perubahan
            flash('Kata sandi Anda telah berhasil diatur ulang!', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', email=email)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()  # Menggunakan model User untuk mencari email
        if user:
            otp = send_otp(email)  # Mengirim OTP
            flash('OTP telah dikirim ke email Anda. Silakan periksa email Anda.', 'success')
            return redirect(url_for('verify_otp', email=email, otp=otp))
        else:
            flash('Email tidak ditemukan dalam data kami.', 'danger')
    return render_template('forgot_password.html')

@app.route('/verify_otp/<email>/<otp>', methods=['GET', 'POST'])
def verify_otp(email, otp):
    if request.method == 'POST':
        # Menggabungkan nilai dari semua input OTP
        entered_otp = ''.join([request.form.get(f'otp{i}') for i in range(1, 7)])  # Mengambil dari otp1 hingga otp6
        print(f"Entered OTP: {entered_otp}")  # Debugging untuk melihat OTP yang dimasukkan

        # Bandingkan OTP yang dimasukkan dengan OTP yang diharapkan
        if entered_otp == otp:
            flash('OTP berhasil diverifikasi!', 'success')
            return redirect(url_for('reset_password', email=email)) 
            # Tambahkan logika untuk melanjutkan proses setelah verifikasi berhasil
        else:
            flash('OTP yang dimasukkan tidak valid.', 'error')

    return render_template('verify_otp.html', email=email, otp=otp)


@app.route("/")
def home():

    return render_template('home.html')  # Render halaman home Anda

@app.route('/homepage')
def homepage():
    return render_template('homepage.html')

@app.route('/setting')
def setting():
    user_id = session.get('user_id')  # Ambil user_id dari sesi login
    if not user_id:
        flash('Anda harus login terlebih dahulu!', 'danger')
        return redirect(url_for('login'))  # Arahkan ke halaman login jika user_id tidak ada

    # Ambil data user berdasarkan ID
    user = User.query.get(user_id)
    
    if not user:
        flash('Pengguna tidak ditemukan.', 'danger')
        return redirect(url_for('homepage'))
    
    # Kirim data user ke template
    return render_template('setting.html', user=user)

# Tentukan folder tempat menyimpan gambar profil
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Fungsi untuk memeriksa ekstensi file yang diizinkan
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    user_id = session.get('user_id')  # Ambil user_id dari sesi
    user = User.query.get(user_id)  # Ambil user yang sedang login

    if request.method == 'POST':
        fullname = request.form['fullname']
        nickname = request.form['nickname']
        email = request.form['email']
        gender = request.form['gender']

        profile_image = request.files['profile_image']  # Ambil file gambar dari form

        # Cek apakah ada file gambar yang diunggah
        if profile_image and allowed_file(profile_image.filename):
            filename = secure_filename(profile_image.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_image.save(filepath)  # Simpan file ke folder yang ditentukan

            # Simpan nama file gambar profil ke database
            user.profile_picture = filename  # Simpan hanya nama file

        # Validasi email
        existing_email_user = User.query.filter(
            User.email == email,
            User.user_id != user.user_id  # Pastikan tidak memeriksa pengguna yang sedang diupdate
        ).first()

        if existing_email_user:
            flash('Email sudah digunakan, silakan coba yang lain.', 'danger')
            return redirect(url_for('edit_profile'))

        # Validasi nickname
        existing_nickname_user = User.query.filter(
            User.nickname == nickname,
            User.user_id != user.user_id  # Pastikan tidak memeriksa pengguna yang sedang diupdate
        ).first()

        if existing_nickname_user:
            flash('Nickname sudah digunakan, silakan coba yang lain.', 'danger')
            return redirect(url_for('edit_profile'))

        # Simpan perubahan lain ke database
        user.fullname = fullname
        user.nickname = nickname
        user.email = email
        user.gender = gender  # Ubah string ke enum

        # Commit perubahan ke database
        db.session.commit()

        flash('Profil berhasil diperbarui', 'success')
        return redirect(url_for('setting'))

    return render_template('setting.html', user=user)



@app.route('/change-password', methods=['POST'])
def change_password():
    user_id = session.get('user_id')  # Ambil user_id dari sesi
    if not user_id:
        flash('Anda harus login terlebih dahulu', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(user_id)  # Ambil user berdasarkan user_id dari sesi

    old_password = request.form['old-password']
    new_password = request.form['new-password']
    confirm_password = request.form['confirm-password']

    # Cek apakah password lama cocok (tanpa hashing)
    if user.password != old_password:
        flash('Password lama tidak cocok', 'danger')
        return redirect(url_for('edit_profile'))

    # Cek apakah password baru dan konfirmasi cocok
    if new_password != confirm_password:
        flash('Password baru dan konfirmasi tidak cocok', 'danger')
        return redirect(url_for('edit_profile'))

    # Ubah password (tanpa hashing)
    user.password = new_password

    # Commit perubahan ke database
    db.session.commit()

    flash('Password berhasil diubah', 'success')
    return redirect(url_for('edit_profile'))




@app.route("/google_login")
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))

    resp = google.get("/oauth2/v2/userinfo")  # Mengambil info pengguna
    if not resp.ok:
        flash("Gagal mengambil info pengguna dari Google.", "danger")
        return redirect(url_for('login'))

    email = resp.json()["email"]  # Pastikan menggunakan 'email' dari response
    # Cek jika pengguna sudah ada di database
    user = User.query.filter_by(email=email).first()
    if user is None:
        # Jika pengguna baru, buat akun baru
        user = User(fullname=email, email=email, password="", gender="Laki-laki", role="user")
        db.session.add(user)
        db.session.commit()

    # Login user
    flash('Login berhasil!', 'success')
    return redirect(url_for('home'))

@app.route("/facebook/login")
def facebook_login():
    if not facebook.authorized:
        return redirect(url_for('facebook.login'))

    resp = facebook.get("/me?fields=id,name,email")  # Mendapatkan informasi pengguna
    if not resp.ok:
        flash("Gagal mengambil info pengguna dari Facebook.", "danger")
        return redirect(url_for('login'))

    email = resp.json()["email"]  # Mengambil email dari respons
    # Cek jika pengguna sudah ada di database
    user = User.query.filter_by(email=email).first()
    if user is None:
        # Jika pengguna baru, buat akun baru
        user = User(fullname=resp.json()["name"], email=email, password="", gender="Laki-laki", role="user")
        db.session.add(user)
        db.session.commit()

    # Login user
    flash('Login successful!', 'success')
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()  # Menghapus semua data sesi
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
