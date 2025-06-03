from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from sqlalchemy import Enum as SaEnum
from enum import Enum
import os   
import base64
from sqlalchemy import func, text
import re
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from nltk.corpus import stopwords

db = SQLAlchemy()

class Role():
    admin = "admin"
    user = "user"

class User(db.Model):
    __tablename__ = 'user'

    user_id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    nickname = db.Column(db.String(50), nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True, default="default.png")
    otp = db.Column(db.Integer, nullable=True)  # Kolom untuk menyimpan kode OTP
    otp_expiration = db.Column(db.DateTime, nullable=True)  # Kolom untuk waktu kedaluwarsa OTP
    otp_attempts = db.Column(db.Integer, default=0)  # Kolom untuk jumlah percobaan OTP

    def init(self, fullname, email, password, gender, role, nickname=None, otp=None, profile_picture=None, otp_expiration=None):
        self.fullname = fullname
        self.email = email
        self.password = password
        self.gender = gender
        self.role = role
        self.nickname = nickname
        self.otp = otp
        self.profile_picture = profile_picture or "default.png"
        self.otp_expiration = otp_expiration
        self.otp_attempts = 0  # Inisialisasi jumlah percobaan ke 0

    # Metode untuk menyimpan OTP ke database
    @classmethod
    def set_otp(cls, email, otp, expires_in=600):
        user = cls.query.filter_by(email=email).first()
        if user:
            user.otp = otp
            user.otp_expiration = datetime.utcnow() + timedelta(seconds=expires_in)
            db.session.commit()
            print(f"Set OTP for {email}: {otp}, expires at: {user.otp_expiration}")
        else:
            print(f"User not found for {email}")

    # Metode untuk mengambil OTP dari database
    @classmethod
    def get_otp(cls, email):
        user = cls.query.filter_by(email=email).first()
        if user:
            # Periksa apakah jumlah percobaan telah mencapai batas
            if user.otp_attempts >= 5:
                print(f"Too many failed attempts for {email}")
                return None

            # Periksa apakah OTP masih valid
            if user.otp and user.otp_expiration and user.otp_expiration > datetime.utcnow():
                print(f"OTP valid for {email}: {user.otp}")
                return user.otp
            else:
                print(f"OTP expired or not set for {email}")
                return None
        print(f"User not found for {email}")
        return None

    # Metode untuk menghapus OTP dari database
    @classmethod
    def delete_otp(cls, email):
        user = cls.query.filter_by(email=email).first()
        if user:
            user.otp = None
            user.otp_expiration = None
            user.otp_attempts = 0  # Reset jumlah percobaan
            db.session.commit()
            print(f"Deleted OTP for {email}")


        # Jika Anda belum memiliki, tambahkan atribut yang dibutuhkan Flask-Login
    def is_active(self):
        return True  # Bisa disesuaikan dengan logika status pengguna

    def is_authenticated(self):
        return True  # Jika pengguna berhasil login

    def is_anonymous(self):
        return False  # Menandakan bahwa pengguna bukan anonim

    def get_id(self):
        return str(self.user_id)  # Pastikan mengembalikan ID pengguna sebagai string
    
    def get_profile_picture(self, base_url):
        if self.profile_picture:
            return f"{base_url}/static/uploads/{self.profile_picture}"
        return f"{base_url}/static/uploads/default.png"


MEDIA_PATH = "/static/Media"
IMAGES_PATH = f"{MEDIA_PATH}/images"
VIDEOS_PATH = f"{MEDIA_PATH}/video"
COMPRESSED_VIDEOS_PATH = f".{MEDIA_PATH}/compressed_video"

class Tokoh(db.Model):
    __tablename__ = 'tokoh'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=True)
    ascencion_document_number = db.Column(db.String(50), nullable=True)
    ascencion_document_date = db.Column(db.String(50), nullable=True)
    ascencion_year = db.Column(db.Integer, nullable=True)
    zaman_perjuangan = db.Column(db.String(50), nullable=True)
    bidang_perjuangan = db.Column(db.String(100), nullable=True)
    photo_url = db.Column(db.String(200), nullable=True)
    birth_date = db.Column(db.String(50), nullable=True)
    birth_place = db.Column(db.String(200), nullable=True)
    death_date = db.Column(db.String(50), nullable=True)
    death_place = db.Column(db.String(200), nullable=True)
    burial_place = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=True)
    peran_utama = db.Column(db.String(50), nullable=True)

    # Relasi ke Timeline
    timelines = db.relationship('Timeline', back_populates='tokoh', cascade="all, delete-orphan")

    def _init_(self, **kwargs):
        super()._init_(**kwargs)


    def to_dict(self, include_base64=False):
        tokoh_dict = {
            'id': self.id,
            'name': self.name,
            'ascencion_document_number': self.ascencion_document_number,
            'ascencion_document_date': self.ascencion_document_date,
            'ascencion_year': self.ascencion_year,
            'zaman_perjuangan': self.zaman_perjuangan,
            'bidang_perjuangan': self.bidang_perjuangan,
            'photo_url': self.photo_url,
            'birth_date': self.birth_date,
            'birth_place': self.birth_place,
            'death_date': self.death_date,
            'death_place': self.death_place,
            'burial_place': self.burial_place,
            'description': self.description,
            'peran_utama': self.peran_utama,
        }

        if include_base64 and self.photo_url:
            file_path = os.path.join('static/images/Pahlawan', self.photo_url)
            if os.path.exists(file_path):
                try:
                    with open(file_path, "rb") as image_file:
                        tokoh_dict['photo_base64'] = base64.b64encode(image_file.read()).decode('utf-8')
                except Exception as e:
                    print(f"Error encoding image to Base64: {e}")
                    tokoh_dict['photo_base64'] = None
            else:
                tokoh_dict['photo_base64'] = None

        return tokoh_dict


#Table Timeline
class Timeline(db.Model):
    __tablename__ = 'timeline'

    # Kolom tabel
    timeline_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nomor_urut = db.Column(db.Integer, nullable=False, unique=True)  # Harus unik dalam satu timeline
    tokoh_id = db.Column(db.Integer, db.ForeignKey('tokoh.id'), nullable=False)
    nama_timeline = db.Column(db.String(100), nullable=False)
    deskripsi = db.Column(db.Text, nullable=False)

    # Relasi ke model Tokoh
    tokoh = db.relationship('Tokoh', back_populates='timelines')

    # Relasi ke model TimelineMedia
    media = db.relationship('TimelineMedia', back_populates='timeline', cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Timeline {self.nama_timeline}>'

    def to_dict(self, include_media=False):
        timeline_dict = {
            "timeline_id": self.timeline_id,
            "nomor_urut": self.nomor_urut,
            "tokoh_id": self.tokoh_id,
            "nama_timeline": self.nama_timeline,
            "deskripsi": self.deskripsi,
            "tokoh_name": self.tokoh.name if self.tokoh else "Tidak diketahui"
        }
        if include_media:
            timeline_dict['media'] = [media.to_dict() for media in self.media]
        return timeline_dict

# Table timeline_media
class TimelineMedia(db.Model):
    __tablename__ = 'timeline_media'

    media_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timeline_id = db.Column(db.Integer, db.ForeignKey('timeline.timeline_id'), nullable=False)
    nomor_urut = db.Column(db.Integer, nullable=False)  # Tidak perlu unik sendiri
    media_type = db.Column(db.Enum('image', 'video'), nullable=False)  # Tipe media
    media_url = db.Column(db.String(255), nullable=False)  # Nama file fisik
    description = db.Column(db.Text, nullable=True)  # Deskripsi opsional

    # Relasi ke Timeline
    timeline = db.relationship('Timeline', back_populates='media')

    # Constraint unik baru: timeline_id + nomor_urut + media_type
    __table_args__ = (
        db.UniqueConstraint('timeline_id', 'nomor_urut', 'media_type', name='unique_timeline_nomor_urut_media_type'),
    )

    def __repr__(self):
        return f'<TimelineMedia {self.media_url} ({self.media_type})>'

    def to_dict(self, base_url=""):
        # Pastikan base_url tidak ada trailing slash
        base_url = base_url.rstrip("/")
        
        # Tentukan path media
        media_path = f"{base_url}{IMAGES_PATH}/{self.media_url}" if self.media_type == "image" else f"{base_url}{VIDEOS_PATH}/{self.media_url}"

        return {
            "media_id": self.media_id,
            "timeline_id": self.timeline_id,
            "nomor_urut": self.nomor_urut,
            "media_type": self.media_type,
            "media_url": media_path,  # Full URL
            "description": self.description
        }

class SentimentAnalyzer:

    def __init__(self, model_path):
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.words_dict = {
            'tdk': 'tidak', 'yg': 'yang', 'ga': 'tidak', 'gak': 'tidak', 'tp': 'tapi', 'd': 'di',
            'sy': 'saya', '&': 'dan', 'dgn': 'dengan', 'utk': 'untuk', 'gk': 'tidak', 'jd': 'jadi',
            'jg': 'juga', 'dr': 'dari', 'krn': 'karena', 'aja': 'saja', 'karna': 'karena', 'udah': 'sudah',
            'kmr': 'kamar', 'g': 'tidak', 'dpt': 'dapat', 'banget': 'sekali', 'bgt': 'sekali', 'kalo': 'kalau',
            'n': 'dan', 'bs': 'bisa', 'oke': 'ok', 'dg': 'dengan', 'pake': 'pakai', 'sampe': 'sampai',
            'dapet': 'dapat', 'ad': 'ada', 'lg': 'lagi', 'bikin': 'buat', 'tak': 'tidak', 'ny': 'nya',
            'ngga': 'tidak', 'nunggu': 'tunggu', 'klo': 'kalau', 'blm': 'belum', 'trus': 'terus', 'kayak': 'seperti',
            'dlm': 'dalam', 'udh': 'sudah', 'tau': 'tahu', 'org': 'orang', 'hrs': 'harus', 'msh': 'masih',
            'sm': 'sama', 'byk': 'banyak', 'krg': 'kurang', 'kmar': 'kamar', 'spt': 'seperti', 'pdhl': 'padahal',
            'chek': 'cek', 'pesen': 'pesan', 'kran': 'keran', 'gitu': 'begitu', 'tpi': 'tapi', 'lbh': 'lebih',
            'tmpt': 'tempat', 'dikasi': 'dikasih', 'serem': 'seram', 'sya': 'saya', 'jgn': 'jangan',
            'dri': 'dari', 'dtg': 'datang', 'gada': 'tidak ada', 'standart': 'standar', 'mlm': 'malam',
            'k': 'ke', 'kl': 'kalau', 'sgt': 'sangat', 'y': 'ya', 'krna': 'karena', 'tgl': 'tanggal',
            'terimakasih': 'terima kasih', 'kecoak': 'kecoa', 'pd': 'pada', 'tdr': 'tidur', 'jdi': 'jadi',
            'kyk': 'seperti', 'sdh': 'sudah', 'ama': 'sama', 'gmana': 'bagaimana', 'dalem': 'dalam',
            'tanyak': 'tanya', 'taru': 'taruh', 'gede': 'besar', 'kaya': 'seperti', 'access': 'akses',
            'tetep': 'tetap', 'mgkin': 'mungkin', 'sower': 'shower', 'idup': 'hidup', 'nyaaa': 'nya',
            'baikk': 'baik', 'hanay': 'hanya', 'tlp': 'telpon', 'kluarga': 'keluarga', 'jln': 'jalan',
            'hr': 'hari', 'ngak': 'tidak', 'bli': 'beli', 'kmar': 'kamar', 'naro': 'taruh'
        }
        self.stop_words = set(stopwords.words('indonesian'))

    def clean_text(self, text):
        text = text.lower()
        for word, replacement in self.words_dict.items():
            text = re.sub(r'\b' + re.escape(word) + r'\b', replacement, text)
        text = ' '.join([word for word in text.split() if word not in self.stop_words])
        return text

    def predict_sentiment(self, text):
        # Clean and preprocess the text
        clean_text_input = self.clean_text(text)
        # Tokenize the text
        inputs = self.tokenizer(clean_text_input, return_tensors="pt", truncation=True, padding=True, max_length=128)
        # Get the model prediction
        outputs = self.model(**inputs)
        logits = outputs.logits
        # Convert logits to probabilities
        probabilities = torch.softmax(logits, dim=1).detach().cpu().numpy()[0]
        # Get the predicted class
        predicted_class = torch.argmax(logits, dim=1).item()
        return predicted_class, probabilities

class Review(db.Model):
    __tablename__ = 'review'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    text = db.Column(db.String(500), nullable=False)

    def _repr_(self):
        return f"<Review id={self.id}, text={self.text}>"


#Model Quiz
class Difficulty(Enum):
    easy = 'easy'
    medium = 'medium'
    hard = 'hard'

class Quiz(db.Model):
    __tablename__ = 'quizzes'

    quiz_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tokoh_id = db.Column(db.Integer, nullable=False)  # Relasi dengan Tokoh
    question = db.Column(db.Text, nullable=False)
    correct_answer = db.Column(db.String(255), nullable=False)
    option_1 = db.Column(db.String(255), nullable=True)
    option_2 = db.Column(db.String(255), nullable=True)
    option_3 = db.Column(db.String(255), nullable=True)
    difficulty = db.Column(db.String(10), nullable=True)
    points = db.Column(db.Integer, nullable=True, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())


class UserQuizScore(db.Model):
    __tablename__ = 'user_quiz_scores'

    score_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.quiz_id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    date_taken = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

    user = db.relationship('User', backref='quiz_scores')
    quiz = db.relationship('Quiz', backref='user_scores')

    def __init__(self, user_id, quiz_id, score, completed_at=None):
        self.user_id = user_id
        self.quiz_id = quiz_id
        self.score = score
        if completed_at:
            self.completed_at = completed_at

    def __repr__(self):
        return f"<UserQuizScore(user_id={self.user_id}, quiz_id={self.quiz_id}, score={self.score})>"

# Fungsi untuk mendapatkan leaderboard dengan filter tanggal
def get_leaderboard():
    today = datetime.today()
    week_start = today - timedelta(days=today.weekday())
    week_end = week_start + timedelta(days=6)

    leaderboard_query = db.session.query(
        UserQuizScore.user_id,
        func.sum(UserQuizScore.score).label('total_score')
    ).filter(
        UserQuizScore.date_taken.between(week_start, week_end)
    ).group_by(UserQuizScore.user_id).order_by(func.sum(UserQuizScore.score).desc())

    leaderboard = []
    for rank, (user_id, total_score) in enumerate(leaderboard_query, start=1):
        user = User.query.get(user_id)
        leaderboard.append({
            "user_id": user_id,
            "fullname": user.fullname,
            "score": total_score,
            "ranking": rank
        })
    return leaderboard


class LeaderboardHistory(db.Model):
    __tablename__ = 'leaderboard_history'

    history_id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Primary key
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)  # Foreign key ke tabel user
    total_score = db.Column(db.Integer, nullable=False, default=0)  # Total skor dari minggu itu
    week_start = db.Column(db.Date, nullable=False)  # Tanggal awal minggu
    week_end = db.Column(db.Date, nullable=False)  # Tanggal akhir minggu

    # Relasi ke tabel user
    user = db.relationship('User', backref='history_scores')

    def _init_(self, user_id, total_score, week_start, week_end):
        self.user_id = user_id
        self.total_score = total_score
        self.week_start = week_start
        self.week_end = week_end
        
        
class ARQuizQuestion(db.Model):
    _tablename_ = 'ar_quiz_questions'

    question_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    level = db.Column(db.Enum('easy', 'medium', 'hard'), nullable=False)
    question_text = db.Column(db.String(255), nullable=True)
    question_image = db.Column(db.String(255), nullable=True)
    option_a_text = db.Column(db.String(100), nullable=True)
    option_a_image = db.Column(db.String(255), nullable=True)
    option_b_text = db.Column(db.String(100), nullable=True)
    option_b_image = db.Column(db.String(255), nullable=True)
    correct_answer = db.Column(db.Enum('A', 'B'), nullable=False)

class ARQuizResult(db.Model):
    _tablename_ = 'ar_quiz_results'

    result_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    level = db.Column(db.Enum('easy', 'medium', 'hard'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    correct_answers = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('ar_quiz_results', lazy=True))


# Model untuk tabel hari_penting
class HariPenting(db.Model):
    __tablename__ = 'hari_penting'

    id = db.Column(db.Integer, primary_key=True)
    tanggal = db.Column(db.String(5), nullable=False)  # Format: 'DD-MM'
    nama = db.Column(db.String(255), nullable=False)

    def _repr_(self):
        return f"<HariPenting {self.nama} ({self.tanggal})>"

    # Metode untuk serialisasi ke JSON
    def to_dict(self):
        return {
            "id": self.id,
            "tanggal": self.tanggal,
            "nama": self.nama
        }
        
# === Model untuk Lagu ===== 
class Region(db.Model):
    __tablename__ = 'regions'  # ✅ perbaiki
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)

    songs = db.relationship('Song', back_populates='region')

class Artist(db.Model):
    __tablename__ = 'artists'  # ✅ perbaiki
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    birth_date = db.Column(db.Date)
    nationality = db.Column(db.String(100))
    bio = db.Column(db.Text)
    photo_url = db.Column(db.String(255))

    songs = db.relationship('SongArtist', back_populates='artist')

class Song(db.Model):
    __tablename__ = 'songs'  # ✅ perbaiki
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    type = db.Column(db.Enum('nasional', 'daerah', name='song_type'), nullable=False)
    region_id = db.Column(db.Integer, db.ForeignKey('regions.id'), nullable=True)
    release_year = db.Column(db.Integer)
    lyrics = db.Column(db.Text)
    audio_url = db.Column(db.String(255))
    cover_url = db.Column(db.String(255))
    duration = db.Column(db.Time)
    language = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    region = db.relationship('Region', back_populates='songs')
    artists = db.relationship('SongArtist', back_populates='song')

class SongArtist(db.Model):
    __tablename__ = 'song_artists'  # ✅ perbaiki
    song_id = db.Column(db.Integer, db.ForeignKey('songs.id'), primary_key=True)
    artist_id = db.Column(db.Integer, db.ForeignKey('artists.id'), primary_key=True)
    role = db.Column(db.Enum('vocal', 'composer', 'arranger', name='artist_role'), primary_key=True)

    song = db.relationship('Song', back_populates='artists')
    artist = db.relationship('Artist', back_populates='songs')

# Model untuk BadWord (Daftar kata terlarang)
class BadWord(db.Model):
    __tablename__ = 'badword'  # Cocokkan dengan nama tabel di database Anda
    id = db.Column(db.Integer, primary_key=True)
    word = db.Column(db.String(100), unique=True, nullable=False)
    
# Model untuk menyimpan token admin
class AdminToken(db.Model):
    __tablename__ = 'admin_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)  # Pastikan ini mengarah ke 'id_user'
    token = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('admin_tokens', lazy=True))


