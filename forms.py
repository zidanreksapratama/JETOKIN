from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField , SubmitField,SelectField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from models import User 

class RegistrationForm(FlaskForm):
    fullname = StringField('Nama', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Konfirmasi Password', validators=[DataRequired(), EqualTo('password')])
    gender = SelectField('Gender', choices=[('Laki-laki', 'Laki-laki'), ('Perempuan', 'Perempuan')], validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')
    
class SetNicknameForm(FlaskForm):
    nickname = StringField('Nickname', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send OTP')

class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')
