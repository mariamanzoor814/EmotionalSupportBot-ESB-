from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FloatField, BooleanField, IntegerField, FileField
from flask_wtf.file import FileAllowed
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp
from wtforms.validators import Optional

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send OTP')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[ 
        DataRequired(), Length(min=6, message="Password must be at least 6 characters long")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[ 
        DataRequired(), EqualTo('password', message="Passwords must match")
    ])
    submit = SubmitField('Reset Password')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Regexp(r'^[A-Za-z0-9_.-]{3,20}$', message="Username must be 3-20 characters and can only contain letters, numbers, dots, underscores, or hyphens.")
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class OTPForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[DataRequired()])
    submit = SubmitField('Verify OTP')
    
class MoodForm(FlaskForm):
    mood_label = StringField('Mood Label', validators=[DataRequired()])
    confidence_score = FloatField('Confidence Score', validators=[DataRequired()])
    sentiment = StringField('Sentiment')
    answers = StringField('Answers')
    submit = SubmitField('Submit')
    
   
    
class SettingsForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    current_password = PasswordField('Current Password', validators=[Length(min=6)])
    new_password = PasswordField('New Password', validators=[
        Length(min=8),
        Regexp(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
               message="Password requirements: 8+ chars, 1 uppercase, 1 lowercase, 1 number, 1 special char")
    ])
    delete_account = BooleanField('Confirm Account Deletion')
    submit = SubmitField('Update Profile')
    
    
class ChatForm(FlaskForm):
    message = StringField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')    
    
    
class FeedbackForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    experience = IntegerField('Experience', default=3, validators=[DataRequired()])
    comments = TextAreaField('Comments')
    submit = SubmitField('SUBMIT')    

class ProfileForm(FlaskForm):
    first_name = StringField('Name', validators=[DataRequired(), Length(max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'readonly': True})
    avatar = FileField('Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    save = SubmitField('Save Changes')