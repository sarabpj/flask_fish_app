from flask_wtf import Form
from wtforms import StringField, PasswordField, FloatField
from wtforms.validators import DataRequired, Length


class UserForm(Form):
  username =  StringField('username', validators=[DataRequired()])
  password =  PasswordField('password', validators=[DataRequired(), Length(6)])

class LoginForm(Form):
  # validators make it easier to validate email, and give access to CSF protrection
  username = StringField('username', validators=[DataRequired()])
  password =  PasswordField('password', validators=[DataRequired(), Length(6)])



class FishForm(Form):
  type =  StringField('type', validators=[DataRequired()])
  weight =  FloatField('weight', validators=[DataRequired()])