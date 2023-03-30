from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'percentileranker'

class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(20), nullable=False, unqiue=True)
  password = db.Column(db.String(80), nullable=format, nullable=False)

class RegisterForm(FlaskForm):
  username = StringField(validators=[InputRequired(), Length(min=4, max=20)], rander_kw={"placeholder": "Usernme"})
  password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], rander_kw={"placeholder": "Usernme"})

  submit = SubmitField("Register")


#class LoginForm(FlaskForm):
#  username = StringField(validators=[InputRequired(), Length(min=4, max=20)], rander_kw={"placeholder": "Usernme"})
#  password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], rander_kw={"placeholder": "Usernme"})
#  submit = SubmitField("Login")


#  def validate_username(self, username): # validates unique usernames
#    existing_user_username = User.query.filter_by(username-username.data).first()
#    if existing_user_username:
#      raise ValidationError("Username already exists. Please choose a different one.")


#@app.route('/signup/', methods=['GET', 'POST']) # second slash allows user to go the page with both or just first slash
#def signup():
  #form = SignUpForm()
  #if form.is_submitted():
    #result = request.form
    #return render_template('user.html', result=result)
  #return render_template('signup.html', form=form)


# Old code

#@app.route('/registerv2', methods=['GET', 'POST'])
#def register():
#  form = RegisterForm()
#  if form.validate_on_submit():    # creates hashed version of password
#    hashed_password = bcrypt.generate_password_hash(form.password.data)  # hashed version makes password more secure
#    new_user = User(username=form.username.data, password=hashed_password)
#    'username.txt'.session.add(new_user)
#    'username.txt'.session.commit()
#    return redirect(url_for('login'))
#  return render_template('register.html', form=form)


#@app.route('/loginv2', methods=['GET', 'POST'])
#def loginpage():
#  form = LoginForm()
#  if form.validate_on_submit():
#    user = User.query.filter_by(username=form.username.data).first()  # check if user exists
#    if user:
#      if bcrypt.check_password_hash(user.password, form.password.data):  # checking if hashed password matches
#        login_user(user)
#        return redirect(url_for('dashboard'))
#  return render_template('login.html', form=form)

#login_manager = LoginManager()  # flask and app works tgt to log in user
#login_manager.init_app(app)
#login_manager.login_view = "login"

#@login_manager.user_loader  # reloads user object from user id stored in the session
#def load_user(user_id):
#  return User.query.get(int(user_id))


#@app.route('/dashboard', methods=['GET', 'POST'])
#@login_required 
#def dashboard():
#  return render_template('dashboard.html')
  

#@app.route('/logout', methods=['GET', 'POST'])
#@login_required
#def logout():
#  logout_user()
#  return redirect(url_for('login'))

  
#@app.route('/upload', methods=['POST'])
#def upload(file_name):
    #uploaded_file = request.files[file_name]
    #uploaded_file.save(uploaded_file.filename)
    #return render_template('index.html')




# Random Code

#@app.route('/extract', methods=['GET'])
#def extract(file_name):
    #data = []
    #with open('comp.txt', 'r') as file:
        #for line in file:
            #data.append(line.strip())
    #return render_template('extracted_data.html', data=data)



  




# routes
#@app.route('/register', methods=['GET', 'POST'])
#def register():
  #return render_template('register.html')
  #if request.method == 'POST':
    #email = request.form['email']
    #password = request.form['password']
    #query = "SELECT email,password FROM users where email= '"+email+"' and password= '"+password+"' "  
    #cursor.execute(query)
    #results = cursor.fetchall()  
    #if len(results) == 0:
      #print("Incorrect Credentials. Try Again")
    #else:
      #return render_template("score.html")


#@app.route('/login', methods=['GET', 'POST'])
#def login():
  #return render_template('login.html')
  #if request.method == 'POST':
    #email = request.form['email']
    #password = request.form['password']
    #query = "SELECT email,password FROM users where email= '"+email+"' and password= '"+password+"' "  
    #cursor.execute(query)
    #results = cursor.fetchall()  
    #if len(results) == 0:
      #print("Incorrect Credentials. Try Again")
    #else:
      #return render_template("score.html")




# Query

# query = "SELECT email,password FROM users where email= '"+email+"' and password= '"+password+"' "  # only select is name is equal to column in form 
# cursor.execute(query)

# results = cursor.fetchall()  # no results == incorrect username & password

# Validation
#if len(results) == 0:
#  print("Incorrect Credentials. Try Again")
#else:
#  return render_template("score.html")






# Register Form Try 2

@app.route('/register', methods=['GET', 'POST'])
def registerform():
  if request.method == "POST":
    email = request.form["Email"]
    password = request.form["Password"]
    SQLconnection = sqlite3.connect(currentlocation + "\accounts.db")
    cursor = SQLconnection.cursor()
    query = "INSERT INTO Users VALUES('{e}','{p}')".format(e = email, p = password)
    cursor.execute(query)
    SQLconnection.commit()
    return redirect(url_for('login'))
  return render_template("login.html")

# Login Form Try 2
@app.route('/login', methods=['GET','POST'])
def loginform():
  EM = request.form['Email']
  PW = request.form['Password']
  SQLconnection = sqlite3.connect(currentlocation + "/accounts.db")    
  cursor = SQLconnection.cursor()   # cursor works with operations / selects queries
  query = "SELECT Email, Password from Users WHERE Email = {em} AND Password = {pw})".format(em = EM, pw = PW)

  rows = cursor.execute(query)
  rows = rows.fetchall()
  if len(rows) == 1:
    return redirect(url_for('score'))
  else:
    return redirect(url_for('register'))