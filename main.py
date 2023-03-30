from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import email_validator
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# SQLite 
currentlocation = "/path/to/directory"
connection = sqlite3.connect('accounts.db')  # creating database
#cursor = connection.cursor() # work with operations / select queries


@app.route('/')
def base():
  return render_template('base.html')

@app.route('/login')
def login():
  return render_template('login.html')

@app.route('/register')
def register():
  return render_template('register.html')

# Login Validation
@app.route('/login', methods=['GET','POST'])
def loginform():
    if request.method == 'POST':
        email = request.form['Email']
        password = request.form['Password']

        # Use parameterized queries to prevent SQL injection attacks
        query = "SELECT email, password FROM users WHERE email = ?"
        parameters = (email,)

        try:
            SQLconnection = sqlite3.connect(currentlocation + "/accounts.db") #  Connect to the database and execute the query
            cursor = SQLconnection.cursor()  # cursor works with operations / selects queries
            cursor.execute(query, parameters)
            result = cursor.fetchone()
            cursor.close()
            SQLconnection.close()

            # Check if the email and password are correct
            if result is not None and check_password_hash(result[1], password):
                return redirect(url_for('score'))  # Successful Login Result
            else:
                return render_template('login.html', error='Invalid email or password') #  Unsuccessful Login
        except Exception as e:
            return "Error: " + str(e)
          
    return render_template('login.html')

  
# Register Form
@app.route('/register', methods=['GET', 'POST'])
def registerform():
    if request.method == "POST":
        email = request.form["Email"]
        password = request.form["Password"]
        # Email Validation
        try:
            email_validator.validate_email(email)
        except email_validator.EmailNotValidError:
            return "Error: Invalid email address"
        # Password Validation
        if len(password) < 8:
            return "Password must be at least 8 characters long. Try Again."
        elif not any(char.isupper() for char in password):
            return "Password must contain at least 1 uppercase letter. Try Again"

        hashed_password = generate_password_hash(password) # hashing password for increased security

        # Use parameterized queries to prevent SQL injection attacks
        query = "INSERT INTO users (email, password) VALUES (?, ?)"
        parameters = (email, hashed_password)

        try:
            SQLconnection = sqlite3.connect(currentlocation + "/accounts.db") # connect to db and execute the query
            cursor = SQLconnection.cursor()
            cursor.execute(query, parameters)
            SQLconnection.commit()
            cursor.close()
            SQLconnection.close()
        except Exception as e:
            return "Error: " + str(e)

        return redirect(url_for('login'))  # Successful Login Result

    return render_template("register.html")


# Easter Egg (when input marks > 100)
@app.route('/cheating')
def cheating():
  return render_template('cheating.html')

@app.route('/motivationalpicture')
def motivational_picture():
  return render_template('motivationalpicture.html')

  
# H2 Computing
file = open('comp.txt', 'r')
read = file.readlines()
comp_scores = []
for line in read:
  comp_scores.append(line.strip())

# H2 Mathematics
file = open('math.txt', 'r')
read = file.readlines()
math_scores = []
for line in read:
  math_scores.append(line.strip())

# H2 Physics
file = open('phy.txt', 'r')
read = file.readlines()
phy_scores = []
for line in read:
  phy_scores.append(line.strip())

# H1 Economics
file = open('econs.txt', 'r')
read = file.readlines()
econs_scores = []
for line in read:
  econs_scores.append(line.strip())

# Sorting Data in Ascending Order 
def data_sorter(data):
  scores = []
  for marks in data:
    if marks[-3:].isdigit() == True:
      scores.append(100)
    elif marks[-2:].isdigit() == True:
      scores.append(int(marks[-2:]))
    else:
      scores.append(int(marks[-1]))
  scores = sorted(scores)
  return scores

# Calculating Percentile
def percentile(data2, score):
  mark_scored = int(score)
  data2.append(mark_scored)
  data2 = sorted(data2)
  if mark_scored in data2:
    index = data2.index(mark_scored) + 1
  percentile = round((index/len(data2)) * 100, 0)
  return percentile
  

@app.route('/score')
def score():
  return render_template('score.html')

@app.route('/score', methods=['GET', 'POST'])
def scoreform():
    if request.method == 'POST':
        subject = request.form['Subject']
        score = int(request.form['Score'])
        if score > 100 or score < 0:
          return render_template("cheating.html")
        elif subject.lower() == "computing":
          percentile_rank = percentile(data_sorter(comp_scores), score)
          if percentile_rank >= 80:
            return render_template(("PercentileGreater80.html"), score=score, percentile_rank=percentile_rank)
          elif percentile_rank >= 50:
            return render_template(("PercentileGreater50.html"), score=score, percentile_rank=percentile_rank)
          else: 
            return render_template(("PercentileLess50.html"), score=score, percentile_rank=percentile_rank)
        elif subject.lower() == "mathematics":
          percentile_rank = percentile(data_sorter(math_scores), score)
          if percentile_rank >= 80:
            return render_template(("PercentileGreater80.html"), score=score, percentile_rank=percentile_rank)
          elif percentile_rank >= 50:
            return render_template(("PercentileGreater50.html"), score=score, percentile_rank=percentile_rank)
          else: 
            return render_template(("PercentileLess50.html"), score=score, percentile_rank=percentile_rank)
        elif subject.lower() == "physics":
          percentile_rank = percentile(data_sorter(phy_scores), score)
          if percentile_rank >= 80:
            return render_template(("PercentileGreater80.html"), score=score, percentile_rank=percentile_rank)
          elif percentile_rank >= 50:
            return render_template(("PercentileGreater50.html"), score=score, percentile_rank=percentile_rank)
          else: 
            return render_template(("PercentileLess50.html"), score=score, percentile_rank=percentile_rank)
        elif subject.lower() == "economics":
          percentile_rank = percentile(data_sorter(econs_scores), score)
          if percentile_rank >= 80:
            return render_template(("PercentileGreater80.html"), score=score, percentile_rank=percentile_rank)
          elif percentile_rank >= 50:
            return render_template(("PercentileGreater50.html"), score=score, percentile_rank=percentile_rank)
          else:
            return render_template(("PercentileLess50.html"), score=score, percentile_rank=percentile_rank)
        else:
          return render_template("score.html")


# Percentile Greater or Equals to 80
@app.route('/above80')
def above80():
  return render_template('PercentileGreater80.html')

# Percentile Greater or Equals to 50
@app.route('/above50')
def above50():
  #percentile_rank = request.args.get('percentile_rank')
  return render_template('PercentileGreater50.html')

# Percentile Less than 50
@app.route('/below50')
def below50():
  #percentile_rank = request.args.get('percentile_rank')
  return render_template('PercentileLess50.html')

  

app.run(host='0.0.0.0', port=81)