from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, join_room, emit
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from pymongo.errors import DuplicateKeyError
from database import get_user, save_user

app = Flask(__name__)
app.secret_key = "los pollos hermanos"
socketio = SocketIO(app)
Login_Manager = LoginManager()
Login_Manager.login_view = "login"
Login_Manager.init_app(app)

clients = {} 

@app.route('/')
def welcome():
    return render_template("welcome.html")

@app.route('/home')
def home():
    return render_template("index.html")

@app.route("/authhome")
def authhome():
    return render_template("authhome.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("authhome"))
    message = ''
    if request.method == 'POST':
        username = request.form.get("username")
        password_input = request.form.get("password")
        user = get_user(username)
        
        if user and user.check_password(password_input):
            login_user(user)
            return redirect(url_for("authhome"))
        else:
            message = "INCORRECT USERNAME OR PASSWORD"
    return render_template("login.html", message=message)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    message = ''
    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        try:
            save_user(username, email, password)
            return redirect(url_for("login"))
        except DuplicateKeyError:
            message = "USERNAME ALREADY IN USE"
    return render_template("signup.html", message=message)

@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
        return redirect(url_for("welcome"))
    else:
        return redirect(url_for("welcome"))
@app.route("/leave")
def leave():
    if current_user.is_authenticated:
        return redirect(url_for("authhome"))
    else:
        return redirect(url_for("home"))

@app.route('/chat')
def chat():
    username = request.args.get('username')
    room = request.args.get('room')
    if username and room:
        return render_template('chat.html', username=username, room=room)
    else:
        return redirect(url_for("home"))

@socketio.on("send_message")
def handle_sent_message(data):
    app.logger.info("{} has sent message to the room {} : {}".format(data["username"], data["room"], data["message"]))
    socketio.emit("receive_message", data, room=data["room"])

@socketio.on("send_private_message")
def handle_private_message(data):
    recipient = data["recipient"]
    recipient_sid = clients.get(recipient)
    
    if recipient_sid:
        app.logger.info("{} has sent a private message to {}: {}".format(data["username"], recipient, data["message"]))
        emit("receive_private_message", data, room=recipient_sid)
    else:
        emit("receive_private_message", {"username": "System", "message": "Recipient not found or not in the room."}, room=request.sid)

@socketio.on("join_room")
def handle_join_room_event(data):
    app.logger.info("{} has joined the room {}".format(data['username'], data['room']))
    clients[data["username"]] = request.sid 
    join_room(data['room'])
    socketio.emit("join_room_announcement", data, room=data['room'])

@Login_Manager.user_loader
def load_user(username):
    return get_user(username)

if __name__ == "__main__":
    socketio.run(app, debug=True)
