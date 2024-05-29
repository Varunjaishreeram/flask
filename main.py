from flask import Flask, request, render_template, redirect, url_for, make_response, session, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import os
from datetime import timedelta
from textblob import TextBlob
from jwt.exceptions import ExpiredSignatureError
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb+srv://varunbharadwaj444:2L2Euh0IeJje73ij@cluster0.lvugg6e.mongodb.net/test?retryWrites=true&w=majority&appName=Cluster0'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this to a more secure secret
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Define the upload folder and subfolders
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static','uploads')
IMAGES_FOLDER = os.path.join(UPLOAD_FOLDER, 'images')
VIDEOS_FOLDER = os.path.join(UPLOAD_FOLDER, 'videos')


app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['IMAGES_FOLDER'] = IMAGES_FOLDER
app.config['VIDEOS_FOLDER'] = VIDEOS_FOLDER

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.route('/')
def index():
    token = request.cookies.get('access_token')
    username = 'Guest User'
    if token:
        try:
            decoded_token = decode_token(token.encode())  # Decode token to bytes
            current_user_id = decoded_token['sub']
            user = mongo.db.users.find_one({"_id": ObjectId(current_user_id)})
            if user:
                username = user['username']
        except ExpiredSignatureError:  # Handle expired token
            session.pop('user_id', None)  # Clear session
            response = make_response(redirect(url_for('index')))  # Redirect to index page
            response.set_cookie('access_token', '', expires=0, httponly=True)  # Clear access token cookie
            return response
        except Exception as e:
            print(f"Token validation error: {e}")
            username = 'Guest User'
    return render_template('index.html', username=username)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))  # Redirect to index if user is already logged in

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        image="images.png"

        if mongo.db.users.find_one({"username": username}):
            return render_template('register.html', message="Username already exists")

        if mongo.db.users.find_one({"email": email}):
            return render_template('register.html', message="Email already exists")

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        mongo.db.users.insert_one({
            "username": username,
            "email": email,
            "password": hashed_password,
            "image":image,
            "video":''
        })
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))  # Redirect to index if user is already logged in

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = mongo.db.users.find_one({"username": username})
        if user and bcrypt.check_password_hash(user['password'], password):
            access_token = create_access_token(identity=str(user['_id']), expires_delta=timedelta(minutes=22))
            response = make_response(redirect(url_for('index')))
            response.set_cookie('access_token', access_token, httponly=True)
            session['user_id'] = str(user['_id'])
            return response

        return render_template('login.html', message="Invalid credentials")

    return render_template('login.html')

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('index')))
    response.set_cookie('access_token', '', expires=0, httponly=True)
    session.pop('user_id', None)
    return response

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if user is not logged in

    user_id = session['user_id']
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})

    if request.method == 'GET':
        if user:
            return render_template('profile.html', user=user)
        else:
            return jsonify({"message": "User not found"}), 404

    elif request.method == 'POST':
        # Get form data
        username = request.form['username']
        email = request.form['email']
        image_filename=user['image']
        video_filename=user['video']

        # Check if files are uploaded
        image = request.files['profile_image'] if 'profile_image' in request.files else None
        video = request.files['video'] if 'video' in request.files else None
        
        
        # Save files to uploads folder
        if image:
            
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['IMAGES_FOLDER'], image_filename))
        

        if video:
            video_filename = secure_filename(video.filename)
            video.save(os.path.join(app.config['VIDEOS_FOLDER'], video_filename))
        

        # Update user data in database
        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {
            "username": username,
            "email": email,
            "image": image_filename,
            "video": video_filename
        }})

        return redirect(url_for('profile'))


@app.route('/analyze', methods=['POST'])

def analyze():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    data = request.json
    if 'text' not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data['text']
    blob = TextBlob(text)
    sentiment = blob.sentiment

    return jsonify({
        "polarity": sentiment.polarity,
        "subjectivity": sentiment.subjectivity
    })



if __name__ == '__main__':
    app.run(debug=True)

