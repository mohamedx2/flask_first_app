from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb+srv://root:root@cluster0.p2dxfqt.mongodb.net/'
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.route('/signup', methods=['POST'])
def sign_up():
    try:
        # Check if user already exists
        existing_user = mongo.db.users.find_one({'email': request.json['email']})

        # If user already signed up, don't allow them to make another account
        if existing_user:
            return jsonify({'message': 'Already signed up', 'success': False}), 200

        # Hash the password with bcrypt
        hashed_password = bcrypt.generate_password_hash(request.json['password']).decode('utf-8')

        # Replace the plain text password with the hashed one
        request.json['password'] = hashed_password

        # Create a new user and save
        new_user = {
            'email': request.json['email'],
            'password': request.json['password']
        }
        saved_user = mongo.db.users.insert_one(new_user)

        # Generate JWT token for the user
        token = create_access_token(identity=str(saved_user.inserted_id))

        # Return success response with the saved user and token
        return jsonify({
            'success': True,
            'message': 'Created new user',
            'data': {
                'user': new_user,
                'token': token
            }
        }), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred while signing up'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        # Check if user exists
        existing_user = mongo.db.users.find_one({'email': request.json['email']})

        # If user doesn't exist, return error response
        if not existing_user:
            return jsonify({'message': 'User not found', 'success': False}), 404

        # Compare the password with bcrypt
        is_password_correct = bcrypt.check_password_hash(existing_user['password'], request.json['password'])

        # If password is incorrect, return error response
        if not is_password_correct:
            return jsonify({'message': 'Invalid credentials', 'success': False}), 401

        # Generate JWT token for the user
        token = create_access_token(identity=str(existing_user['_id']))

        # Return success response with the generated token
        return jsonify({
            'success': True,
            'message': 'Logged in successfully',
            'data': {
                'user': existing_user,
                'token': token
            }
        }), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred while logging in'}), 500

@app.route('/articles', methods=['GET'])
def show_articles():
    try:
        all_articles = mongo.db.articles.find()
        return jsonify(all_articles), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred while fetching articles'}), 500

@app.route('/articles/mine', methods=['GET'])
@jwt_required
def my_articles():
    try:
        current_user = get_jwt_identity()
        user_articles = mongo.db.articles.find({'poster': current_user})
        return jsonify(user_articles), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred while fetching user articles'}), 500

@app.route('/articles', methods=['POST'])
@jwt_required
def create_article():
    try:
        current_user = get_jwt_identity()
        new_article = {
            'title': request.json['title'],
            'body': request.json['body'],
            'poster': current_user
        }
        saved_article = mongo.db.test.articles.insert_one(new_article)
        return jsonify({
            'success': True,
            'message': 'Created new article',
            'data': new_article
        }), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred while creating article'}), 500

@app.route('/articles/<article_id>', methods=['PUT'])
@jwt_required
def update_article(article_id):
    try:
        current_user = get_jwt_identity()
        article = mongo.db.test.articles.find_one({'_id': article_id})

        if not article:
            return jsonify({'message': 'Article not found'}), 404

        if current_user != article['poster']:
            return jsonify({'message': 'Unauthorized'}), 401

        updated_article = mongo.db.test.articles.find_one_and_update(
            {'_id': article_id},
            {'$set': {'title': request.json['title'], 'content': request.json['content']}},
            return_document=True
        )

        return jsonify({
            'updated_article': updated_article,
            'message': 'Updated successfully'
        }), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred while updating article'}), 500

@app.route('/articles/<article_id>', methods=['DELETE'])
@jwt_required
def delete_article(article_id):
    try:
        current_user = get_jwt_identity()
        article = mongo.db.articles.find_one({'_id': article_id})

        if not article:
            return jsonify({'message': 'Article not found'}), 404

        if current_user != article['poster']:
            return jsonify({'message': 'Unauthorized'}), 401

        mongo.db.articles.delete_one({'_id': article_id})

        return jsonify({'message': 'Article deleted successfully'}), 200
    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred while deleting article'}), 500

if __name__ == '__main__':
    app.run(debug=True)

