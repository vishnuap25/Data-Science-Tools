#library import
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

#app initialization
app = Flask(__name__)

#Secret key to encode/decode tokens
app.config['SECRET_KEY'] = 'X34RSS1R76R2SVSEAL'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

#Class for User Data Database
class User(db.Model):    
    
    __tablename__='user'
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

#function to check token existance
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message':'token is required'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message':'token is required'}), 401
        return f(current_user,*args,**kwargs)
    return decorated
            
#function to get user list
@app.route('/users',methods=['GET'])
@token_required 
def get_all_users(current_user):
    users = User.query.all()
    output = []
    for user in users:
        user_data ={}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)        
    return jsonify({'users' : output})

#function to get user details
@app.route('/users/<public_id>',methods=['GET'])
@token_required
def get_users_details(current_user,public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'user does not exist'})
    else:  
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin        
        return jsonify({'user' : user_data})

#function to create new users
@app.route('/users',methods=['POST'])
@token_required
def create_new_users(current_user):
    if not current_user.admin:
        return jsonify({'message':'Required admin privillages for this operation'})
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    publicid = str(uuid.uuid4())
    new_user = User(public_id=publicid, name = data['name'],
                    password = hashed_password, admin = False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'operation':'User Creation',
                    'username':data['name'],
                    'public_id':publicid})

#function to edit the users
@app.route('/users/<public_id>',methods=['PUT'])
@token_required
def edit_users(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message':'Required admin privillages for this operation'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'user does not exist'})
    data = request.get_json()
    if 'name' in data:
        name = data['name']
        user.name = name
    if 'admin' in data:
            if data['admin'].lower() =='true':
                admin = True
            elif data['admin'].lower() =='false':
                admin = False
            else:
                return jsonify({'message' : 'unexpected value in admin field'})
            user.admin = admin 
    db.session.commit()
    return jsonify({'message' : 'user has been modified'})

#function to delete the user
@app.route('/users/<public_id>',methods=['DELETE'])
@token_required 
def delete_users(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':'Required admin privillages for this operation'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'user does not exist'})
    else:  
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message' : 'user deleted'})

#function to Autentication and token generation
@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Required Basic Authentication', 401, 
               {'WWW-Authenticate': 'Basic realm = "Login Required"'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Required Basic Authentication', 401, 
               {'WWW-Authenticate': 'Basic realm = "Login Required"'}) 
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 
                            'exp' : datetime.datetime.utcnow() + 
                            datetime.timedelta(minutes=30)},
                            app.config['SECRET_KEY'])
        return jsonify({'x-access-token' : token.decode('UTF-8')})
    return make_response('Required Basic Authentication', 401, 
               {'WWW-Authenticate': 'Basic realm = "Login Required"'}) 
        
#main function
if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5001)
