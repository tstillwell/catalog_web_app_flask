import os
from flask import Flask, request, redirect, jsonify, render_template, make_response, flash
from PIL import Image
from werkzeug import secure_filename
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Category, Item, User, Base
from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import urllib
import httplib2
import json
import requests
import ConfigParser

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

app = Flask(__name__)

engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

UPLOAD_FOLDER = './static/images/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

config = ConfigParser.RawConfigParser()
config.read('config.ini')
APP_SECRET = config.get('app-keys', 'AppSecretKey')
MS_APP_ID = config.get('app-keys', 'MicrosoftID')
MS_SECRET = config.get('app-keys', 'MicrosoftSecretKey')
GOOGLE_APP_ID = config.get('app-keys', 'GoogleID')
GOOGLE_SECRET_KEY = config.get('app-keys', 'GoogleSecretKey')

def make_user(login_session):
	new_user = User(name = login_session['username'],
					email = login_session['email'])
	session.add(new_user)
	session.commit()
	user = session.query(User).filter_by(email = login_session['email']).one()
	return user.id

def user_by_session_id():
	try:
		user = session.query(User).filter_by(id = login_session['user_id']).one()
	except:
		user = None
	finally:
		return user

def userid_by_email(email):
	try:
		user = session.query(User).filter_by(email = email).one()
		return user.id
	except:
		return None


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def save_image(file):
	if file and allowed_file(file.filename.lower()):
		filename = secure_filename(file.filename)
		file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
		return filename
	else:
		return None

def save_image_as_jpg(image_path):
	""" Takes uploaded image, and saves it in jpg format """
	try:
		filename = image_path.split('/')[-1]
		filename_no_extension = filename.split('.')[1]
		image_file = Image.open(image_path)
		image_file.save(filename_no_extension + '.jpg')
		return True
	except:
		return False

def itemCard(item):
	""" Used in templates to create cards which display item info """
	return render_template('card.html', item=item)
# Add itemCard to jinja globals so it can be called in templates
app.jinja_env.globals.update(itemCard=itemCard)


# Front Page
@app.route('/')
def FrontPage():
	categories = session.query(Category).all()
	items = session.query(Item).all()
	return render_template('frontpage.html',
							categories = categories,
							items = items)

def potential_new_category(name):
	""" Create a new category unless one by that name exists """
	category = session.query(Category).filter_by(name=name).one_or_none()
	if category:
		return category
	if category is None:
		category = Category(name=name)
		session.add(category)
		session.commit()
		return category

def add_photo_to_database(filename, item):
	if filename is not None:
		print "Ok, in the add_photo_to_db function "
		print "Filename is " + filename
		file_path = UPLOAD_FOLDER + filename
		file = open(file_path, "r")
		file_contents = file.read()
		file.close()
		os.remove(file_path)
		new_filename = 'itemimg-' + str(item.id) + '-'
		# give the file a unique name to avoid browser caching stale images
		new_filename += str(id(file_contents)) + '.jpg'
		new_file_path = UPLOAD_FOLDER + new_filename
		new_file = open(new_file_path, "w")
		new_file.write(file_contents)
		new_file.close()
		save_image_as_jpg(UPLOAD_FOLDER + new_filename)
		item.photo_path = "/static/images/" + new_filename
		session.add(item)
		session.commit()
	else:
		pass


# Add item
@app.route('/newitem/', methods=['GET', 'POST'])
def AddNewItem():
	if 'username' not in login_session:
		return redirect('/login')

	if request.method == 'GET':
		categories = session.query(Category).all()
		return render_template('additem.html', categories = categories)
		
	if request.method == 'POST':
		submitted_category = request.form['category']
		item_category = potential_new_category(submitted_category)
		file = request.files['item-image']
		filename = save_image(file)
		newItem = Item(name=request.form['item-name'],
					   description=request.form['item-description'],
					   category=item_category,
					   user_id=login_session['user_id'])
		session.add(newItem)
		session.commit()
		add_photo_to_database(filename, newItem)
		flash('Item added successfully.')
		return redirect('/')


# View item
@app.route('/item/<int:item_id>/')
def ViewItem(item_id):
	item_to_view = session.query(Item).filter_by(id=item_id).one()
	return render_template('viewitem.html', item = item_to_view)


# Edit item
@app.route('/item/<int:item_id>/edit/', methods=['GET', 'POST'])
def EditItem(item_id):
	if 'username' not in login_session:
		return redirect('/login')
	
	item = session.query(Item).filter_by(id = item_id).one()
	if item.user_id != userid_by_email(login_session['email']):
		return "You are not the owner of this item."

	if request.method == 'GET':
		categories = session.query(Category).all()
		item_to_edit = session.query(Item).filter_by(id=item_id).one()
		return render_template('edititem.html',
								categories=categories, item=item_to_edit)
		
	if request.method == 'POST':
		item_to_edit = session.query(Item).filter_by(id=item_id).one()
		file = request.files['new-item-image']
		filename = save_image(file)
		add_photo_to_database(filename, item_to_edit)

        submitted_category = request.form['category']
        item_category = potential_new_category(submitted_category)
        item_to_edit.name = request.form['new-item-name']
        item_to_edit.description = request.form['new-item-description']
        item_to_edit.category = item_category
        session.add(item_to_edit)
        session.commit()
        flash('Item updated.')
        return redirect('/myitems/')


# Delete item
@app.route('/item/<int:item_id>/delete/', methods=['GET', 'POST'])
def DeleteItem(item_id):
	if 'username' not in login_session:
		return redirect('/login')
	item = session.query(Item).filter_by(id = item_id).one()
	if item.user_id != userid_by_email(login_session['email']):
		return "You are not the owner of this item."

	if request.method == 'GET':
		return render_template('deleteitem.html', item=item)

	if request.method == 'POST':
		session.delete(item)
		session.commit()
		flash('Item removed from catalog.')
		return redirect('/')

# Login
@app.route('/login/')
def Login():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
	login_session['state'] = state
	ms_auth_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?'
	ms_auth_params = {"client_id": MS_APP_ID,
					  "scope": "user.read",
					  "response_type" : "code",
					  "response_mode" : "query",
					  "redirect_uri" : "http://localhost:5000/msconnect/",
					  "state" : state}
	ms_auth_url += urllib.urlencode(ms_auth_params)
	return render_template('login.html', STATE=state, ms_url = ms_auth_url, 
	                        google_app_id = GOOGLE_APP_ID)


def error_response_auth_flow(message):
	response = make_response(json.dumps(message), 401)
	response.headers['Content-Type'] = 'application/json'
	return response


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ Google OAUTH2 Callback """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        return error_response_auth_flow('Invalid state parameter.')
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        return error_response_auth_flow('Failed to upgrade the authorization code.')

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        return error_response_auth_flow(result.get('error'))

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        return error_response_auth_flow("Token's user ID doesn't match given user ID.")

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        return error_response_auth_flow("Token's client ID does not match app's.")

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']
    
    if userid_by_email(login_session['email']) == None:
        make_user(login_session)
    login_session['user_id'] = userid_by_email(login_session['email'])

    login_session['auth_provider'] = 'google'
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    return output


@app.route('/msconnect/')
def msconnect():
	""" Microsoft OAUTH2 callback """
	if request.args.get('state') != login_session['state']:
		return error_response_auth_flow('Invalid state parameter.')
	code = request.args.get('code') # code lives in memory
	# Exchange the auth code for a token
	token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
	request_data = {'client_id': MS_APP_ID,
					'scope': 'user.read',
					'grant_type':'authorization_code',
					'redirect_uri':'http://localhost:5000/msconnect/',
					'client_secret':MS_SECRET,
					'code': code}
	token_request = requests.post(token_url, data = request_data)
	token_response = token_request.json()
	access_token = token_response['access_token']
	# Use the access token to get the users info
	info_url = 'https://graph.microsoft.com/v1.0/me'
	info_request = requests.get(info_url, headers={'Authorization': 'Bearer %s' % access_token})
	data = info_request.json()
	login_session['username'] = data['displayName']
	login_session['email'] = data['userPrincipalName']
	if userid_by_email(login_session['email']) == None:
		make_user(login_session)
	login_session['user_id'] = userid_by_email(login_session['email'])
	login_session['auth_provider'] = 'microsoft'
	return redirect('/')

@app.route('/gdisconnect/')
def gdisconnect():
   access_token = login_session.get('access_token')
   if access_token is None:
       response = make_response(json.dumps('Current user not connected.'), 401)
       response.headers['Content-Type'] = 'application/json'
       return response
   url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
   h = httplib2.Http()
   result = h.request(url, 'GET')[0]
   if result['status'] == '200':
       del login_session['access_token']
       del login_session['username']
       del login_session['email']
       del login_session['gplus_id']
       del login_session['user_id']
       del login_session['auth_provider']
       flash('Logged out of your Google account.')
   return redirect('/')

@app.route('/msdisconnect/')
def msdisconnect():
	del login_session['username']
	del login_session['email']
	del login_session['user_id']
	del login_session['auth_provider']
	logout_url = 'https://login.live.com/oauth20_logout.srf?'
	logout_params = {'client_id': MS_APP_ID, 'redirect_uri': "http://localhost:5000"}
	logout_url += urllib.urlencode(logout_params)
	flash('Logged out of your Microsoft account.')
	return redirect(logout_url)

@app.route('/logout/')
def logout():
	if login_session['auth_provider'] == 'google':
		return redirect('/gdisconnect/')
	if login_session['auth_provider'] == 'microsoft':
		return redirect('/msdisconnect')

# JSON item
@app.route('/item/<int:item_id>/json/')
def ItemJson(item_id):
	item = session.query(Item).filter_by(id=item_id).one()
	return jsonify(Item=item.serialize)


# View Category
@app.route('/category/<category_name>/')
def ViewCategory(category_name):
	all_items = session.query(Item).all()
	categories = session.query(Category).all()
	items_in_category = []
	for item in all_items:
		if item.category.name.lower() == category_name.lower():
			items_in_category.append(item)
	return render_template('viewcategory.html',
							category_name = category_name,
							categories = categories,
							items = items_in_category)

# My items view
@app.route('/myitems/')
def MyItems():
	user_id = login_session['user_id']
	users_items = session.query(Item).filter_by(user_id = user_id).all()
	response = make_response(render_template('myitems.html', items = users_items))
	response.cache_control.no_store = True
	response.cache_control.no_cache = True
	return response
# Need to make sure this link redirects to login if no user detected
	
if __name__ == '__main__':
	app.debug = True
	app.secret_key = APP_SECRET # imported from config.ini
	app.run(host='0.0.0.0', port=5000)