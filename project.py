# -*- coding: utf-8 -*-

from database_setup import Base, CatalogItem, Catalog, User
from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   jsonify,
                   url_for,
                   flash)
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from flask import session as login_session
import random
import string

# adding auth
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from functools import wraps

app = Flask(__name__)

# reading client_secrets.json file
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog App"

# Connect to Database and create database session
engine = create_engine('sqlite:///catalogwithuser.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# check the login in a session
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect(url_for('showLogin'))
        return f(*args, **kwargs)
    return decorated_function

# signing in routing,
@app.route('/login')
def showLogin():
    """
    purpose :handle /login
    :return: render login.html
    """
    # Create anti-forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# google signin
@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Log into Google Accounts."""
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200
        )
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
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

##########################################################
# User Helper Functions###################################
def createUser(login_session):
    """
    putpose: create user in database
    :param login_session:
    :return: user id
    """
    newUser = User(name=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """
    purpose: get user from database
    :param user_id:
    :return: user object
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """
    purpose: get user id from database
    :param email:
    :return: user id
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.',
            400)
        )
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/disconnect')
def disconnect():
    """
    disconnect user from site
    :return: redirect to public catalog page
    """
    if 'provider' in login_session:
        if 'gplus_id' in login_session:
            del login_session['gplus_id']
        if 'credentials' in login_session:
            del login_session['credentials']
        else:
            flash("You were not logged in")
            return redirect(url_for('showCatalogs'))

#######################################################
###################flask routing ######################
# Show all catalog
@app.route('/')
@app.route('/catalog/')
def showCatalogs():
    catalogs = session.query(Catalog).order_by(asc(Catalog.name))
    items = session.query(CatalogItem).order_by(asc(CatalogItem.name))
    quantity = items.count()
    if 'username' not in login_session:
        return render_template(
            'catalogspublic.html',
            catalogs=catalogs,
            title="Latest items",
            items=items,
            quantity=quantity
            )
    else:
        return render_template(
            'catalogs.html',
            catalogs=catalogs,
            title="Latest items",
            items=items,
            quantity=quantity
            )


# Show catalog items for specific catalog
@app.route('/catalog/<string:catalog_name>/items/')
def showCatalogItems(catalog_name):
    catalogs = session.query(Catalog).order_by(asc(Catalog.name))
    # query catalog for the catalog name passed
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    items = session.query(CatalogItem).filter_by(
        catalog_id=catalog.id).order_by(asc(CatalogItem.name))
    quantity = items.count()
    if 'username' not in login_session:
        return render_template(
            'catalogspublic.html',
            catalogs=catalogs,
            title=catalog_name + " items",
            items=items,
            quantity=quantity
        )
    else:
        return render_template(
            'catalogs.html',
            catalogs=catalogs,
            title=catalog_name + " items",
            items=items,
            quantity=quantity
        )


# show item details
@app.route('/catalog/<string:catalog_name>/<string:item_id>/')
def showItemDetails(catalog_name, item_id):
    item = session.query(CatalogItem).filter_by(id=item_id).one()
    catalogs = item.catalog_id
    if 'username' not in login_session:
        return render_template('itemdetailsPublic.html',
                               item_name=item.name,
                               item_description=item.description
                               )
    if item.user_id != login_session['user_id']:
        return render_template('itemdetailsPublic.html',
                               item_name=item.name,
                               item_description=item.description
                               )
    else:
        return render_template('itemdetails.html',
                               item=item,
                               catalogs=catalogs
                               )


# edit catalog item if the user is login and user_id = item.user_id
@app.route('/catalog/<int:catalog_id>/<string:item_id>/edit/',
           methods=['GET', 'POST'])
@login_required
def editItem(item_id, catalog_id):
    item = session.query(CatalogItem).filter_by(id=item_id).one()
    if login_session['user_id'] != item.user_id:
        return redirect(url_for('addItem'))
    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        if request.form['catalog']:
            item.catalog_id = catalog_id
        session.add(item)
        session.commit()
        flash("Catalog item updated!", 'success')
        return redirect(url_for('showCatalogs'))
    else:
        catalogs = session.query(Catalog).order_by(asc(Catalog.name))
        return render_template('edit.html', item=item, catalogs=catalogs)


# delete item
@app.route('/catalog/<int:catalog_id>/<string:item_id>/delete/',
           methods=['GET', 'POST'])
@login_required
def deleteItem(item_id, catalog_id):
    item = session.query(CatalogItem).filter_by(id=item_id).one()
    if login_session['user_id'] != item.user_id:
        return redirect(url_for('addItem'))
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash("Catalog item deleted successfully!", 'success')
        return redirect(url_for('showCatalogs'))
    else:
        return render_template('delete.html', item=item)


# add item to database .
# require user login
@app.route('/catalog/add/', methods=['GET', 'POST'])
@login_required
def addItem():
    if request.method == 'POST':
        if request.form['catalog']:
            catalog = session.query(Catalog).filter_by(
                name=request.form['catalog']).one()
        newItem = CatalogItem(
            name=request.form['name'],
            description=request.form['description'],
            catalog_id=catalog.id,
            user_id=login_session['user_id']
        )
        session.add(newItem)
        session.commit()
        return redirect(url_for('showCatalogs'))
    else:
        catalogs = session.query(Catalog).order_by(asc(Catalog.name))
        return render_template('addItem.html', catalogs=catalogs)


# JSON APIs to view Catalog Information
@app.route('/catalog.json')
def catalogJSON():
    catalog_json = []
    catalogs = session.query(Catalog).all()
    for catalog in catalogs:
        items = session.query(CatalogItem).filter_by(
            catalog_id=catalog.id).all()
        items_list = []
        for item in items:
            item_data = {
                'cat_id': item.catalog_id,
                'name': item.name,
                'id': item.id,
                'description': item.description
            }
            items_list.append(item_data)
        catalog_list = {
            'id': catalog.id,
            'name': catalog.name
        }
        catalog_json.append(catalog_list)
        catalog_json.append(items_list)
    return jsonify(Catalog=catalog_json)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
