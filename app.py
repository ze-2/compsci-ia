from functools import wraps
import json
import sys
from flask import Flask, render_template, redirect, url_for, request, flash, session
from model import User
# from flask_sslify import SSLify
import sqlite3
from flask_login import LoginManager, login_required, login_user, logout_user, current_user

# Initial configs of stuff
app = Flask(__name__)
# SSLify(app)

# Auth config
app = Flask(__name__)
app.secret_key = "af8abc87f384cdfb0c88d20bb0d66fa67dc6b8040ec877f079e9112b46ce7215"
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(email):
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute(
            "SELECT type FROM users WHERE email = (?)", (email,))
        rows = cur.fetchall()
    role = rows[0]['type']

    return User(email, role)


@app.route('/')
def index():
    # Idk what to put for the index page so we're rendering the login page
    return render_template('login.html')


def login_required(roles=["any"]):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            auth = False
            for role in roles:
                if ((current_user.role == role) or (role == "any")):
                    auth = True
                    break
            return login_manager.unauthorized() if auth == False else fn(*args, **kwargs)
        return decorated_view
    return wrapper

# User

# TODO: don't let user choose the organization (I FORGOT)


@app.route('/user', methods=['POST', 'GET'])
@login_required(['user'])
def user():
    if request.method == 'POST':
        with sqlite3.connect('database.db') as con:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute(
                "SELECT organization, name FROM users WHERE email=(?)", (current_user.get_id(),))
            rows = cur.fetchall()

        org = rows[0][0]
        creator = rows[0][1]
        created = request.form['created']
        updated = request.form['updated']
        title = request.form['title']
        desc = request.form['desc']
        requester = request.form['requester']
        priority = request.form['priority']
        status = request.form['status']
        location = request.form['location']
        uid = request.form['uid']
        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("UPDATE tickets SET organization=(?), created=(?), updated=(?), title=(?), description=(?), requester=(?), priority=(?), status=(?), location=(?), creator=(?) WHERE id=(?)",
                        (org, created, updated, title, desc, requester, priority, status, location, creator, uid))
            con.commit()
        flash('Updated successfully!!', 'alert-success')
        return render_template('user.html')
    else:
        return render_template('user.html')

# TODO assignment system


@app.route('/get_tickets')
@login_required(["tech", "admin"])
def get_tickets():
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM tickets")
        rows = cur.fetchall()

    tickets = []
    for ticket in rows:
        ticket = dict(ticket)
        tickets.append(ticket)
    return json.dumps(tickets)


@app.route('/get_orgs')
@login_required(["any"])
def get_orgs():
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM organizations")
        rows = cur.fetchall()

    orgs = []
    for org in rows:
        org = dict(org)
        orgs.append(org)
    return json.dumps(orgs)


@app.route('/get_ticket')
@login_required(["any"])
def get_ticket():
    ticket_id = request.args.get('id')
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM tickets WHERE id=(?)", (ticket_id,))
        rows = cur.fetchall()

    tickets = []
    for ticket in rows:
        ticket = dict(ticket)
        tickets.append(ticket)
    return json.dumps(tickets)


@app.route('/get_org')
@login_required(["any"])
def get_org():
    org_id = request.args.get('id')
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM organizations WHERE id=(?)", (org_id))
        rows = cur.fetchall()

    orgs = []
    for org in rows:
        org = dict(org)
        orgs.append(org)
    return json.dumps(orgs)

# TODO: maybe implement pagination if there's time :)


@app.route('/get_tech_admin')
@login_required(["any"])
def get_tech_admin():
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE type='tech' OR type='admin'")
        rows = cur.fetchall()

    orgs = []
    for org in rows:
        org = dict(org)
        orgs.append(org)
    return json.dumps(orgs)


@app.route('/tickets', methods=['GET', 'POST'])
@login_required(['admin', 'tech'])
def tickets():
    if request.method == 'POST':
        org = request.form['org']
        created = request.form['created']
        updated = request.form['updated']
        title = request.form['title']
        desc = request.form['desc']
        requester = request.form['requester']
        # priority = request.form['priority'] - remove for closing functionality
        status = request.form['status']
        location = request.form['location']
        with sqlite3.connect('database.db') as con:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute(
                "SELECT name FROM users WHERE email=(?)", (current_user.get_id(),))
            rows = cur.fetchall()
        creator = rows[0][0]
        uid = request.form['uid']
        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("UPDATE tickets SET organization=(?), created=(?), updated=(?), title=(?), description=(?), requester=(?), status=(?), location=(?), creator=(?) WHERE id=(?)",
                        (org, created, updated, title, desc, requester, status, location, creator, uid, ))
            con.commit()
        flash('Updated successfully!!', 'alert-success')
        return render_template('tickets.html')
    else:
        return render_template('tickets.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if (current_user.is_authenticated):
        role = current_user.get_role()
        if role == 'admin':
            flash('Redirecting...', 'alert-primary')
            return redirect(url_for('tickets'))
        elif role == 'user':
            flash('Redirecting...', 'alert-primary')
            return redirect(url_for('user'))
        else:
            return 'huh. how did you get here.'

    if request.method == 'POST':
        # Get values from login
        email = request.form['email']
        password = request.form['password']

        # Gets user's password
        # yes, plaintext, yes, i will change it, maybe
        with sqlite3.connect('database.db') as con:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute(
                "SELECT password FROM users WHERE email = (?)", (email,))
            rows = cur.fetchall()

        try:
            db_password = rows[0]['password']
        except:
            flash(
                "User doesn't exist - contact your administrator for help.", 'alert-danger')
            return redirect(url_for('login'))

        if db_password == password:
            login_user(User(email=email, role="user"), remember=True)
            with sqlite3.connect('database.db') as con:
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                cur.execute(
                    "SELECT type FROM users WHERE email = (?)", (email,))
                rows = cur.fetchall()
            account_type = rows[0]['type']
            if account_type == 'admin':
                flash('Logged in successfully.', 'alert-success')
                return redirect(url_for('tickets'))
            elif account_type == 'user':
                flash('Logged in successfully.', 'alert-success')
                return redirect(url_for('user'))
            else:
                return 'huh. how did you get here.'
        else:
            flash("Incorrect login credentials.", 'alert-danger')
            return render_template('login.html')

    # If user gets there by GET - they haven't submitted the form
    else:
        return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/new', methods=['POST', 'GET'])
@login_required(['admin', 'tech'])
def new():
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        date = request.form['date']
        location = request.form['location']
        requester = request.form['requester']
        priority = request.form['priority']
        status = request.form['status']
        org = request.form['org']
        creator = request.form['creator']

        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("INSERT INTO tickets(title, description, creator, organization, priority, status, created, requester, location) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (title, desc, creator, org, priority, status, date, requester, location, ))
            con.commit()
            flash("Created successfully!", 'alert-success')
        return render_template('new.html')
    else:
        return render_template('new.html')


@app.route('/new_ticket_user', methods=['POST', 'GET'])
def new_ticket_user():
    if request.method == 'POST':
        with sqlite3.connect('database.db') as con:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute(
                "SELECT organization, name FROM users WHERE email=(?)", (current_user.get_id(),))
            rows = cur.fetchall()
        org = rows[0][0]
        creator = rows[0][1]
        title = request.form['title']
        desc = request.form['desc']
        date = request.form['date']
        requester = request.form['requester']
        location = request.form['location']
        assignee = request.form['assignee']
        priority = request.form['priority']
        status = request.form['status']

        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("INSERT INTO tickets(title, description, assignee,  creator, organization, priority, status, created, location, requester) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (title, desc, assignee, creator, org, priority, status, date, location, requester,))
            con.commit()
            flash("Created successfully!", 'alert-success')
        return render_template('new_ticket_user.html')
    else:
        return render_template('new_ticket_user.html')


@app.route('/user_settings', methods=['POST', 'GET'])
@login_required(['user'])
def user_settings():
    return 'todo'


@app.route('/admin_settings', methods=['POST', 'GET'])
@login_required(['admin'])
def admin_settings():
    if request.method == 'POST':
        usr_email = current_user.get_id()
        name = request.form['name']
        org = request.form['org']
        email = request.form['email']
        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("UPDATE users SET email=(?), name=(?), organization=(?) WHERE email=(?)",
                        (email, name, org, usr_email))
            con.commit()
        flash('Updated successfully!', 'alert-success')
        return render_template('admin_settings.html', name=name, org=org, email=email)
    else:
        email = current_user.get_id()

        with sqlite3.connect('database.db') as con:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute(
                "SELECT name, organization, email FROM users WHERE email = (?)", (email,))
            rows = cur.fetchall()

        name = rows[0]['name']
        org = rows[0]['organization']
        email = rows[0]['email']
        return render_template('admin_settings.html', name=name, org=org, email=email)

# todo: when organization is changed, changes in users & tickets also updated


@app.route('/manage_organizations', methods=['POST', 'GET'])
@login_required(['admin', 'tech'])
def manage_organizations():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        org_type = request.form['type']
        org_id = request.form['org_id']
        old_org = request.form['old_org']
        print(old_org, file=sys.stdout, flush=True)
        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("UPDATE organizations SET email=(?), name=(?), type=(?) WHERE id=(?)",
                        (email, name, org_type, org_id,))
            con.commit()
        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute(
                "UPDATE users SET organization=(?) WHERE organization=(?)", (name, old_org,))
            con.commit()

        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute(
                "UPDATE tickets SET organization=(?) WHERE organization=(?)", (name, old_org,))
            con.commit()

        flash('Updated successfully!!', 'alert-success')
        return render_template('manage_organizations.html')
    else:
        return render_template('manage_organizations.html')


@app.route('/add_organization', methods=['POST', 'GET'])
@login_required(['admin', 'tech'])
def add_organization():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        org_type = request.form['type']
        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("INSERT INTO organizations(name, email, type) VALUES (?, ?, ?)",
                        (name, email, org_type))
            con.commit()
            flash("Created successfully!", 'alert-success')
        return render_template('add_organization.html')
    else:
        return render_template('add_organization.html')


@app.route('/manage_users', methods=['GET', 'POST'])
@login_required(['admin', 'tech'])
def manage_users():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        org = request.form['org']
        uid = request.form['uid']

        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("SELECT email FROM users WHERE id=(?)",
                        (uid,))
            rows = cur.fetchall()

        old_email = rows[0][0]

        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("UPDATE users SET email=(?), name=(?), password=(?), organization=(?) WHERE id=(?)",
                        (email, name, password, org, uid,))

            con.commit()

        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("UPDATE tickets SET creator=(?), organization=(?) WHERE creator=(?)",
                        (email, org, old_email))

            con.commit()

        flash('Updated successfully!!', 'alert-success')
        return render_template('manage_users.html')
    else:
        return render_template('manage_users.html')


@app.route('/add_location', methods=['GET', 'POST'])
@login_required(['admin', 'tech'])
def add_location():
    if request.method == 'POST':
        location = request.form['location']
        org = request.form['org']

        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("INSERT INTO locations(location, organization) VALUES (?, ?)",
                        (location, org,))
            con.commit()

            con.commit()
        flash('Added successfully!!', 'alert-success')
        return render_template('add_location.html')
    else:
        return render_template('add_location.html')


@app.route('/manage_locations', methods=['GET', 'POST'])
@login_required(['admin', 'tech'])
def manage_locations():
    if request.method == 'POST':
        location = request.form['location']
        org = request.form['org']
        uid = request.form['uid']

        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("UPDATE locations SET location=(?), organization=(?) WHERE id=(?)",
                        (location, org, uid,))

            con.commit()
        flash('Updated successfully!!', 'alert-success')
        return render_template('manage_locations.html')
    else:
        return render_template('manage_locations.html')


@app.route('/add_user', methods=['GET', 'POST'])
@login_required(['admin', 'tech'])
def add_user():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        org = request.form['org']
        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("INSERT INTO users(name, email, password, type, organization) VALUES (?, ?, ?, ?, ?)",
                        (name, email, password, "user", org))
            con.commit()
            flash("Created successfully!", 'alert-success')
            return render_template('add_user.html')
    else:
        return render_template('add_user.html')


@app.route('/get_users')
@login_required(["admin", "tech"])
def get_users():
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM users where type='user'")
        rows = cur.fetchall()

    users = []
    for user in rows:
        user = dict(user)
        users.append(user)
    return json.dumps(users)


@app.route('/get_all')
@login_required(["admin", "tech"])
def get_all():
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM users")
        rows = cur.fetchall()

    users = []
    for user in rows:
        user = dict(user)
        users.append(user)
    return json.dumps(users)


@app.route('/get_user')
@login_required(["admin", "tech"])
def get_user():
    uid = request.args.get('uid')
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE id=(?)", (uid))
        rows = cur.fetchall()

    orgs = []
    for org in rows:
        org = dict(org)
        orgs.append(org)
    return json.dumps(orgs)


@app.route('/get_user_tickets')
def get_user_tickets():
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM tickets WHERE creator=(?)",
                    (current_user.get_id(),))
        rows = cur.fetchall()
    tickets = []
    for ticket in rows:
        ticket = dict(ticket)
        tickets.append(ticket)
    return json.dumps(tickets)


@app.route('/manage_tech', methods=['GET', 'POST'])
@login_required(['admin'])
def manage_tech():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        org = request.form['org']
        uid = request.form['uid']

        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("UPDATE users SET email=(?), name=(?), password=(?), organization=(?) WHERE id=(?)",
                        (email, name, password, org, uid))
            con.commit()
        flash('Updated successfully!!', 'alert-success')
        return render_template('manage_tech.html')
    else:
        return render_template('manage_tech.html')


@app.route('/add_tech', methods=['GET', 'POST'])
@login_required(['admin'])
def add_tech():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        org = request.form['org']
        with sqlite3.connect('database.db') as con:
            cur = con.cursor()
            cur.execute("INSERT INTO users(name, email, password, type, organization) VALUES (?, ?, ?, ?, ?)",
                        (name, email, password, "tech", org))
            con.commit()
            flash("Created successfully!", 'alert-success')
            return render_template('add_tech.html')
    else:
        return render_template('add_tech.html')


@app.route('/get_techs')
@login_required(["admin", "tech"])
def get_techs():
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM users where type='tech'")
        rows = cur.fetchall()

    # Grammar who
    techs = []
    for tech in rows:
        tech = dict(tech)
        techs.append(tech)
    return json.dumps(techs)


@app.route('/render_orgs')
@login_required(['any'])
def render_orgs():
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM organizations")
        rows = cur.fetchall()

    orgs = []
    for org in rows:
        org = dict(org)
        orgs.append(org)
    return json.dumps(orgs)


@app.route('/get_locations')
@login_required(["admin", "tech"])
def get_locations():
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM locations")
        rows = cur.fetchall()

    locations = []
    for location in rows:
        location = dict(location)
        locations.append(location)
    return json.dumps(locations)


@app.route('/get_location')
@login_required(["admin", "tech"])
def get_location():
    uid = request.args.get('uid')
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM locations WHERE id=(?)", (uid))
        rows = cur.fetchall()

    locations = []
    for location in rows:
        location = dict(location)
        locations.append(location)
    return json.dumps(locations)

# todo: delete organization button
# todo: resolve all placeholders

# closing system: on button press, pullover confirmation, js hits this endpoint and takes ID, close ticket here.
@app.route('/close_ticket', methods=['POST', 'GET'])
@login_required(['any'])
def close_ticket():
    uid = request.args.get('uid')
    return 'todo'


@app.route('/get_user_org')
@login_required(['admin', 'tech'])
def get_user_org():
    name = request.args.get('id')
    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT organization FROM users WHERE name=(?)", (name,))
        rows = cur.fetchall()
    return rows[0][0]


if __name__ == "__main__":
    app.run()
