from functools import wraps
import json
from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, session
from model import User
# from flask_sslify import SSLify
import sqlite3
from flask_login import LoginManager, login_required, login_user, logout_user, current_user


# Initial configs of stuff
app = Flask(__name__)
app.secret_key = "your_secret_key"
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

    with sqlite3.connect('database.db') as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute(
            "SELECT name FROM users WHERE email = (?)", (email,))
        rows = cur.fetchall()
    name = rows[0]['name']
    return User(email=email, role=role, name=name)


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

class OrganizationManager:
    def __init__(self, db):
        self.db = db

    def update_organization(self, org_data):
        self.db.execute_query("""
            UPDATE organizations SET email=(?), name=(?), type=(?) WHERE id=(?)
        """, (
            org_data['email'], org_data['name'], org_data['type'], org_data['id']
        ))
        self.db.execute_query("""
            UPDATE users SET organization=(?) WHERE organization=(?)
        """, (
            org_data['name'], org_data['old_org']
        ))
        flash('Updated successfully!!', 'alert-success')


    def get_orgs(self):
        rows = self.db.execute_query("SELECT * FROM organizations")
        return [dict(org) for org in rows]

    def get_org(self, org_id):
        rows = self.db.execute_query("SELECT * FROM organizations WHERE id=(?)", (org_id,))
        return [dict(org) for org in rows]

class Database:
    def __init__(self, db_name):
        self.db_name = db_name

    def execute_query(self, query, params=()):
        with sqlite3.connect(self.db_name) as con:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()
            con.commit()
        return rows


    def create_organization(self, name, email, org_type):
        self.execute_query("INSERT INTO organizations(name, email, type) VALUES (?, ?, ?)",
                           (name, email, org_type))
        flash("Created successfully!", 'alert-success')

    def manage_users(self, name, email, password, org, uid):
        old_email = self.execute_query("SELECT email FROM users WHERE id=(?)", (uid,))[0][0]
        self.execute_query("UPDATE users SET email=(?), name=(?), password=(?), organization=(?) WHERE id=(?)",
                           (email, name, password, org, uid))
        self.execute_query("UPDATE tickets SET creator=(?), organization=(?) WHERE creator=(?)",
                           (email, org, old_email))
        flash('Updated successfully!!', 'alert-success')

    def add_user(self, name, email, password, org):
        self.execute_query("INSERT INTO users(name, email, password, type, organization) VALUES (?, ?, ?, ?, ?)",
                           (name, email, password, "user", org))
        flash("Created successfully!", 'alert-success')

    def get_users(self):
        rows = self.execute_query("SELECT * FROM users where type='user'")
        users = [dict(row) for row in rows]
        return json.dumps(users)

    def get_all(self):
        rows = self.execute_query("SELECT * FROM users")
        users = [dict(row) for row in rows]
        return json.dumps(users)

    def add_tech(self, name, email, password, org):
        self.execute_query("INSERT INTO users(name, email, password, type, organization) VALUES (?, ?, ?, ?, ?)",
                           (name, email, password, "tech", org))
        flash("Created successfully!", 'alert-success')

    def get_techs(self):
        rows = self.execute_query("SELECT * FROM users where type='tech'")
        techs = [dict(row) for row in rows]
        return json.dumps(techs)

    def render_orgs(self):
        rows = self.execute_query("SELECT * FROM organizations")
        orgs = [dict(row) for row in rows]
        return json.dumps(orgs)

    def get_user_org(self, name):
        rows = self.execute_query("SELECT organization FROM users WHERE name=(?)", (name,))
        return rows[0][0]

    def get_user(self, uid):
        rows = self.execute_query("SELECT * FROM users WHERE id=(?)", (uid,))
        user = [dict(row) for row in rows]
        return json.dumps(user)

    def get_user_tickets(self, name):
        print(name)
        rows = self.execute_query("SELECT * FROM tickets WHERE creator=(?)", (name,))
        return [dict(ticket) for ticket in rows]

    def manage_tech(self, name, email, password, org, uid):
        self.execute_query("UPDATE users SET email=(?), name=(?), password=(?), organization=(?) WHERE id=(?)",
                           (email, name, password, org, uid))
        flash('Updated successfully!!', 'alert-success')


class UserManager:
    def __init__(self, db):
        self.db = db

    def update_user_settings(self, user_data):
        self.db.execute_query("""
            UPDATE users SET email=(?), name=(?), organization=(?) WHERE email=(?)
        """, (
            user_data['email'], user_data['name'], user_data['organization'], user_data['email']
        ))
        flash('Updated successfully!', 'alert-success')

    def get_tech_admin_users(self):
        rows = self.db.execute_query("SELECT * FROM users WHERE type='tech' OR type='admin'")
        return [dict(user) for user in rows]



class TicketManager:
    def __init__(self, db):
        self.db = db

    def get_tickets(self):
        rows = self.db.execute_query("SELECT * FROM tickets")
        return [dict(ticket) for ticket in rows]

    def get_ticket(self, ticket_id):
        rows = self.db.execute_query("SELECT * FROM tickets WHERE id=(?)", (ticket_id,))
        return [dict(ticket) for ticket in rows]


    def get_tickets(self):
        rows = self.db.execute_query("SELECT * FROM tickets")
        return [dict(ticket) for ticket in rows]

    def create_ticket(self, ticket_data):
        self.db.execute_query("""
            INSERT INTO tickets(title, description, creator, organization, priority, status, created)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            ticket_data['title'], ticket_data['description'], ticket_data['creator'],
            ticket_data['organization'], ticket_data['priority'], ticket_data['status'], ticket_data['created']
        ))
        flash('Ticket created successfully!!', 'alert-success')

    def update_ticket(self, ticket_data):
        self.db.execute_query("""
            UPDATE tickets SET
            organization=(?), created=(?), updated=(?), title=(?), description=(?), priority=(?), status=(?), creator=(?)
            WHERE id=(?)
        """, (
            ticket_data['organization'], ticket_data['created'], ticket_data['updated'],
            ticket_data['title'], ticket_data['description'],
            ticket_data['priority'], ticket_data['status'],
            ticket_data['creator'], ticket_data['id']
        ))
        flash('Updated successfully!!', 'alert-success')


# Initialize database and managers
db = Database('database.db')
user_manager = UserManager(db)
ticket_manager = TicketManager(db)
org_manager = OrganizationManager(db)

@app.route('/')
def index():
    return render_template('login.html')


@app.route('/user', methods=['POST', 'GET'])
@login_required(['user'])
def user():
    if request.method == 'POST':
        ticket_data = {
            'organization': request.form['org'],
            'title': request.form['title'],
            'description': request.form['desc'],
            'created': request.form['created'],
            'updated': request.form['updated'],
            'priority': request.form['priority'],
            'status': request.form['status'],
            'creator': request.form['creator'],
            'id': request.form['uid']
        }
        ticket_manager.update_ticket(ticket_data)
        return render_template('user.html')
    else:
        tickets = ticket_manager.get_tickets()
        return render_template('user.html', tickets=tickets)


@app.route('/get_tickets')
@login_required(["tech", "admin"])
def get_tickets():
    tickets = ticket_manager.get_tickets()
    return jsonify(tickets)


@app.route('/get_orgs')
@login_required(["any"])
def get_orgs():
    orgs = org_manager.get_orgs()
    return jsonify(orgs)


@app.route('/get_ticket')
@login_required(["any"])
def get_ticket():
    ticket_id = request.args.get('id')
    ticket = ticket_manager.get_ticket(ticket_id)
    return jsonify(ticket)


@app.route('/get_org')
@login_required(["any"])
def get_org():
    org_id = request.args.get('id')
    org = org_manager.get_org(org_id)
    return jsonify(org)


@app.route('/get_tech_admin')
@login_required(["any"])
def get_tech_admin():
    users = user_manager.get_tech_admin_users()
    return jsonify(users)


@app.route('/tickets', methods=['GET', 'POST'])
@login_required(['admin', 'tech'])
def tickets():
    if request.method == 'POST':
        ticket_data = {
            'organization': request.form['org'],
            'title': request.form['title'],
            'description': request.form['desc'],
            'created': request.form['created'],
            'updated': request.form['updated'],
            'priority': request.form['priority'],
            'status': request.form['status'],
            'creator': request.form['creator'],
            'id': request.form['uid']
        }
        ticket_manager.update_ticket(ticket_data)
        return render_template('tickets.html')
    else:
        tickets = ticket_manager.get_tickets()
        return render_template('tickets.html', tickets=tickets)


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
            with sqlite3.connect('database.db') as con:
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                cur.execute(
                    "SELECT name FROM users WHERE email = (?)", (email,))
                rows = cur.fetchall()
            name = rows[0]['name']

            login_user(User(email=email, role="user", name=name), remember=True)
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
            elif account_type == 'tech':
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


@app.route('/new_ticket_user', methods=['POST', 'GET'])
def new_ticket_user():
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        date = request.form['date']
        priority = request.form['priority']
        status = request.form['status']
        org = request.form['org']
        creator = request.form['creator']

        ticket_data = {
            'title': title,
            'description': desc,
            'creator': creator,
            'organization': org,
            'priority': priority,
            'status': status,
            'created': date,
        }

        ticket_manager.create_ticket(ticket_data)
        return render_template('new_ticket_user.html')
    else:
        return render_template('new_ticket_user.html')


@app.route('/admin_settings', methods=['POST', 'GET'])
@login_required(['admin', 'tech'])
def admin_settings():
    if request.method == 'POST':
        usr_email = current_user.get_id()
        name = request.form['name']
        org = request.form['org']
        email = request.form['email']

        user_data = {
            'email': email,
            'name': name,
            'organization': org,
            'email': usr_email
        }

        user_manager.update_user_settings(user_data)
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
        if current_user.get_role() == 'tech':
            return render_template('tech_settings.html', name=name, org=org, email=email)

        return render_template('admin_settings.html', name=name, org=org, email=email)


@app.route('/manage_organizations', methods=['POST', 'GET'])
@login_required(['admin', 'tech'])
def manage_organizations():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        org_type = request.form['type']
        org_id = request.form['org_id']
        old_org = request.form['old_org']

        org_data = {
            'name': name,
            'email': email,
            'type': org_type,
            'id': org_id,
            'old_org': old_org
        }

        org_manager.update_organization(org_data)
        return render_template('manage_organizations.html')
    else:
        if current_user.get_role() == 'tech':
            return render_template('manage_organizations_tech.html')
        return render_template('manage_organizations.html')


@app.route('/new', methods=['POST', 'GET'])
@login_required(['admin', 'tech'])
def new():
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        date = request.form['date']
        priority = request.form['priority']
        status = request.form['status']
        org = request.form['org']
        creator = request.form['creator']

        ticket_data = {
            'title': title,
            'description': desc,
            'creator': creator,
            'organization': org,
            'priority': priority,
            'status': status,
            'created': date,
        }

        ticket_manager.create_ticket(ticket_data)
        return render_template('new.html')
    else:
        return render_template('new.html')


@app.route('/add_organization', methods=['POST', 'GET'])
@login_required(['admin', 'tech'])
def add_organization():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        org_type = request.form['type']
        db.create_organization(name, email, org_type)
        return render_template('add_organization.html')
    else:
        if current_user.get_role() == 'tech':
            return render_template('add_organization_tech.html')

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
        db.manage_users(name, email, password, org, uid)
        return render_template('manage_users.html')
    else:
        if current_user.get_role() == 'tech':
            return render_template('manage_users_tech.html')

        return render_template('manage_users.html')


@app.route('/add_user', methods=['GET', 'POST'])
@login_required(['admin', 'tech'])
def add_user():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        org = request.form['org']
        db.add_user(name, email, password, org)
        return render_template('add_user.html')
    else:
        if current_user.get_role() == 'tech':
            return render_template('add_user_tech.html')
        return render_template('add_user.html')



@app.route('/get_all')
@login_required(["any"])
def get_all():
    return db.get_all()

@app.route('/get_users')
@login_required(["admin", "tech"])
def get_users():
    return db.get_users()

@app.route('/get_user')
@login_required(["admin", "tech"])
def get_user():
    uid = request.args.get('uid')
    return db.get_user(uid)


@app.route('/get_user_tickets')
def get_user_tickets():
    return db.get_user_tickets(current_user.get_name())


@app.route('/manage_tech', methods=['GET', 'POST'])
@login_required(['admin'])
def manage_tech():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        org = request.form['org']
        uid = request.form['uid']
        db.manage_tech(name, email, password, org, uid)
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
        db.add_tech(name, email, password, org)
        return render_template('add_tech.html')
    else:
        return render_template('add_tech.html')


@app.route('/get_techs')
@login_required(["admin", "tech"])
def get_techs():
    return db.get_techs()


@app.route('/render_orgs')
@login_required(['any'])
def render_orgs():
    return db.render_orgs()


@app.route('/get_user_org')
@login_required(['admin', 'tech'])
def get_user_org():
    name = request.args.get('id')
    return db.get_user_org(name)


if __name__ == '__main__':
    app.run(debug=True)

if __name__ == '__main__':
    app.run(debug=True)