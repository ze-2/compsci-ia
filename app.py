# Higher-order functionality on objects.
# Wrap, or wrappers, are classes that encapsulate the behaviour of another function.
# Needed for Flask's decorators, as they use wrappers. (decorators are the @app's)
from functools import wraps

# Python package for working with JSON data.
# JSON is a format that allows for easy storing and exchanging data, mostly with APIs.
# Stands for JavaScript Object Notation.
import json

# Flask is the main class in the flask framework and we use it to create the flask app.
# render_template lets us render HTML whilst also adding Python variables into the HTML page. It
# redirect lets use direct the user to a different route or URL in the flask app.
# url_for is used to generate URLs for specific routes in the flask app. It takes the name of the route function as an argument and uses that to return a corresponding URL.
# request represents incoming HTTP requests made to the flask app, allowing usage of form data etc.
# flash is used to display flash messages, which are temporary messages that can be displayed to the user.
# session is used to represent a user's session data (OSI L5). Stores data specific to a user's session
from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, session

# Imports the User class from the file model.py, as a module.
# The User class encapsulates several variables, such as name, role and email, providing accessor and mutator methods to it.
from model import User

# sqlite3 is a lightweight, disk-based database that is serverless.
import sqlite3

# LoginManager is used to manage user sessions and as an extension, their logins.
# The other functions are self-explanatory and moderate several login processes.
from flask_login import LoginManager, login_required, login_user, logout_user, current_user


# The above creates a Flask application instance.
# __name__ is a special variable that represents the name of the current module being run.
# Auth config
app = Flask(__name__)

# Sets the secret key for securing sessions. As sessions are not used, this is never used so it can be kept in plaintext here, but it is also required for sessions to run.
app.secret_key = "SECRET_KEY"
# Login management is started by creating an instance of the LoginManager class, which handles user authentication.
# Initialises the login manager with the Flask app.
login_manager = LoginManager()
login_manager.init_app(app)

# On login, creates User object with email, role and name
@login_manager.user_loader
def load_user(email):
    # Retreives user information from the database and loads them.
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
    # User object stores and makes frequently-accessed information like email, role and name available
    return User(email=email, role=role, name=name)


def login_required(roles=["any"]):
    # Below is a custom decorator function that declares that something requries user authentication.
    # This allows for role-access control (RAC).
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
            # fn() is the decorated function and is used to check whether the user is authenticated.
        return decorated_view
    return wrapper

# OOP here allows me to encapsulate the data of a manager, which is a classified role.
# It also abstracts certain methods. Future devs won't need to manage how database operations are done, only that they need to call 'update_organization' etc.
# Further development can now also inherit, for example DepartmentManager can inherit from this class.

# OrganizationManager class provides functionality for managing organizations in the application.
# Interacts with the database to perform operations such as updating organization details and retrieving organization data.
class OrganizationManager:
    """
    Attributes:
        db (Database): An instance of the Database class, which is used to execute SQL queries.

    Methods:
        update_organization(org_data): Updates an organization in the database.
        get_orgs(): Retrieves all organizations from the database.
        get_org(org_id): Retrieves a specific organization from the database.
    """
    def __init__(self, db):
        # Initialize OrganizationManager with the provided database object.
        self.db = db

    def update_organization(self, org_data):
        # Execute an SQL query to update the details of an organization in the 'organization' table.
        # Update all fields: email, name, type
        # Updates using ID
        self.db.execute_query("""
            UPDATE organizations SET email=(?), name=(?), type=(?) WHERE id=(?)
        """, (
            org_data['email'], org_data['name'], org_data['type'], org_data['id']
        ))

        # Execute an SQL query to update the organization name in the 'users' table for users associated with the old organization name
        self.db.execute_query("""
            UPDATE users SET organization=(?) WHERE organization=(?)
        """, (
            org_data['name'], org_data['old_org']
        ))
        # Flash a success message indicating that the update was successful
        flash('Updated successfully!!', 'alert-success')

    # Returns all organizations from the database as a list of dictionary items.
    def get_orgs(self):
        rows = self.db.execute_query("SELECT * FROM organizations")
        return [dict(org) for org in rows]

    # Execute an SQL query to retrieve all the details of a specific organization from the 'organizations' table
    def get_org(self, org_id):
        rows = self.db.execute_query("SELECT * FROM organizations WHERE id=(?)", (org_id,))
        return [dict(org) for org in rows]

# The Database class provides a simplified interface for executing SQL queries and interacting with the SQLite database.
# It encapsulates the database connection and provides methods for creating, retrieving, and updating data in the database.

class Database:
    # Initialize the Database object with the provided database name.
    def __init__(self, db_name):
        # Assign the provided database name to the instance variable 'db_name' to access the database later
        self.db_name = db_name

    # Execute any custom SQL query with optional parameters.
    def execute_query(self, query, params=()):
        # Connects to the SQLITE instance for R/W
        with sqlite3.connect(self.db_name) as con:
            # Set the row factory to sqlite3.Row to return rows as dictionaries
            con.row_factory = sqlite3.Row
            # Create a cursor object to execute SQL queries
            cur = con.cursor()
            # Execute the queries
            cur.execute(query, params)
            # Receives the data (if applicable)
            rows = cur.fetchall()
            # Commit the changes to the database
            con.commit()
        # Returns as a list containing results
        return rows

    # Create a new organization in the database.
    # Takes in name, email, and organization type as inputs.
    def create_organization(self, name, email, org_type):
        # Execute an SQL query to insert a new organization into the 'organizations' table
        self.execute_query("INSERT INTO organizations(name, email, type) VALUES (?, ?, ?)",
                           (name, email, org_type))
        # Flash a success message indicating that the organization was created successfully
        flash("Created successfully!", 'alert-success')

    # Update the details of a user in the database.
    # Name, email, password, org as inputs. ID to identify/select the entry to edit.
    def manage_users(self, name, email, password, org, uid):
        # Execute an SQL query to select the email of the user with the specified ID from the 'users' table
        old_email = self.execute_query("SELECT email FROM users WHERE id=(?)", (uid,))[0][0]
        # Execute an SQL query to update the user details in the 'users' table
        self.execute_query("UPDATE users SET email=(?), name=(?), password=(?), organization=(?) WHERE id=(?)",
                           (email, name, password, org, uid))
        # Execute an SQL query to update the creator and organization of tickets associated with the user's old email
        self.execute_query("UPDATE tickets SET creator=(?), organization=(?) WHERE creator=(?)",
                           (email, org, old_email))
        # Flash a success message indicating that the user was updated successfully
        flash('Updated successfully!!', 'alert-success')

    # Add a new user to the database.
    # Takes in name, email, password and organization as an email.
    def add_user(self, name, email, password, org):
        # Execute an SQL query to insert a new user into the 'users' table with the type 'user'
        self.execute_query("INSERT INTO users(name, email, password, type, organization) VALUES (?, ?, ?, ?, ?)",
                           (name, email, password, "user", org))
        # Flash a success message indicating that the user was created successfully
        flash("Created successfully!", 'alert-success')

    # Retrieve all users with the type 'user' from the database.
    # Returns a JSON object of a list of dictionary objects, each representing a user.
    def get_users(self):
        # Execute an SQL query to select all users with the type 'user' from the 'users' table
        rows = self.execute_query("SELECT * FROM users where type='user'")
        # Convert each row to a dictionary
        users = [dict(row) for row in rows]
        # Return the users as a JSON object
        return json.dumps(users)

    # Retrieve all users of any type from the database.
    def get_all(self):
        # Execute an SQL query to select all users with any type from the 'users' table
        rows = self.execute_query("SELECT * FROM users")
        # Convert each row to a dictionary
        users = [dict(row) for row in rows]
        # Return the users as a JSON object
        return json.dumps(users)

    # Add a new tech user to the database.
    # Takes in name, email, password and organization as an input
    def add_tech(self, name, email, password, org):
        # Execute an SQL query to insert a new user into the 'users' table with the type 'tech'
        self.execute_query("INSERT INTO users(name, email, password, type, organization) VALUES (?, ?, ?, ?, ?)",
                           (name, email, password, "tech", org))
        # Flash a success message indicating that the tech user was created successfully
        flash("Created successfully!", 'alert-success')

    # Retrieve all tech users from the database.
    def get_techs(self):
        # Execute an SQL query to select all techs from the 'users' table
        rows = self.execute_query("SELECT * FROM users where type='tech'")
        # Converts it to list of dictionary objects, each representing a user.
        techs = [dict(row) for row in rows]
        # Return the tech users as a JSON object
        return json.dumps(techs)

    # Retrieve all organizations from the database.
    def render_orgs(self):
        # Execute an SQL query to select all organizations with any type from the 'users' table
        rows = self.execute_query("SELECT * FROM organizations")
        # Converts it to list of dictionary objects, each representing a organization.
        orgs = [dict(row) for row in rows]
        # Return the organizations as a JSON object
        return json.dumps(orgs)

    # Retrieves the organization a specific user is associated with
    def get_user_org(self, name):
        # Execute an SQL query to retrieve the organization a specific user is associated with
        rows = self.execute_query("SELECT organization FROM users WHERE name=(?)", (name,))
        # Returns the name of the organization
        return rows[0][0]

    # retrieve a specific user using their ID
    def get_user(self, uid):
        # Execute an SQL query to retrieve the specific user using their ID
        rows = self.execute_query("SELECT * FROM users WHERE id=(?)", (uid,))
        # Formats the user
        user = [dict(row) for row in rows]
        # Return the specific user as a JSON object
        return json.dumps(user)

    # retrieve all tickets a specific user is associated with
    def get_user_tickets(self, name):
        # Execute an SQL query to retrieve the tickets a user created
        rows = self.execute_query("SELECT * FROM tickets WHERE creator=(?)", (name,))
        # Formats and returns the tickets
        return [dict(ticket) for ticket in rows]

    # Update the details of a tech user in the database.
    # Name, email, password, org as inputs. ID to identify/select the entry to edit.
    def manage_tech(self, name, email, password, org, uid):
        # Execute an SQL query to update the tech details in the 'users' table
        self.execute_query("UPDATE users SET email=(?), name=(?), password=(?), organization=(?) WHERE id=(?)",
                           (email, name, password, org, uid))
        # Flash a success message indicating that the user was updated successfully
        flash('Updated successfully!!', 'alert-success')


# The UserManager class is responsible for managing user-related operations in the database.
# It provides methods to update user settings and retrieve tech and admin users.
class UserManager:

    def __init__(self, db):
       # Initialize the UserManager instance with a database connection.

       # Store the database connection object in the instance variable 'db'
       # This allows the UserManager instance to access the database connection throughout its lifecycle
        self.db = db

    # Update the settings of a user in the database based on the provided user data.
    # Email, name, organization as an input. Email used as UID.
    def update_user_settings(self, user_data):

       # Execute an SQL UPDATE query to update the user's email, name, and organization in the 'users' table
       # The query uses placeholders `(?)` to prevent SQL injection attacks
        self.db.execute_query("""
            UPDATE users
            SET email=(?), name=(?),  organization=(?)
            WHERE email=(?)
        """, (
             user_data['email'], user_data['name'], user_data['organization'], user_data['email']
        ))

       # Display a success message to the user that the user has been updated successfully
        flash('Updated successfully!', 'alert-success')

    # Retrieve all users with the type 'tech' or 'admin' from the database.
    def get_tech_admin_users(self):
       # Execute an SQL SELECT query to retrieve all users with the type 'tech' or 'admin' from the 'users' table
        rows = self.db.execute_query("SELECT * FROM users WHERE type='tech' OR type='admin'")

       # Convert the result rows to a list of dictionaries, where each dictionary represents a user and contains user data. Easier to access data.
        return [dict(user) for user in rows]

# Responsible for managing ticket-related operations in the database.
# Provides methods to retrieve tickets, create new tickets, and update existing tickets.
class TicketManager:
    def __init__(self, db):
        # Store the database connection object in the instance variable 'db' on  initialization
        # This allows the TicketManager  instance to access the database connection throughout its lifecycle
        self.db = db

    # Retrieve a specific ticket from the database based on its ID (taken as input)
    def get_ticket(self, ticket_id):

        # Execute an SQL SELECT query to retrieve the ticket with the specified ID from the 'tickets' table
        # The query uses a placeholder (?) for the ticket ID to prevent SQL injection attacks
        rows = self.db.execute_query("SELECT * FROM tickets WHERE id=(?)", (ticket_id,))

        # Convert the result rows to a list of dictionaries, where each dictionary represents a ticket and contains ticket data. Easier to access data.
        return [dict(ticket) for ticket in rows]

    # Retrieve all tickets from the database.
    def get_tickets(self):
        # Execute an SQL SELECT query to retrieve all tickets from the 'tickets' table
        # The query selects all columns (*) from the 'tickets' table
        rows = self.db.execute_query("SELECT * FROM tickets")

        # Converts and returns the result rows to a list of dictionaries, where each dictionary represents a ticket and contains ticket data.
        return [dict(ticket) for ticket in rows]

    # Create a new ticket in the database based on the provided ticket data.
    def create_ticket(self, ticket_data):

       # Execute an SQL INSERT query to insert a new ticket into the 'tickets' table with the provided data (required in the ticket field)
       # The query uses placeholders (?) to prevent SQL injection attacks
       self.db.execute_query("""
           INSERT INTO tickets(title, description, creator, organization, priority, status, created)
           VALUES (?, ?, ?, ?, ?, ?, ?)
       """, (
           ticket_data['title'],
           ticket_data['description'],
           ticket_data['creator'],
           ticket_data['organization'],
           ticket_data['priority'],
           ticket_data['status'],
           ticket_data['created']
       ))
       # Display a success message to the user using the flash function
       flash('Ticket created successfully!!', 'alert-success')

    # Update an existing ticket in the database based on provided ticket data.
    def update_ticket(self, ticket_data):

       # Execute an SQL UPDATE query to update the ticket with the specified ID using the provided data
       # The query uses placeholders (?) to prevent SQL injection attacks
       self.db.execute_query("""
           UPDATE tickets
           SET organization=(?), created=(?), updated=(?), title=(?), description=(?), priority=(?), status=(?), creator=(?)
           WHERE id=(?)
       """, (
           ticket_data['organization'],
           ticket_data['created'],
           ticket_data['updated'],
           ticket_data['title'],
           ticket_data['description'],
           ticket_data['priority'],
           ticket_data['status'],
           ticket_data['creator'],
           ticket_data['id']
       ))

       # Display a success message to the user using the flash function
       flash('Updated successfully!!', 'alert-success')

# Initialize database and managers
db = Database('database.db')
user_manager = UserManager(db)
ticket_manager = TicketManager(db)
org_manager = OrganizationManager(db)

# The route for the index page, "/", which returns the login page so that it is the first page that users encounter when using the app.
@app.route('/')
def index():
    return render_template('login.html')

# ---- USER ---- #
# Handles both POST and GET requests for the '/user' route.
@app.route('/user', methods=['POST', 'GET'])
@login_required(['user']) # Decorated function from earlier, now with 'user' so that only users can access this function - restricted to authenticated users only due to the `@login_required` decorator.
def user():
    # Runs only if the client is sending a POST request - when they submit a form. The only POST request sent from /user is from a ticket edit.
    if request.method == 'POST':
        # Extracts form data from the request.
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
        # Updates the ticket in the database with the new details.
        ticket_manager.update_ticket(ticket_data)
        # Renders 'user.html' template and returns it as a response.
        return render_template('user.html')
    else:
        # As the route only accepts POST and GET, this will run if a GET request is made - when the user navigates to this link.
        tickets = ticket_manager.get_tickets()
        # user.html lists all the tickets that the user submits, with editing functionality
        return render_template('user.html', tickets=tickets)

# Landing page for tech and admin roles.     # Handles both POST and GET requests for the '/tickets' route, which is used to view all tickets and manage them.
@app.route('/tickets', methods=['GET', 'POST'])
@login_required(['admin', 'tech']) # Decorated function, now such that only tech and admins can access this function.
def tickets():
    # Runs only if the client is sending a POST request - when tech/admins submit a form. The only POST request sent from /tickets is from a ticket edit.
    if request.method == 'POST':
        # Extracts form data from the request.
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
        # Updates the ticket in the database with the new details using the ticket manager class.
        ticket_manager.update_ticket(ticket_data)
        # Renders 'tickets.html' template and returns it as a response.
        return render_template('tickets.html')
    else:
        # As the route only accepts POST and GET, this will run if a GET request is made - when the user navigates to this link.
        tickets = ticket_manager.get_tickets()
        # user.html lists all the tickets that the user submits, with editing functionality
        return render_template('tickets.html', tickets=tickets)

# Handles user login and redirection based on their role.
@app.route('/login', methods=['POST', 'GET'])
def login():
    # If the user is not authenticated and the request method is POST, it retrieves the user's email and password from the form, checks the password against the database, logs the user in, and redirects them to the appropriate page.
    if request.method == 'POST':
        # Get values from login
        email = request.form['email']
        password = request.form['password']

        # Attempts to get user's password from db given the user-provided email
        with sqlite3.connect('database.db') as con:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute(
                "SELECT password FROM users WHERE email = (?)", (email,))
            rows = cur.fetchall()

        try:
            # Attempt to get the password of the user
            db_password = rows[0]['password']
        except:
            # If an entry with that email doesn't exist (user doesn't exist in the database), an error will occur
            flash(
                "User doesn't exist - contact your administrator for help.", 'alert-danger')
            return redirect(url_for('login'))

        if db_password == password:

            # Gets extra information needed to log the user in - their name
            # Gets this from the database using their email
            with sqlite3.connect('database.db') as con:
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                cur.execute(
                    "SELECT name FROM users WHERE email = (?)", (email,))
                rows = cur.fetchall()
            name = rows[0]['name']

            # Gets extra information needed to log the user in - their role
            # Gets this from the database using their email
            with sqlite3.connect('database.db') as con:
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                cur.execute(
                    "SELECT type FROM users WHERE email = (?)", (email,))
                rows = cur.fetchall()
            account_type = rows[0]['type']

            # Logs the user in using the User object, which stores easily-accessible information like email, name, and their role.
            login_user(User(email=email, role=account_type, name=name), remember=True)

            # Upon password authentication, the user is redirected to the appropriate page based on their role.
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
                return 'Error - contact admin.'
        else:
            # If the user submits the wrong password. (Submitted password doesn't match db password)
            flash("Incorrect login credentials.", 'alert-danger')
            return render_template('login.html')

    # If user gets there by GET - they haven't submitted the form
    else:
        # This function checks if the user is already authenticated and redirects them to the appropriate page based on their role immediately without having to login or press anything.
        if (current_user.is_authenticated):
            role = current_user.get_role()
            if role == 'admin' or role == 'tech':
                flash('Redirecting...', 'alert-primary')
                return redirect(url_for('tickets'))
            elif role == 'user':
                flash('Redirecting...', 'alert-primary')
                return redirect(url_for('user'))
            else:
                return 'huh. how did you get here.'

        # If user not already authenticated, return the login page.
        return render_template('login.html')

# Directly calls the Flask function and logs the user out.
# Redirects user to login / unauthenticated landing screen.
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# Handles both GET and POST requests for creating new tickets by user roles.
# Clearer seperated RAC so future devs can easily change user ticket functionality instead of having to change all of admin/tech/user. Using a decorator is more clear than an if statement in the same function.
@app.route('/new_ticket_user', methods=['POST', 'GET'])
def new_ticket_user():
    # Retrieves form data for ticket attributes.
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        date = request.form['date']
        priority = request.form['priority']
        status = request.form['status']
        org = request.form['org']
        creator = request.form['creator']

        # Puts it in a dict to add it to the database for more standardized processing
        ticket_data = {
            'title': title,
            'description': desc,
            'creator': creator,
            'organization': org,
            'priority': priority,
            'status': status,
            'created': date,
        }

        # Uses the ticket_manager object functionality to create a new ticket and put it into the database
        ticket_manager.create_ticket(ticket_data)
        # After ticket creation, stay on the same page.
        return render_template('new_ticket_user.html')
    else:
        # 'new_ticket_user.html' rendered as a response when the user navigates to this link/route.
        return render_template('new_ticket_user.html')

# Handles both GET and POST requests for creating new tickets by admin/tech roles.
# Clearer seperated RAC so future devs can easily change admin/tech ticket functionality instead of having to change all of admin/tech/user. Using a decorator is more clear than an if statement in the same function.
@app.route('/new', methods=['POST', 'GET'])
@login_required(['admin', 'tech']) # This function is restricted to authenticated users with the roles 'admin' or 'tech'.
def new():
    if request.method == 'POST':
        # Retrieves form data for ticket attributes.
        title = request.form['title']
        desc = request.form['desc']
        date = request.form['date']
        priority = request.form['priority']
        status = request.form['status']
        org = request.form['org']
        creator = request.form['creator']

        # Puts it in a dict to add it to the database for more standardized processing
        ticket_data = {
            'title': title,
            'description': desc,
            'creator': creator,
            'organization': org,
            'priority': priority,
            'status': status,
            'created': date,
        }

        # Uses the ticket_manager object functionality to create a new ticket and put it into the database
        ticket_manager.create_ticket(ticket_data)
        # After ticket creation, stay on the same page.
        return render_template('new.html')
    else:
        # 'new.html' rendered as a response when the user navigates to this link/route.
        return render_template('new.html')

# Handles both GET and POST requests for admin settings, which is changing one's email/name/org.
@app.route('/admin_settings', methods=['POST', 'GET'])
@login_required(['admin', 'tech']) # This function is restricted to authenticated users with the role 'admin'/'tech'.
def admin_settings():
    # POST req --> form is sent. The only reason why a form would be sent is to request an update/edit to their details.
    if request.method == 'POST':
        # Retrieves form data for user attributes.
        usr_email = current_user.get_id()
        name = request.form['name']
        org = request.form['org']
        email = request.form['email']

        # Puts it in a dict to add it to the database for more standardized processing
        user_data = {
            'email': email,
            'name': name,
            'organization': org,
            'email': usr_email
        }

        # Updates the user's details in the database with the new details using user_manager functionality
        user_manager.update_user_settings(user_data)

        # Renders the 'admin_settings.html' template with the updated user details.
        return render_template('admin_settings.html', name=name, org=org, email=email)
    else:
        # Fetches the current user's details from the database using their email.
        email = current_user.get_id()

        # Gets user's name, organization and email from the `users` table.
        with sqlite3.connect('database.db') as con:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute(
                "SELECT name, organization, email FROM users WHERE email = (?)", (email,))
            rows = cur.fetchall()

        name = rows[0]['name']
        org = rows[0]['organization']
        email = rows[0]['email']

        # If the user's role is tech, return the HTML page for their role.
        if current_user.get_role() == 'tech':
            return render_template('tech_settings.html', name=name, org=org, email=email)

        # Renders 'admin_settings.html' template with the current user's details.
        return render_template('admin_settings.html', name=name, org=org, email=email)

# To manage organizations, handles both GET/POST requests.
@app.route('/manage_organizations', methods=['POST', 'GET'])
@login_required(['admin', 'tech']) # RAC so only these roles can manage users
def manage_organizations():
    # For POST requests, it updates the organization details in the database and redirects the user back to the management page.
    # POST requests can only be sent when the user is editing something
    if request.method == 'POST':

        # Retrieve form data
        name = request.form['name']
        email = request.form['email']
        org_type = request.form['type']
        org_id = request.form['org_id']
        old_org = request.form['old_org']

        # Puts it in a dict to add it to the database for more standardized processing
        org_data = {
            'name': name,
            'email': email,
            'type': org_type,
            'id': org_id,
            'old_org': old_org
        }

        # Updates the user's details in the database with the new details using org_manager functionality
        org_manager.update_organization(org_data)

        # After updating, render org management page that they were at.
        if current_user.get_role() == 'tech':
            return render_template('manage_organizations_tech.html')
        return render_template('manage_organizations.html')
    else:
        # For GET requests, it simply renders the 'manage_organizations.html' template based on the user's role.
        if current_user.get_role() == 'tech':
            return render_template('manage_organizations_tech.html')
        return render_template('manage_organizations.html')


# Route for adding a new organization. Handles both POST and GET requests.
@app.route('/add_organization', methods=['POST', 'GET'])
@login_required(['admin', 'tech']) # RAC so only these roles can manage users
def add_organization():
    # For POST requests, it inserts the new organization into the database and redirects the user back to the add organization page.
    # POST requests can only be sent when the user adds a new organization
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        email = request.form['email']
        org_type = request.form['type']

        # Insert new organisation to database.
        db.create_organization(name, email, org_type)

        # After updating, render add organization page that they were at.
        if current_user.get_role() == 'tech':
            return render_template('add_organization_tech.html')

        return render_template('add_organization.html')
    else:
    # For GET requests, it simply renders the 'add_organization.html' template based on the user's role.
        if current_user.get_role() == 'tech':
            return render_template('add_organization_tech.html')

        return render_template('add_organization.html')

# Manages users, handles POST and GET requests
@app.route('/manage_users', methods=['GET', 'POST'])
@login_required(['admin', 'tech']) # RAC so only these roles can manage users
def manage_users():
    # For POST requests, it inserts the updated user into the database and redirects the user back to the manage user page.
    # POST requests can only be sent when the user updates an org
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        org = request.form['org']
        uid = request.form['uid']

        # Insert new organisation to database.
        db.manage_users(name, email, password, org, uid)
        # After updating, render manage organization page that they were at.
        if current_user.get_role() == 'tech':
            return render_template('manage_users_tech.html')

        return render_template('manage_users.html')
    else:
        # For GET requests, it simply renders the 'add_organization.html' template based on the user's role.
        if current_user.get_role() == 'tech':
            return render_template('manage_users_tech.html')

        return render_template('manage_users.html')

# Adds users, handles POST and GET requests
@app.route('/add_user', methods=['GET', 'POST'])
@login_required(['admin', 'tech']) # RAC so only these roles can manage users
def add_user():
    # For POST requests, it adds the updated user into the database and redirects the user back to the add user page.
    # POST requests can only be sent when the user creates a new user
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        org = request.form['org']

        # Insert new organisation to database.
        db.add_user(name, email, password, org)

        # After updating, render add user page that they were at.

        if current_user.get_role() == 'tech':
            return render_template('add_user_tech.html')

        return render_template('add_user.html')
    else:
        # For GET requests, it simply renders the 'add_user.html' template based on the user's role.
        if current_user.get_role() == 'tech':
            return render_template('add_user_tech.html')
        return render_template('add_user.html')

# Manages tech users, handles POST and GET requests
@app.route('/manage_tech', methods=['GET', 'POST'])
@login_required(['admin']) # RAC so only admin can manage techs
def manage_tech():
    # For POST requests, it updates tech in the database and redirects the user back to the manage tech page.
    # POST requests can only be sent when admin creates a new tech
    if request.method == 'POST':
        # Gets from data
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        org = request.form['org']
        uid = request.form['uid']

        # Updates in DB
        db.manage_tech(name, email, password, org, uid)
        # Renders the 'manage_tech.html' (same screen) after updating.
        return render_template('manage_tech.html')
    else:
        # For GET requests, it simply renders the 'manage_tech.html'
        return render_template('manage_tech.html')

# Adds tech users, handles POST and GET requests
@app.route('/add_tech', methods=['GET', 'POST'])
@login_required(['admin']) # RAC so only admin can manage techs
def add_tech():
    # For POST requests, it adds the updated user into the database and redirects the user back to the add user page.
    # POST requests can only be sent when the admin creates a new tech
    if request.method == 'POST':
        # Gets form data
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        org = request.form['org']

        # Updates in DB
        db.add_tech(name, email, password, org)
        # Renders the 'add_tech.html' (same screen) after updating.
        return render_template('add_tech.html')
    else:
        # For GET requests, it simply renders the 'add_tech.html'
        return render_template('add_tech.html')

# Utility function to get all users from db.
@app.route('/get_all')
@login_required(["any"]) # RAC, any logged-in user can access this endpoint
def get_all():
    return db.get_all()

# Utility function to get all normal users (non-tech, non-admin) from db.
@app.route('/get_users')
@login_required(["admin", "tech"]) # RAC, only admin and tech can access this endpoint
def get_users():
    return db.get_users()

# Utility function to get one user from db.
@app.route('/get_user')
@login_required(["admin", "tech"]) # RAC, only admin and tech can access this endpoint
def get_user():
    # Gets specific user through their unique ID
    uid = request.args.get('uid')
    return db.get_user(uid)


# Utility class used for rendering from front-end. Returns all tickets in a JSON format.
@app.route('/get_tickets')
@login_required(["tech", "admin"]) # Same decorator function that allows only tech and admin to use this.
def get_tickets():
    # Utilizes the ticket_manager class.
    tickets = ticket_manager.get_tickets()
    return jsonify(tickets)

# Does the same thing as the function above (get_tickets()) except for organizations. Uses the org_manager class.
@app.route('/get_orgs')
@login_required(["any"])
def get_orgs():
    orgs = org_manager.get_orgs()
    return jsonify(orgs)

# Retrieve a specific ticket from the database based on the provided ticket ID and return it as a JSON response.
# Used to render details of one ticket using the ticket ID when user clicks on "More".
@app.route('/get_ticket')
# Same decorator function that allows any role to use (has to be logged in)
@login_required(["any"])
def get_ticket():
    # Gotten from the query parameters. Request is sent here from the frontend. Backend processes request and parses it, returning it to the frontend.
    ticket_id = request.args.get('id')
    ticket = ticket_manager.get_ticket(ticket_id)
    return jsonify(ticket)

# Retrieve a specific organization from the database based on the provided organization ID and return it as a JSON response.
@app.route('/get_org')
# Same decorator function that allows any role to use (has to be logged in)
@login_required(["any"])
def get_org():
    org_id = request.args.get('id')
    org = org_manager.get_org(org_id)
    return jsonify(org)

# Retrieve all tickets associated with (created by) the current user as a JSON response.
@app.route('/get_user_tickets')
def get_user_tickets():
    return db.get_user_tickets(current_user.get_name())

# Retrieve all users with the role 'tech' or 'admin' from the database and return them as a JSON response.
# Utility function to automatically render the creator list
@app.route('/get_tech_admin')
# Same decorator function that allows any role to use (has to be logged in)
@login_required(["any"])
def get_tech_admin():
    # Utilizes functionality in the user_manager class
    users = user_manager.get_tech_admin_users()
    # Request is sent here from the frontend. Backend processes request and parses it, returning it to the frontend.
    return jsonify(users)

# Utility function to get all tech users from db.
@app.route('/get_techs')
@login_required(["admin", "tech"]) # RAC, only admin and tech users can use this function.
def get_techs():
    return db.get_techs()

# Utility function to get all organizations from db.
@app.route('/render_orgs')
@login_required(['any']) # Utility function to get all users from db.
def render_orgs():
    return db.render_orgs()

# RUns the app.
if __name__ == '__main__':
    app.run(debug=True)