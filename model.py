# Contains models for flask-login
class User:
    def __init__(self, email, role):
        self.email = email
        self.role = role

    def is_active(self):
        return True

    def get_id(self):
        try:
            return str(self.email)
        except AttributeError:
            return None

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_role(self):
        return self.role