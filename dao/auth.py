from dao.model.user import User

class AuthDAO:
    def __init__(self, session):
        self.session = session

    def get_user_by_username(self, username):
        return self.session.query(User).filter(User.username == username).first()
