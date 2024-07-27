from app import db,User
from werkzeug.security import generate_password_hash

def create_admin():
    username = "ravi"
    email = "ravi@gmail.com"
    password = "ravi2004"
    role = "admin"

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, email=email, password=hashed_password, role=role)

    db.session.add(new_user)
    db.session.commit()

if __name__ == "__main__":
    from app import app
    with app.app_context():
        create_admin()
    print("Admin created successfully!")
