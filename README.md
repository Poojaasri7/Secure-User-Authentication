Secure User Authentication
This repository contains a Flask application for Secure user Authentication , featuring login, signup, and role-based access control. The application is designed with security and user experience in mind, implementing features such as password hashing, session management, and flash messaging for user feedback.

Features
User Authentication: Secure login and signup forms with validation and password hashing.
Role-Based Access Control: Admin users have additional capabilities, such as managing other users.
Session Management: Sessions have a configurable lifetime and are protected with strong security measures.
User Management: Admin users can view, delete, and update the roles of other users.
Responsive Design: The application is designed to be responsive and user-friendly on various devices.

Requirements
Flask
Flask-SQLAlchemy
Flask-Login
Werkzeug

Usage
Login: Users can log in with their username and password.
Signup: New users can create an account with a username, email, and password.
Admin Dashboard: Admin users can view, delete, and update user roles.
Code Overview
app.py: Main application file with route definitions and logic for user management.
templates/: HTML templates for rendering pages.
static/: Static files such as CSS and JavaScript.

Security Considerations
Ensure SESSION_COOKIE_SECURE is set to True in production environments to enforce HTTPS.
Use a strong and unique SECRET_KEY to enhance application security.
