import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"})
    
    username = request.form.get("username")
    password = request.form.get("password")
    access_level = request.form.get("access_level")
    
    if username is None or password is None or access_level is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    
    # Added input length validation for username to prevent DoS
    if len(username) > 50:
        return jsonify({"error": "Username exceeds maximum length"}), 400
        
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )

    # Validate username format
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "Invalid username format"}), 400
    
    # Improved access level validation with role-based approach
    role_mapping = {
        "0": 0,  # admin
        "1": 1,  # moderator
        "2": 2   # regular user
    }
    
    if access_level not in role_mapping:
        return jsonify({"error": "Invalid access level. Must be 0, 1, or 2"}), 400
    
    access_level_int = role_mapping[access_level]
    
    # Implemented password hashing for security
    hashed_password = generate_password_hash(password)
    
    # Using parameterized queries to prevent SQL injection
    query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"

    try:
        query_db(query, [username, hashed_password, access_level_int], False, True)
        return jsonify({"success": True})
    except sqlite3.Error as err:
        # Enhanced error handling to avoid exposing database errors
        current_app.logger.error(f"Database error during user creation: {str(err)}")
        return jsonify({"error": "Could not create user due to a system error"}), 500
