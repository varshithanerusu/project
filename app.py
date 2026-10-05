from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    session,
    redirect,
    url_for
)

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from functools import wraps
from datetime import datetime
from io import BytesIO

from dotenv import load_dotenv
import os

import pandas as pd
import numpy as np

from sqlalchemy import or_

from database import db
from models import User, Student, Course, Grade


# =========================================================
# APP CONFIGURATION
# =========================================================

load_dotenv()

app = Flask(__name__)

# Browser session secret key
app.secret_key = "student-performance-secret-key"

# JWT configuration
app.config["JWT_SECRET_KEY"] = "student-performance-jwt-secret-key"

# MySQL configuration
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}"
    f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# Initialize extensions
db.init_app(app)
jwt = JWTManager(app)


# =========================================================
# CREATE DATABASE TABLES
# =========================================================

with app.app_context():
    db.create_all()


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if "user_id" not in session:
        return redirect("/login")

    if session.get("user_role") == "admin":
        return redirect("/students")

    return redirect("/my-grades")


# =========================================================
# BROWSER LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def browser_login():

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(
            user.password,
            password
        ):
            return render_template(
                "login.html",
                error="Invalid email or password"
            )

        # Store login information in browser session
        session["user_id"] = user.id
        session["user_role"] = user.role
        session["user_name"] = user.name

        if user.role == "admin":
            return redirect("/students")

        return redirect("/my-grades")

    return render_template("login.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# =========================================================
# BROWSER AUTHORIZATION DECORATORS
# =========================================================

def admin_dashboard_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            return redirect("/login")

        if session.get("user_role") != "admin":
            return "Access denied. Admin only.", 403

        return function(*args, **kwargs)

    return wrapper


def student_dashboard_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            return redirect("/login")

        if session.get("user_role") != "student":
            return "Student access required.", 403

        return function(*args, **kwargs)

    return wrapper


# =========================================================
# JWT ADMIN DECORATOR
# =========================================================

def admin_required():

    def decorator(function):

        @wraps(function)
        @jwt_required()
        def wrapper(*args, **kwargs):

            user_id = get_jwt_identity()

            user = db.session.get(User, int(user_id))

            if not user:
                return jsonify({
                    "status": "error",
                    "message": "User not found"
                }), 404

            if user.role != "admin":
                return jsonify({
                    "status": "error",
                    "message": "Admin access required"
                }), 403

            return function(*args, **kwargs)

        return wrapper

    return decorator


# =========================================================
# REGISTER API
# =========================================================

@app.route("/auth/register", methods=["POST"])
def register():

    data = request.get_json()

    if not data:
        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({
            "status": "error",
            "message": "Name, email and password are required"
        }), 400

    existing_user = User.query.filter_by(
        email=email
    ).first()

    if existing_user:
        return jsonify({
            "status": "error",
            "message": "Email already registered"
        }), 409

    # Public registration always creates a student.
    # This prevents anyone from registering themselves as admin.
    role = "student"

    hashed_password = generate_password_hash(password)

    user = User(
        name=name,
        email=email,
        password=hashed_password,
        role=role
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "User registered successfully",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role
        }
    }), 201


# =========================================================
# LOGIN API
# =========================================================

@app.route("/auth/login", methods=["POST"])
def login():

    data = request.get_json()

    if not data:
        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "status": "error",
            "message": "Email and password are required"
        }), 400

    user = User.query.filter_by(
        email=email
    ).first()

    if not user:
        return jsonify({
            "status": "error",
            "message": "Invalid email or password"
        }), 401

    if not check_password_hash(
        user.password,
        password
    ):
        return jsonify({
            "status": "error",
            "message": "Invalid email or password"
        }), 401

    access_token = create_access_token(
        identity=str(user.id)
    )

    # Also create browser session
    session["user_id"] = user.id
    session["user_role"] = user.role
    session["user_name"] = user.name

    return jsonify({
        "status": "success",
        "message": "Login successful",
        "access_token": access_token,
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role
        }
    }), 200


# =========================================================
# STUDENT BROWSER DASHBOARD
# =========================================================

@app.route("/my-grades")
@student_dashboard_required
def my_grades_dashboard():

    user_id = session.get("user_id")

    user = db.session.get(
        User,
        user_id
    )

    if not user:
        session.clear()
        return redirect("/login")

    student = Student.query.filter_by(
        email=user.email
    ).first()

    if not student:

        return render_template(
            "grades.html",
            grades=[],
            student_mode=True,
            message="Student record not found"
        )

    grades = Grade.query.filter_by(
        student_id=student.id
    ).all()

    return render_template(
        "grades.html",
        grades=grades,
        student_mode=True,
        student=student
    )


# =========================================================
# STUDENT BROWSER CRUD
# ADMIN ONLY
# =========================================================

@app.route("/students")
@admin_dashboard_required
def students():

    search = request.args.get(
        "search",
        ""
    ).strip()

    if search:

        students = Student.query.filter(
            or_(
                Student.name.ilike(
                    f"%{search}%"
                ),
                Student.email.ilike(
                    f"%{search}%"
                )
            )
        ).all()

    else:

        students = Student.query.all()

    return render_template(
        "students.html",
        students=students,
        search=search
    )


@app.route("/students/new")
@admin_dashboard_required
def new_student():

    return render_template(
        "student_form.html"
    )


@app.route("/students", methods=["POST"])
@admin_dashboard_required
def create_student():

    name = request.form.get(
        "name",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip()

    if not name or not email:

        return "Name and email are required.", 400

    existing = Student.query.filter_by(
        email=email
    ).first()

    if existing:

        return "Student email already exists.", 409

    student = Student(
        name=name,
        email=email
    )

    db.session.add(student)
    db.session.commit()

    return redirect("/students")


@app.route("/students/<int:id>")
@admin_dashboard_required
def student_detail(id):

    student = Student.query.get_or_404(id)

    return render_template(
        "student_detail.html",
        student=student
    )


@app.route("/students/<int:id>/edit")
@admin_dashboard_required
def edit_student(id):

    student = Student.query.get_or_404(id)

    return render_template(
        "student_edit.html",
        student=student
    )


@app.route("/students/<int:id>", methods=["POST"])
@admin_dashboard_required
def update_student(id):

    student = Student.query.get_or_404(id)

    name = request.form.get(
        "name",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip()

    if not name or not email:

        return "Name and email are required.", 400

    existing = Student.query.filter_by(
        email=email
    ).first()

    if existing and existing.id != student.id:

        return "Email already belongs to another student.", 409

    student.name = name
    student.email = email

    db.session.commit()

    return redirect("/students")


@app.route(
    "/students/<int:id>/delete",
    methods=["POST"]
)
@admin_dashboard_required
def delete_student(id):

    student = Student.query.get_or_404(id)

    db.session.delete(student)
    db.session.commit()

    return redirect("/students")


# =========================================================
# STUDENT REST API
# =========================================================

@app.route("/api/students", methods=["GET"])
@admin_required()
def api_get_students():

    students = Student.query.all()

    student_list = []

    for student in students:

        student_list.append({
            "id": student.id,
            "name": student.name,
            "email": student.email
        })

    return jsonify({
        "status": "success",
        "data": student_list
    }), 200


@app.route("/api/students", methods=["POST"])
@admin_required()
def api_create_student():

    data = request.get_json()

    if not data:

        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    name = data.get("name")
    email = data.get("email")

    if not name or not email:

        return jsonify({
            "status": "error",
            "message": "Name and email are required"
        }), 400

    existing = Student.query.filter_by(
        email=email
    ).first()

    if existing:

        return jsonify({
            "status": "error",
            "message": "Student email already exists"
        }), 409

    student = Student(
        name=name,
        email=email
    )

    db.session.add(student)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Student created successfully",
        "data": {
            "id": student.id,
            "name": student.name,
            "email": student.email
        }
    }), 201


@app.route("/api/students/<int:id>", methods=["GET"])
@admin_required()
def api_get_student(id):

    student = Student.query.get_or_404(id)

    return jsonify({
        "status": "success",
        "data": {
            "id": student.id,
            "name": student.name,
            "email": student.email
        }
    }), 200


@app.route("/api/students/<int:id>", methods=["PUT"])
@admin_required()
def api_update_student(id):

    student = Student.query.get_or_404(id)

    data = request.get_json()

    if not data:

        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    name = data.get("name")
    email = data.get("email")

    if not name or not email:

        return jsonify({
            "status": "error",
            "message": "Name and email are required"
        }), 400

    existing = Student.query.filter_by(
        email=email
    ).first()

    if existing and existing.id != student.id:

        return jsonify({
            "status": "error",
            "message": "Email already belongs to another student"
        }), 409

    student.name = name
    student.email = email

    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Student updated successfully",
        "data": {
            "id": student.id,
            "name": student.name,
            "email": student.email
        }
    }), 200


@app.route("/api/students/<int:id>", methods=["PATCH"])
@admin_required()
def api_patch_student(id):

    student = Student.query.get_or_404(id)

    data = request.get_json()

    if not data:

        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    if "name" in data:

        if not data["name"]:
            return jsonify({
                "status": "error",
                "message": "Name cannot be empty"
            }), 400

        student.name = data["name"]

    if "email" in data:

        existing = Student.query.filter_by(
            email=data["email"]
        ).first()

        if existing and existing.id != student.id:

            return jsonify({
                "status": "error",
                "message": "Email already belongs to another student"
            }), 409

        student.email = data["email"]

    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Student partially updated successfully",
        "data": {
            "id": student.id,
            "name": student.name,
            "email": student.email
        }
    }), 200


@app.route("/api/students/<int:id>", methods=["DELETE"])
@admin_required()
def api_delete_student(id):

    student = Student.query.get_or_404(id)

    db.session.delete(student)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Student deleted successfully"
    }), 200


# =========================================================
# COURSE BROWSER CRUD
# ADMIN ONLY
# =========================================================

@app.route("/courses")
@admin_dashboard_required
def courses():

    courses = Course.query.all()

    return render_template(
        "courses.html",
        courses=courses
    )


@app.route("/courses/new")
@admin_dashboard_required
def new_course():

    return render_template(
        "course_form.html"
    )


@app.route("/courses", methods=["POST"])
@admin_dashboard_required
def create_course():

    name = request.form.get(
        "name",
        ""
    ).strip()

    code = request.form.get(
        "code",
        ""
    ).strip()

    if not name or not code:

        return "Course name and code are required.", 400

    existing = Course.query.filter_by(
        code=code
    ).first()

    if existing:

        return "Course code already exists.", 409

    course = Course(
        name=name,
        code=code
    )

    db.session.add(course)
    db.session.commit()

    return redirect("/courses")


@app.route("/courses/<int:id>")
@admin_dashboard_required
def course_detail(id):

    course = Course.query.get_or_404(id)

    return render_template(
        "course_detail.html",
        course=course
    )


@app.route("/courses/<int:id>/edit")
@admin_dashboard_required
def edit_course(id):

    course = Course.query.get_or_404(id)

    return render_template(
        "course_edit.html",
        course=course
    )


@app.route("/courses/<int:id>", methods=["POST"])
@admin_dashboard_required
def update_course(id):

    course = Course.query.get_or_404(id)

    name = request.form.get(
        "name",
        ""
    ).strip()

    code = request.form.get(
        "code",
        ""
    ).strip()

    if not name or not code:

        return "Course name and code are required.", 400

    existing = Course.query.filter_by(
        code=code
    ).first()

    if existing and existing.id != course.id:

        return "Course code already belongs to another course.", 409

    course.name = name
    course.code = code

    db.session.commit()

    return redirect("/courses")


@app.route(
    "/courses/<int:id>/delete",
    methods=["POST"]
)
@admin_dashboard_required
def delete_course(id):

    course = Course.query.get_or_404(id)

    db.session.delete(course)
    db.session.commit()

    return redirect("/courses")


# =========================================================
# COURSE REST API
# =========================================================

@app.route("/api/courses", methods=["GET"])
@admin_required()
def api_get_courses():

    courses = Course.query.all()

    course_list = []

    for course in courses:

        course_list.append({
            "id": course.id,
            "name": course.name,
            "code": course.code
        })

    return jsonify({
        "status": "success",
        "data": course_list
    }), 200


@app.route("/api/courses", methods=["POST"])
@admin_required()
def api_create_course():

    data = request.get_json()

    if not data:

        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    name = data.get("name")
    code = data.get("code")

    if not name or not code:

        return jsonify({
            "status": "error",
            "message": "Course name and code are required"
        }), 400

    existing = Course.query.filter_by(
        code=code
    ).first()

    if existing:

        return jsonify({
            "status": "error",
            "message": "Course code already exists"
        }), 409

    course = Course(
        name=name,
        code=code
    )

    db.session.add(course)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Course created successfully",
        "data": {
            "id": course.id,
            "name": course.name,
            "code": course.code
        }
    }), 201


@app.route("/api/courses/<int:id>", methods=["GET"])
@admin_required()
def api_get_course(id):

    course = Course.query.get_or_404(id)

    return jsonify({
        "status": "success",
        "data": {
            "id": course.id,
            "name": course.name,
            "code": course.code
        }
    }), 200


@app.route("/api/courses/<int:id>", methods=["PUT"])
@admin_required()
def api_update_course(id):

    course = Course.query.get_or_404(id)

    data = request.get_json()

    if not data:

        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    name = data.get("name")
    code = data.get("code")

    if not name or not code:

        return jsonify({
            "status": "error",
            "message": "Course name and code are required"
        }), 400

    existing = Course.query.filter_by(
        code=code
    ).first()

    if existing and existing.id != course.id:

        return jsonify({
            "status": "error",
            "message": "Course code already belongs to another course"
        }), 409

    course.name = name
    course.code = code

    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Course updated successfully",
        "data": {
            "id": course.id,
            "name": course.name,
            "code": course.code
        }
    }), 200


@app.route("/api/courses/<int:id>", methods=["PATCH"])
@admin_required()
def api_patch_course(id):

    course = Course.query.get_or_404(id)

    data = request.get_json()

    if not data:

        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    if "name" in data:

        if not data["name"]:

            return jsonify({
                "status": "error",
                "message": "Course name cannot be empty"
            }), 400

        course.name = data["name"]

    if "code" in data:

        existing = Course.query.filter_by(
            code=data["code"]
        ).first()

        if existing and existing.id != course.id:

            return jsonify({
                "status": "error",
                "message": "Course code already belongs to another course"
            }), 409

        course.code = data["code"]

    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Course partially updated successfully",
        "data": {
            "id": course.id,
            "name": course.name,
            "code": course.code
        }
    }), 200


@app.route("/api/courses/<int:id>", methods=["DELETE"])
@admin_required()
def api_delete_course(id):

    course = Course.query.get_or_404(id)

    db.session.delete(course)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Course deleted successfully"
    }), 200


# =========================================================
# GRADE BROWSER CRUD
# ADMIN ONLY
# =========================================================

@app.route("/grades")
@admin_dashboard_required
def grades():

    grades = Grade.query.all()

    return render_template(
        "grades.html",
        grades=grades,
        student_mode=False
    )


@app.route("/grades/new")
@admin_dashboard_required
def new_grade():

    students = Student.query.all()
    courses = Course.query.all()

    return render_template(
        "grade_form.html",
        students=students,
        courses=courses
    )


@app.route("/grades", methods=["POST"])
@admin_dashboard_required
def create_grade():

    student_id = request.form.get(
        "student_id",
        type=int
    )

    course_id = request.form.get(
        "course_id",
        type=int
    )

    score = request.form.get(
        "score",
        type=float
    )

    date = request.form.get("date")

    if (
        student_id is None
        or course_id is None
        or score is None
        or not date
    ):

        return "All grade fields are required.", 400

    if score < 0 or score > 100:

        return "Score must be between 0 and 100.", 400

    student = db.session.get(
        Student,
        student_id
    )

    course = db.session.get(
        Course,
        course_id
    )

    if not student:

        return "Student not found.", 404

    if not course:

        return "Course not found.", 404

    try:

        grade_date = datetime.strptime(
            date,
            "%Y-%m-%d"
        ).date()

    except ValueError:

        return "Date must be YYYY-MM-DD.", 400

    grade = Grade(
        student_id=student_id,
        course_id=course_id,
        score=score,
        date=grade_date
    )

    db.session.add(grade)
    db.session.commit()

    return redirect("/grades")


@app.route("/grades/<int:id>")
@admin_dashboard_required
def grade_detail(id):

    grade = Grade.query.get_or_404(id)

    return render_template(
        "grade_detail.html",
        grade=grade
    )


@app.route("/grades/<int:id>/edit")
@admin_dashboard_required
def edit_grade(id):

    grade = Grade.query.get_or_404(id)

    students = Student.query.all()
    courses = Course.query.all()

    return render_template(
        "grade_edit.html",
        grade=grade,
        students=students,
        courses=courses
    )


@app.route("/grades/<int:id>", methods=["POST"])
@admin_dashboard_required
def update_grade(id):

    grade = Grade.query.get_or_404(id)

    student_id = request.form.get(
        "student_id",
        type=int
    )

    course_id = request.form.get(
        "course_id",
        type=int
    )

    score = request.form.get(
        "score",
        type=float
    )

    date = request.form.get("date")

    if (
        student_id is None
        or course_id is None
        or score is None
        or not date
    ):

        return "All grade fields are required.", 400

    if score < 0 or score > 100:

        return "Score must be between 0 and 100.", 400

    student = db.session.get(
        Student,
        student_id
    )

    course = db.session.get(
        Course,
        course_id
    )

    if not student:

        return "Student not found.", 404

    if not course:

        return "Course not found.", 404

    try:

        grade_date = datetime.strptime(
            date,
            "%Y-%m-%d"
        ).date()

    except ValueError:

        return "Date must be YYYY-MM-DD.", 400

    grade.student_id = student_id
    grade.course_id = course_id
    grade.score = score
    grade.date = grade_date

    db.session.commit()

    return redirect("/grades")


@app.route(
    "/grades/<int:id>/delete",
    methods=["POST"]
)
@admin_dashboard_required
def delete_grade(id):

    grade = Grade.query.get_or_404(id)

    db.session.delete(grade)
    db.session.commit()

    return redirect("/grades")


# =========================================================
# GRADE REST API
# =========================================================

@app.route("/api/grades", methods=["GET"])
@admin_required()
def api_get_grades():

    grades = Grade.query.all()

    grade_list = []

    for grade in grades:

        grade_list.append({
            "id": grade.id,
            "student_id": grade.student_id,
            "course_id": grade.course_id,
            "score": grade.score,
            "date": grade.date.isoformat()
        })

    return jsonify({
        "status": "success",
        "data": grade_list
    }), 200


@app.route("/api/grades", methods=["POST"])
@admin_required()
def api_create_grade():

    data = request.get_json()

    if not data:

        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    student_id = data.get("student_id")
    course_id = data.get("course_id")
    score = data.get("score")
    date = data.get("date")

    if (
        student_id is None
        or course_id is None
        or score is None
        or not date
    ):

        return jsonify({
            "status": "error",
            "message": "student_id, course_id, score and date are required"
        }), 400

    student = db.session.get(
        Student,
        student_id
    )

    course = db.session.get(
        Course,
        course_id
    )

    if not student:

        return jsonify({
            "status": "error",
            "message": "Student not found"
        }), 404

    if not course:

        return jsonify({
            "status": "error",
            "message": "Course not found"
        }), 404

    try:

        score = float(score)

    except (ValueError, TypeError):

        return jsonify({
            "status": "error",
            "message": "Score must be a number"
        }), 400

    if score < 0 or score > 100:

        return jsonify({
            "status": "error",
            "message": "Score must be between 0 and 100"
        }), 400

    try:

        grade_date = datetime.strptime(
            date,
            "%Y-%m-%d"
        ).date()

    except ValueError:

        return jsonify({
            "status": "error",
            "message": "Date must be in YYYY-MM-DD format"
        }), 400

    grade = Grade(
        student_id=student_id,
        course_id=course_id,
        score=score,
        date=grade_date
    )

    db.session.add(grade)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Grade created successfully",
        "data": {
            "id": grade.id,
            "student_id": grade.student_id,
            "course_id": grade.course_id,
            "score": grade.score,
            "date": grade.date.isoformat()
        }
    }), 201


@app.route("/api/grades/<int:id>", methods=["GET"])
@admin_required()
def api_get_grade(id):

    grade = Grade.query.get_or_404(id)

    return jsonify({
        "status": "success",
        "data": {
            "id": grade.id,
            "student_id": grade.student_id,
            "course_id": grade.course_id,
            "score": grade.score,
            "date": grade.date.isoformat()
        }
    }), 200


@app.route("/api/grades/<int:id>", methods=["PUT"])
@admin_required()
def api_update_grade(id):

    grade = Grade.query.get_or_404(id)

    data = request.get_json()

    if not data:

        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    student_id = data.get("student_id")
    course_id = data.get("course_id")
    score = data.get("score")
    date = data.get("date")

    if (
        student_id is None
        or course_id is None
        or score is None
        or not date
    ):

        return jsonify({
            "status": "error",
            "message": "student_id, course_id, score and date are required"
        }), 400

    student = db.session.get(
        Student,
        student_id
    )

    course = db.session.get(
        Course,
        course_id
    )

    if not student:

        return jsonify({
            "status": "error",
            "message": "Student not found"
        }), 404

    if not course:

        return jsonify({
            "status": "error",
            "message": "Course not found"
        }), 404

    try:

        score = float(score)

        grade_date = datetime.strptime(
            date,
            "%Y-%m-%d"
        ).date()

    except (ValueError, TypeError):

        return jsonify({
            "status": "error",
            "message": "Invalid score or date"
        }), 400

    if score < 0 or score > 100:

        return jsonify({
            "status": "error",
            "message": "Score must be between 0 and 100"
        }), 400

    grade.student_id = student_id
    grade.course_id = course_id
    grade.score = score
    grade.date = grade_date

    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Grade updated successfully",
        "data": {
            "id": grade.id,
            "student_id": grade.student_id,
            "course_id": grade.course_id,
            "score": grade.score,
            "date": grade.date.isoformat()
        }
    }), 200


@app.route("/api/grades/<int:id>", methods=["PATCH"])
@admin_required()
def api_patch_grade(id):

    grade = Grade.query.get_or_404(id)

    data = request.get_json()

    if not data:

        return jsonify({
            "status": "error",
            "message": "JSON data is required"
        }), 400

    if "student_id" in data:

        student = db.session.get(
            Student,
            data["student_id"]
        )

        if not student:

            return jsonify({
                "status": "error",
                "message": "Student not found"
            }), 404

        grade.student_id = data["student_id"]

    if "course_id" in data:

        course = db.session.get(
            Course,
            data["course_id"]
        )

        if not course:

            return jsonify({
                "status": "error",
                "message": "Course not found"
            }), 404

        grade.course_id = data["course_id"]

    if "score" in data:

        try:

            score = float(data["score"])

        except (ValueError, TypeError):

            return jsonify({
                "status": "error",
                "message": "Score must be a number"
            }), 400

        if score < 0 or score > 100:

            return jsonify({
                "status": "error",
                "message": "Score must be between 0 and 100"
            }), 400

        grade.score = score

    if "date" in data:

        try:

            grade.date = datetime.strptime(
                data["date"],
                "%Y-%m-%d"
            ).date()

        except ValueError:

            return jsonify({
                "status": "error",
                "message": "Date must be YYYY-MM-DD"
            }), 400

    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Grade partially updated successfully",
        "data": {
            "id": grade.id,
            "student_id": grade.student_id,
            "course_id": grade.course_id,
            "score": grade.score,
            "date": grade.date.isoformat()
        }
    }), 200


@app.route("/api/grades/<int:id>", methods=["DELETE"])
@admin_required()
def api_delete_grade(id):

    grade = Grade.query.get_or_404(id)

    db.session.delete(grade)
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Grade deleted successfully"
    }), 200


# =========================================================
# STUDENT OWN GRADES API
# =========================================================

@app.route("/api/my-grades", methods=["GET"])
@jwt_required()
def api_my_grades():

    user_id = get_jwt_identity()

    user = db.session.get(
        User,
        int(user_id)
    )

    if not user:

        return jsonify({
            "status": "error",
            "message": "User not found"
        }), 404

    # Admin can see all grades
    if user.role == "admin":

        grades = Grade.query.all()

    else:

        student = Student.query.filter_by(
            email=user.email
        ).first()

        if not student:

            return jsonify({
                "status": "error",
                "message": "Student record not found"
            }), 404

        grades = Grade.query.filter_by(
            student_id=student.id
        ).all()

    grade_list = []

    for grade in grades:

        grade_list.append({
            "id": grade.id,
            "student_id": grade.student_id,
            "course_id": grade.course_id,
            "score": grade.score,
            "date": grade.date.isoformat()
        })

    return jsonify({
        "status": "success",
        "data": grade_list
    }), 200


# =========================================================
# ANALYTICS API
# ADMIN ONLY
# =========================================================

@app.route("/api/analytics", methods=["GET"])
@admin_required()
def api_analytics():

    grades = Grade.query.all()

    if not grades:

        return jsonify({
            "status": "success",
            "message": "No grades available for analytics",
            "data": []
        }), 200

    data = []

    for grade in grades:

        data.append({
            "student_id": grade.student_id,
            "course_id": grade.course_id,
            "score": grade.score
        })

    df = pd.DataFrame(data)

    analytics = {
        "total_grades": len(df),
        "mean": float(np.mean(df["score"])),
        "median": float(np.median(df["score"])),
        "standard_deviation": float(np.std(df["score"]))
    }

    return jsonify({
        "status": "success",
        "data": analytics
    }), 200


@app.route("/api/analytics/courses", methods=["GET"])
@admin_required()
def course_analytics():

    grades = Grade.query.all()

    if not grades:

        return jsonify({
            "status": "success",
            "message": "No grades available",
            "data": []
        }), 200

    data = []

    for grade in grades:

        data.append({
            "student_id": grade.student_id,
            "course_id": grade.course_id,
            "score": grade.score
        })

    df = pd.DataFrame(data)

    course_average = (
        df.groupby("course_id")["score"]
        .mean()
        .reset_index()
    )

    df["rank"] = (
        df.groupby("course_id")["score"]
        .rank(
            method="dense",
            ascending=False
        )
    )

    return jsonify({
        "status": "success",
        "course_average": course_average.to_dict(
            orient="records"
        ),
        "student_ranking": df.to_dict(
            orient="records"
        )
    }), 200


@app.route("/api/analytics/filter", methods=["GET"])
@admin_required()
def filter_analytics():

    student_id = request.args.get(
        "student_id",
        type=int
    )

    course_id = request.args.get(
        "course_id",
        type=int
    )

    query = Grade.query

    if student_id is not None:

        query = query.filter_by(
            student_id=student_id
        )

    if course_id is not None:

        query = query.filter_by(
            course_id=course_id
        )

    grades = query.all()

    if not grades:

        return jsonify({
            "status": "success",
            "message": "No grades found",
            "data": []
        }), 200

    data = []

    for grade in grades:

        data.append({
            "id": grade.id,
            "student_id": grade.student_id,
            "course_id": grade.course_id,
            "score": grade.score,
            "date": grade.date.isoformat()
        })

    df = pd.DataFrame(data)

    result = {
        "total_grades": len(df),
        "average": float(np.mean(df["score"])),
        "median": float(np.median(df["score"])),
        "standard_deviation": float(np.std(df["score"])),
        "grades": data
    }

    return jsonify({
        "status": "success",
        "data": result
    }), 200


# =========================================================
# ANALYTICS BROWSER DASHBOARD
# ADMIN ONLY
# =========================================================

@app.route("/analytics")
@admin_dashboard_required
def analytics_dashboard():

    student_id = request.args.get(
        "student_id",
        type=int
    )

    course_id = request.args.get(
        "course_id",
        type=int
    )

    students = Student.query.all()
    courses = Course.query.all()

    query = Grade.query

    if student_id is not None:

        query = query.filter_by(
            student_id=student_id
        )

    if course_id is not None:

        query = query.filter_by(
            course_id=course_id
        )

    grades = query.all()

    if not grades:

        return render_template(
            "analytics.html",
            students=students,
            courses=courses,
            selected_student=student_id,
            selected_course=course_id,
            total=0,
            average=0,
            median=0,
            std_dev=0,
            grades=[]
        )

    data = []

    for grade in grades:

        data.append({
            "student_name": grade.student.name,
            "course_name": grade.course.name,
            "score": grade.score,
            "date": grade.date
        })

    df = pd.DataFrame(data)

    total = len(df)

    average = round(
        float(np.mean(df["score"])),
        2
    )

    median = round(
        float(np.median(df["score"])),
        2
    )

    std_dev = round(
        float(np.std(df["score"])),
        2
    )

    return render_template(
        "analytics.html",
        students=students,
        courses=courses,
        selected_student=student_id,
        selected_course=course_id,
        total=total,
        average=average,
        median=median,
        std_dev=std_dev,
        grades=data
    )


# =========================================================
# CSV UPLOAD
# ADMIN ONLY
# =========================================================

@app.route(
    "/api/grades/upload",
    methods=["POST"]
)
@admin_required()
def upload_grades_csv():

    if "file" not in request.files:

        return jsonify({
            "status": "error",
            "message": "CSV file is required"
        }), 400

    file = request.files["file"]

    if file.filename == "":

        return jsonify({
            "status": "error",
            "message": "No file selected"
        }), 400

    try:

        df = pd.read_csv(file)

        required_columns = [
            "student_id",
            "course_id",
            "score",
            "date"
        ]

        for column in required_columns:

            if column not in df.columns:

                return jsonify({
                    "status": "error",
                    "message": f"Missing column: {column}"
                }), 400

        count = 0

        for _, row in df.iterrows():

            student = db.session.get(
                Student,
                int(row["student_id"])
            )

            course = db.session.get(
                Course,
                int(row["course_id"])
            )

            if not student or not course:

                continue

            score = float(row["score"])

            if score < 0 or score > 100:

                continue

            grade_date = datetime.strptime(
                str(row["date"]),
                "%Y-%m-%d"
            ).date()

            grade = Grade(
                student_id=int(row["student_id"]),
                course_id=int(row["course_id"]),
                score=score,
                date=grade_date
            )

            db.session.add(grade)

            count += 1

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "CSV uploaded successfully",
            "grades_added": count
        }), 201

    except Exception as e:

        db.session.rollback()

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 400


# =========================================================
# CSV EXPORT
# ADMIN ONLY
# =========================================================

@app.route(
    "/api/grades/export/csv",
    methods=["GET"]
)
@admin_required()
def export_grades_csv():

    grades = Grade.query.all()

    data = []

    for grade in grades:

        data.append({
            "id": grade.id,
            "student_id": grade.student_id,
            "course_id": grade.course_id,
            "score": grade.score,
            "date": grade.date.isoformat()
        })

    df = pd.DataFrame(data)

    csv_data = df.to_csv(
        index=False
    )

    response = app.response_class(
        csv_data,
        mimetype="text/csv"
    )

    response.headers[
        "Content-Disposition"
    ] = "attachment; filename=grades_report.csv"

    return response


# =========================================================
# EXCEL EXPORT
# ADMIN ONLY
# =========================================================

@app.route(
    "/api/grades/export/excel",
    methods=["GET"]
)
@admin_required()
def export_grades_excel():

    grades = Grade.query.all()

    data = []

    for grade in grades:

        data.append({
            "id": grade.id,
            "student_id": grade.student_id,
            "course_id": grade.course_id,
            "score": grade.score,
            "date": grade.date.isoformat()
        })

    df = pd.DataFrame(data)

    output = BytesIO()

    with pd.ExcelWriter(
        output,
        engine="openpyxl"
    ) as writer:

        df.to_excel(
            writer,
            sheet_name="Grades",
            index=False
        )

    output.seek(0)

    response = app.response_class(
        output.getvalue(),
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        )
    )

    response.headers[
        "Content-Disposition"
    ] = "attachment; filename=grades_report.xlsx"

    return response

@app.route("/grades/upload", methods=["POST"])
@admin_dashboard_required
def browser_upload_grades_csv():

    if "file" not in request.files:
        return "CSV file is required.", 400

    file = request.files["file"]

    if file.filename == "":
        return "No file selected.", 400

    try:
        df = pd.read_csv(file)

        required_columns = [
            "student_id",
            "course_id",
            "score",
            "date"
        ]

        for column in required_columns:
            if column not in df.columns:
                return f"Missing column: {column}", 400

        count = 0

        for _, row in df.iterrows():

            student = db.session.get(
                Student,
                int(row["student_id"])
            )

            course = db.session.get(
                Course,
                int(row["course_id"])
            )

            if not student or not course:
                continue

            score = float(row["score"])

            if score < 0 or score > 100:
                continue

            grade_date = datetime.strptime(
                str(row["date"]),
                "%Y-%m-%d"
            ).date()

            grade = Grade(
                student_id=int(row["student_id"]),
                course_id=int(row["course_id"]),
                score=score,
                date=grade_date
            )

            db.session.add(grade)
            count += 1

        db.session.commit()

        return redirect("/grades")

    except Exception as e:

        db.session.rollback()

        return f"CSV upload failed: {str(e)}", 400

@app.route("/grades/export/csv")
@admin_dashboard_required
def browser_export_grades_csv():

    grades = Grade.query.all()

    data = []

    for grade in grades:

        data.append({
            "id": grade.id,
            "student_id": grade.student_id,
            "course_id": grade.course_id,
            "score": grade.score,
            "date": grade.date.isoformat()
        })

    df = pd.DataFrame(data)

    csv_data = df.to_csv(index=False)

    response = app.response_class(
        csv_data,
        mimetype="text/csv"
    )

    response.headers[
        "Content-Disposition"
    ] = "attachment; filename=grades_report.csv"

    return response

@app.route("/dashboard")
@admin_dashboard_required
def dashboard():

    total_students = Student.query.count()

    total_courses = Course.query.count()

    total_grades = Grade.query.count()

    grades = Grade.query.all()

    if grades:
        average_score = round(
            sum(grade.score for grade in grades) / len(grades),
            2
        )
    else:
        average_score = 0

    return render_template(
        "dashboard.html",
        user_name=session.get("user_name"),
        total_students=total_students,
        total_courses=total_courses,
        total_grades=total_grades,
        average_score=average_score
    )
# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )