from database import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="student")


class Student(db.Model):
    __tablename__ = "students"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    grades = db.relationship(
        "Grade",
        backref="student",
        cascade="all, delete-orphan"
    )


class Course(db.Model):
    __tablename__ = "courses"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)

    grades = db.relationship(
        "Grade",
        backref="course",
        cascade="all, delete-orphan"
    )


class Grade(db.Model):
    __tablename__ = "grades"

    id = db.Column(db.Integer, primary_key=True)

    student_id = db.Column(
        db.Integer,
        db.ForeignKey("students.id"),
        nullable=False
    )

    course_id = db.Column(
        db.Integer,
        db.ForeignKey("courses.id"),
        nullable=False
    )

    score = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)