from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.forms import QuestionForm
from app.models import Question
from app.permissions import role_required

questions_bp = Blueprint("questions", __name__)


@questions_bp.route("/questions")
@login_required
def questions():
    question_id = request.args.get("question_id", 1, type=int)
    all_questions = Question.query.order_by(Question.timestamp.desc()).all()

    return render_template(
        "questions.html",
        title="Practice Questions",
        questions=all_questions,
        loop_index=question_id,
    )


@questions_bp.route("/question/submit", methods=["POST"])
@login_required
def submit():
    question_id = request.args.get("question_id")

    for key, value in request.form.items():
        if key == "csrf_token":
            continue
        question = Question.query.filter_by(id=key).first_or_404()
        if question.answer == value:
            flash("Correct!", "success")
        else:
            flash("Incorrect!", "danger")

    return redirect(url_for("questions.questions", question_id=question_id))


@questions_bp.route("/question/add_question", methods=["POST", "GET"])
@login_required
@role_required("senior_student", "teacher")
def add_question():
    form = QuestionForm()

    if form.validate_on_submit():
        question = Question(
            question=form.question.data,
            option1=form.option1.data,
            option2=form.option2.data,
            option3=form.option3.data,
            option4=form.option4.data,
            answer=form.answer.data,
        )
        db.session.add(question)
        db.session.commit()

        flash("Question added!", "success")
        return redirect(url_for("questions.questions"))

    return render_template("add_question.html", title="Add New Question", form=form)
