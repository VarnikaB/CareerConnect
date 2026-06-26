from app.models import Question


def test_questions_requires_login(client):
    response = client.get("/questions")
    assert response.status_code == 302


def test_questions_page(authenticated_client, db):
    response = authenticated_client.get("/questions")
    assert response.status_code == 200


def test_add_question_get(authenticated_client, db):
    response = authenticated_client.get("/question/add_question")
    assert response.status_code == 200


def test_add_question_post(authenticated_client, db):
    response = authenticated_client.post(
        "/question/add_question",
        data={
            "question": "What is Python?",
            "option1": "A language",
            "option2": "A snake",
            "option3": "A framework",
            "option4": "A database",
            "answer": "A language",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    q = Question.query.filter_by(question="What is Python?").first()
    assert q is not None
    assert q.answer == "A language"


def test_submit_correct_answer(authenticated_client, db):
    q = Question(
        question="1+1?",
        option1="1",
        option2="2",
        option3="3",
        option4="4",
        answer="2",
    )
    db.session.add(q)
    db.session.commit()

    response = authenticated_client.post(
        f"/question/submit?question_id={q.id}",
        data={str(q.id): "2"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Correct" in response.data


def test_submit_incorrect_answer(authenticated_client, db):
    q = Question(
        question="2+2?",
        option1="3",
        option2="4",
        option3="5",
        option4="6",
        answer="4",
    )
    db.session.add(q)
    db.session.commit()

    response = authenticated_client.post(
        f"/question/submit?question_id={q.id}",
        data={str(q.id): "3"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Incorrect" in response.data
