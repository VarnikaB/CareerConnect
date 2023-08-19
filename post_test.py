import pytest
from app import app, Post, User
from datetime import datetime
from pytz import timezone

@pytest.fixture
def new_post():
    return Post(
        title="Test Post",
        timestamp=datetime.now(timezone('Asia/Kolkata')),
        caption="Test Caption",
        user_id=1
    )
class MockQuery:
    def order_by(self, order_by_param):
        return self

    def all(self):
        # Create and return mock Post objects
        mock_posts = [new_post()]
        return mock_posts

@pytest.fixture
def client():
    app.config['TESTING'] = True
    client = app.test_client()

    with app.app_context():
        yield client

@pytest.fixture
def mock_db_session(monkeypatch):
    def mock_query(cls):
        return MockQuery()
    monkeypatch.setattr(Post, 'query', mock_query)

def test_create_post(new_post):
    assert new_post.title == "Test Post"
    assert new_post.caption == "Test Caption"
    assert new_post.user_id == 1

def test_post_repr(new_post):
    assert repr(new_post) == f"Post('{new_post.id}', '{new_post.title}', '{new_post.timestamp}')"
