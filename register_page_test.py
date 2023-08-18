import pytest
from unittest.mock import Mock, patch
from app import app


@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

@patch("app.render_template")
def test_register_is_displayed(mock_render_template, client):
    mock_render_template.return_value = "Mocked Template Content"
    response = client.get("/register")
    print(response)
    assert response.status_code == 200
    assert b"Mocked Template Content" in response.data

