[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Pylint](https://github.com/VarnikaB/CareerConnect/actions/workflows/pylint.yml/badge.svg)](https://github.com/VarnikaB/CareerConnect/actions/workflows/pylint.yml)

# Career Connect

A platform for connecting with other users and sharing your experience. 

The application is designed to be easy to use, with a focus on user experience. Whether you're a working professional or student, our application makes it easy to share your experience with the world and connect with other users.

###

### Features : 

- User registration and login

- Create and manage posts

- Upload image while creating and updating posts

- Change username and profile image

- Search for other users using their usernames

- Search for posts with keyword 

- Like and comment on other users' posts

- Chat with other users

- Edit and delete comments

- Responsive design

##
### Technologies Used : 

- Flask - web framework

- Jinja2 - templating engine

- Bootstrap - for HTML and CSS styling

- SQLite - for data storage


##
### Tools used to make the code better
- black: for pep8 formatting
  `black app.py`
- pylint: for code quality
- radon: for obtaining raw metrics on line counts, Cyclomatic Complexity, Halstead metrics and maintainability metrics.

## Getting Started

### Prerequisites

- Python 3.x
- pip

### Run the application
- Clone this repo
- Run `source newenv/bin/activate
- pip install -r requirements.txt
- python app.py

### Run code quality tests
- pylint app.py `Code quality: 8.3/10`
- radon cc app.py `Cyclomatic Complexity: All the functions, class, methods are A/B`
- radon mi app.py `Maintainability Index: All A`

Now the application will start running on `http://localhost:5000`





