[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Pylint](https://github.com/VarnikaB/CareerConnect/actions/workflows/pylint.yml/badge.svg)](https://github.com/VarnikaB/CareerConnect/actions/workflows/pylint.yml)

# Career Connect

A platform for connecting with other users and sharing your experience.

The application is designed to be easy to use, with a focus on user experience. Whether you're a working professional or student, our application makes it easy to share your experience with the world and connect with other users.

## Features

- User registration and login
- Create and manage posts
- Upload image while creating and updating posts
- Change username and profile image
- Search for other users using their usernames
- Search for posts with keyword
- Like and comment on other users' posts
- Chat with other users
- Edit and delete comments
- Practice questions with multiple choice
- Prometheus metrics and Grafana dashboard for monitoring
- Responsive design

## Technologies Used

- Flask - web framework
- Jinja2 - templating engine
- Bootstrap - for HTML and CSS styling
- SQLite - for data storage
- Prometheus - for metrics collection
- Grafana - for metrics visualization

## Getting Started

### Prerequisites

- Python 3.x
- pip

### Installation

```bash
# Clone this repo
git clone https://github.com/VarnikaB/CareerConnect.git
cd CareerConnect

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration
```

### Run the Application

```bash
python run.py
```

The application will start running on `http://localhost:5000`.

### Run Tests

```bash
pytest tests/ -v
```

This runs the full test suite (58 tests) covering authentication, posts, comments, chat, users, questions, models, and error handling.

### Run Code Quality Tools

```bash
black app/
pylint app/
```

## Monitoring

### Prometheus Metrics

Once the app is running, Prometheus metrics are exposed at:

```
http://localhost:5000/metrics
```

Available metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `flask_http_requests_total` | Counter | Total HTTP requests (by method, endpoint, status_code) |
| `flask_http_request_duration_seconds` | Histogram | Request latency (by method, endpoint) |
| `careerconnect_user_registrations_total` | Counter | Total user registrations |
| `careerconnect_user_logins_total` | Counter | Total successful logins |
| `careerconnect_posts_created_total` | Counter | Total posts created |
| `careerconnect_comments_created_total` | Counter | Total comments created |
| `careerconnect_likes_total` | Counter | Total likes given |
| `careerconnect_chats_sent_total` | Counter | Total chat messages sent |

### Grafana Dashboard

A pre-built Grafana dashboard is included at `monitoring/grafana/dashboards/careerconnect.json`.

To set up with Docker:

```bash
# 1. Add scrape target to your prometheus.yml
#    scrape_configs:
#      - job_name: 'careerconnect'
#        static_configs:
#          - targets: ['host.docker.internal:5000']

# 2. Run Grafana with auto-provisioned dashboard
docker run -d -p 3000:3000 \
  -v $(pwd)/monitoring/grafana/dashboards:/var/lib/grafana/dashboards \
  -v $(pwd)/monitoring/grafana/provisioning:/etc/grafana/provisioning \
  grafana/grafana
```

Open Grafana at `http://localhost:3000` (default credentials: admin/admin). The "CareerConnect Overview" dashboard will be automatically available with panels for:

- HTTP request rate and error rate
- Latency percentiles (P50/P95/P99)
- Business metrics (registrations, logins, posts, comments, likes, chats)
- Top endpoints by traffic and latency

## Project Structure

```
CareerConnect/
├── app/
│   ├── __init__.py          # App factory
│   ├── models.py            # Database models
│   ├── forms.py             # WTForms definitions
│   ├── extensions.py        # Flask extensions
│   ├── metrics.py           # Prometheus metrics
│   ├── utils.py             # Image upload helpers
│   ├── errors.py            # Error handlers
│   └── routes/
│       ├── auth.py          # Login/register/logout
│       ├── posts.py         # CRUD posts, like/unlike
│       ├── comments.py      # CRUD comments
│       ├── chat.py          # Messaging
│       ├── search.py        # Search users and posts
│       ├── questions.py     # Practice questions
│       ├── users.py         # Profile management
│       ├── main.py          # Feed and welcome page
│       └── metrics.py       # /metrics endpoint
├── tests/                   # Test suite (58 tests)
├── monitoring/grafana/      # Grafana dashboard and provisioning
├── config.py                # App configuration
├── run.py                   # Entry point
└── requirements.txt
```

