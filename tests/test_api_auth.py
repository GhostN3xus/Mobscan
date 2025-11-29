"""
Tests for API authentication endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mobscan.api.app import create_app
from mobscan.database import Base, get_db
from mobscan.models.db_models import User
from mobscan.api.auth import create_user, hash_password


# Setup test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override get_db dependency"""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


@pytest.fixture
def test_db():
    """Create test database"""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(test_db):
    """Create test client"""
    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


@pytest.fixture
def test_user(test_db):
    """Create test user"""
    db = TestingSessionLocal()
    user = create_user(
        db,
        username="testuser",
        email="test@example.com",
        password="password123"
    )
    db.close()
    return user


class TestAuthEndpoints:
    """Test authentication endpoints"""

    def test_register_user(self, client):
        """Test user registration"""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "securepassword123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "user_id" in data
        assert data["username"] == "newuser"

    def test_register_duplicate_user(self, client, test_user):
        """Test registration with duplicate username"""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "username": "testuser",
                "email": "another@example.com",
                "password": "password123"
            }
        )
        assert response.status_code == 400

    def test_login_success(self, client, test_user):
        """Test successful login"""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "username": "testuser",
                "password": "password123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_invalid_password(self, client, test_user):
        """Test login with invalid password"""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "username": "testuser",
                "password": "wrongpassword"
            }
        )
        assert response.status_code == 401

    def test_login_nonexistent_user(self, client):
        """Test login with non-existent user"""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "username": "nonexistent",
                "password": "password123"
            }
        )
        assert response.status_code == 401

    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded"]
        assert data["api_version"] == "1.1.0"

    def test_root_endpoint(self, client):
        """Test root endpoint"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Mobscan API"
        assert data["version"] == "1.1.0"
