from fastapi import FastAPI, Request, Form, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import create_engine, Column, String, inspect, DateTime, Integer, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from dotenv import load_dotenv
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
from datetime import datetime
from user_agents import parse as parse_ua
from typing import Optional
import os
import logging

# Load environment variables
load_dotenv()

# Logging config
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app with docs urls
app = FastAPI(docs_url="/docs", redoc_url="/redoc")

# Add session middleware for session management
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY", "default-secret"))

# Setup templates directory
templates = Jinja2Templates(directory="templates")

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database setup
DATABASE_URL = f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    email = Column(String(120), primary_key=True, index=True)
    password_hash = Column(String(128))
    last_login = Column(DateTime, nullable=True)
    previous_login = Column(DateTime, nullable=True)
    activities = relationship("ActivityLog", back_populates="user")

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.password_hash)

class ActivityLog(Base):
    __tablename__ = "activity_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(120), ForeignKey("users.email"))
    activity_type = Column(String(50))
    description = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    device_info = Column(String(255))

    user = relationship("User", back_populates="activities")

# Create tables if not exists
def init_db():
    inspector = inspect(engine)
    if not inspector.has_table("users"):
        Base.metadata.create_all(bind=engine)
        logger.info("Created tables.")
    else:
        logger.info("Tables already exist.")

init_db()

# Helper: Get current logged-in user email from session
def get_current_user(request: Request) -> Optional[str]:
    return request.session.get("user_email")

# Helper: Parse device info from user-agent
def get_device_info(ua_string: str) -> str:
    ua = parse_ua(ua_string)
    return f"{ua.browser.family} {ua.browser.version_string} on {ua.os.family} {ua.os.version_string}"

# Routes

@app.get("/", response_class=HTMLResponse)
async def root():
    return RedirectResponse(url="/login")

@app.get("/signup", response_class=HTMLResponse)
async def signup(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.post("/register")
async def register(request: Request, email: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    try:
        if db.query(User).filter(User.email == email).first():
            return templates.TemplateResponse("signup.html", {"request": request, "error": "Email already registered"})

        hashed = pwd_context.hash(password)
        user = User(email=email, password_hash=hashed)
        db.add(user)

        device_info = get_device_info(request.headers.get("user-agent", "Unknown"))
        db.add(ActivityLog(user_email=email, activity_type="registration", description="Account created", device_info=device_info))

        db.commit()
        return RedirectResponse(url="/login?success=Registration successful", status_code=303)
    except Exception as e:
        db.rollback()
        logger.error(f"Register error: {e}")
        return templates.TemplateResponse("signup.html", {"request": request, "error": "Internal error"})
    finally:
        db.close()

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request, success: Optional[str] = None):
    return templates.TemplateResponse("login.html", {"request": request, "success": success})

@app.post("/login")
async def login_post(request: Request, email: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user and user.verify_password(password):
            user.previous_login = user.last_login
            user.last_login = datetime.utcnow()

            device_info = get_device_info(request.headers.get("user-agent", "Unknown"))
            db.add(ActivityLog(user_email=email, activity_type="login", description="User logged in", device_info=device_info))

            db.commit()
            request.session["user_email"] = user.email
            return RedirectResponse(url="/dashboard", status_code=303)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    finally:
        db.close()

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, current_user: Optional[str] = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse("/login", status_code=303)

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == current_user).first()
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "user_email": user.email,
            "last_login": user.last_login,
            "previous_login": user.previous_login
        })
    finally:
        db.close()

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.post("/reset-password")
async def reset_password(
    request: Request,
    email: str = Form(...),
    old_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    db = SessionLocal()
    try:
        if new_password != confirm_password:
            return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Passwords do not match"})

        user = db.query(User).filter(User.email == email).first()
        if not user or not user.verify_password(old_password):
            return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Invalid credentials"})

        user.password_hash = pwd_context.hash(new_password)
        db.commit()

        return RedirectResponse(url="/login?success=Password changed", status_code=303)
    finally:
        db.close()

@app.get("/activity-log", response_class=HTMLResponse)
async def activity_log(request: Request, current_user: Optional[str] = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    db = SessionLocal()
    try:
        logs = db.query(ActivityLog).filter(ActivityLog.user_email == current_user).order_by(ActivityLog.timestamp.desc()).all()
        return templates.TemplateResponse("activity_log.html", {
            "request": request,
            "activities": logs,
            "user_email": current_user
        })
    finally:
        db.close()
@app.get("/delete-account", response_class=HTMLResponse)
async def delete_account(request: Request, current_user: Optional[str] = Depends(get_current_user)):        