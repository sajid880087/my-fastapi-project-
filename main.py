from fastapi import FastAPI, Request, Form, status, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import create_engine, Column, String, inspect, DateTime, Integer, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import os
from dotenv import load_dotenv
from passlib.context import CryptContext
import logging
from starlette.middleware.sessions import SessionMiddleware
from datetime import datetime
from user_agents import parse as parse_ua
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY", "default-secret"))

templates = Jinja2Templates(directory="templates")

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database configuration
DATABASE_URL = f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:{os.getenv('DB_PASSWORD', '')}@{os.getenv('DB_HOST', 'localhost')}/{os.getenv('DB_NAME', 'user_db')}"

# Create engine and session local, but defer engine connect until needed
try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
except Exception as e:
    logger.error(f"Error creating database engine: {e}")
    engine = None
    SessionLocal = None

Base = declarative_base()

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
    device_info = Column(String(255), nullable=True)

    user = relationship("User", back_populates="activities")

def init_db() -> None:
    if engine is None:
        logger.error("Database engine is not initialized, skipping DB init")
        return
    try:
        inspector = inspect(engine)
        if not inspector.has_table("users"):
            Base.metadata.create_all(bind=engine)
            logger.info("Database tables created successfully")
        else:
            logger.info("Database tables already exist")
    except Exception as e:
        logger.error(f"Error checking/creating database tables: {e}")

# Call DB init safely
init_db()

def get_db():
    if SessionLocal is None:
        raise Exception("DB session not available")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request) -> Optional[str]:
    return request.session.get("user_email")

def get_device_info(user_agent_str: str) -> str:
    ua = parse_ua(user_agent_str)
    device = f"{ua.browser.family} {ua.browser.version_string} on {ua.os.family} {ua.os.version_string}"
    return device

@app.get("/", response_class=HTMLResponse)
async def root():
    return RedirectResponse(url="/login")

@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, success: Optional[str] = None):
    return templates.TemplateResponse("login.html", {"request": request, "success": success})

@app.post("/login")
async def login(request: Request, email: str = Form(...), password: str = Form(...), db=Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if user and user.verify_password(password):
        user.previous_login = user.last_login
        user.last_login = datetime.utcnow()

        user_agent_str = request.headers.get("user-agent", "Unknown device")
        device_info = get_device_info(user_agent_str)

        activity = ActivityLog(
            user_email=email,
            activity_type="login",
            description="Logged in from your usual device",
            device_info=device_info
        )
        db.add(activity)

        try:
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"DB commit error during login: {e}")
            return templates.TemplateResponse("login.html", {"request": request, "error": "Internal error, please try again."})

        request.session["user_email"] = user.email
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid email or password"})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, current_user: Optional[str] = Depends(get_current_user), db=Depends(get_db)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    user = db.query(User).filter(User.email == current_user).first()
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user_email": current_user,
        "now": datetime.now(),
        "last_login": user.last_login,
        "previous_login": user.previous_login
    })

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/register")
async def register(request: Request, email: str = Form(...), password: str = Form(...), db=Depends(get_db)):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        return templates.TemplateResponse("signup.html", {"request": request, "error": "Email already registered"})

    password_hash = pwd_context.hash(password)
    user = User(email=email, password_hash=password_hash)
    db.add(user)

    user_agent_str = request.headers.get("user-agent", "Unknown device")
    device_info = get_device_info(user_agent_str)

    activity = ActivityLog(
        user_email=email,
        activity_type="registration",
        description="Account created",
        device_info=device_info
    )
    db.add(activity)

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"DB commit error during registration: {e}")
        return templates.TemplateResponse("signup.html", {"request": request, "error": "Internal error, please try again."})

    return RedirectResponse(url="/login?success=Registration successful! Please login.", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.post("/reset-password")
async def reset_password(
    request: Request,
    email: str = Form(...),
    old_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db=Depends(get_db)
):
    if new_password != confirm_password:
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "New passwords do not match"})

    user = db.query(User).filter(User.email == email).first()
    if not user:
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Email not found"})

    if not user.verify_password(old_password):
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "Current password is incorrect"})

    user.password_hash = pwd_context.hash(new_password)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Error during password reset: {e}")
        return templates.TemplateResponse("forgot_password.html", {"request": request, "error": "An error occurred. Please try again."})

    return RedirectResponse(url="/login?success=Password updated successfully. Please login with your new password.", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/activity-log", response_class=HTMLResponse)
async def activity_log(request: Request, current_user: Optional[str] = Depends(get_current_user), db=Depends(get_db)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    user = db.query(User).filter(User.email == current_user).first()
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    activities = db.query(ActivityLog).filter(ActivityLog.user_email == current_user).order_by(ActivityLog.timestamp.desc()).all()

    return templates.TemplateResponse("activity_log.html", {
        "request": request,
        "user_email": current_user,
        "activities": activities
    })
