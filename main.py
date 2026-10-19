
import os
import re
import hmac
import base64
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager

import jwt
import uvicorn

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, Text,
    create_engine, select, func, or_
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, Session,
    mapped_column, relationship, sessionmaker,
)


# ==================================================
# fiqhMedia Backend — Version 1.3.0
# FastAPI + PostgreSQL + Email Login + Admin
# ==================================================

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
AUTH_SECRET = os.getenv("AUTH_SECRET", "")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://", "postgresql://", 1
    )

if not ADMIN_EMAIL:
    raise RuntimeError("ADMIN_EMAIL is missing")

if len(ADMIN_PASSWORD) < 12:
    raise RuntimeError(
        "ADMIN_PASSWORD must contain at least 12 characters"
    )

if len(AUTH_SECRET) < 32:
    raise RuntimeError(
        "AUTH_SECRET must contain at least 32 characters"
    )


engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=5,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)


# ==================================================
# DATABASE MODELS
# ==================================================

class Base(DeclarativeBase):
    pass


class Madhhab(Base):
    __tablename__ = "madhhabs"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )

    code: Mapped[str] = mapped_column(
        String(30), unique=True, nullable=False
    )

    name: Mapped[str] = mapped_column(
        String(100), nullable=False
    )


class Author(Base):
    __tablename__ = "authors"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )

    full_name: Mapped[str] = mapped_column(
        String(300), nullable=False
    )

    arabic_name: Mapped[str | None] = mapped_column(
        String(300), nullable=True
    )

    biography: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    birth_year: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    death_year: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    teachers: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    students: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    scholarly_contributions: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    verified: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    books: Mapped[list["Book"]] = relationship(
        back_populates="author"
    )


class Book(Base):
    __tablename__ = "books"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )

    title: Mapped[str] = mapped_column(
        String(300), nullable=False
    )

    arabic_title: Mapped[str | None] = mapped_column(
        String(300), nullable=True
    )

    description: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    madhhab_code: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("madhhabs.code"),
        nullable=False,
        index=True,
    )

    author_id: Mapped[int] = mapped_column(
        ForeignKey("authors.id"),
        nullable=False,
    )

    edition: Mapped[str | None] = mapped_column(
        String(300), nullable=True
    )

    verified: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    author: Mapped["Author"] = relationship(
        back_populates="books"
    )

    articles: Mapped[list["Article"]] = relationship(
        back_populates="book"
    )


class Article(Base):
    __tablename__ = "articles"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )

    title: Mapped[str] = mapped_column(
        String(300), nullable=False
    )

    category: Mapped[str] = mapped_column(
        String(150), nullable=False
    )

    content: Mapped[str] = mapped_column(
        Text, nullable=False
    )

    madhhab_code: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("madhhabs.code"),
        nullable=False,
        index=True,
    )

    book_id: Mapped[int] = mapped_column(
        ForeignKey("books.id"),
        nullable=False
    )

    chapter: Mapped[str | None] = mapped_column(
        String(300), nullable=True
    )

    page_reference: Mapped[str | None] = mapped_column(
        String(150), nullable=True
    )

    original_text: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    review_notes: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    book: Mapped["Book"] = relationship(
        back_populates="articles"
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )

    email: Mapped[str] = mapped_column(
        String(254),
        unique=True,
        index=True,
        nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        Text, nullable=False
    )

    role: Mapped[str] = mapped_column(
        String(30),
        default="user",
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# ==================================================
# PASSWORD SECURITY
# ==================================================

EMAIL_PATTERN = re.compile(
    r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
)

TOKEN_HOURS = 12

bearer = HTTPBearer(auto_error=False)


def normalize_email(email: str) -> str:
    email = email.strip().lower()

    if not EMAIL_PATTERN.fullmatch(email):
        raise HTTPException(
            status_code=422,
            detail="Invalid email address",
        )

    return email


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = 600_000

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(hashed).decode("ascii"),
    )


def verify_password(
    password: str,
    password_hash: str,
) -> bool:
    try:
        scheme, rounds, salt, saved_hash = (
            password_hash.split("$")
        )

        if scheme != "pbkdf2_sha256":
            return False

        rounds = int(rounds)

        if rounds < 100_000 or rounds > 1_000_000:
            return False

        salt_bytes = base64.b64decode(
            salt, validate=True
        )

        expected = base64.b64decode(
            saved_hash, validate=True
        )

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt_bytes,
            rounds,
        )

        return hmac.compare_digest(
            actual, expected
        )

    except (ValueError, TypeError):
        return False


# ==================================================
# INITIAL DATABASE
# ==================================================

INITIAL_MADHHABS = [
    ("hanafi", "Hanafiy"),
    ("shafii", "Shofe’iy"),
    ("maliki", "Molikiy"),
    ("hanbali", "Hanbaliy"),
]


def bootstrap_admin():
    email = normalize_email(ADMIN_EMAIL)

    with SessionLocal() as db:
        admin = db.scalar(
            select(User).where(User.email == email)
        )

        if admin is None:
            admin = User(
                email=email,
                password_hash=hash_password(
                    ADMIN_PASSWORD
                ),
                role="super_admin",
            )

            db.add(admin)

        else:
            admin.role = "super_admin"

            if not verify_password(
                ADMIN_PASSWORD,
                admin.password_hash,
            ):
                admin.password_hash = hash_password(
                    ADMIN_PASSWORD
                )

        db.commit()


def initialize_database():
    # Does not delete existing tables or data.
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        for code, name in INITIAL_MADHHABS:
            existing = db.scalar(
                select(Madhhab).where(
                    Madhhab.code == code
                )
            )

            if existing is None:
                db.add(
                    Madhhab(
                        code=code,
                        name=name,
                    )
                )

        db.commit()

    bootstrap_admin()


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()

    yield

    engine.dispose()


# ==================================================
# APPLICATION
# ==================================================

app = FastAPI(
    title="fiqhMedia API",
    version="1.3.0",
    description=(
        "Verified Islamic knowledge platform "
        "with secure accounts and admin roles."
    ),
    lifespan=lifespan,
)


# ==================================================
# LOGIN SCHEMAS
# ==================================================

class Credentials(BaseModel):
    email: str = Field(
        min_length=5, max_length=254
    )

    password: str = Field(
        min_length=12, max_length=128
    )


def user_data(user: User):
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
    }


def create_token(user: User):
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user.id),
        "iat": now,
        "exp": now + timedelta(
            hours=TOKEN_HOURS
        ),
        "typ": "access",
    }

    return jwt.encode(
        payload,
        AUTH_SECRET,
        algorithm="HS256",
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = (
        Depends(bearer)
    ),
):
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
    ):
        raise HTTPException(
            status_code=401,
            detail="Login required",
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            AUTH_SECRET,
            algorithms=["HS256"],
            options={
                "require": [
                    "sub",
                    "iat",
                    "exp",
                ]
            },
        )

        if payload.get("typ") != "access":
            raise ValueError("Invalid token type")

        user_id = int(payload["sub"])

    except (
        jwt.InvalidTokenError,
        ValueError,
        TypeError,
        KeyError,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        )

    with SessionLocal() as db:
        user = db.get(User, user_id)

        if user is None:
            raise HTTPException(
                status_code=401,
                detail="User not found",
            )

        return user


def require_admin(
    user: User = Depends(get_current_user),
):
    if user.role not in (
        "admin",
        "super_admin",
    ):
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

    return user


# ==================================================
# REGISTER
# ==================================================

@app.post("/auth/register", status_code=201)
def register(credentials: Credentials):
    email = normalize_email(
        credentials.email
    )

    if email == ADMIN_EMAIL:
        raise HTTPException(
            status_code=403,
            detail="Reserved admin account",
        )

    with SessionLocal() as db:
        new_user = User(
            email=email,
            password_hash=hash_password(
                credentials.password
            ),
            role="user",
        )

        db.add(new_user)

        try:
            db.commit()
            db.refresh(new_user)

        except IntegrityError:
            db.rollback()

            raise HTTPException(
                status_code=409,
                detail="Email already registered",
            )

        return {
            "user": user_data(new_user),
            "access_token": create_token(
                new_user
            ),
            "token_type": "bearer",
        }


# ==================================================
# LOGIN
# ==================================================

@app.post("/auth/login")
def login(credentials: Credentials):
    email = normalize_email(
        credentials.email
    )

    with SessionLocal() as db:
        user = db.scalar(
            select(User).where(
                User.email == email
            )
        )

        if (
            user is None
            or not verify_password(
                credentials.password,
                user.password_hash,
            )
        ):
            raise HTTPException(
                status_code=401,
                detail="Incorrect email or password",
            )

        return {
            "user": user_data(user),
            "access_token": create_token(
                user
            ),
            "token_type": "bearer",
        }


# ==================================================
# CURRENT USER
# ==================================================

@app.get("/auth/me")
def get_my_profile(
    user: User = Depends(get_current_user),
):
    return user_data(user)


# ==================================================
# ADMIN
# ==================================================

@app.get("/admin/status")
def admin_status(
    user: User = Depends(require_admin),
):
    with SessionLocal() as db:
        return {
            "admin": user_data(user),
            "authors": db.scalar(
                select(func.count(Author.id))
            ),
            "books": db.scalar(
                select(func.count(Book.id))
            ),
            "articles": db.scalar(
                select(func.count(Article.id))
            ),
        }


# ==================================================
# RESPONSE HELPERS
# ==================================================

def author_data(author: Author):
    return {
        "id": author.id,
        "full_name": author.full_name,
        "arabic_name": author.arabic_name,
        "biography": author.biography,
        "birth_year": author.birth_year,
        "death_year": author.death_year,
        "teachers": author.teachers,
        "students": author.students,
        "scholarly_contributions": (
            author.scholarly_contributions
        ),
    }


def book_data(book: Book):
    return {
        "id": book.id,
        "title": book.title,
        "arabic_title": book.arabic_title,
        "description": book.description,
        "madhhab": book.madhhab_code,
        "edition": book.edition,
        "author": author_data(book.author),
    }


def article_data(article: Article):
    return {
        "id": article.id,
        "title": article.title,
        "category": article.category,
        "content": article.content,
        "madhhab": article.madhhab_code,
        "chapter": article.chapter,
        "page_reference": article.page_reference,
        "original_text": article.original_text,
        "book": book_data(article.book),
    }


def validate_madhhab(code: str):
    codes = {
        "hanafi",
        "shafii",
        "maliki",
        "hanbali",
    }

    if code not in codes:
        raise HTTPException(
            status_code=400,
            detail="Invalid madhhab",
        )


# ==================================================
# ROOT
# ==================================================

@app.get("/")
def root():
    return {
        "name": "fiqhMedia API",
        "version": "1.3.0",
        "status": "online",
        "documentation": "/docs",
    }


# ==================================================
# HEALTH
# ==================================================

@app.get("/health")
def health():
    with SessionLocal() as db:
        db.execute(select(1)).scalar_one()

    return {
        "status": "healthy",
        "database": "connected",
    }


# ==================================================
# MADHHABS
# ==================================================

@app.get("/madhhabs")
def get_madhhabs():
    with SessionLocal() as db:
        rows = db.scalars(
            select(Madhhab).order_by(
                Madhhab.id
            )
        ).all()

        return [
            {
                "code": row.code,
                "name": row.name,
            }
            for row in rows
        ]


# ==================================================
# AUTHORS
# ==================================================

@app.get("/authors")
def get_authors(
    limit: int = Query(
        default=30,
        ge=1,
        le=100,
    ),
):
    with SessionLocal() as db:
        authors = db.scalars(
            select(Author)
            .where(
                Author.verified.is_(True)
            )
            .order_by(Author.id)
            .limit(limit)
        ).all()

        return [
            author_data(author)
            for author in authors
        ]


@app.get("/authors/{author_id}")
def get_author(author_id: int):
    with SessionLocal() as db:
        author = db.scalar(
            select(Author).where(
                Author.id == author_id,
                Author.verified.is_(True),
            )
        )

        if author is None:
            raise HTTPException(
                status_code=404,
                detail="Verified author not found",
            )

        return author_data(author)


# ==================================================
# BOOKS
# ==================================================

@app.get("/books")
def get_books(
    madhhab: str = Query(...),
    limit: int = Query(
        default=30,
        ge=1,
        le=100,
    ),
):
    validate_madhhab(madhhab)

    with SessionLocal() as db:
        books = db.scalars(
            select(Book)
            .join(
                Author,
                Book.author_id == Author.id,
            )
            .where(
                Book.madhhab_code == madhhab,
                Book.verified.is_(True),
                Author.verified.is_(True),
            )
            .order_by(Book.id)
            .limit(limit)
        ).all()

        return [
            book_data(book)
            for book in books
        ]


# ==================================================
# VERIFIED ARTICLES
# ==================================================

@app.get("/articles")
def get_articles(
    madhhab: str = Query(...),
    limit: int = Query(
        default=30,
        ge=1,
        le=100,
    ),
):
    validate_madhhab(madhhab)

    with SessionLocal() as db:
        articles = db.scalars(
            select(Article)
            .join(
                Book,
                Article.book_id == Book.id,
            )
            .join(
                Author,
                Book.author_id == Author.id,
            )
            .where(
                Article.madhhab_code == madhhab,
                Book.madhhab_code == madhhab,
                Article.verified.is_(True),
                Book.verified.is_(True),
                Author.verified.is_(True),
            )
            .order_by(Article.id)
            .limit(limit)
        ).all()

        return [
            article_data(article)
            for article in articles
        ]


# ==================================================
# SEARCH
# ==================================================

@app.get("/search")
def search_articles(
    madhhab: str = Query(...),
    q: str = Query(
        ...,
        min_length=2,
        max_length=200,
    ),
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
):
    validate_madhhab(madhhab)

    phrase = q.strip()

    if len(phrase) < 2:
        raise HTTPException(
            status_code=400,
            detail="Search query too short",
        )

    safe = (
        phrase
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )

    pattern = f"%{safe}%"

    with SessionLocal() as db:
        articles = db.scalars(
            select(Article)
            .join(
                Book,
                Article.book_id == Book.id,
            )
            .join(
                Author,
                Book.author_id == Author.id,
            )
            .where(
                Article.madhhab_code == madhhab,
                Book.madhhab_code == madhhab,
                Article.verified.is_(True),
                Book.verified.is_(True),
                Author.verified.is_(True),
                or_(
                    Article.title.ilike(
                        pattern,
                        escape="\\",
                    ),
                    Article.category.ilike(
                        pattern,
                        escape="\\",
                    ),
                    Article.content.ilike(
                        pattern,
                        escape="\\",
                    ),
                ),
            )
            .order_by(Article.id)
            .limit(limit)
        ).all()

        return {
            "madhhab": madhhab,
            "query": phrase,
            "count": len(articles),
            "results": [
                article_data(article)
                for article in articles
            ],
        }


# ==================================================
# SINGLE ARTICLE
# ==================================================

@app.get("/articles/{article_id}")
def get_article(article_id: int):
    with SessionLocal() as db:
        article = db.scalar(
            select(Article)
            .join(
                Book,
                Article.book_id == Book.id,
            )
            .join(
                Author,
                Book.author_id == Author.id,
            )
            .where(
                Article.id == article_id,
                Article.verified.is_(True),
                Book.verified.is_(True),
                Author.verified.is_(True),
                Article.madhhab_code == (
                    Book.madhhab_code
                ),
            )
        )

        if article is None:
            raise HTTPException(
                status_code=404,
                detail="Verified article not found",
            )

        return article_data(article)


# ==================================================
# START
# ==================================================

if __name__ == "__main__":
    port = int(
        os.getenv("PORT", "8000")
    )

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
    )
