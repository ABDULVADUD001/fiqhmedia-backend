
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    func,
    or_,
    select,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)


# ======================================================
# fiqhMedia Backend 1.0
# PostgreSQL + FastAPI
#
# Religious content must be verified before publication.
# No automatic fatwa generation.
# ======================================================


DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is missing. "
        "Set it in Railway Variables."
    )

# Railway may use postgres:// in some environments.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql://",
        1,
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


# ======================================================
# DATABASE BASE
# ======================================================


class Base(DeclarativeBase):
    pass


# ======================================================
# MADHHABS
# ======================================================


class Madhhab(Base):
    __tablename__ = "madhhabs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    code: Mapped[str] = mapped_column(
        String(30),
        unique=True,
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )


# ======================================================
# AUTHORS / SCHOLARS
# ======================================================


class Author(Base):
    __tablename__ = "authors"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    full_name: Mapped[str] = mapped_column(
        String(300),
        nullable=False,
    )

    arabic_name: Mapped[str | None] = mapped_column(
        String(300),
        nullable=True,
    )

    biography: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    birth_year: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    death_year: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    teachers: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    students: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    scholarly_contributions: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    books: Mapped[list["Book"]] = relationship(
        back_populates="author",
    )


# ======================================================
# BOOKS
# ======================================================


class Book(Base):
    __tablename__ = "books"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    title: Mapped[str] = mapped_column(
        String(300),
        nullable=False,
    )

    arabic_title: Mapped[str | None] = mapped_column(
        String(300),
        nullable=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
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
        String(300),
        nullable=True,
    )

    verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    author: Mapped["Author"] = relationship(
        back_populates="books",
    )

    articles: Mapped[list["Article"]] = relationship(
        back_populates="book",
    )


# ======================================================
# ARTICLES / VERIFIED ANSWERS
# ======================================================


class Article(Base):
    __tablename__ = "articles"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    title: Mapped[str] = mapped_column(
        String(300),
        nullable=False,
    )

    category: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    madhhab_code: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("madhhabs.code"),
        nullable=False,
        index=True,
    )

    book_id: Mapped[int] = mapped_column(
        ForeignKey("books.id"),
        nullable=False,
    )

    chapter: Mapped[str | None] = mapped_column(
        String(300),
        nullable=True,
    )

    page_reference: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True,
    )

    original_text: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    review_notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
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
        back_populates="articles",
    )


# ======================================================
# INITIAL MADHHABS
# ======================================================


INITIAL_MADHHABS = [
    ("hanafi", "Hanafiy"),
    ("shafii", "Shofe’iy"),
    ("maliki", "Molikiy"),
    ("hanbali", "Hanbaliy"),
]


def initialize_database():
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        for code, name in INITIAL_MADHHABS:
            exists = db.scalar(
                select(Madhhab).where(
                    Madhhab.code == code
                )
            )

            if exists is None:
                db.add(
                    Madhhab(
                        code=code,
                        name=name,
                    )
                )

        db.commit()


# ======================================================
# FASTAPI LIFESPAN
# ======================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield
    engine.dispose()


app = FastAPI(
    title="fiqhMedia API",
    description=(
        "Verified Islamic Fiqh Knowledge Platform. "
        "Articles are separated by madhhab."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ======================================================
# RESPONSE HELPERS
# ======================================================


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
    if code not in {
        "hanafi",
        "shafii",
        "maliki",
        "hanbali",
    }:
        raise HTTPException(
            status_code=400,
            detail="Invalid madhhab code",
        )


# ======================================================
# API HOME
# ======================================================


@app.get("/")
def home():
    return {
        "app": "fiqhMedia",
        "service": "Backend API",
        "version": "1.0.0",
        "status": "online",
        "message": (
            "Only verified religious material "
            "can be published."
        ),
    }


# ======================================================
# HEALTH CHECK
# ======================================================


@app.get("/health")
def health():
    try:
        with SessionLocal() as db:
            db.execute(select(func.count(Madhhab.id))).scalar()

        return {
            "status": "healthy",
            "database": "connected",
        }

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        )


# ======================================================
# LIST MADHHABS
# ======================================================


@app.get("/madhhabs")
def get_madhhabs():
    with SessionLocal() as db:
        items = db.scalars(
            select(Madhhab).order_by(Madhhab.id)
        ).all()

        return [
            {
                "code": item.code,
                "name": item.name,
            }
            for item in items
        ]


# ======================================================
# AUTHORS
# ======================================================


@app.get("/authors")
def get_authors(
    limit: int = Query(default=30, ge=1, le=100),
):
    with SessionLocal() as db:
        stmt = (
            select(Author)
            .where(Author.verified.is_(True))
            .order_by(Author.id)
            .limit(limit)
        )

        authors = db.scalars(stmt).all()

        return [author_data(a) for a in authors]


@app.get("/authors/{author_id}")
def get_author(author_id: int):
    with SessionLocal() as db:
        author = db.get(Author, author_id)

        if author is None or not author.verified:
            raise HTTPException(
                status_code=404,
                detail="Verified author not found",
            )

        return author_data(author)


# ======================================================
# BOOKS - MADHHAB IS REQUIRED
# ======================================================


@app.get("/books")
def get_books(
    madhhab: str = Query(...),
    limit: int = Query(default=30, ge=1, le=100),
):
    validate_madhhab(madhhab)

    with SessionLocal() as db:
        stmt = (
            select(Book)
            .join(Author, Book.author_id == Author.id)
            .where(
                Book.madhhab_code == madhhab,
                Book.verified.is_(True),
                Author.verified.is_(True),
            )
            .order_by(Book.id)
            .limit(limit)
        )

        books = db.scalars(stmt).all()

        return [book_data(b) for b in books]


# ======================================================
# VERIFIED ARTICLES BY MADHHAB
# ======================================================


@app.get("/articles")
def get_articles(
    madhhab: str = Query(...),
    limit: int = Query(default=30, ge=1, le=100),
):
    validate_madhhab(madhhab)

    with SessionLocal() as db:
        stmt = (
            select(Article)
            .join(Book, Article.book_id == Book.id)
            .join(Author, Book.author_id == Author.id)
            .where(
                Article.madhhab_code == madhhab,
                Book.madhhab_code == madhhab,
                Article.verified.is_(True),
                Book.verified.is_(True),
                Author.verified.is_(True),
            )
            .order_by(Article.id)
            .limit(limit)
        )

        results = db.scalars(stmt).all()

        return [article_data(a) for a in results]


# ======================================================
# SEARCH - NO MADHHAB MIXING
# ======================================================


@app.get("/search")
def search_articles(
    madhhab: str = Query(...),
    q: str = Query(..., min_length=2, max_length=200),
    limit: int = Query(default=20, ge=1, le=100),
):
    validate_madhhab(madhhab)

    phrase = q.strip()

    if len(phrase) < 2:
        raise HTTPException(
            status_code=400,
            detail="Search query is too short",
        )

    # Escape LIKE wildcard characters so the
    # user's query is treated as text.
    safe_phrase = (
        phrase.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )

    pattern = f"%{safe_phrase}%"

    with SessionLocal() as db:
        stmt = (
            select(Article)
            .join(Book, Article.book_id == Book.id)
            .join(Author, Book.author_id == Author.id)
            .where(
                Article.madhhab_code == madhhab,
                Book.madhhab_code == madhhab,
                Article.verified.is_(True),
                Book.verified.is_(True),
                Author.verified.is_(True),
                or_(
                    Article.title.ilike(
                        pattern, escape="\\"
                    ),
                    Article.category.ilike(
                        pattern, escape="\\"
                    ),
                    Article.content.ilike(
                        pattern, escape="\\"
                    ),
                ),
            )
            .order_by(Article.id)
            .limit(limit)
        )

        results = db.scalars(stmt).all()

        return {
            "madhhab": madhhab,
            "query": phrase,
            "count": len(results),
            "results": [
                article_data(a) for a in results
            ],
        }


# ======================================================
# SINGLE ARTICLE
# ======================================================


@app.get("/articles/{article_id}")
def get_article(article_id: int):
    with SessionLocal() as db:
        stmt = (
            select(Article)
            .join(Book, Article.book_id == Book.id)
            .join(Author, Book.author_id == Author.id)
            .where(
                Article.id == article_id,
                Article.verified.is_(True),
                Book.verified.is_(True),
                Author.verified.is_(True),
                Article.madhhab_code == Book.madhhab_code,
            )
        )

        article = db.scalar(stmt)

        if article is None:
            raise HTTPException(
                status_code=404,
                detail="Verified article not found",
            )

        return article_data(article)


# ======================================================
# RUN SERVER
# ======================================================


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
    )
