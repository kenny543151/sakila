from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import List
import os
from dotenv import load_dotenv
from fastapi.staticfiles import StaticFiles

# Load .env variables
load_dotenv()

# FastAPI app
app = FastAPI(title="Sakila DVD Rental API")

# Serve static files for favicon and others
app.mount("/static", StaticFiles(directory="static"), name="static")

# Environment variables
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# Database connection
engine = create_engine(DATABASE_URL)
Base = declarative_base()

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Helpers
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Pydantic models
class Film(BaseModel):
    film_id: int
    title: str
    rental_rate: float
    release_year: int

class Customer(BaseModel):
    customer_id: int
    first_name: str
    last_name: str
    email: str
    address_id: int

class Rental(BaseModel):
    rental_id: int
    customer_id: int
    film_id: int
    rental_date: datetime

class Token(BaseModel):
    access_token: str
    token_type: str

# Dependency
def get_db():
    db = Session(bind=engine)
    try:
        yield db
    finally:
        db.close()

# JWT
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username

# Root Endpoint
@app.get("/")
async def read_root():
    return {"message": "Welcome to the Sakila DVD Rental API"}

# Auth Endpoints
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    query = text("SELECT * FROM staff WHERE username = :username")
    result = db.execute(query, {"username": form_data.username}).mappings().fetchone()

    if not result or not verify_password(form_data.password, result["password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    token = create_access_token(data={"sub": form_data.username})
    return {"access_token": token, "token_type": "bearer"}

@app.delete("/token")
async def revoke_token(current_user: str = Depends(get_current_user)):
    return {"message": "Token revoked successfully"}

# Film Endpoints
@app.get("/films/", response_model=List[Film])
async def get_films(db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    query = text("SELECT film_id, title, rental_rate, release_year FROM film LIMIT 100")
    return [Film(**dict(row)) for row in db.execute(query).mappings().all()]

@app.get("/films/by_category/{category_id}", response_model=List[Film])
async def get_films_by_category(category_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    query = text("""
        SELECT f.film_id, f.title, f.rental_rate, f.release_year
        FROM film f
        JOIN film_category fc ON f.film_id = fc.film_id
        WHERE fc.category_id = :category_id
    """)
    result = db.execute(query, {"category_id": category_id}).mappings().all()
    if not result:
        raise HTTPException(status_code=404, detail="No films found for this category")
    return [Film(**row) for row in result]

# Customer Endpoints
@app.get("/customers/active/{store_id}", response_model=List[Customer])
async def get_active_customers(store_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    query = text("""
        SELECT customer_id, first_name, last_name, email, address_id
        FROM customer
        WHERE store_id = :store_id AND active = 1
    """)
    result = db.execute(query, {"store_id": store_id}).mappings().all()
    if not result:
        raise HTTPException(status_code=404, detail="No active customers found")
    return [Customer(**row) for row in result]

@app.post("/customers/", response_model=Customer)
async def create_customer(customer: Customer, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    query = text("""
        INSERT INTO customer (store_id, first_name, last_name, email, address_id, active)
        VALUES (1, :first_name, :last_name, :email, :address_id, 1)
    """)
    try:
        db.execute(query, customer.dict())
        db.commit()
        return customer
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@app.put("/customers/{customer_id}", response_model=Customer)
async def update_customer(customer_id: int, customer: Customer, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    query = text("""
        UPDATE customer
        SET first_name = :first_name, last_name = :last_name, email = :email, address_id = :address_id
        WHERE customer_id = :customer_id
    """)
    try:
        result = db.execute(query, {**customer.dict(), "customer_id": customer_id})
        db.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Customer not found")
        return customer
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/customers/{customer_id}")
async def delete_customer(customer_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    query = text("UPDATE customer SET active = 0 WHERE customer_id = :customer_id")
    try:
        result = db.execute(query, {"customer_id": customer_id})
        db.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Customer not found")
        return {"message": "Customer deactivated successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

# Rental Deletion
@app.delete("/rentals/{rental_id}")
async def delete_rental(rental_id: int, db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    query = text("DELETE FROM rental WHERE rental_id = :rental_id")
    try:
        result = db.execute(query, {"rental_id": rental_id})
        db.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Rental not found")
        return {"message": "Rental deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
