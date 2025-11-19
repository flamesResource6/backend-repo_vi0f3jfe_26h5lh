import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db

# App setup
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth/JWT setup
SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Utilities
class TokenOut(BaseModel):
    token: str

class UserOut(BaseModel):
    id: str
    email: EmailStr
    name: Optional[str] = None

class CredentialsIn(BaseModel):
    email: EmailStr
    password: str

class RegisterIn(CredentialsIn):
    name: Optional[str] = None

class HabitIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    color: str = Field("from-emerald-500 to-green-500")
    weekly_goal: int = Field(3, ge=1, le=7)

class HabitUpdate(BaseModel):
    name: Optional[str] = None
    color: Optional[str] = None
    weekly_goal: Optional[int] = Field(None, ge=1, le=7)

class HabitOut(BaseModel):
    id: str
    name: str
    color: str
    weekly_goal: int

class CompletionToggle(BaseModel):
    habit_id: str
    date: str  # YYYY-MM-DD

class CompletionOut(BaseModel):
    habit_id: str
    date: str


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@app.get("/")
def read_root():
    return {"message": "Steadily.me backend running"}

@app.get("/api/version")
def version():
    return {"version": os.getenv("APP_VERSION", "0.1.0")}

# Auth endpoints
@app.post("/api/auth/register", response_model=TokenOut)
def register(body: RegisterIn):
    existing = db["user"].find_one({"email": body.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "email": body.email.lower(),
        "password_hash": get_password_hash(body.password),
        "name": body.name or None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(user_doc)
    token = create_access_token({"sub": str(res.inserted_id)})
    return {"token": token}

@app.post("/api/auth/login", response_model=TokenOut)
def login(body: CredentialsIn):
    user = db["user"].find_one({"email": body.email.lower()})
    if not user or not verify_password(body.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(user["_id"])})
    return {"token": token}

@app.post("/api/auth/google")
def google_auth():
    raise HTTPException(status_code=501, detail="Google auth not implemented yet")

@app.post("/api/auth/forgot-password")
def forgot_password(email: EmailStr):
    # Stub endpoint for now
    return {"message": "Password reset link sent if account exists"}

@app.get("/api/me", response_model=UserOut)
async def me(user=Depends(get_current_user)):
    return {"id": str(user["_id"]), "email": user["email"], "name": user.get("name")}


# Habits CRUD
@app.get("/api/habits", response_model=List[HabitOut])
async def get_habits(user=Depends(get_current_user)):
    items = []
    cursor = db["habit"].find({"user_id": str(user["_id"])})
    for h in cursor:
        items.append({
            "id": str(h["_id"]),
            "name": h["name"],
            "color": h.get("color", "from-emerald-500 to-green-500"),
            "weekly_goal": int(h.get("weekly_goal", 3)),
        })
    return items

@app.post("/api/habits", response_model=HabitOut)
async def create_habit(body: HabitIn, user=Depends(get_current_user)):
    doc = {
        "user_id": str(user["_id"]),
        "name": body.name,
        "color": body.color,
        "weekly_goal": body.weekly_goal,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["habit"].insert_one(doc)
    return {"id": str(res.inserted_id), "name": body.name, "color": body.color, "weekly_goal": body.weekly_goal}

@app.put("/api/habits/{habit_id}", response_model=HabitOut)
async def update_habit(habit_id: str, body: HabitUpdate, user=Depends(get_current_user)):
    h = db["habit"].find_one({"_id": ObjectId(habit_id), "user_id": str(user["_id"])})
    if not h:
        raise HTTPException(status_code=404, detail="Habit not found")
    updates = {k: v for k, v in body.model_dump(exclude_unset=True).items()}
    if not updates:
        updates = {}
    updates["updated_at"] = datetime.now(timezone.utc)
    db["habit"].update_one({"_id": ObjectId(habit_id)}, {"$set": updates})
    h = db["habit"].find_one({"_id": ObjectId(habit_id)})
    return {"id": habit_id, "name": h["name"], "color": h.get("color", "from-emerald-500 to-green-500"), "weekly_goal": int(h.get("weekly_goal", 3))}

@app.delete("/api/habits/{habit_id}")
async def delete_habit(habit_id: str, user=Depends(get_current_user)):
    db["habit"].delete_one({"_id": ObjectId(habit_id), "user_id": str(user["_id"])})
    # Also remove completions
    db["completion"].delete_many({"habit_id": habit_id, "user_id": str(user["_id"])})
    return {"ok": True}


# Completions
@app.get("/api/completions", response_model=List[CompletionOut])
async def get_completions(start: str, end: str, user=Depends(get_current_user)):
    cursor = db["completion"].find({
        "user_id": str(user["_id"]),
        "date": {"$gte": start, "$lte": end},
    })
    out: List[CompletionOut] = []
    for c in cursor:
        out.append({"habit_id": c["habit_id"], "date": c["date"]})
    return out

@app.post("/api/completions")
async def toggle_completion(body: CompletionToggle, user=Depends(get_current_user)):
    # Ensure habit belongs to user
    h = db["habit"].find_one({"_id": ObjectId(body.habit_id), "user_id": str(user["_id"])})
    if not h:
        raise HTTPException(status_code=404, detail="Habit not found")
    existing = db["completion"].find_one({
        "user_id": str(user["_id"]),
        "habit_id": body.habit_id,
        "date": body.date,
    })
    if existing:
        db["completion"].delete_one({"_id": existing["_id"]})
        return {"status": "removed"}
    else:
        db["completion"].insert_one({
            "user_id": str(user["_id"]),
            "habit_id": body.habit_id,
            "date": body.date,
            "created_at": datetime.now(timezone.utc),
        })
        return {"status": "added"}


# Health/test
@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = getattr(db, 'name', '✅ Connected')
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
