"""
Database Schemas for Steadily.me

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercased class name (e.g., Habit -> "habit").
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional

class User(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password_hash: str = Field(..., description="BCrypt password hash")
    name: Optional[str] = Field(None, description="Display name")

class Habit(BaseModel):
    user_id: str = Field(..., description="Owner user id (stringified ObjectId)")
    name: str = Field(..., min_length=1, max_length=100)
    color: str = Field("from-emerald-500 to-green-500", description="Tailwind gradient e.g., 'from-rose-500 to-pink-500'")
    weekly_goal: int = Field(3, ge=1, le=7)

class Completion(BaseModel):
    user_id: str = Field(..., description="Owner user id")
    habit_id: str = Field(..., description="Habit id (stringified ObjectId)")
    date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$", description="YYYY-MM-DD")
