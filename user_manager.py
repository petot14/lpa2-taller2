"""
User Manager Module

Este módulo proporciona la funcionalidad para la gestión de cuentas de usuario:
- Creación, Actualización y Eliminación de cuentas de usuario
- Autenticación
- Validación de contraseña
"""

import re
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from datetime import datetime, timedelta



@dataclass
class User:
    """User data class representing a user account."""
    username: str
    email: str
    password: str  # In a real system, this would be hashed
    created_at: datetime = None
    is_active: bool = True
    last_login: datetime = None
    role: str = "user"  # Options: "user", "admin", "guest"

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()


class UserManager:
    """Class for managing user accounts."""
    def __init__(self):
        self.users: Dict[str, User] = {}

    def create_user(self, username: str, email: str, password: str, role: str = "user") -> Union[User, str]:
        if username in self.users:
            return "Username already exists"

        if not self._is_valid_email(email):
            return "Invalid email format"

        if role not in ["user", "admin", "guest"]:
            return "Invalid role"

        password_check = self._check_password_strength(password)
        if password_check != "ok":
            return password_check

        new_user = User(username=username, email=email, password=password, role=role)
        self.users[username] = new_user
        return new_user

    def get_user(self, username: str) -> Optional[User]:
        return self.users.get(username)

    def update_user(self, username: str, **kwargs) -> Union[User, str]:
        user = self.get_user(username)
        if user is None:
            return "User not found"

        if "email" in kwargs and kwargs["email"] != user.email:
            if not self._is_valid_email(kwargs["email"]):
                return "Invalid email format"

        if "password" in kwargs:
            password_check = self._check_password_strength(kwargs["password"])
            if password_check != "ok":
                return password_check
            user.password = kwargs["password"]


        if "is_active" in kwargs:
            user.is_active = bool(kwargs["is_active"])

        if "role" in kwargs:
            if kwargs["role"] not in ["user", "admin", "guest"]:
                return "Invalid role"
            user.role = kwargs["role"]

        return user

    def delete_user(self, username: str) -> bool:
        if username in self.users:
            del self.users[username]
            return True
        return False
    
    def authenticate(self, username: str, password: str) -> Union[User, str]:
        """
        Authenticate a user.
        
        Args:
            username: The username to authenticate
            password: The password to check
            
        Returns:
            User object if authentication successful, error message string if failed
        """
        user = self.get_user(username)
        if not user or user.password != password:
            return "Invalid username or password"

        if not user.is_active:
            return "Account is inactive"

        user.last_login = datetime.now()
        return user

    def list_users(self, active_only: bool = False) -> List[User]:
        if active_only:
            return [user for user in self.users.values() if user.is_active]
        return list(self.users.values())

    def _is_valid_email(self, email: str) -> bool:
        if email is None:
            return False
        pattern = (
            r"^(?!.*\.\.)"           # no permitir dos puntos seguidos
            r"[A-Za-z0-9]+"
            r"([._+-][A-Za-z0-9]+)*" # permite ., _, +, - pero no repetidos consecutivos
            r"@"
            r"[A-Za-z0-9-]+"
            r"(\.[A-Za-z0-9-]+)*"
            r"\.[A-Za-z]{2,}$"
        )
        return re.match(pattern, email) is not None

    def _check_password_strength(self, password: str) -> str:
        if len(password) < 8:
            return "Password must be at least 8 characters long"
        if not re.search(r"[A-Z]", password):
            return "Password must contain at least one uppercase letter"
        if not re.search(r"[a-z]", password):
            return "Password must contain at least one lowercase letter"
        if not re.search(r"\d", password):
            return "Password must contain at least one digit"
        return "ok"

    def deactivate_inactive_users(self, days: int) -> int:
        cutoff = datetime.now() - timedelta(days=days)
        count = 0
        for user in self.users.values():
            if user.last_login is None or user.last_login < cutoff:
                if user.is_active:
                    user.is_active = False
                    count += 1
        return count

    def get_users_by_role(self, role: str) -> List[User]:
        return [user for user in self.users.values() if user.role == role]

