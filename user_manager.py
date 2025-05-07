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
from datetime import datetime


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
        """
        Create a new user account.
        
        Args:
            username: Unique username
            email: Valid email address
            password: User password (should meet password requirements)
            role: User role (default: "user")
            
        Returns:
            User object if successful, error message string if failed
        """
        # TODO: Validar si el usuario existe? NO -> "Username already exists"
        
        # TODO: Validar el correo? NO -> "Invalid email format"
        
        # Verificar que la contraseña es fuerte!
        password_check = self._check_password_strength(password)
        if password_check != "ok":
            return password_check
            
        # TODO: Validar el Rol del usuario, debe ser: user, admin, guest - NO -> "Invalid role"
            
        # Crear un usuario y almacenarlo
        new_user = User(username=username, email=email, password=password, role=role)
        self.users[username] = new_user
        return new_user
    
    def get_user(self, username: str) -> Optional[User]:
        """
        Retrieve a user by username.
        
        Args:
            username: The username to look up
            
        Returns:
            User object if found, None otherwise
        """
        return self.users.get(username)
    
    def update_user(self, username: str, **kwargs) -> Union[User, str]:
        """
        Update user information.
        
        Args:
            username: The username of the user to update
            **kwargs: Fields to update (email, password, is_active, role)
            
        Returns:
            Updated User object if successful, error message string if failed
        """
        user = self.get_user(username)
        # TODO: Si el usuario no existe -> "User not found"
            
        if "email" in kwargs and kwargs["email"] != user.email:
            if not self._is_valid_email(kwargs["email"]):
                return "Invalid email format"
            user.email = kwargs["email"]
            
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
        """
        Delete a user account.
        
        Args:
            username: The username of the user to delete
            
        Returns:
            True if user was deleted, False if user was not found
        """
        # TODO: Eliminar el usuario
        pass
    
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
        
        # TODO: Si no es un usuario -> "Invalid username or password"
            
        # TODO: Si el usuario no está activo -> "Account is inactive"
        
        # TODO: Si la contraseña no es la correcta -> "Invalid username or password"
            
        # Update last login time
        user.last_login = datetime.now()
        return user
    
    def list_users(self, active_only: bool = False) -> List[User]:
        """
        List all users.
        
        Args:
            active_only: If True, only return active users
            
        Returns:
            List of User objects
        """
        # TODO: Listas todos los usuarios activos
        pass
    
    def _is_valid_email(self, email: str) -> bool:
        """
        Validate email format.
        
        Args:
            email: Email to validate
            
        Returns:
            True if valid, False otherwise
        """
        # TODO: Verifica que sea un correo válido! usando una expresión regular
        pass
    
    def _check_password_strength(self, password: str) -> str:
        """
        Check password strength.
        
        Args:
            password: Password to check
            
        Returns:
            "ok" if password is strong enough, error message otherwise
        """
        # TODO: "Password must be at least 8 characters long"
            
        # TODO: "Password must contain at least one uppercase letter"
            
        # TODO: "Password must contain at least one lowercase letter"
            
        # TODO: "Password must contain at least one digit"
            
        return "ok"

