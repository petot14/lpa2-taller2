"""
Pruebas unitarias para la clase UserManager.

"""

import pytest
import re

from datetime import datetime , timedelta
from unittest.mock import patch, MagicMock
from user_manager import UserManager, User

@pytest.fixture
def user_manager():
    """Retorna una instancia nueva de UserManager por prueba."""
    return UserManager()


@pytest.fixture
def populated_user_manager():
    """Retorna una instancia de UserManager con usuarios predefinidos."""
    manager = UserManager()

    manager.create_user("testuser", "test@example.com", "Password123")
    manager.create_user("admin", "admin@example.com", "AdminPass123", role="admin")
    inactive = manager.create_user("inactive", "inactive@example.com", "Inactive123")
    manager.update_user("inactive", is_active=False)

>>>>>>> a49405b (commit f)
    return manager


@pytest.fixture(scope="module")
def module_user_manager():
<<<<<<< HEAD
    """
    A module-scoped fixture that creates the UserManager only once for the entire module.
    This demonstrates different fixture scopes.
    """
    print("\nCreating module-scoped UserManager")
    manager = UserManager()
    yield manager
    print("\nCleaning up module-scoped UserManager")


# ---- TEST CLASSES ----

class TestUserCreation:
    """Tests for user creation functionality."""
    
    def test_create_valid_user(self, user_manager):
        """Test creating a valid user with default role."""
        user = user_manager.create_user(
            username="alice", 
            email="alice@example.com", 
            password="SecurePass123"
        )
        
        assert isinstance(user, User)
        assert user.username == "alice"
        assert user.email == "alice@example.com"
        assert user.password == "SecurePass123"
        assert user.role == "user"
        assert user.is_active is True
        assert isinstance(user.created_at, datetime)
        assert user.last_login is None
        
    def test_create_user_with_role(self, user_manager):
        """Test creating a user with a specific role."""
        user = user_manager.create_user(
            username="bob", 
            email="bob@example.com", 
            password="SecurePass123", 
            role="admin"
        )
        
        assert isinstance(user, User)
        assert user.role == "admin"
        
    def test_create_duplicate_user(self, user_manager):
        """Test creating a user with an existing username."""
        # Create the first user
        user_manager.create_user(
            username="charlie", 
            email="charlie@example.com", 
            password="SecurePass123"
        )
        
        # Try to create another user with the same username
        result = user_manager.create_user(
            username="charlie", 
            email="different@example.com", 
            password="DifferentPass123"
        )
        
        assert result == "Username already exists"
        assert len(user_manager.users) == 1
        
    @pytest.mark.parametrize("invalid_email", [
        "invalid_email",
        "user@",
        "@domain.com",
        "user@domain",
        "",
        None
    ])
    def test_create_user_invalid_email(self, user_manager, invalid_email):
        """Test creating a user with various invalid email formats."""
        result = user_manager.create_user(
            username="test_user", 
            email=invalid_email, 
            password="SecurePass123"
        )
        
        assert result == "Invalid email format"
        assert len(user_manager.users) == 0
        
    @pytest.mark.parametrize("password, expected_message", [
=======
    """Fixture con alcance de módulo (una vez por módulo)."""
    print("\nCreando UserManager de módulo")
    manager = UserManager()
    yield manager
    print("\nLimpiando UserManager de módulo")


# --------------------
# PRUEBAS DE CREACIÓN
# --------------------

class TestUserCreation:

    def test_crear_usuario_valido(self, user_manager):
        user = user_manager.create_user("alice", "alice@example.com", "SecurePass123")
        assert isinstance(user, User)
        assert user.username == "alice"
        assert user.email == "alice@example.com"
        assert user.role == "user"
        assert user.is_active is True
        assert user.last_login is None
        assert isinstance(user.created_at, datetime)

    def test_crear_usuario_con_rol(self, user_manager):
        user = user_manager.create_user("bob", "bob@example.com", "SecurePass123", role="admin")
        assert user.role == "admin"

    def test_usuario_duplicado(self, user_manager):
        user_manager.create_user("charlie", "charlie@example.com", "SecurePass123")
        result = user_manager.create_user("charlie", "other@example.com", "OtherPass123")
        assert result == "Username already exists"
        assert len(user_manager.users) == 1

    @pytest.mark.parametrize("email_invalido", [
        "invalid_email", "user@", "@domain.com", "user@domain", "", None
    ])
    def test_crear_usuario_con_email_invalido(self, user_manager, email_invalido):
        result = user_manager.create_user("test_user", email_invalido, "SecurePass123")
        assert result == "Invalid email format"
        assert len(user_manager.users) == 0

    @pytest.mark.parametrize("password, esperado", [
>>>>>>> a49405b (commit f)
        ("short", "Password must be at least 8 characters long"),
        ("lowercase123", "Password must contain at least one uppercase letter"),
        ("UPPERCASE123", "Password must contain at least one lowercase letter"),
        ("NoDigitsHere", "Password must contain at least one digit"),
        ("Valid123", "ok")
    ])
<<<<<<< HEAD
    def test_password_strength_validation(self, user_manager, password, expected_message):
        """Test password strength validation with various passwords."""
        if expected_message == "ok":
            user = user_manager.create_user(
                username="test_user", 
                email="valid@example.com", 
                password=password
            )
            assert isinstance(user, User)
        else:
            result = user_manager.create_user(
                username="test_user", 
                email="valid@example.com", 
                password=password
            )
            assert result == expected_message
            
    def test_create_user_invalid_role(self, user_manager):
        """Test creating a user with an invalid role."""
        result = user_manager.create_user(
            username="test_user", 
            email="valid@example.com", 
            password="SecurePass123", 
            role="superuser"  # Not a valid role
        )
        
=======
    def test_validacion_de_password(self, user_manager, password, esperado):
        if esperado == "ok":
            user = user_manager.create_user("test_user", "valid@example.com", password)
            assert isinstance(user, User)
        else:
            result = user_manager.create_user("test_user", "valid@example.com", password)
            assert result == esperado

    def test_crear_usuario_con_rol_invalido(self, user_manager):
        result = user_manager.create_user("test_user", "valid@example.com", "SecurePass123", role="superuser")
>>>>>>> a49405b (commit f)
        assert result == "Invalid role"
        assert len(user_manager.users) == 0


<<<<<<< HEAD
class TestUserRetrieval:
    """Tests for user retrieval functionality."""
    
    def test_get_existing_user(self, populated_user_manager):
        """Test retrieving an existing user."""
        user = populated_user_manager.get_user("testuser")
        
        assert user is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        
    def test_get_nonexistent_user(self, populated_user_manager):
        """Test retrieving a user that doesn't exist."""
        user = populated_user_manager.get_user("nonexistent")
        
        assert user is None
        
    def test_list_all_users(self, populated_user_manager):
        """Test listing all users."""
        users = populated_user_manager.list_users()
        
        assert len(users) == 3
        usernames = [user.username for user in users]
        assert set(usernames) == {"testuser", "admin", "inactive"}
        
    def test_list_active_users(self, populated_user_manager):
        """Test listing only active users."""
        users = populated_user_manager.list_users(active_only=True)
        
        assert len(users) == 2
        usernames = [user.username for user in users]
        assert set(usernames) == {"testuser", "admin"}
        assert "inactive" not in usernames


class TestUserAuthentication:
    """Tests for user authentication functionality."""
    
    def test_successful_authentication(self, populated_user_manager):
        """Test successful user authentication."""
        result = populated_user_manager.authenticate("testuser", "Password123")
        
        assert isinstance(result, User)
        assert result.username == "testuser"
        assert result.last_login is not None  # Last login timestamp should be updated
        
    def test_nonexistent_user_authentication(self, populated_user_manager):
        """Test authentication with a nonexistent username."""
        result = populated_user_manager.authenticate("nonexistent", "Password123")
        
        assert result == "Invalid username or password"
        
    def test_wrong_password_authentication(self, populated_user_manager):
        """Test authentication with an incorrect password."""
        result = populated_user_manager.authenticate("testuser", "WrongPassword")
        
        assert result == "Invalid username or password"
        
    def test_inactive_user_authentication(self, populated_user_manager):
        """Test authentication with an inactive user account."""
        result = populated_user_manager.authenticate("inactive", "Inactive123")
        
        assert result == "Account is inactive"


class TestUserUpdates:
    """Tests for user update functionality."""
    
    def test_update_email(self, populated_user_manager):
        """Test updating a user's email."""
        result = populated_user_manager.update_user(
            "testuser", 
            email="newemail@example.com"
        )
        
        assert isinstance(result, User)
        assert result.email == "newemail@example.com"
        
        # Verify the update persisted
        user = populated_user_manager.get_user("testuser")
        assert user.email == "newemail@example.com"
        
    def test_update_nonexistent_user(self, populated_user_manager):
        """Test updating a nonexistent user."""
        result = populated_user_manager.update_user(
            "nonexistent", 
            email="newemail@example.com"
        )
        
        assert result == "User not found"
        
    def test_update_invalid_email(self, populated_user_manager):
        """Test updating a user with an invalid email."""
        result = populated_user_manager.update_user(
            "testuser", 
            email="invalid_email"
        )
        
        assert result == "Invalid email format"
        
        # Verify the email didn't change
        user = populated_user_manager.get_user("testuser")
        assert user.email == "test@example.com"
        
    def test_update_password(self, populated_user_manager):
        """Test updating a user's password."""
        result = populated_user_manager.update_user(
            "testuser", 
            password="NewSecurePass123"
        )
        
        assert isinstance(result, User)
        
        # Verify authentication works with the new password
        auth_result = populated_user_manager.authenticate("testuser", "NewSecurePass123")
        assert isinstance(auth_result, User)
        
    def test_update_weak_password(self, populated_user_manager):
        """Test updating a user with a weak password."""
        result = populated_user_manager.update_user(
            "testuser", 
            password="weak"
        )
        
        assert result == "Password must be at least 8 characters long"
        
    def test_update_multiple_fields(self, populated_user_manager):
        """Test updating multiple user fields at once."""
        result = populated_user_manager.update_user(
            "testuser", 
            email="updated@example.com",
            password="UpdatedPass123",
            is_active=False,
            role="admin"
        )
        
        assert isinstance(result, User)
        assert result.email == "updated@example.com"
        assert result.password == "UpdatedPass123"
=======
# --------------------
# PRUEBAS DE RECUPERACIÓN
# --------------------

class TestUserRetrieval:

    def test_recuperar_usuario_existente(self, populated_user_manager):
        user = populated_user_manager.get_user("testuser")
        assert user is not None
        assert user.username == "testuser"

    def test_recuperar_usuario_inexistente(self, populated_user_manager):
        user = populated_user_manager.get_user("ghost")
        assert user is None

    def test_listar_todos_los_usuarios(self, populated_user_manager):
        users = populated_user_manager.list_users()
        assert len(users) == 3
        assert {"testuser", "admin", "inactive"} == {u.username for u in users}

    def test_listar_usuarios_activos(self, populated_user_manager):
        users = populated_user_manager.list_users(active_only=True)
        assert len(users) == 2
        assert "inactive" not in [u.username for u in users]


# --------------------
# PRUEBAS DE AUTENTICACIÓN
# --------------------

class TestUserAuthentication:

    def test_autenticacion_exitosa(self, populated_user_manager):
        user = populated_user_manager.authenticate("testuser", "Password123")
        assert isinstance(user, User)
        assert user.last_login is not None

    def test_autenticacion_usuario_inexistente(self, populated_user_manager):
        result = populated_user_manager.authenticate("ghost", "password")
        assert result == "Invalid username or password"

    def test_autenticacion_contraseña_incorrecta(self, populated_user_manager):
        result = populated_user_manager.authenticate("testuser", "wrongpass")
        assert result == "Invalid username or password"

    def test_autenticacion_usuario_inactivo(self, populated_user_manager):
        result = populated_user_manager.authenticate("inactive", "Inactive123")
        assert result == "Account is inactive"


# --------------------
# PRUEBAS DE ACTUALIZACIÓN
# --------------------

class TestUserUpdates:

    def test_actualizar_email(self, populated_user_manager):
        result = populated_user_manager.update_user("testuser", email="nuevo@example.com")
        assert isinstance(result, User)
        assert result.email == "nuevo@example.com"

    def test_actualizar_usuario_inexistente(self, populated_user_manager):
        result = populated_user_manager.update_user("ghost", email="x@example.com")
        assert result == "User not found"

    def test_actualizar_email_invalido(self, populated_user_manager):
        result = populated_user_manager.update_user("testuser", email="correo")
        assert result == "Invalid email format"

    def test_actualizar_password_valido(self, populated_user_manager):
        result = populated_user_manager.update_user("testuser", password="NuevaPass123")
        assert isinstance(result, User)
        auth = populated_user_manager.authenticate("testuser", "NuevaPass123")
        assert isinstance(auth, User)

    def test_actualizar_password_debil(self, populated_user_manager):
        result = populated_user_manager.update_user("testuser", password="123")
        assert result == "Password must be at least 8 characters long"

    def test_actualizar_campos_multiples(self, populated_user_manager):
        result = populated_user_manager.update_user(
            "testuser", email="x@x.com", password="StrongPass123", is_active=False, role="admin"
        )
        assert isinstance(result, User)
        assert result.email == "x@x.com"
>>>>>>> a49405b (commit f)
        assert result.is_active is False
        assert result.role == "admin"


<<<<<<< HEAD
class TestUserDeletion:
    """Tests for user deletion functionality."""
    
    def test_delete_existing_user(self, populated_user_manager):
        """Test deleting an existing user."""
        initial_count = len(populated_user_manager.users)
        result = populated_user_manager.delete_user("testuser")
        
        assert result is True
        assert len(populated_user_manager.users) == initial_count - 1
        assert populated_user_manager.get_user("testuser") is None
        
    def test_delete_nonexistent_user(self, populated_user_manager):
        """Test deleting a nonexistent user."""
        initial_count = len(populated_user_manager.users)
        result = populated_user_manager.delete_user("nonexistent")
        
        assert result is False
        assert len(populated_user_manager.users) == initial_count


# ---- SPECIALIZED TEST TECHNIQUES ----

class TestWithPatching:
    """Tests demonstrating mocking and patching."""
    
    @patch('user_manager.datetime')
    def test_user_creation_timestamp(self, mock_datetime, user_manager):
        """Test that user creation uses the current timestamp."""
        # Setup the mock
        mock_now = datetime(2023, 1, 1, 12, 0, 0)
        mock_datetime.now.return_value = mock_now
        
        # Create a user
        user = user_manager.create_user(
            username="timestamp_test", 
            email="time@example.com", 
            password="TimePass123"
        )
        
        # Verify the timestamp was set correctly
        assert user.created_at == mock_now
        assert mock_datetime.now.called
        
    def test_email_validation_with_regex_mock(self, user_manager):
        """Test email validation by mocking the regex function."""
        with patch('re.match') as mock_match:
            # Force regex to always return False (invalid email)
            mock_match.return_value = None
            
            result = user_manager.create_user(
                username="email_test", 
                email="valid@example.com",  # This would normally be valid
                password="ValidPass123"
            )
            
=======
# --------------------
# PRUEBAS DE ELIMINACIÓN
# --------------------

class TestUserDeletion:

    def test_eliminar_usuario_existente(self, populated_user_manager):
        cantidad = len(populated_user_manager.users)
        result = populated_user_manager.delete_user("testuser")
        assert result is True
        assert len(populated_user_manager.users) == cantidad - 1

    def test_eliminar_usuario_inexistente(self, populated_user_manager):
        cantidad = len(populated_user_manager.users)
        result = populated_user_manager.delete_user("ghost")
        assert result is False
        assert len(populated_user_manager.users) == cantidad


# --------------------
# PRUEBAS CON MOCKS
# --------------------

class TestWithPatching:

    @patch("user_manager.datetime")
    def test_timestamp_creacion_usuario(self, mock_datetime, user_manager):
        mock_now = datetime(2023, 1, 1, 12, 0, 0)
        mock_datetime.now.return_value = mock_now
        user = user_manager.create_user("fecha", "fecha@example.com", "TimePass123")
        assert user.created_at == mock_now
        assert mock_datetime.now.called

    def test_mock_regex_email_invalido(self, user_manager):
        with patch("re.match", return_value=None) as mock_match:
            result = user_manager.create_user("regex", "valido@example.com", "Password123")
>>>>>>> a49405b (commit f)
            assert result == "Invalid email format"
            mock_match.assert_called_once()


<<<<<<< HEAD
# ---- BOUNDARY AND EDGE CASES ----

@pytest.mark.parametrize("test_input, expected", [
    # Extreme values
    ("a" * 100 + "@example.com", True),  # Very long local part
    ("user@" + "a" * 100 + ".com", True),  # Very long domain
    
    # Special characters
    ("user+tag@example.com", True),       # + in local part
    ("user.name@example.com", True),      # . in local part
    ("user-name@example.com", True),      # - in local part
    ("user_name@example.com", True),      # _ in local part
    ("user@sub.domain.com", True),        # Multiple subdomains
    
    # Invalid formats
    ("user@domain@example.com", False),   # Multiple @ signs
    (".user@example.com", False),         # Leading dot in local part
    ("user.@example.com", False),         # Trailing dot in local part
    ("user..name@example.com", False),    # Consecutive dots
])
def test_email_validator_edge_cases(user_manager, test_input, expected):
    """Test email validation with various edge cases."""
    # Use the actual implementation but intercept the result
    is_valid = user_manager._is_valid_email(test_input)
    assert is_valid == expected


# ---- ERROR HANDLING TESTS ----

def test_exception_handling():
    """Test how the code handles unexpected exceptions."""
    manager = UserManager()
    
    # Create a mock that raises an exception when used
    with patch('re.match', side_effect=Exception("Simulated error")):
        # The method should handle the exception gracefully
=======
# --------------------
# CASOS LÍMITE DE EMAIL
# --------------------

@pytest.mark.parametrize("email, valido", [
    ("a" * 100 + "@example.com", True),
    ("user@" + "a" * 100 + ".com", True),
    ("user+tag@example.com", True),
    ("user.name@example.com", True),
    ("user-name@example.com", True),
    ("user_name@example.com", True),
    ("user@sub.domain.com", True),
    ("user@domain@example.com", False),
    (".user@example.com", False),
    ("user.@example.com", False),
    ("user..name@example.com", False)
])
def test_email_edge_cases(user_manager, email, valido):
    assert user_manager._is_valid_email(email) == valido


# --------------------
# MANEJO DE EXCEPCIONES
# --------------------

def test_manejo_de_excepciones():
    manager = UserManager()
    with patch("re.match", side_effect=Exception("Simulado")):
>>>>>>> a49405b (commit f)
        with pytest.raises(Exception):
            manager._is_valid_email("test@example.com")


<<<<<<< HEAD
# ---- DYNAMIC TEST GENERATION ----

def get_test_cases():
    """Generate test cases dynamically."""
    test_cases = []
    # Generate a series of test cases with increasing password lengths
    for i in range(5, 12):
        password = "A" + "a" * (i-2) + "1"
        expected = "ok" if i >= 8 else "Password must be at least 8 characters long"
        test_cases.append((password, expected))
    return test_cases

@pytest.mark.parametrize("password, expected", get_test_cases())
def test_dynamic_password_validation(user_manager, password, expected):
    """Test password validation with dynamically generated test cases."""
    result = user_manager._check_password_strength(password)
    assert result == expected


# ---- TEST WITH SETUP/TEARDOWN ----

@pytest.fixture
def db_connection():
    """
    A fixture that simulates database setup and teardown.
    This demonstrates the classic setup/teardown pattern.
    """
    # Setup
    print("\nSetting up test database connection")
    conn = MagicMock()
    conn.is_connected.return_value = True
    
    # Provide the resource to the test
    yield conn
    
    # Teardown
    print("\nClosing test database connection")
    conn.close()


def test_with_db_connection_fixture(db_connection):
    """Test using a fixture with setup and teardown."""
    assert db_connection.is_connected()
    # Perform some operations with the connection
=======
# --------------------
# PRUEBA DINÁMICA
# --------------------

def generar_passwords():
    cases = []
    for i in range(5, 12):
        pwd = "A" + "a" * (i - 2) + "1"
        expected = "ok" if i >= 8 else "Password must be at least 8 characters long"
        cases.append((pwd, expected))
    return cases

@pytest.mark.parametrize("password, esperado", generar_passwords())
def test_password_dinamico(user_manager, password, esperado):
    result = user_manager._check_password_strength(password)
    assert result == esperado


# --------------------
# SETUP Y TEARDOWN
# --------------------

@pytest.fixture
def db_connection():
    print("\nConectando a base de datos ficticia")
    conn = MagicMock()
    conn.is_connected.return_value = True
    yield conn
    print("\nCerrando conexión ficticia")
    conn.close()

def test_conexion_base_datos(db_connection):
    assert db_connection.is_connected()
>>>>>>> a49405b (commit f)
    db_connection.execute("SELECT * FROM users")
    assert db_connection.execute.called


<<<<<<< HEAD
# ---- PERFORMANCE TESTS ----

@pytest.mark.slow
def test_performance_large_user_list():
    """Test performance with a large number of users."""
    import time
    
    manager = UserManager()
    
    # Create many users
    start_time = time.time()
    for i in range(100):
        username = f"user{i}"
        email = f"user{i}@example.com"
        password = f"Password{i}123"
        manager.create_user(username, email, password)
    
    creation_time = time.time() - start_time
    
    # Test listing users performance
    start_time = time.time()
    all_users = manager.list_users()
    listing_time = time.time() - start_time
    
    # No strict assertions, but print performance metrics
    print(f"\nTime to create 100 users: {creation_time:.4f} seconds")
    print(f"Time to list 100 users: {listing_time:.4f} seconds")
    
    assert len(all_users) == 100
    assert creation_time < 1.0, "User creation should be reasonably fast"
    assert listing_time < 0.1, "User listing should be very fast"


# ---- TEST SKIPPING AND MARKING ----

@pytest.mark.skip(reason="Demonstration of skipping a test")
def test_skipped():
    """This test will be skipped."""
    assert False, "This test should never run"


@pytest.mark.skipif(
    datetime.now().weekday() >= 5,
    reason="Skip on weekends for demonstration"
)
def test_weekday_only():
    """This test runs only on weekdays."""
    assert datetime.now().weekday() < 5


@pytest.mark.xfail(reason="This test is expected to fail for demonstration")
def test_expected_failure():
    """This test is expected to fail."""
    assert 1 == 2, "This should fail"


# ---- CLEANUP TESTS ----

@pytest.fixture
def resource_with_context():
    """A fixture using context manager protocol for cleanup."""
    # Setup
    print("\nAcquiring resource")
    resource = MagicMock()
    
    try:
        yield resource
    finally:
        # Cleanup always runs
        print("\nReleasing resource")
        resource.release()


def test_with_resource_cleanup(resource_with_context):
    """Test using a resource that needs cleanup."""
    # Use the resource
    resource_with_context.use()
    assert resource_with_context.use.called
    
    # Even if the test fails, cleanup will run
    assert True


# ---- TEST FIXTURES DEPENDENCY INJECTION ----

@pytest.fixture
def first_fixture():
    """First fixture that returns a value."""
    return 10


@pytest.fixture
def second_fixture(first_fixture):
    """Second fixture that depends on the first fixture."""
    return first_fixture + 5


def test_fixture_dependency_injection(second_fixture):
    """Test using a fixture that depends on another fixture."""
    # second_fixture should be 15 (10 + 5)
    assert second_fixture == 15

=======
# --------------------
# PRUEBAS DE RENDIMIENTO
# --------------------

@pytest.mark.slow
def test_performance_usuarios():
    import time
    manager = UserManager()
    start = time.time()
    for i in range(100):
        manager.create_user(f"user{i}", f"user{i}@test.com", f"Password{i}123")
    tiempo_creacion = time.time() - start

    start = time.time()
    users = manager.list_users()
    tiempo_listado = time.time() - start

    print(f"\nCrear 100 usuarios: {tiempo_creacion:.4f}s")
    print(f"Listar usuarios: {tiempo_listado:.4f}s")

    assert len(users) == 100
    assert tiempo_creacion < 1.0
    assert tiempo_listado < 0.1


# --------------------
# SKIPS Y EXPECTED FAILURES
# --------------------

@pytest.mark.skip(reason="Ejemplo de test omitido")
def test_omitido():
    assert False

@pytest.mark.skipif(datetime.now().weekday() >= 5, reason="Se omite en fines de semana")
def test_dia_laboral():
    assert datetime.now().weekday() < 5

@pytest.mark.xfail(reason="Demostración de fallo esperado")
def test_fallo_esperado():
    assert 1 == 2


# --------------------
# LIMPIEZA CON CONTEXTOS
# --------------------

@pytest.fixture
def recurso_contexto():
    print("\nAdquiriendo recurso")
    recurso = MagicMock()
    yield recurso
    print("\nLiberando recurso")
    recurso.release()

def test_recurso_con_contexto(recurso_contexto):
    recurso_contexto.use()
    assert recurso_contexto.use.called


# --------------------
# FIXTURES DEPENDIENTES
# --------------------

@pytest.fixture
def primer_fixture():
    return 10

@pytest.fixture
def segundo_fixture(primer_fixture):
    return primer_fixture + 5

def test_dependencia_fixtures(segundo_fixture):
    assert segundo_fixture == 15
class TestUserManagerNewFunctions:

    def test_deactivate_inactive_users(self, populated_user_manager):
        # Activa a todos los usuarios para testear
        for u in populated_user_manager.users.values():
            u.is_active = True
            u.last_login = datetime.now() - timedelta(days=10)

        # Desactiva usuarios que no hayan iniciado sesión en los últimos 5 días
        desactivados = populated_user_manager.deactivate_inactive_users(5)

        assert desactivados == len(populated_user_manager.users)
        for user in populated_user_manager.users.values():
            assert user.is_active is False

        # Si llamamos otra vez, no desactiva nada porque ya están inactivos
        desactivados_2 = populated_user_manager.deactivate_inactive_users(5)
        assert desactivados_2 == 0

    def test_get_users_by_role(self, populated_user_manager):
        admins = populated_user_manager.get_users_by_role("admin")
        users = populated_user_manager.get_users_by_role("user")
        no_role = populated_user_manager.get_users_by_role("nonexistent")

        assert all(user.role == "admin" for user in admins)
        assert all(user.role == "user" for user in users)
        assert no_role == []
>>>>>>> a49405b (commit f)
