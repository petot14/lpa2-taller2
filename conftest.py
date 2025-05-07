"""
Archivo de configuración de pruebas de pytest

Este archivo contiene los Fixtures (facilitadores) y plugins para todas las pruebas.
"""

import pytest
from datetime import datetime


# Define pytest hooks and configuration

def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--run-slow", 
        action="store_true", 
        default=False, 
        help="run slow tests"
    )


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "slow: mark test as slow to run")


def pytest_collection_modifyitems(config, items):
    """Skip slow tests unless --run-slow is specified."""
    if not config.getoption("--run-slow"):
        skip_slow = pytest.mark.skip(reason="need --run-slow option to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)


# Define fixtures available to all test modules

@pytest.fixture(scope="session")
def global_timestamp():
    """
    A session-scoped fixture that provides a timestamp.
    
    This fixture is created once for the entire test session.
    """
    return datetime.now()


@pytest.fixture(scope="session", autouse=True)
def test_suite_setup_teardown():
    """
    Session-scoped fixture that runs automatically to set up and tear down 
    the entire test suite.
    """
    # Setup
    print("\n------------ TEST SUITE STARTING ------------")
    
    yield  # This is where the testing happens
    
    # Teardown
    print("\n------------ TEST SUITE COMPLETE ------------")


@pytest.fixture(autouse=True)
def function_setup_teardown():
    """
    Function-scoped fixture that runs automatically before and after each test.
    This can be used for common setup/teardown operations.
    """
    # Setup
    start_time = datetime.now()
    
    yield  # This is where the test function runs
    
    # Teardown
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    print(f"\nTest duration: {duration:.6f} seconds")

