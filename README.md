ejemplos de pruebas con pytest

# Mejores Prácticas `pytest`

Este proyecto demuestra las mejores prácticas para realizar pruebas de código Python usando [pytest](https://docs.pytest.org/). Utiliza la clase `UserManager` para realizar pruebas exhaustivas que muestran las características de `pytest`.

## Estructura del Proyecto

```
pytest_demo/
├── README.md               # este archivo
├── requirements.txt        # listado de dependencias del proyecto
├── user_manager.py         # módulo principal que se está probando
├── conftest.py             # configuración global de pytest y sus facilitadores (fixtures)
└── test_user_manager.py    # contiene las pruebas de pytest
```

## Instalación

1. Crea un ambiente virtual:

   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Instalación de dependencias:
   ```
   pip install -r requirements.txt
   ```

## Ejecución de las Pruebas

Ejecutar el conjunto de pruebas básico:
```
pytest
```

Ejecutar con salida detallada (_verbose_):
```
pytest -v
```

Ejecutar con la captura de salida deshabilitada:
```
pytest -s
```

Ejecutar incluyendo pruebas lentas:
```
pytest --run-slow
```

Ejecutar una prueba específica:
```
pytest test_user_manager.py::TestUserCreation::test_create_valid_user
```

Ejecutar pruebas que coincidan con un patrón:
```
pytest -k "email"
```

Generar informe de cobertura:
```
pytest --cov=user_manager
```

Generar informe de cobertura HTML:
```
pytest --cov=user_manager --cov-report=html
```

## Caracteristicas clave de pytest incluidas:

1. **Test Organization**: Las pruebas se organizan en clases por funcionalidad.
2. **Fixtures**: Diversos ámbitos de _fixtures_ (función, módulo, sesión).
3. **parameterized Testing**: Prueba de múltiples entradas con `@pytest.mark.parametrize`.
4. **Mocking**: Uso de `unittest.mock` para simular dependencias.
5. **Test Markers**: Marcadores personalizados para categorizar pruebas.
6. **Error Handling**: Prueba de cómo el código gestiona las excepciones.
7. **Edge Cases**: Prueba de condiciones límite.
8. **Performance Testing**: Pruebas de rendimiento básicas con temporización.
9. **Skipping Tests**: Omisión condicional de pruebas.
10. **Expected Failures**: Marcado de pruebas que se espera que fallen.
11. **Dependency Injection**: _Fixtures_ que dependen de otros _fixtures_.
12. **Setup/Teardown Patterns**: Uso de _fixtures_ para la gestión de recursos.
13. **Test Hooks**: Personalización. Recopilación y ejecución de pruebas
14. **Test Configuration**: Opciones y configuración personalizadas de la línea de comandos

## Mejores prácticas de Pruebas utilizadas

1. **Isolation**: Cada prueba está aislada, es independiente y no depende del estado de otras pruebas.
2. **Specific Assertions**: Las pruebas hacen afirmaciones específicas sobre los resultados esperados.
3. **Test Coverage**: Las pruebas cubren casos normales, casos extremos y condiciones de error.
4. **Code Organization**: Las pruebas están bien organizadas y siguen un patrón consistente.
5. **Descriptive Names**: Las funciones de prueba tienen nombres claros y descriptivos.
6. **Setup/Teardown**: Los recursos se configuran y depuran correctamente.
7. **Parameterization**: Los casos de prueba similares se parametrizan para evitar repeticiones.
8. **Documentation**: Las pruebas están bien documentadas con cadenas de documentación.
9. **Mocking**: Las dependencias externas se simulan cuando corresponde.
10. **Fixtures**: El código de configuración común se traslada a los _fixtures_.

## Pasos de la Práctica

1. Empieza por comprender el módulo `user_manager.py` y su funcionalidad.
2. Examina las pruebas básicas en `test_user_manager.py` que verifican la funcionalidad principal.
3. Analiza pruebas más avanzadas que utilizan parametrización, accesorios y simulaciones.
4. Estudia el archivo `conftest.py` para comprender los accesorios globales y la configuración.
5. Experimenta añadiendo dos (2) funciones nuevas a `user_manager.py` y escribe las pruebas para ellas.
6. Intenta ejecutar pruebas con diferentes opciones de `pytest` para ver cómo afectan la salida.

