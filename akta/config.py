from pydantic_settings import BaseSettings, SettingsConfigDict, PydanticBaseSettingsSource, YamlConfigSettingsSource
from pydantic import Field
from typing import Tuple, Type
from pathlib import Path

"""
Manages application settings using Pydantic Settings.

This module defines the `Settings` class, which loads configuration from environment variables,
.env files, and a YAML configuration file (`config.yaml` at the project root).
It provides a single `settings` instance for easy access to configuration values throughout the application.
"""

class Settings(BaseSettings):
    """
    Application settings model.

    Defines all configurable parameters for the application, their default values, and validation rules.
    Settings are loaded from multiple sources with a defined priority (see `settings_customise_sources`).
    """
    # Server settings
    host: str = Field(default="0.0.0.0", description="Host to bind the FastAPI server to.")
    port: int = Field(default=8000, description="Port to bind the FastAPI server to.")
    reload: bool = Field(default=False, description="Enable auto-reload for the FastAPI server (for development). Uvicorn's --reload flag.")

    # Application metadata
    app_name: str = Field(default="My CLI-Server App", description="Application name, used for logging and potentially other display purposes.")

    # Operational settings
    debug: bool = Field(default=False, description="Enable debug mode. This might affect logging verbosity and FastAPI debug features.")
    log_level: str = Field(default="INFO", description="Logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL).")
    log_format: str = Field(
        default="json",
        description="Log format. Supported values: 'json' for structured JSON logs, 'text' for plain text logs."
    )

    # Database settings (example, can be expanded)
    database_url: str = Field(
        default="sqlite:///./orbit.db",
        description="Database connection URL. Example: 'postgresql://user:pass@host:port/dbname' or 'sqlite:///./app.db'."
    )

    model_config = SettingsConfigDict(
        env_prefix="APP_", # Prefix for environment variables (e.g., APP_HOST, APP_PORT)
        extra="ignore",    # Ignore extra fields from sources rather than raising an error
        validate_default=True, # Validate default values as well
        # Define the path to the YAML configuration file relative to this config.py file
        # Path(__file__) is src/config.py
        # .parent is src/
        # .parent.parent is the project root (assuming config.py is in src/)
        # Corrected path: parent.parent to go up two levels from src/ to project root for config.yaml
        yaml_file=Path(__file__).resolve().parent.parent / "config.yaml"
    )


    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        """
        Customizes the priority of settings sources for Pydantic.

        The order defines the override precedence (later sources override earlier ones):
        1. `init_settings`: Values provided during `Settings` class initialization (highest priority).
        2. `env_settings`: Environment variables (e.g., `APP_HOST`).
        3. `dotenv_settings`: Variables loaded from a `.env` file.
        4. `YamlConfigSettingsSource`: Variables loaded from the `config.yaml` file specified in `model_config`.
        5. `file_secret_settings`: Settings loaded from files typically used for secrets (e.g., Docker secrets).

        Returns:
            A tuple of settings sources in the desired order of precedence.
        """
        return (
            init_settings,         # Highest priority: direct initialization
            env_settings,          # Next: environment variables
            dotenv_settings,       # Next: .env file
            YamlConfigSettingsSource(settings_cls), # Next: YAML config file
            file_secret_settings,  # Lowest priority: file secrets
        )


# Instantiate a single shared Settings object for use across the application
# This object will be populated based on the sources defined above.
settings = Settings()


