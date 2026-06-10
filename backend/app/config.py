"""Environment-aware configuration for AETHER."""

import os
from dataclasses import dataclass


@dataclass
class DatabaseConfig:
    """PostgreSQL database configuration."""
    url: str
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 1800


@dataclass
class RedisConfig:
    """Redis configuration for caching and rate limiting."""
    url: str = "redis://localhost:6379/0"
    max_connections: int = 20


@dataclass
class JWTConfig:
    """JWT token configuration."""
    secret: str
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7


@dataclass
class SMTPConfig:
    """SMTP email configuration."""
    host: str = "smtp.gmail.com"
    port: int = 587
    user: str = ""
    password: str = ""
    from_address: str = "AETHER <noreply@aether.local>"
    use_tls: bool = True


@dataclass
class OAuthConfig:
    """OAuth provider configuration."""
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/api/v1/auth/google/callback"
    github_client_id: str = ""
    github_client_secret: str = ""
    github_redirect_uri: str = "http://localhost:8000/api/v1/auth/github/callback"


@dataclass
class AppConfig:
    """Main application configuration."""
    environment: str = "development"
    debug: bool = False
    frontend_url: str = "http://localhost:8080"
    api_url: str = "http://localhost:8000"
    port: int = 8000
    web_concurrency: int = 2
    
    database: DatabaseConfig = None
    redis: RedisConfig = None
    jwt: JWTConfig = None
    smtp: SMTPConfig = None
    oauth: OAuthConfig = None
    
    def __post_init__(self):
        """Initialize sub-configurations from environment variables."""
        if self.database is None:
            self.database = DatabaseConfig(
                url=os.getenv("DATABASE_URL", "postgresql://aether:aether_dev_password@localhost:5432/aether"),
                pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
                max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
            )
        
        if self.redis is None:
            self.redis = RedisConfig(
                url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            )
        
        if self.jwt is None:
            self.jwt = JWTConfig(
                secret=os.getenv("AETHER_JWT_SECRET", "dev_secret_change_in_production"),
                access_token_expire_minutes=int(os.getenv("JWT_ACCESS_EXPIRE_MINUTES", "60")),
                refresh_token_expire_days=int(os.getenv("JWT_REFRESH_EXPIRE_DAYS", "7")),
            )
        
        if self.smtp is None:
            self.smtp = SMTPConfig(
                host=os.getenv("SMTP_HOST", "smtp.gmail.com"),
                port=int(os.getenv("SMTP_PORT", "587")),
                user=os.getenv("SMTP_USER", ""),
                password=os.getenv("SMTP_PASSWORD", ""),
                from_address=os.getenv("SMTP_FROM", "AETHER <noreply@aether.local>"),
            )
        
        if self.oauth is None:
            self.oauth = OAuthConfig(
                google_client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
                google_client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
                google_redirect_uri=os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/v1/auth/google/callback"),
                github_client_id=os.getenv("GITHUB_CLIENT_ID", ""),
                github_client_secret=os.getenv("GITHUB_CLIENT_SECRET", ""),
                github_redirect_uri=os.getenv("GITHUB_REDIRECT_URI", "http://localhost:8000/api/v1/auth/github/callback"),
            )


def get_config() -> AppConfig:
    """Get application configuration based on environment."""
    environment = os.getenv("ENVIRONMENT", "development")
    
    config = AppConfig(
        environment=environment,
        debug=environment == "development",
        frontend_url=os.getenv("FRONTEND_URL", "http://localhost:8080"),
        api_url=os.getenv("AETHER_PUBLIC_API_URL", "http://localhost:8000"),
        port=int(os.getenv("PORT", "8000")),
        web_concurrency=int(os.getenv("WEB_CONCURRENCY", "2")),
    )
    
    # Production-specific overrides
    if environment == "production":
        config.debug = False
        config.database.pool_size = int(os.getenv("DB_POOL_SIZE", "20"))
        config.database.max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "20"))
        config.jwt.access_token_expire_minutes = int(os.getenv("JWT_ACCESS_EXPIRE_MINUTES", "30"))
    
    return config


# Global config instance
config = get_config()
