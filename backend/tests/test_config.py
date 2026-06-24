import os
import unittest
from unittest.mock import patch

from app.config import (
    DatabaseConfig,
    RedisConfig,
    JWTConfig,
    SMTPConfig,
    OAuthConfig,
    AppConfig,
    get_config,
)


class TestDatabaseConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = DatabaseConfig(url="postgresql://localhost/test")
        self.assertEqual(cfg.url, "postgresql://localhost/test")
        self.assertEqual(cfg.pool_size, 5)
        self.assertEqual(cfg.max_overflow, 10)
        self.assertEqual(cfg.pool_timeout, 30)
        self.assertEqual(cfg.pool_recycle, 1800)

    def test_custom_overrides(self):
        cfg = DatabaseConfig(url="pg://x", pool_size=20, max_overflow=5)
        self.assertEqual(cfg.pool_size, 20)
        self.assertEqual(cfg.max_overflow, 5)


class TestRedisConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = RedisConfig()
        self.assertEqual(cfg.url, "redis://localhost:6379/0")
        self.assertEqual(cfg.max_connections, 20)

    def test_custom_url(self):
        cfg = RedisConfig(url="redis://prod:6379")
        self.assertEqual(cfg.url, "redis://prod:6379")


class TestJWTConfig(unittest.TestCase):
    def test_fields(self):
        cfg = JWTConfig(secret="my-secret")
        self.assertEqual(cfg.secret, "my-secret")
        self.assertEqual(cfg.access_token_expire_minutes, 60)
        self.assertEqual(cfg.refresh_token_expire_days, 7)


class TestSMTPConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = SMTPConfig()
        self.assertEqual(cfg.host, "smtp.gmail.com")
        self.assertEqual(cfg.port, 587)
        self.assertTrue(cfg.use_tls)


class TestOAuthConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = OAuthConfig()
        self.assertEqual(cfg.google_client_id, "")
        self.assertIn("google/callback", cfg.google_redirect_uri)
        self.assertIn("github/callback", cfg.github_redirect_uri)


class TestAppConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = AppConfig()
        self.assertEqual(cfg.environment, "development")
        self.assertFalse(cfg.debug)
        self.assertEqual(cfg.port, 8000)

    def test_post_init_creates_sub_configs(self):
        cfg = AppConfig()
        self.assertIsInstance(cfg.database, DatabaseConfig)
        self.assertIsInstance(cfg.redis, RedisConfig)
        self.assertIsInstance(cfg.jwt, JWTConfig)
        self.assertIsInstance(cfg.smtp, SMTPConfig)
        self.assertIsInstance(cfg.oauth, OAuthConfig)

    @patch.dict(os.environ, {"DATABASE_URL": "postgresql://test-db/test"})
    def test_post_init_reads_env(self):
        cfg = AppConfig()
        self.assertEqual(cfg.database.url, "postgresql://test-db/test")

    @patch.dict(os.environ, {"AETHER_JWT_SECRET": "production-secret"})
    def test_jwt_from_env(self):
        cfg = AppConfig()
        self.assertEqual(cfg.jwt.secret, "production-secret")

    @patch.dict(os.environ, {"REDIS_URL": "redis://prod:6379"})
    def test_redis_from_env(self):
        cfg = AppConfig()
        self.assertEqual(cfg.redis.url, "redis://prod:6379")


class TestGetConfig(unittest.TestCase):
    @patch.dict(os.environ, {"ENVIRONMENT": "development"}, clear=False)
    def test_development(self):
        cfg = get_config()
        self.assertEqual(cfg.environment, "development")
        self.assertTrue(cfg.debug)

    @patch.dict(os.environ, {"ENVIRONMENT": "production"}, clear=False)
    def test_production(self):
        cfg = get_config()
        self.assertEqual(cfg.environment, "production")
        self.assertFalse(cfg.debug)
        self.assertEqual(cfg.database.pool_size, 20)

    @patch.dict(os.environ, {"PORT": "9000"}, clear=False)
    def test_custom_port(self):
        cfg = get_config()
        self.assertEqual(cfg.port, 9000)


if __name__ == "__main__":
    unittest.main()
