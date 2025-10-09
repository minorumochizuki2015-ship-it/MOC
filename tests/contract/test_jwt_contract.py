#!/usr/bin/env python3
"""
Contract tests for JWT authentication
Ensures token-based authentication reliability across different scenarios
"""

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
import pytest

from src.security import SecurityManager, UserRole


class TestJWTContract:
    """Contract tests for JWT authentication"""

    @pytest.fixture
    def security_manager(self, test_config):
        """Create SecurityManager instance for testing"""
        return SecurityManager(test_config)

    @pytest.fixture
    def jwt_secret(self, test_config):
        """Get JWT secret from config"""
        return test_config["jwt"]["secret_key"]

    @pytest.fixture
    def test_user_data(self):
        """Test user data for JWT creation"""
        return {
            "user_id": "test-user-123",
            "username": "testuser",
            "email": "test@example.com",
            "role": UserRole.OPERATOR,
        }

    @pytest.mark.contract
    def test_valid_jwt_token_accepted(self, security_manager, test_user_data):
        """Contract: Valid JWT token should be accepted and decoded correctly"""
        # Arrange
        token = security_manager.create_jwt_token(
            user_id=test_user_data["user_id"],
            username=test_user_data["username"],
            email=test_user_data["email"],
            role=test_user_data["role"],
        )

        # Act
        user = security_manager.verify_jwt_token(token)

        # Assert
        assert user is not None, "Valid JWT token should be accepted"
        assert user.user_id == test_user_data["user_id"], "User ID should match"
        assert user.username == test_user_data["username"], "Username should match"
        assert user.email == test_user_data["email"], "Email should match"
        assert user.role == test_user_data["role"], "Role should match"

    @pytest.mark.contract
    def test_expired_jwt_token_rejected(self, security_manager, jwt_secret, test_user_data):
        """Contract: Expired JWT token should be rejected"""
        # Arrange
        # Create token that expired 1 hour ago
        expired_payload = {
            "user_id": test_user_data["user_id"],
            "username": test_user_data["username"],
            "email": test_user_data["email"],
            "role": test_user_data["role"].value,
            "exp": datetime.utcnow() - timedelta(hours=1),
            "iat": datetime.utcnow() - timedelta(hours=2),
        }

        expired_token = jwt.encode(expired_payload, jwt_secret, algorithm="HS256")

        # Act
        user = security_manager.verify_jwt_token(expired_token)

        # Assert
        assert user is None, "Expired JWT token should be rejected"

    @pytest.mark.contract
    def test_invalid_signature_rejected(self, security_manager, test_user_data):
        """Contract: JWT with invalid signature should be rejected"""
        # Arrange
        # Create token with wrong secret
        wrong_secret = "wrong-secret-key"
        payload = {
            "user_id": test_user_data["user_id"],
            "username": test_user_data["username"],
            "email": test_user_data["email"],
            "role": test_user_data["role"].value,
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow(),
        }

        invalid_token = jwt.encode(payload, wrong_secret, algorithm="HS256")

        # Act
        user = security_manager.verify_jwt_token(invalid_token)

        # Assert
        assert user is None, "JWT with invalid signature should be rejected"

    @pytest.mark.contract
    def test_malformed_jwt_token_rejected(self, security_manager):
        """Contract: Malformed JWT tokens should be rejected"""
        # Arrange
        malformed_tokens = [
            "invalid.token.format",
            "not-a-jwt-token",
            "header.payload",  # Missing signature
            "header.payload.signature.extra",  # Too many parts
            "",  # Empty string
            None,  # None value
            "Bearer invalid",  # With Bearer prefix (short placeholder to avoid secret scanner)
        ]

        for malformed_token in malformed_tokens:
            # Act
            user = security_manager.verify_jwt_token(malformed_token)

            # Assert
            assert user is None, f"Malformed token '{malformed_token}' should be rejected"

    @pytest.mark.contract
    def test_jwt_token_without_required_claims_rejected(self, security_manager, jwt_secret):
        """Contract: JWT tokens missing required claims should be rejected"""
        # Arrange
        incomplete_payloads = [
            # Missing user_id
            {
                "username": "testuser",
                "email": "test@example.com",
                "role": UserRole.OPERATOR.value,
                "exp": datetime.utcnow() + timedelta(hours=1),
            },
            # Missing username
            {
                "user_id": "test-user-123",
                "email": "test@example.com",
                "role": UserRole.OPERATOR.value,
                "exp": datetime.utcnow() + timedelta(hours=1),
            },
            # Missing role
            {
                "user_id": "test-user-123",
                "username": "testuser",
                "email": "test@example.com",
                "exp": datetime.utcnow() + timedelta(hours=1),
            },
            # Missing exp
            {
                "user_id": "test-user-123",
                "username": "testuser",
                "email": "test@example.com",
                "role": UserRole.OPERATOR.value,
            },
        ]

        for payload in incomplete_payloads:
            # Arrange
            token = jwt.encode(payload, jwt_secret, algorithm="HS256")

            # Act
            user = security_manager.verify_jwt_token(token)

            # Assert
            assert user is None, f"Token with incomplete payload should be rejected: {payload}"

    @pytest.mark.contract
    def test_jwt_token_with_invalid_role_rejected(
        self, security_manager, jwt_secret, test_user_data
    ):
        """Contract: JWT tokens with invalid roles should be rejected"""
        # Arrange
        invalid_roles = [
            "invalid_role",
            "SUPER_ADMIN",  # Non-existent role
            123,  # Non-string role
            None,  # None role
            "",  # Empty role
        ]

        for invalid_role in invalid_roles:
            payload = {
                "user_id": test_user_data["user_id"],
                "username": test_user_data["username"],
                "email": test_user_data["email"],
                "role": invalid_role,
                "exp": datetime.utcnow() + timedelta(hours=1),
                "iat": datetime.utcnow(),
            }

            token = jwt.encode(payload, jwt_secret, algorithm="HS256")

            # Act
            user = security_manager.verify_jwt_token(token)

            # Assert
            assert user is None, f"Token with invalid role '{invalid_role}' should be rejected"

    @pytest.mark.contract
    def test_jwt_token_algorithm_validation(
        self, security_manager, jwt_secret, test_user_data, jwt_rsa_private_key
    ):
        """Contract: Only HS256 algorithm should be accepted"""
        # Arrange
        payload = {
            "user_id": test_user_data["user_id"],
            "username": test_user_data["username"],
            "email": test_user_data["email"],
            "role": test_user_data["role"].value,
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow(),
        }

        # Test different algorithms
        algorithms_and_expected = [
            ("HS256", True),  # Should be accepted
            ("HS512", False),  # Should be rejected
            ("RS256", False),  # Should be rejected
            ("none", False),  # Should be rejected
        ]

        for algorithm, should_accept in algorithms_and_expected:
            if algorithm == "none":
                # Special case for 'none' algorithm
                token = jwt.encode(payload, "", algorithm="none")
            elif algorithm == "RS256":
                # Use test RSA private key for RS256 token generation
                token = jwt.encode(payload, jwt_rsa_private_key, algorithm="RS256")
            else:
                token = jwt.encode(payload, jwt_secret, algorithm=algorithm)

            # Act
            user = security_manager.verify_jwt_token(token)

            # Assert
            if should_accept:
                assert user is not None, f"Token with {algorithm} algorithm should be accepted"
            else:
                assert user is None, f"Token with {algorithm} algorithm should be rejected"

    @pytest.mark.contract
    def test_jwt_token_issued_at_validation(self, security_manager, jwt_secret, test_user_data):
        """Contract: JWT tokens with future 'iat' claim should be rejected"""
        # Arrange
        future_iat_payload = {
            "user_id": test_user_data["user_id"],
            "username": test_user_data["username"],
            "email": test_user_data["email"],
            "role": test_user_data["role"].value,
            "exp": datetime.utcnow() + timedelta(hours=2),
            "iat": datetime.utcnow() + timedelta(hours=1),  # Future issued at
        }

        token = jwt.encode(future_iat_payload, jwt_secret, algorithm="HS256")

        # Act
        user = security_manager.verify_jwt_token(token)

        # Assert
        assert user is None, "Token with future 'iat' claim should be rejected"

    @pytest.mark.contract
    def test_jwt_token_refresh_behavior(self, security_manager, test_user_data):
        """Contract: JWT tokens should maintain consistent user data across refresh"""
        # Arrange
        original_token = security_manager.create_jwt_token(
            user_id=test_user_data["user_id"],
            username=test_user_data["username"],
            email=test_user_data["email"],
            role=test_user_data["role"],
        )

        # Verify original token
        original_user = security_manager.verify_jwt_token(original_token)

        # Create new token for same user
        new_token = security_manager.create_jwt_token(
            user_id=test_user_data["user_id"],
            username=test_user_data["username"],
            email=test_user_data["email"],
            role=test_user_data["role"],
        )

        new_user = security_manager.verify_jwt_token(new_token)

        # Assert
        assert original_user is not None, "Original token should be valid"
        assert new_user is not None, "New token should be valid"
        assert original_user.user_id == new_user.user_id, "User ID should be consistent"
        assert original_user.username == new_user.username, "Username should be consistent"
        assert original_user.email == new_user.email, "Email should be consistent"
        assert original_user.role == new_user.role, "Role should be consistent"

    @pytest.mark.contract
    def test_jwt_token_role_hierarchy(self, security_manager):
        """Contract: Different user roles should be handled correctly"""
        # Arrange
        roles_to_test = [UserRole.VIEWER, UserRole.OPERATOR, UserRole.ADMIN]

        for role in roles_to_test:
            # Create token for each role
            token = security_manager.create_jwt_token(
                user_id=f"user-{role.value}",
                username=f"user_{role.value}",
                email=f"{role.value}@example.com",
                role=role,
            )

            # Act
            user = security_manager.verify_jwt_token(token)

            # Assert
            assert user is not None, f"Token for role {role.value} should be valid"
            assert user.role == role, f"Role should be preserved as {role.value}"

    @pytest.mark.contract
    def test_jwt_token_special_characters_handling(self, security_manager):
        """Contract: JWT tokens should handle special characters in user data"""
        # Arrange
        special_user_data = {
            "user_id": "user-123-äöü",
            "username": "test_user@domain.com",
            "email": "test+tag@example-domain.co.uk",
            "role": UserRole.OPERATOR,
        }

        # Act
        token = security_manager.create_jwt_token(
            user_id=special_user_data["user_id"],
            username=special_user_data["username"],
            email=special_user_data["email"],
            role=special_user_data["role"],
        )

        user = security_manager.verify_jwt_token(token)

        # Assert
        assert user is not None, "Token with special characters should be valid"
        assert (
            user.user_id == special_user_data["user_id"]
        ), "Special characters in user_id should be preserved"
        assert (
            user.username == special_user_data["username"]
        ), "Special characters in username should be preserved"
        assert (
            user.email == special_user_data["email"]
        ), "Special characters in email should be preserved"

    @pytest.mark.contract
    @pytest.mark.performance
    def test_jwt_verification_performance(self, security_manager, test_user_data, benchmark):
        """Contract: JWT verification should complete within performance limits"""
        # Arrange
        token = security_manager.create_jwt_token(
            user_id=test_user_data["user_id"],
            username=test_user_data["username"],
            email=test_user_data["email"],
            role=test_user_data["role"],
        )

        # Act & Assert
        user = benchmark(security_manager.verify_jwt_token, token)

        assert user is not None, "JWT verification should succeed"
        # Performance assertion is handled by benchmark fixture

    @pytest.mark.contract
    def test_concurrent_jwt_verification(self, security_manager, test_user_data):
        """Contract: JWT verification should be thread-safe"""
        import concurrent.futures

        # Arrange
        token = security_manager.create_jwt_token(
            user_id=test_user_data["user_id"],
            username=test_user_data["username"],
            email=test_user_data["email"],
            role=test_user_data["role"],
        )

        results = []
        errors = []

        def verify_token():
            try:
                user = security_manager.verify_jwt_token(token)
                results.append(user)
            except Exception as e:
                errors.append(e)

        # Act
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(verify_token) for _ in range(50)]
            concurrent.futures.wait(futures)

        # Assert
        assert len(errors) == 0, f"No errors should occur during concurrent verification: {errors}"
        assert len(results) == 50, "All verifications should complete"
        assert all(user is not None for user in results), "All verifications should succeed"
        assert all(
            user.user_id == test_user_data["user_id"] for user in results
        ), "All results should have correct user_id"

    @pytest.mark.contract
    def test_jwt_token_revocation_simulation(self, security_manager, test_user_data):
        """Contract: Simulate token revocation by changing secret"""
        # Arrange
        token = security_manager.create_jwt_token(
            user_id=test_user_data["user_id"],
            username=test_user_data["username"],
            email=test_user_data["email"],
            role=test_user_data["role"],
        )

        # Verify token is initially valid
        user = security_manager.verify_jwt_token(token)
        assert user is not None, "Token should be initially valid"

        # Simulate secret rotation (in real implementation, this would be done through config update)
        # For testing, we'll create a new security manager with different secret
        revoked_config = security_manager.config.copy()
        revoked_config["jwt"]["secret_key"] = "new-secret-after-revocation"
        revoked_security_manager = SecurityManager(revoked_config)

        # Act
        revoked_user = revoked_security_manager.verify_jwt_token(token)

        # Assert
        assert revoked_user is None, "Token should be invalid after secret rotation"

    @pytest.mark.contract
    def test_jwt_token_time_skew_tolerance(self, security_manager, jwt_secret, test_user_data):
        """Contract: JWT tokens should handle reasonable time skew"""
        # Arrange
        # Create token with slight time skew (30 seconds in the past)
        past_time = datetime.utcnow() - timedelta(seconds=30)

        payload = {
            "user_id": test_user_data["user_id"],
            "username": test_user_data["username"],
            "email": test_user_data["email"],
            "role": test_user_data["role"].value,
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": past_time,
        }

        token = jwt.encode(payload, jwt_secret, algorithm="HS256")

        # Act
        user = security_manager.verify_jwt_token(token)

        # Assert
        assert user is not None, "Token with reasonable time skew should be accepted"

    @pytest.mark.contract
    def test_jwt_token_edge_case_expiry(self, security_manager, jwt_secret, test_user_data):
        """Contract: JWT tokens at edge of expiry should be handled correctly"""
        # Arrange
        # Create token that expires in 1 second
        near_expiry_payload = {
            "user_id": test_user_data["user_id"],
            "username": test_user_data["username"],
            "email": test_user_data["email"],
            "role": test_user_data["role"].value,
            "exp": datetime.utcnow() + timedelta(seconds=1),
            "iat": datetime.utcnow(),
        }

        token = jwt.encode(near_expiry_payload, jwt_secret, algorithm="HS256")

        # Act - Verify immediately
        user_immediate = security_manager.verify_jwt_token(token)

        # Wait for token to expire
        time.sleep(2)

        # Act - Verify after expiry
        user_expired = security_manager.verify_jwt_token(token)

        # Assert
        assert user_immediate is not None, "Token should be valid immediately after creation"
        assert user_expired is None, "Token should be invalid after expiry"
