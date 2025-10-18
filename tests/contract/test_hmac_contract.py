#!/usr/bin/env python3
"""
Contract tests for HMAC signature verification
Ensures webhook authentication reliability across different scenarios
"""

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict

import pytest

from src.security import SecurityManager


class TestHMACContract:
    """Contract tests for HMAC signature verification"""

    @pytest.fixture
    def security_manager(self, test_config):
        """Create SecurityManager instance for testing"""
        return SecurityManager(test_config)

    @pytest.fixture
    def webhook_secret(self, test_config):
        """Get webhook secret from config"""
        return test_config["webhook"]["secret"]

    @pytest.fixture
    def sample_payload(self):
        """Sample webhook payload"""
        return {
            "event": "task.completed",
            "task_id": "test-task-123",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"status": "success", "duration": 45.2},
        }

    def create_hmac_signature(
        self, payload: Dict[str, Any], secret: str, timestamp: str = None
    ) -> str:
        """Create HMAC signature for payload"""
        if timestamp is None:
            timestamp = str(int(time.time()))

        payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        message = f"{timestamp}.{payload_str}"

        signature = hmac.new(
            secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return f"t={timestamp},v1={signature}"

    @pytest.mark.contract
    def test_valid_hmac_signature(self, security_manager, webhook_secret, sample_payload):
        """Contract: Valid HMAC signature should be accepted"""
        # Arrange
        timestamp = str(int(time.time()))
        signature = self.create_hmac_signature(sample_payload, webhook_secret, timestamp)

        # Act
        result = security_manager.verify_hmac_signature(
            payload=json.dumps(sample_payload, sort_keys=True, separators=(",", ":")),
            signature=signature,
            secret=webhook_secret,
        )

        # Assert
        assert result is True, "Valid HMAC signature should be accepted"

    @pytest.mark.contract
    def test_invalid_signature_rejected(self, security_manager, webhook_secret, sample_payload):
        """Contract: Invalid HMAC signature should be rejected"""
        # Arrange
        timestamp = str(int(time.time()))
        # Create signature with wrong secret
        wrong_signature = self.create_hmac_signature(sample_payload, "wrong-secret", timestamp)

        # Act
        result = security_manager.verify_hmac_signature(
            payload=json.dumps(sample_payload, sort_keys=True, separators=(",", ":")),
            signature=wrong_signature,
            secret=webhook_secret,
        )

        # Assert
        assert result is False, "Invalid HMAC signature should be rejected"

    @pytest.mark.contract
    def test_expired_timestamp_rejected(self, security_manager, webhook_secret, sample_payload):
        """Contract: Expired timestamp should be rejected"""
        # Arrange
        # Create signature with timestamp older than tolerance (120 seconds)
        old_timestamp = str(int(time.time()) - 300)  # 5 minutes ago
        signature = self.create_hmac_signature(sample_payload, webhook_secret, old_timestamp)

        # Act
        result = security_manager.verify_hmac_signature(
            payload=json.dumps(sample_payload, sort_keys=True, separators=(",", ":")),
            signature=signature,
            secret=webhook_secret,
        )

        # Assert
        assert result is False, "Expired timestamp should be rejected"

    @pytest.mark.contract
    def test_future_timestamp_rejected(self, security_manager, webhook_secret, sample_payload):
        """Contract: Future timestamp should be rejected"""
        # Arrange
        # Create signature with timestamp in the future (beyond tolerance)
        future_timestamp = str(int(time.time()) + 300)  # 5 minutes in future
        signature = self.create_hmac_signature(sample_payload, webhook_secret, future_timestamp)

        # Act
        result = security_manager.verify_hmac_signature(
            payload=json.dumps(sample_payload, sort_keys=True, separators=(",", ":")),
            signature=signature,
            secret=webhook_secret,
        )

        # Assert
        assert result is False, "Future timestamp should be rejected"

    @pytest.mark.contract
    def test_timestamp_within_tolerance_accepted(
        self, security_manager, webhook_secret, sample_payload
    ):
        """Contract: Timestamp within tolerance should be accepted"""
        # Arrange
        # Create signature with timestamp at edge of tolerance (119 seconds ago)
        edge_timestamp = str(int(time.time()) - 119)
        signature = self.create_hmac_signature(sample_payload, webhook_secret, edge_timestamp)

        # Act
        result = security_manager.verify_hmac_signature(
            payload=json.dumps(sample_payload, sort_keys=True, separators=(",", ":")),
            signature=signature,
            secret=webhook_secret,
        )

        # Assert
        assert result is True, "Timestamp within tolerance should be accepted"

    @pytest.mark.contract
    def test_malformed_signature_rejected(self, security_manager, webhook_secret, sample_payload):
        """Contract: Malformed signature should be rejected"""
        # Arrange
        malformed_signatures = [
            "invalid-format",
            "t=123456",  # Missing v1 part
            "v1=abcdef",  # Missing timestamp part
            "t=not-a-number,v1=abcdef",  # Invalid timestamp
            "t=123456,v1=",  # Empty signature
            "",  # Empty string
            None,  # None value
        ]

        payload_str = json.dumps(sample_payload, sort_keys=True, separators=(",", ":"))

        for malformed_sig in malformed_signatures:
            # Act
            result = security_manager.verify_hmac_signature(
                payload=payload_str, signature=malformed_sig, secret=webhook_secret
            )

            # Assert
            assert result is False, f"Malformed signature '{malformed_sig}' should be rejected"

    @pytest.mark.contract
    def test_payload_modification_detected(self, security_manager, webhook_secret, sample_payload):
        """Contract: Payload modification should be detected"""
        # Arrange
        timestamp = str(int(time.time()))
        signature = self.create_hmac_signature(sample_payload, webhook_secret, timestamp)

        # Modify payload after signature creation
        modified_payload = sample_payload.copy()
        modified_payload["data"]["status"] = "failed"  # Change status

        # Act
        result = security_manager.verify_hmac_signature(
            payload=json.dumps(modified_payload, sort_keys=True, separators=(",", ":")),
            signature=signature,
            secret=webhook_secret,
        )

        # Assert
        assert result is False, "Modified payload should be detected and rejected"

    @pytest.mark.contract
    def test_json_serialization_consistency(self, security_manager, webhook_secret):
        """Contract: JSON serialization should be consistent"""
        # Arrange
        # Test different JSON representations of the same data
        payload1 = {"b": 2, "a": 1}  # Different key order
        payload2 = {"a": 1, "b": 2}  # Different key order

        timestamp = str(int(time.time()))

        # Create signatures for both payloads
        sig1 = self.create_hmac_signature(payload1, webhook_secret, timestamp)
        sig2 = self.create_hmac_signature(payload2, webhook_secret, timestamp)

        # Both should produce the same signature due to sort_keys=True
        assert sig1 == sig2, "JSON serialization should be consistent regardless of key order"

        # Both should verify successfully
        payload1_str = json.dumps(payload1, sort_keys=True, separators=(",", ":"))
        payload2_str = json.dumps(payload2, sort_keys=True, separators=(",", ":"))

        result1 = security_manager.verify_hmac_signature(payload1_str, sig1, webhook_secret)
        result2 = security_manager.verify_hmac_signature(payload2_str, sig2, webhook_secret)

        assert result1 is True, "Payload1 should verify successfully"
        assert result2 is True, "Payload2 should verify successfully"

    @pytest.mark.contract
    def test_unicode_payload_handling(self, security_manager, webhook_secret):
        """Contract: Unicode characters in payload should be handled correctly"""
        # Arrange
        unicode_payload = {
            "message": "Hello 世界! 🌍",
            "emoji": "🚀✨",
            "special_chars": "àáâãäåæçèéêë",
        }

        timestamp = str(int(time.time()))
        signature = self.create_hmac_signature(unicode_payload, webhook_secret, timestamp)

        # Act
        result = security_manager.verify_hmac_signature(
            payload=json.dumps(
                unicode_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ),
            signature=signature,
            secret=webhook_secret,
        )

        # Assert
        assert result is True, "Unicode payload should be handled correctly"

    @pytest.mark.contract
    def test_large_payload_handling(self, security_manager, webhook_secret):
        """Contract: Large payloads should be handled correctly"""
        # Arrange
        # Create a large payload (1MB of data)
        large_data = "x" * (1024 * 1024)  # 1MB string
        large_payload = {"event": "large_data_transfer", "data": large_data}

        timestamp = str(int(time.time()))
        signature = self.create_hmac_signature(large_payload, webhook_secret, timestamp)

        # Act
        result = security_manager.verify_hmac_signature(
            payload=json.dumps(large_payload, sort_keys=True, separators=(",", ":")),
            signature=signature,
            secret=webhook_secret,
        )

        # Assert
        assert result is True, "Large payload should be handled correctly"

    @pytest.mark.contract
    def test_empty_payload_handling(self, security_manager, webhook_secret):
        """Contract: Empty payload should be handled correctly"""
        # Arrange
        empty_payload = {}

        timestamp = str(int(time.time()))
        signature = self.create_hmac_signature(empty_payload, webhook_secret, timestamp)

        # Act
        result = security_manager.verify_hmac_signature(
            payload=json.dumps(empty_payload, sort_keys=True, separators=(",", ":")),
            signature=signature,
            secret=webhook_secret,
        )

        # Assert
        assert result is True, "Empty payload should be handled correctly"

    @pytest.mark.contract
    def test_multiple_signature_versions(self, security_manager, webhook_secret, sample_payload):
        """Contract: Only v1 signatures should be accepted"""
        # Arrange
        timestamp = str(int(time.time()))
        payload_str = json.dumps(sample_payload, sort_keys=True, separators=(",", ":"))
        message = f"{timestamp}.{payload_str}"

        # Create different signature versions
        v1_sig = hmac.new(webhook_secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        v0_sig = hmac.new(webhook_secret.encode(), message.encode(), hashlib.md5).hexdigest()

        signatures = [
            f"t={timestamp},v1={v1_sig}",  # Should be accepted
            f"t={timestamp},v0={v0_sig}",  # Should be rejected
            f"t={timestamp},v2={v1_sig}",  # Should be rejected
        ]

        expected_results = [True, False, False]

        for signature, expected in zip(signatures, expected_results):
            # Act
            result = security_manager.verify_hmac_signature(
                payload=payload_str, signature=signature, secret=webhook_secret
            )

            # Assert
            assert result == expected, f"Signature '{signature}' should return {expected}"

    @pytest.mark.contract
    @pytest.mark.performance
    def test_hmac_verification_performance(
        self, security_manager, webhook_secret, sample_payload, benchmark
    ):
        """Contract: HMAC verification should complete within performance limits"""
        # Arrange
        timestamp = str(int(time.time()))
        signature = self.create_hmac_signature(sample_payload, webhook_secret, timestamp)
        payload_str = json.dumps(sample_payload, sort_keys=True, separators=(",", ":"))

        # Act & Assert
        result = benchmark(
            security_manager.verify_hmac_signature,
            payload=payload_str,
            signature=signature,
            secret=webhook_secret,
        )

        assert result is True, "HMAC verification should succeed"
        # Performance assertion is handled by benchmark fixture

    @pytest.mark.contract
    def test_concurrent_hmac_verification(self, security_manager, webhook_secret, sample_payload):
        """Contract: HMAC verification should be thread-safe"""
        import concurrent.futures

        # Arrange
        timestamp = str(int(time.time()))
        signature = self.create_hmac_signature(sample_payload, webhook_secret, timestamp)
        payload_str = json.dumps(sample_payload, sort_keys=True, separators=(",", ":"))

        results = []
        errors = []

        def verify_signature():
            try:
                result = security_manager.verify_hmac_signature(
                    payload=payload_str, signature=signature, secret=webhook_secret
                )
                results.append(result)
            except Exception as e:
                errors.append(e)

        # Act
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(verify_signature) for _ in range(50)]
            concurrent.futures.wait(futures)

        # Assert
        assert len(errors) == 0, f"No errors should occur during concurrent verification: {errors}"
        assert len(results) == 50, "All verifications should complete"
        assert all(result is True for result in results), "All verifications should succeed"

    @pytest.mark.contract
    def test_signature_replay_attack_prevention(
        self, security_manager, webhook_secret, sample_payload
    ):
        """Contract: Signature replay attacks should be prevented by timestamp validation"""
        # Arrange
        old_timestamp = str(int(time.time()) - 200)  # 200 seconds ago (beyond tolerance)
        signature = self.create_hmac_signature(sample_payload, webhook_secret, old_timestamp)
        payload_str = json.dumps(sample_payload, sort_keys=True, separators=(",", ":"))

        # Act - First verification (should fail due to old timestamp)
        result1 = security_manager.verify_hmac_signature(
            payload=payload_str, signature=signature, secret=webhook_secret
        )

        # Act - Second verification (should also fail)
        result2 = security_manager.verify_hmac_signature(
            payload=payload_str, signature=signature, secret=webhook_secret
        )

        # Assert
        assert result1 is False, "Old signature should be rejected on first attempt"
        assert result2 is False, "Old signature should be rejected on replay attempt"
