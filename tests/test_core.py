"""
Tests for core ResponseVerifier class.
"""

import pytest
from qwed_open_responses import ResponseVerifier, VerificationResult
from qwed_open_responses.guards.base import BaseGuard, GuardResult


class MockPassGuard(BaseGuard):
    """Always passes."""

    name = "MockPassGuard"

    def check(self, response, context=None):
        return self.pass_result()


class MockFailGuard(BaseGuard):
    """Always fails."""

    name = "MockFailGuard"

    def check(self, response, context=None):
        return self.fail_result("Mock failure")


class MockWarnGuard(BaseGuard):
    """Always warns."""

    name = "MockWarnGuard"

    def check(self, response, context=None):
        return self.warn_result("Mock warning")


class TestResponseVerifier:
    """Test ResponseVerifier class."""

    def test_verify_empty_guards(self):
        """Verify with no guards should pass."""
        verifier = ResponseVerifier()
        result = verifier.verify({"test": "data"})

        assert result.verified is True
        assert result.guards_passed == 0
        assert result.guards_failed == 0

    def test_verify_all_pass(self):
        """All guards pass."""
        verifier = ResponseVerifier()
        result = verifier.verify(
            {"test": "data"}, guards=[MockPassGuard(), MockPassGuard()]
        )

        assert result.verified is True
        assert result.guards_passed == 2
        assert result.guards_failed == 0

    def test_verify_one_fails(self):
        """One guard fails."""
        verifier = ResponseVerifier()
        result = verifier.verify(
            {"test": "data"}, guards=[MockPassGuard(), MockFailGuard()]
        )

        assert result.verified is False
        assert result.guards_passed == 1
        assert result.guards_failed == 1

    def test_verify_tool_call(self):
        """Test verify_tool_call method."""
        verifier = ResponseVerifier()
        result = verifier.verify_tool_call(
            tool_name="search", arguments={"query": "test"}, guards=[MockPassGuard()]
        )

        assert result.verified is True
        assert result.response["type"] == "tool_call"
        assert result.response["tool_name"] == "search"

    def test_verify_structured_output(self):
        """Test verify_structured_output method."""
        verifier = ResponseVerifier()
        result = verifier.verify_structured_output(
            output={"name": "John", "age": 30}, guards=[MockPassGuard()]
        )

        assert result.verified is True

    def test_default_guards(self):
        """Test default guards are used."""
        verifier = ResponseVerifier(default_guards=[MockPassGuard()])
        result = verifier.verify({"test": "data"})

        assert result.guards_passed == 1

    def test_parse_string_json(self):
        """Test parsing JSON string."""
        verifier = ResponseVerifier()
        result = verifier.verify('{"name": "test"}')

        assert result.response["name"] == "test"

    def test_parse_plain_text(self):
        """Test parsing plain text."""
        verifier = ResponseVerifier()
        result = verifier.verify("Hello world")

        assert result.response["type"] == "text"
        assert result.response["content"] == "Hello world"

    def test_result_to_dict(self):
        """Test VerificationResult serialization."""
        verifier = ResponseVerifier()
        result = verifier.verify({"test": "data"}, guards=[MockPassGuard()])

        result_dict = result.to_dict()
        assert "verified" in result_dict
        assert "guards_passed" in result_dict
        assert "timestamp" in result_dict

    def test_result_str(self):
        """Test VerificationResult string representation."""
        verifier = ResponseVerifier()

        pass_result = verifier.verify({}, guards=[MockPassGuard()])
        assert "[OK]" in str(pass_result)

        fail_result = verifier.verify({}, guards=[MockFailGuard()])
        assert "[FAIL]" in str(fail_result)


class TestGuardResult:
    """Test GuardResult class."""

    def test_pass_result(self):
        guard = MockPassGuard()
        result = guard.pass_result("Test passed")

        assert result.passed is True
        assert result.severity == "info"

    def test_fail_result(self):
        guard = MockFailGuard()
        result = guard.fail_result("Test failed")

        assert result.passed is False
        assert result.severity == "error"

    def test_warn_result(self):
        guard = MockWarnGuard()
        result = guard.warn_result("Test warning")

        assert result.passed is False
        assert result.severity == "warning"

    def test_to_dict(self):
        guard = MockPassGuard()
        result = guard.pass_result()

        result_dict = result.to_dict()
        assert result_dict["guard"] == "MockPassGuard"
        assert result_dict["passed"] is True
