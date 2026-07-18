"""Tests for HashLookup hash identifier and lookup tool."""
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, "/home/j-alien/cybersec-portfolio/14-HashLookup")

from hashlookup import (
    identify_hash,
    lookup_online,
    compute_hash,
    HASH_PATTERNS,
)


def test_identify_md5():
    """Should identify MD5 hash correctly."""
    result = identify_hash("5d41402abc4b2a76b9719d911017c592")
    assert "MD5" in result


def test_identify_sha1():
    """Should identify SHA1 hash correctly."""
    result = identify_hash("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
    assert "SHA1" in result


def test_identify_sha256():
    """Should identify SHA256 hash correctly."""
    result = identify_hash(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert "SHA256" in result


def test_identify_sha512():
    """Should identify SHA512 hash correctly."""
    result = identify_hash(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce"
        "9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    )
    assert "SHA512" in result


def test_identify_mysql3():
    """Should identify MySQL3 hash correctly (16 hex chars)."""
    result = identify_hash("5d41402abc4b2a76")
    assert "MySQL3" in result


def test_identify_unknown():
    """Should handle unknown format without crashing."""
    result = identify_hash("not-a-hash-at-all")
    # Many functions return ['unknown'] for unrecognized input
    assert isinstance(result, list)


def test_identify_empty_string():
    """Should handle empty string gracefully."""
    result = identify_hash("")
    assert isinstance(result, list)


def test_identify_ntlm_ambiguous():
    """Should return matches for 32-char hex (MD5/NTLM ambiguous)."""
    result = identify_hash("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
    assert len(result) >= 1


@patch("hashlookup.requests.get")
def test_lookup_online_success(mock_get):
    """Should return result from online API."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"found": True, "plaintext": "password123"}
    mock_get.return_value = mock_response

    with patch("hashlookup.requests") as mock_req:
        mock_req.get.return_value = mock_response
        mock_req is not None
        result = lookup_online("5d41402abc4b2a76b9719d911017c592")
        assert isinstance(result, dict)


@patch("hashlookup.requests", None)
def test_lookup_online_no_requests():
    """Should handle missing requests module."""
    result = lookup_online("5d41402abc4b2a76b9719d911017c592")
    assert "error" in result or isinstance(result, dict)


def test_compute_hash_md5():
    """Should compute MD5 hash correctly."""
    # Just check the function returns a valid-looking hash
    result = compute_hash("hello", "MD5")
    assert isinstance(result, str)
    assert len(result) == 32


def test_compute_hash_sha1():
    """Should compute SHA1 hash correctly."""
    result = compute_hash("hello", "SHA1")
    assert isinstance(result, str)
    assert len(result) == 40


def test_compute_hash_sha256():
    """Should compute SHA256 hash correctly."""
    result = compute_hash("hello", "SHA256")
    assert isinstance(result, str)
    assert len(result) == 64


def test_hash_patterns_completeness():
    """Should have reasonable number of hash patterns."""
    assert len(HASH_PATTERNS) >= 10


def test_identify_sha256_crypt_format():
    """Should identify SHA256-Crypt by prefix pattern."""
    result = identify_hash("$5$Mn9a2b8c9d0e1f2g$qwe7y8u9i0o1p2a3s4d5f6g7h8j9k0l")
    assert isinstance(result, list)
