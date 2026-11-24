"""Tests para core/exclusions.py"""


from core.exclusions import is_excluded, parse_exclusions


def test_parse_exclusions_empty():
    assert parse_exclusions("") == []
    assert parse_exclusions(None) == []
    assert parse_exclusions("\n\n") == []


def test_parse_exclusions_basic():
    text = "C:\\Temp\\malware\nC:\\Users\\test\\bad.exe\n"
    result = parse_exclusions(text)
    assert result == ["C:\\Temp\\malware", "C:\\Users\\test\\bad.exe"]


def test_is_excluded_exact_match():
    exclusions = ["C:\\Temp\\malware"]
    assert is_excluded("C:\\Temp\\malware", exclusions) is True


def test_is_excluded_folder_match():
    exclusions = ["C:\\Temp"]
    assert is_excluded("C:\\Temp\\sub\\file.exe", exclusions) is True


def test_is_excluded_no_prefix_false_positive():
    """C:\\Temp no debe excluir C:\\Temporal."""
    exclusions = ["C:\\Temp"]
    assert is_excluded("C:\\Temporal\\file.exe", exclusions) is False


def test_is_excluded_case_insensitive():
    exclusions = ["C:\\Temp"]
    assert is_excluded("c:\\temp\\file.exe", exclusions) is True


def test_is_excluded_empty_list():
    assert is_excluded("C:\\any\\file.exe", []) is False


def test_is_excluded_none_list():
    assert is_excluded("C:\\any\\file.exe", None) is False
