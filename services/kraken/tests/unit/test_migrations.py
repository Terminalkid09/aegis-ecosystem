import pytest

from app.db.session import _legacy_baseline


def test_fresh_database_upgrades_from_base():
    assert _legacy_baseline(
        has_version_table=False,
        has_legacy_schema=False,
        has_new_tables=False,
        has_ntlm_hash=False,
    ) is None


def test_legacy_create_all_database_is_stamped_at_0003():
    assert _legacy_baseline(
        has_version_table=False,
        has_legacy_schema=True,
        has_new_tables=False,
        has_ntlm_hash=False,
    ) == "0003"


def test_existing_version_table_needs_no_stamp():
    assert _legacy_baseline(
        has_version_table=True,
        has_legacy_schema=True,
        has_new_tables=False,
        has_ntlm_hash=False,
    ) is None


def test_complete_42_create_all_database_is_stamped_at_0006():
    assert _legacy_baseline(
        has_version_table=False,
        has_legacy_schema=True,
        has_new_tables=True,
        has_ntlm_hash=True,
    ) == "0006"


def test_partial_42_schema_is_refused():
    with pytest.raises(RuntimeError, match="ambiguous upgrade"):
        _legacy_baseline(
            has_version_table=False,
            has_legacy_schema=True,
            has_new_tables=True,
            has_ntlm_hash=False,
        )
