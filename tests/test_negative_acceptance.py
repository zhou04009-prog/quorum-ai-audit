
def test_quorum_negative_acceptance():
    """Controlled failure to verify that CI blocks invalid assertions."""
    assert False, "QUORUM_NEGATIVE_ACCEPTANCE_EXPECTED_FAILURE"
