from worker.range_discovery import expand_targets


def test_expand_targets_for_small_cidr() -> None:
    targets = expand_targets("10.10.0.0/30", [443, 8443])

    assert targets == [
        ("10.10.0.1", 443),
        ("10.10.0.1", 8443),
        ("10.10.0.2", 443),
        ("10.10.0.2", 8443),
    ]
