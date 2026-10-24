from nullgate import get_pixel_challenge


def test_pixel_challenge_embedded_among_statements() -> None:
    html = """
        <html><script>
        window.ready = true; var bazadebezolkohpepadr = '001234'; finish();
        </script></html>
    """
    assert get_pixel_challenge(html) == "001234"


def test_missing_pixel_challenge() -> None:
    assert get_pixel_challenge('<script>var other = "1234";</script>') is None
