"""Tests for output minimization (header allowlist, body sanitization)."""

from gmail_proxy.config import Policy
from gmail_proxy.models import Attachment, Message
from gmail_proxy.output import format_detail, minimize_body

POLICY = Policy(allowed_categories=["promotions"])


def test_html_script_and_style_content_stripped():
    m = Message(
        id="1", thread_id="1", label_ids=["CATEGORY_PROMOTIONS"],
        body_html=(
            "<html><head><style>.x{color:red}</style></head>"
            "<body><script>alert('xss steal token')</script>"
            "<p>Hello <b>deal</b> here</p></body></html>"
        ),
    )
    body, flags = minimize_body(m, POLICY)
    content = body["content"]
    assert "Hello" in content and "deal" in content
    for leak in ("alert", "xss", "color:red", "steal token"):
        assert leak not in content


def test_body_truncation_flag():
    pol = Policy(allowed_categories=["promotions"], max_body_bytes=1024)
    small = Message(id="1", thread_id="1", label_ids=["CATEGORY_PROMOTIONS"], body_text="A" * 100)
    _, flags = minimize_body(small, pol)
    assert flags["truncated"] is False
    big = Message(id="2", thread_id="2", label_ids=["CATEGORY_PROMOTIONS"], body_text="A" * 5000)
    _, flags2 = minimize_body(big, pol)
    assert flags2["truncated"] is True


def test_attachments_stripped_with_marker():
    m = Message(id="1", thread_id="1", label_ids=["CATEGORY_PROMOTIONS"],
                body_text="see attached", attachments=[Attachment("x.pdf", "application/pdf", 10)])
    body, flags = minimize_body(m, POLICY)
    assert flags["had_attachments"] is True
    assert "[attachments removed]" in body["content"]


def test_headers_minimized_drops_other_recipients():
    m = Message(id="1", thread_id="1", label_ids=["CATEGORY_PROMOTIONS"],
                headers={"From": "a@b.com", "Subject": "hi", "Date": "2026-01-01",
                         "To": "victim@x.com", "Cc": "leak@x.com", "Bcc": "secret@x.com"})
    d = format_detail(m, POLICY, salt=b"salt")
    assert "to" not in d and "cc" not in d and "bcc" not in d
    assert d["from"]["content"] == "a@b.com"


def test_sender_redaction_tokenizes():
    m = Message(id="1", thread_id="1", label_ids=["CATEGORY_PROMOTIONS"],
                headers={"From": "a@b.com", "Subject": "hi"})
    d = format_detail(m, Policy(allowed_categories=["promotions"], redact_sender_address=True),
                      salt=b"salt")
    assert d["from"]["content"].startswith("sender:")
    assert "a@b.com" not in d["from"]["content"]
