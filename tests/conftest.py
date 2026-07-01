import yaml
import pytest

from gmail_proxy.config import Policy, Settings
from gmail_proxy.context import build_context
from gmail_proxy.gmail.mock_client import sample_backend


@pytest.fixture
def make_ctx(tmp_path):
    """Factory: build an AppContext with a fresh mock backend + chosen policy.

    Writes the policy to a temp policy.yaml and points settings at it, so admin
    config-save tests never touch the repo's policy.yaml.
    """

    def _make(**policy_kw):
        policy_kw.setdefault("allowed_categories", ["promotions", "social"])
        pol = Policy(**policy_kw)
        ppath = tmp_path / "policy.yaml"
        ppath.write_text(yaml.safe_dump(pol.model_dump()))
        settings = Settings(data_dir=str(tmp_path), gmail_backend="mock", policy_path=str(ppath))
        return build_context(settings, backend=sample_backend(), policy=pol)

    return _make


@pytest.fixture
def ctx(make_ctx):
    return make_ctx()
