"""Browser-sandbox logic that needs no browser: field classification, credential detection, brand claims, scoring."""
import pytest

from core_engine import browser_sandbox as bs


def field(**kw):
    base = {"tag": "input", "type": "text", "name": "", "id": "", "placeholder": "", "autocomplete": "", "aria": "",
            "label": "", "maxlength": 0, "visible": True, "inputmode": ""}
    base.update(kw)
    return base


@pytest.mark.parametrize("info,expected", [
    (field(type="password"), "password"),
    (field(name="pwd"), "password"),
    (field(autocomplete="current-password"), "password"),
    (field(name="passport_no"), "gov_id"),                      # "pass" inside "passport" is not a password
    (field(type="email"), "email"),
    (field(type="tel"), "phone"),
    (field(name="otp", maxlength=6), "otp"),
    (field(autocomplete="one-time-code"), "otp"),
    (field(name="cvv"), "cvv"),
    (field(name="security_code"), "cvv"),                       # card code, not an OTP
    (field(autocomplete="cc-number"), "card"),
    (field(placeholder="Enter your Aadhaar number"), "gov_id"),
    (field(tag="textarea", placeholder="Enter your 12 word recovery phrase"), "wallet_phrase"),
    (field(name="customer_id"), "username"),
    (field(type="hidden", name="csrf_token"), "other"),
    (field(type="submit"), "other"),
    (field(name="q", placeholder="Search"), "other"),
])
def test_field_classification(info, expected):
    assert bs.classify_field(info) == expected


def test_credential_forms_versus_harmless_forms():
    login = bs.analyse_inputs([field(type="email"), field(type="password")])
    assert login["credential"] and "password" in login["sensitive"]
    newsletter = bs.analyse_inputs([field(type="email", name="email", placeholder="Your email")])
    contact = bs.analyse_inputs([field(name="name", placeholder="Your name"), field(type="email"), field(tag="textarea", name="message")])
    search = bs.analyse_inputs([field(name="q", placeholder="Search")])
    assert not newsletter["credential"] and not contact["credential"] and not search["credential"]
    assert bs.analyse_inputs([field(name="phone", type="tel"), field(name="otp", maxlength=6)])["credential"]    # phone + OTP login
    assert bs.analyse_inputs([field(name="card_number"), field(name="cvv")])["credential"]                        # card entry
    assert bs.analyse_inputs([field(tag="textarea", placeholder="recovery phrase")])["credential"]
    assert not bs.analyse_inputs([field(type="password", visible=False)])["credential"]                           # hidden until a click


def test_two_step_login_is_recognised_only_on_login_pages():
    email_only = [field(type="email", name="identifier")]
    assert bs.analyse_inputs(email_only, login_intent=True)["multi_step"]
    assert not bs.analyse_inputs(email_only, login_intent=False)["credential"]                                    # a newsletter box


def test_invisible_inputs_do_not_count_unless_password():
    assert not bs.analyse_inputs([field(type="email", visible=False)])["credential"]


def state(title="", text="", ogSite="", logoAlts=None, links=None, **kw):
    return {"title": title, "text": text, "ogSite": ogSite, "ogTitle": "", "logoAlts": logoAlts or [], "links": links or [], **kw}


def test_brand_claim_needs_the_headline_not_a_passing_mention():
    legit = bs.detect_brand(state(title="City Council Login", text="Residents can pay with apple pay or google pay at the counter. " * 3),
                            "citycouncil.example")
    assert legit["claimed_brand"] == ""
    fake = bs.detect_brand(state(title="HDFC Bank NetBanking Login", text="welcome"), "secure-hdfc-kyc.com")
    assert fake["claimed_brand"] == "hdfc" and fake["brand_owns_domain"] is False and fake["brand_in_domain_label"] is True
    real = bs.detect_brand(state(title="HDFC Bank NetBanking Login"), "hdfcbank.com")
    assert real["claimed_brand"] == "hdfc" and real["brand_owns_domain"] is True and real["brand_in_domain_label"] is False


def test_short_ambiguous_brand_names_are_ignored_in_prose():
    assert bs.detect_brand(state(text="Ups and downs of life. ups ups ups ups ups ups"), "diary.example")["claimed_brand"] == ""


def test_exfil_hosts_and_ip_detection():
    assert bs.host_is_exfil("api.telegram.org") and bs.host_is_exfil("hooks.slack.com") and bs.host_is_exfil("webhook.site")
    assert not bs.host_is_exfil("example.com") and not bs.host_is_exfil("telegram-fan-club.example")
    assert bs._is_ip("192.0.2.5") and not bs._is_ip("example.com")


def test_wording_categories():
    w = bs.wording_counts("URGENT: your account will be suspended within 24 hours. Verify your KYC now. Connect wallet, seed phrase.")
    assert w["urgency"] and w["threat"] and w["credentials"] and w["crypto"] >= 2
    assert sum(bs.wording_counts("Tomatoes need sun and water.").values()) == 0


def base_evidence(**kw):
    ev = bs.BrowserSandbox._empty_evidence()
    ev.update(kw)
    return ev


def test_unverified_pages_never_score_as_threats():
    assert bs.evidence_score(base_evidence(verification_state="unverified", unverified_reason="bot_protection")) == 0
    assert bs.evidence_score(base_evidence(verification_state="unverified", unverified_reason="timeout")) == 0


def test_evidence_scoring_is_proportionate():
    benign = base_evidence(credential_surface_found=True, has_privacy_link=True, has_terms_link=True, has_contact_link=True,
                           same_site_link_ratio=0.95, n_links=30)
    assert bs.evidence_score(benign) == 0
    theft = base_evidence(credential_surface_found=True, probe_credentials_sent=True, submit_cross_domain=True,
                          brand_impersonation=1, wording={"urgency": 2, "threat": 1})
    assert bs.evidence_score(theft) >= 90
    assert bs.evidence_score(base_evidence(submit_to_messaging_api=True)) >= 80
    sso = base_evidence(credential_surface_found=True, login_leads_to_other_domain=True, idp_login=True, form_cross_domain=True)
    assert bs.evidence_score(sso) < 35                                  # signing in with Google/Microsoft is normal


def test_legacy_keys_are_filled_for_the_pipeline():
    sandbox = bs.BrowserSandbox()
    ev = base_evidence(credential_surface_found=True, sensitive_field_types=["password"], form_cross_domain=True,
                       claimed_brand="paypal", brand_owns_domain=False, page_title="PayPal login")
    out = sandbox._finish(ev)
    for key in ("sandbox_has_password_field", "external_form_action", "suspicious_exfiltration", "sandbox_hidden_iframes",
                "sandbox_title_mismatch", "brand_impersonation", "sandbox_unreachable", "sandbox_threat_score"):
        assert key in out
    assert out["sandbox_has_password_field"] == 1 and out["brand_impersonation"] == 1 and out["impersonated_brand"] == "paypal"


def test_registered_domain_helper():
    assert bs.registered("https://login.secure.example.co.uk/x") == "example.co.uk"
    assert bs.registered("https://abc.vercel.app/") == "vercel.app"


def test_brand_spelled_with_spaces_and_hyphenated_lookalike_domain():
    c = bs.detect_brand(state(title="American Express - Card Applications", text="apply now"), "american-express-applications.vercel.app")
    assert c["claimed_brand"] == "americanexpress" and c["brand_owns_domain"] is False and c["brand_in_domain_label"] is True
    assert bs.detect_brand(state(title="American Express"), "americanexpress.com")["brand_owns_domain"] is True


def test_storage_buckets_count_as_free_hosting():
    from core_engine.link_threat_pipeline import is_user_content_host
    assert is_user_content_host("https://j1has6zgife5b8jillo0.s3.amazonaws.com/x") and is_user_content_host("http://b.s3.eu-west-1.amazonaws.com/")
