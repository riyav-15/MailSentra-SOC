from datetime import datetime, timedelta

from app.services.campaign_correlation import CorrelationFeatures, campaign_match_score, normalize_subject, subject_similarity


def test_subject_normalization_and_similarity():
    assert normalize_subject("RE: Urgent Microsoft Password Alert!!!") == "microsoft password"
    assert subject_similarity("Microsoft password reset notice", "FW: Microsoft password alert") >= 0.55


def test_campaign_match_scores_overlap_features():
    now = datetime.utcnow()
    campaign = CorrelationFeatures(
        normalized_subject="microsoft password",
        sender_domain="mailer.example",
        url_domains={"micros0ft-login.example"},
        attachment_hashes={"abc123"},
        brands={"microsoft"},
        created_at=now - timedelta(hours=2),
    )
    incident = CorrelationFeatures(
        normalized_subject="microsoft password reset",
        sender_domain="mailer.example",
        url_domains={"micros0ft-login.example"},
        attachment_hashes=set(),
        brands={"microsoft"},
        created_at=now,
    )

    assert campaign_match_score(campaign, incident) >= 35


def test_campaign_match_respects_time_window():
    now = datetime.utcnow()
    campaign = CorrelationFeatures(
        normalized_subject="payroll update",
        sender_domain="sender.example",
        url_domains={"example.com"},
        attachment_hashes=set(),
        brands=set(),
        created_at=now - timedelta(days=30),
    )
    incident = CorrelationFeatures(
        normalized_subject="payroll update",
        sender_domain="sender.example",
        url_domains={"example.com"},
        attachment_hashes=set(),
        brands=set(),
        created_at=now,
    )

    assert campaign_match_score(campaign, incident) == 0
