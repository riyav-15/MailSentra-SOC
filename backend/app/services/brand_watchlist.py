from sqlalchemy.orm import Session

from ..models import BrandWatchlist


DEFAULT_BRANDS = [
    ("Microsoft", ["microsoft.com", "office.com", "live.com", "outlook.com", "office365.com"], ["microsoft", "office", "outlook", "teams"], "microsoft"),
    ("Google", ["google.com", "gmail.com", "accounts.google.com"], ["google", "gmail", "workspace"], "google"),
    ("Amazon", ["amazon.com", "amazonaws.com"], ["amazon", "aws"], "amazon"),
    ("PayPal", ["paypal.com", "paypalobjects.com"], ["paypal"], "paypal"),
    ("Netflix", ["netflix.com", "nflxext.com"], ["netflix"], "netflix"),
    ("DHL", ["dhl.com"], ["dhl", "parcel", "shipment"], "dhl"),
    ("FedEx", ["fedex.com"], ["fedex", "shipment", "tracking"], "fedex"),
    ("LinkedIn", ["linkedin.com"], ["linkedin"], "linkedin"),
    ("GitHub", ["github.com"], ["github"], "github"),
    ("Apple", ["apple.com", "icloud.com"], ["apple", "icloud"], "apple"),
    ("Bank of America", ["bankofamerica.com", "bofa.com"], ["bank of america", "bofa"], "bank"),
    ("Chase", ["chase.com", "jpmorgan.com"], ["chase", "jpmorgan"], "bank"),
    ("Wells Fargo", ["wellsfargo.com"], ["wells fargo"], "bank"),
    ("Citibank", ["citi.com", "citibank.com"], ["citi", "citibank"], "bank"),
    ("HDFC Bank", ["hdfcbank.com"], ["hdfc", "hdfc bank"], "bank"),
    ("ICICI Bank", ["icicibank.com"], ["icici", "icici bank"], "bank"),
    ("State Bank of India", ["sbi.co.in", "onlinesbi.sbi"], ["sbi", "state bank of india"], "bank"),
]


def seed_brand_watchlist(db: Session, college_domain: str | None = None, college_name: str | None = None) -> None:
    existing = {brand.brand_name.lower() for brand in db.query(BrandWatchlist).all()}
    for brand_name, domains, keywords, logo_hint in DEFAULT_BRANDS:
        if brand_name.lower() not in existing:
            db.add(
                BrandWatchlist(
                    brand_name=brand_name,
                    legitimate_domains=domains,
                    keywords=keywords,
                    logo_hint=logo_hint,
                )
            )
    if college_domain:
        brand_name = college_name or "College Domain"
        if brand_name.lower() not in existing:
            db.add(
                BrandWatchlist(
                    brand_name=brand_name,
                    legitimate_domains=[college_domain.lower().strip()],
                    keywords=[brand_name.lower()],
                    logo_hint="education",
                )
            )


def brand_profiles_from_db(db: Session) -> dict:
    profiles = {}
    for item in db.query(BrandWatchlist).all():
        profiles[item.brand_name.lower()] = {
            "domains": item.legitimate_domains or [],
            "keywords": item.keywords or [],
        }
    return profiles
