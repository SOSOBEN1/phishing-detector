from app.ml.predict import predict_url
from app.ml.features import extract_features, get_domain

urls = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.amazon.com",
    "https://www.facebook.com",
    "https://www.univ-oran1.dz",
    "http://192.168.0.1/secure-login@bank.com",
    "http://paypal-verify-account-login.xyz/signin",
]
for u in urls:
    print(u, "| domaine:", get_domain(u), "|", predict_url(u))

print()
print(extract_features("https://www.google.com"))
