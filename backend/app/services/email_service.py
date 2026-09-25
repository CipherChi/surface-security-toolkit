"""Read-only email checks using public DNS, Gravatar, and optional HIBP."""

import hashlib
from urllib.parse import quote

import httpx

from app.config import Settings
from app.models.email import EmailSignal


class EmailService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()

    def check(self, email: str) -> tuple[str, list[EmailSignal]]:
        normalized = email.strip().lower()
        domain = normalized.rsplit("@", 1)[1]
        signals = [self._check_mx(domain), self._check_breach(normalized), self._check_gravatar(normalized)]
        return domain, signals

    @staticmethod
    def _check_mx(domain: str) -> EmailSignal:
        try:
            response = httpx.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": domain, "type": "MX"},
                headers={"accept": "application/dns-json"},
                timeout=5.0,
            )
            response.raise_for_status()
            answer = response.json()
            records = answer.get("Answer", [])
            if answer.get("Status") == 0 and records:
                return EmailSignal(signal="Email domain MX", status="clean", details=f"{len(records)} public MX record(s) found for {domain}.")
            return EmailSignal(signal="Email domain MX", status="checked", details=f"No public MX record was found for {domain}; the domain may not accept email.")
        except (httpx.HTTPError, ValueError):
            return EmailSignal(signal="Email domain MX", status="not_checked", details="The DNS-over-HTTPS lookup could not complete.")

    def _check_breach(self, email: str) -> EmailSignal:
        if not self.settings.hibp_api_key:
            return self._check_breach_xon(email)
        try:
            response = httpx.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}",
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": self.settings.hibp_api_key, "user-agent": "Surface Domain Exposure Checker"},
                timeout=8.0,
            )
            if response.status_code == 404:
                return EmailSignal(signal="Known breach exposure", status="clean", details="No breach entries were returned by Have I Been Pwned.", source_url="https://haveibeenpwned.com/")
            response.raise_for_status()
            breaches = response.json()
            count = len(breaches) if isinstance(breaches, list) else 0
            return EmailSignal(signal="Known breach exposure", status="exposed" if count else "clean", details=f"Listed in {count} known breach(es) according to Have I Been Pwned.", source_url="https://haveibeenpwned.com/")
        except (httpx.HTTPError, ValueError):
            return EmailSignal(signal="Known breach exposure", status="not_checked", details="The Have I Been Pwned lookup could not complete.")

    @staticmethod
    def _check_breach_xon(email: str) -> EmailSignal:
        """Use XposedOrNot's keyless personal-use API when HIBP is not configured."""
        try:
            response = httpx.get(
                f"https://api.xposedornot.com/v1/check-email/{quote(email, safe='')}",
                headers={"user-agent": "Surface Domain Exposure Checker"},
                timeout=8.0,
            )
            if response.status_code == 404:
                return EmailSignal(signal="Known breach exposure", status="clean", details="No breach entries were returned by XposedOrNot.", source_url="https://xposedornot.com/")
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, dict):
                raise ValueError("Unexpected XposedOrNot response")
            if str(body.get("Error", "")).lower() == "not found":
                return EmailSignal(signal="Known breach exposure", status="clean", details="No breach entries were returned by XposedOrNot.", source_url="https://xposedornot.com/")
            groups = body.get("breaches", [])
            breach_names = sorted({str(name) for group in groups if isinstance(group, list) for name in group if isinstance(name, str)}) if isinstance(groups, list) else []
            if not breach_names:
                return EmailSignal(signal="Known breach exposure", status="clean", details="No breach entries were returned by XposedOrNot.", source_url="https://xposedornot.com/")
            preview = ", ".join(breach_names[:4])
            extra = f" and {len(breach_names) - 4} more" if len(breach_names) > 4 else ""
            return EmailSignal(signal="Known breach exposure", status="exposed", details=f"Found in {len(breach_names)} known breach(es): {preview}{extra}. Source: XposedOrNot.", source_url="https://xposedornot.com/")
        except (httpx.HTTPError, ValueError):
            return EmailSignal(signal="Known breach exposure", status="not_checked", details="The keyless XposedOrNot breach lookup could not complete. Try again later.", source_url="https://xposedornot.com/")

    @staticmethod
    def _check_gravatar(email: str) -> EmailSignal:
        email_hash = hashlib.sha256(email.encode("utf-8")).hexdigest()
        try:
            response = httpx.get(
                f"https://www.gravatar.com/avatar/{email_hash}",
                params={"d": "404", "s": "1"},
                timeout=5.0,
                follow_redirects=True,
            )
            if response.status_code == 404:
                return EmailSignal(signal="Public Gravatar avatar", status="clean", details="No Gravatar avatar was found for this email hash.")
            response.raise_for_status()
            return EmailSignal(signal="Public Gravatar avatar", status="exposed", details="A public Gravatar avatar is associated with this email hash. This is a weak account association signal.")
        except httpx.HTTPError:
            return EmailSignal(signal="Public Gravatar avatar", status="not_checked", details="The Gravatar lookup could not complete.")
