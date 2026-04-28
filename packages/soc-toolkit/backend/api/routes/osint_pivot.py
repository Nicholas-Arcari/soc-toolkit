from fastapi import APIRouter
from pydantic import BaseModel
from sec_common.integrations import (
    ASNClient,
    CrtShClient,
    MnemonicPdnsClient,
    ReverseDNSClient,
    SecurityTrailsClient,
    ShodanClient,
    WhoisClient,
)

from config import settings
from core.osint_pivot.pivot_engine import PivotClients, pivot

router = APIRouter()


class PivotRequest(BaseModel):
    type: str
    value: str


class PivotResponse(BaseModel):
    target: str
    target_type: str
    summary: dict
    pivot: dict
    error: str | None = None


def _build_pivot_clients() -> PivotClients:
    """Settings → DI bundle. Clients without a key degrade silently."""
    return PivotClients(
        crtsh=CrtShClient(),
        securitytrails=SecurityTrailsClient(api_key=settings.get_api_key("securitytrails")),
        mnemonic=MnemonicPdnsClient(),
        whois=WhoisClient(),
        asn=ASNClient(),
        reverse_dns=ReverseDNSClient(),
        shodan=ShodanClient(api_key=settings.get_api_key("shodan")),
    )


@router.post("/pivot", response_model=PivotResponse)
async def osint_pivot(request: PivotRequest) -> PivotResponse:
    """Fan out an indicator across OSINT sources for pivoting.

    Domains → CT logs, passive DNS, WHOIS, WHOIS history, subdomains.
    IPs → ASN, reverse DNS, passive DNS, Shodan.
    Each source runs in parallel; missing API keys produce empty sections
    rather than errors.
    """
    clients = _build_pivot_clients()
    result = await pivot(request.type, request.value, clients=clients)
    return PivotResponse(**result)
