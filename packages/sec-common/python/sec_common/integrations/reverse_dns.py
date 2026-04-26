"""Reverse DNS (PTR) lookups via ``dnspython`` async resolver.

Free, no auth - PTR records are standard DNS. A single IP can have
multiple PTR records (rare but possible) so the client returns a list.
"""
from sec_common.cache import get_cached, set_cached

try:
    import dns.asyncresolver
    import dns.reversename
except ImportError:  # pragma: no cover
    dns = None  # type: ignore[assignment]


class ReverseDNSClient:
    """Async PTR lookups with cache."""

    CACHE_TTL = 3 * 3600
    TIMEOUT = 5.0

    async def lookup(self, ip: str) -> list[str]:
        """Return PTR hostnames for ``ip`` (trailing dot stripped)."""
        if dns is None:
            return []

        cached = get_cached("reverse_dns", "ptr", ip)
        if cached is not None:
            return list(cached.get("ptr", []))

        try:
            rev = dns.reversename.from_address(ip)
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = self.TIMEOUT
            resolver.lifetime = self.TIMEOUT
            answer = await resolver.resolve(rev, "PTR")
            ptrs = sorted({str(r).rstrip(".").lower() for r in answer})
        except Exception:
            return []

        set_cached("reverse_dns", "ptr", ip, {"ptr": ptrs}, ttl=self.CACHE_TTL)
        return ptrs
