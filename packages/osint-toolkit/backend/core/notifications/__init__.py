"""Outbound notifications for severe events.

Only fires when the operator has explicitly wired a webhook URL into
the config - by default the toolkit is silent. Kept deliberately
simple: one JSON POST per severe finding. No retries, no queue. A
dropped notification is not the end of the world (findings persist in
the DB regardless), and adding a durable queue is a separate concern
with its own operational cost.
"""
from .webhook import notify_severe_findings

__all__ = ["notify_severe_findings"]
