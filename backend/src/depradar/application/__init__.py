"""Use cases: each one orchestrates entities, domain rules, and ports inside a transaction.

The application never imports infrastructure or interfaces; it declares what it needs from
the outside world in ``ports`` and receives implementations from the entry points.
"""
