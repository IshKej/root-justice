"""2:1 Autonomous Defender Swarm Coordinator.

For every detected Artex attacker stream (1), spawns two specialized defender agents (2):
  1. Containment & Virtual-Patch Agent: blocks IPs, patches probed paths, triggers 429/tarpits.
  2. Attribution, REA & Evidence Agent: logs origin IPs, runs RDAP/ASN & REA static analysis,
     and prepares STIX 2.1 / FBI IC3 / CISA reporting records.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .shield import DetectionResult, RequestEvent, VirtualPatchRegistry


@dataclass
class AgentPair:
    """Represents the 2 defender agents assigned to 1 attacker stream."""

    stream_id: str
    containment_agent_id: str
    attribution_agent_id: str
    actions_taken: List[str] = field(default_factory=list)
    evidence_records: List[Dict[str, Any]] = field(default_factory=list)


class DefenderSwarmCoordinator:
    """Maintains a strict 2:1 defender-to-attacker agent ratio per detected stream."""

    def __init__(
        self,
        patches: VirtualPatchRegistry,
        attribution_hook: Optional[Callable[[RequestEvent, DetectionResult], Dict[str, Any]]] = None,
    ) -> None:
        self.patches = patches
        self.attribution_hook = attribution_hook
        self.active_pairs: Dict[str, AgentPair] = {}

    def ensure_pair(self, stream_id: str) -> AgentPair:
        if stream_id not in self.active_pairs:
            self.active_pairs[stream_id] = AgentPair(
                stream_id=stream_id,
                containment_agent_id=f"contain-{stream_id}",
                attribution_agent_id=f"attrib-{stream_id}",
            )
        return self.active_pairs[stream_id]

    async def _run_containment_agent(
        self,
        pair: AgentPair,
        event: RequestEvent,
        detection: DetectionResult,
    ) -> str:
        """Agent 1 of 2: virtual-patch the exact probed path and contain the attributed IP."""
        # Attribute to the resolved origin (socket peer inward), not the spoofable
        # leftmost X-Forwarded-For value.
        primary_ip = detection.attributed_ip or (
            event.forwarded_for[0] if event.forwarded_for else event.remote_ip
        )
        exact_path = event.path.split("?")[0] or "/"

        if detection.recommended_action in ("block", "tarpit"):
            self.patches.block_ip(primary_ip, ",".join(detection.reasons))
            action = f"[{pair.containment_agent_id}] blocked IP {primary_ip} & enforced {detection.recommended_action}"
        elif exact_path == "/":
            # Never install a site-wide patch from a single probe to root.
            self.patches.block_ip(primary_ip, ",".join(detection.reasons))
            action = f"[{pair.containment_agent_id}] contained IP {primary_ip} (root probe; no site-wide patch)"
        else:
            self.patches.add_virtual_patch(exact_path, ",".join(detection.reasons))
            action = f"[{pair.containment_agent_id}] virtual-patched '{exact_path}' + 429 backoff trap"

        pair.actions_taken.append(action)
        return action

    async def _run_attribution_agent(
        self,
        pair: AgentPair,
        event: RequestEvent,
        detection: DetectionResult,
    ) -> Dict[str, Any]:
        """Agent 2 of 2: record chain-of-custody, origin IPs, and optional RDAP/REA enrichment."""
        origin_ip = detection.attributed_ip or (
            event.forwarded_for[0] if event.forwarded_for else event.remote_ip
        )
        record: Dict[str, Any] = {
            "agent_id": pair.attribution_agent_id,
            "stream_id": pair.stream_id,
            "timestamp_utc": event.timestamp_utc,
            "origin_ip": origin_ip,
            "attributed_confidence": detection.attributed_confidence,
            "is_reportable": detection.is_reportable,
            "ip_chain": detection.origin_chain or event.forwarded_for or [event.remote_ip],
            "method": event.method,
            "path": event.path,
            "user_agent": event.user_agent,
            "body_sha256": event.body_sha256,
            "severity": detection.severity,
            "reasons": detection.reasons,
            # Order-preserving client header fingerprint when the request path
            # attached one (empty otherwise); lets analysts cluster a toolkit
            # across rotating source IPs. getattr keeps older DetectionResults safe.
            "client_fingerprint": getattr(detection, "client_fingerprint", ""),
        }
        if self.attribution_hook is not None:
            record["enrichment"] = self.attribution_hook(event, detection)
        pair.evidence_records.append(record)
        return record

    async def dispatch(self, event: RequestEvent, detection: DetectionResult) -> Optional[AgentPair]:
        """Dispatch 2 defender agents in parallel for 1 flagged attacker stream."""
        if not detection.flagged:
            return None
        pair = self.ensure_pair(detection.stream_id)
        await asyncio.gather(
            self._run_containment_agent(pair, event, detection),
            self._run_attribution_agent(pair, event, detection),
        )
        return pair

    def swarm_ratio(self) -> Dict[str, int]:
        attacker_streams = len(self.active_pairs)
        defender_agents = attacker_streams * 2
        return {
            "attacker_streams": attacker_streams,
            "defender_agents": defender_agents,
            "ratio": 2 if attacker_streams > 0 else 0,
        }
