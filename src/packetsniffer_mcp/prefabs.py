"""Prefab-UI card builders."""

from __future__ import annotations

from prefab_ui.components import Badge, Card, Metric, Row


def build_status_card(payload: dict) -> Card:
    healthy = payload.get("healthy", True)
    return Card(
        title="PacketsnifferMcp Status",
        badges=[Badge(label="Healthy" if healthy else "Degraded")],
        children=[
            Row(
                children=[
                    Metric(label="Version", value=str(payload.get("version", "0.1.0"))),
                    Metric(label="Tools", value=str(payload.get("tool_count", "-"))),
                ]
            )
        ],
    )
