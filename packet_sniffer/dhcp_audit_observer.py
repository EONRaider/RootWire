#!/usr/bin/env python3
"""
Observer that records DHCP traffic during live capture.

The class follows the same ``Output`` contract as :class:`output.OutputToScreen`
so it can be registered on :class:`core.PacketSniffer` without changing the core
capture loop.
"""

from __future__ import annotations

from typing import List, Optional

from dhcp_alerts import Alert, DhcpObservation, analyze_observations, format_observation_line
from dhcp_audit_runner import render_report_json, render_report_text
from dhcp_integration import observation_from_decoder_frame
from output import Output


class DhcpAuditObserver(Output):
    """
    Accumulate DHCP-related observations while the sniffer is running.

    At shutdown (Ctrl+C) :meth:`finalize` should be invoked so alerts can be
    computed — :meth:`core.PacketSniffer.finalize_observers` performs this
    automatically from the CLI.
    """

    def __init__(
        self,
        subject,
        *,
        observation_window_seconds: Optional[float] = None,
        json_on_exit: bool = False,
        verbose: bool = False,
    ) -> None:
        """
        Register this observer on ``subject`` (a :class:`core.PacketSniffer`).

        :param subject: The sniffer whose ``register`` hook will store ``self``.
        :param observation_window_seconds: Optional trailing window (seconds)
            applied when computing H1/H2 after capture stops. ``None`` analyses
            the full trace (recommended for short lab captures).
        :param json_on_exit: Emit JSON from :meth:`finalize` instead of text.
        :param verbose: Print each matching DHCP datagram as it arrives (can be
            noisy on busy networks).
        """
        super().__init__(subject)
        self._observation_window_seconds = observation_window_seconds
        self._json_on_exit = json_on_exit
        self._verbose = verbose
        self._observations: List[DhcpObservation] = []

    def update(self, frame, *args, **kwargs) -> None:
        """
        Handle a decoded frame emitted by :class:`core.Decoder`.

        Non-DHCP traffic is ignored. DHCP payloads are parsed immediately so
        parse errors (H3) still retain Ethernet/IP metadata even if the BOOTP
        portion is corrupt.
        """
        observation = observation_from_decoder_frame(frame)
        if observation is None:
            return
        self._observations.append(observation)
        if self._verbose:
            print(format_observation_line(observation))

    def finalize(self) -> None:
        """
        Run heuristics and print the audit report.

        Safe to call multiple times (subsequent calls re-print using the same
        buffered observations).
        """
        alerts = analyze_observations(
            self._observations,
            observation_window_seconds=self._observation_window_seconds,
        )
        if self._json_on_exit:
            print(render_report_json(self._observations, alerts))
            return

        render_report_text(
            self._observations,
            alerts,
            include_observations=not self._verbose,
        )
