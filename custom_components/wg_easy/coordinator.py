from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from aiohttp import ClientError

from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util
from homeassistant.util.json import json_loads 

from .const import DEFAULT_POLL_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)


class WGEasyCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    def __init__(
        self,
        hass,
        *,
        config_entry_id: str,
        url: str,
        password: str,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=poll_interval),
        )
        self.url = url
        self.password = password
        self.config_entry_id = config_entry_id
        self.session = async_get_clientsession(hass)
        self._known_client_keys: set[str] = set()
        self.peer_map: dict[str, dict[str, Any]] = {}
        self._previous_counters: dict[str, tuple[datetime, int, int]] = {}
        self.session_cookie = None
        self.last_response = None
        self.last_data = None

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from the wg-easy API endpoints."""
        base_url = self.url.rstrip("/")
        session_url = f"{base_url}/api/session"
        data_url = f"{base_url}/api/wireguard/client"

        try:
            if not self.session_cookie:
                login_payload = {"password": self.password}
                async with self.session.post(session_url, json=login_payload) as login_resp:
                    if login_resp.status != 200:
                        raise UpdateFailed(f"Login failed with status {login_resp.status}")

                    login_data = await login_resp.json()
                    if not login_data.get("success"):
                        raise UpdateFailed("wg-easy rejected the password configuration")

                    self.session_cookie = login_resp.cookies.get("connect.sid")

            headers = {"Accept": "application/json"}
            cookies = {}
            if self.session_cookie:
                cookies["connect.sid"] = self.session_cookie.value

            async with self.session.get(data_url, headers=headers, cookies=cookies) as response:
                if response.status == 401:
                    self.session_cookie = None
                    raise UpdateFailed("Unauthorized - Session expired, retrying next poll")

                if response.status >= 400:
                    body = await response.text()
                    raise UpdateFailed(f"HTTP {response.status}: {body[:200]}")

                data = await self._get_data(response)

        except ClientError as err:
            raise UpdateFailed(f"Request failed: {err}") from err
        except ValueError as err:
            raise UpdateFailed(f"Invalid JSON response: {err}") from err

        self.peer_map = {client["id"]: client for client in data["clients"]}
        if set(self.peer_map) != self._known_client_keys:
            self._remove_stale_devices(set(self.peer_map))
        return data

    async def _get_data(self, response):
        current_raw_response = await response.read()
        
        if current_raw_response != self.last_response or self.last_data is None:
            self.last_response = current_raw_response
            payload = await response.json(loads=json_loads)
            self.last_data = self._normalize_payload(payload)
        else:
            if (self.last_data == None):
                self.last_data = self._normalize_payload(None)
            now = dt_util.utcnow()
            for client_id in self._previous_counters:
                _, rx, tx = self._previous_counters[client_id]
                self._previous_counters[client_id] = (now, rx, tx)
        return self.last_data


    def _normalize_payload(self, payload: Any) -> dict[str, Any]:
        """Normalize payload to handle direct array structures from server."""
        if isinstance(payload, list):
            clients = payload
            base_payload = {}
        elif isinstance(payload, dict):
            clients = payload.get("clients") or []
            base_payload = payload
        else:
            clients = []
            base_payload = {}

        now = dt_util.utcnow()
        normalized_clients: list[dict[str, Any]] = []
        next_previous_counters: dict[str, tuple[datetime, int, int]] = {}

        for client in clients:
            client_id = client.get("id") or client.get("publicKey")
            if not client_id:
                continue

            transfer_rx = int(client.get("transferRx") or 0)
            transfer_tx = int(client.get("transferTx") or 0)
            transfer_rx_rate = 0.0
            transfer_tx_rate = 0.0

            previous = self._previous_counters.get(client_id)
            if previous is not None:
                previous_time, previous_rx, previous_tx = previous
                elapsed = (now - previous_time).total_seconds()
                if elapsed > 0:
                    rx_delta = transfer_rx - previous_rx
                    tx_delta = transfer_tx - previous_tx
                    transfer_rx_rate = max(0.0, rx_delta / elapsed)
                    transfer_tx_rate = max(0.0, tx_delta / elapsed)

            next_previous_counters[client_id] = (now, transfer_rx, transfer_tx)

            # Modern IP layout extraction fallback map
            allowed_ips = client.get("allowedIps") or []
            inferred_ip = allowed_ips[0] if isinstance(allowed_ips, list) and allowed_ips else None

            ipv4_val = client.get("address") or client.get("ipv4Address") or inferred_ip

            # HANDSHAKE TIME CONVERSION EXTRACTION: Track absolute duration in seconds
            latest_handshake = client.get("latestHandshakeAt")

            normalized_clients.append(
                {
                    **client,
                    "id": client_id,
                    "publicKey": client_id,
                    "name": client.get("name") or client_id[:8],
                    "transferRx": transfer_rx,
                    "transferTx": transfer_tx,
                    "transferRxRate": round(transfer_rx_rate, 2),
                    "transferTxRate": round(transfer_tx_rate, 2),
                    "ipv4Address": ipv4_val,
                    "ipv6Address": client.get("ipv6Address") or None,
                    "enabled": bool(client.get("enabled", False)),
                    "latestHandshakeAt": latest_handshake,
                }
            )

        self._previous_counters = next_previous_counters

        return {
            **base_payload,
            "clients": normalized_clients,
            "wireguard_configured_peers": base_payload.get(
                "wireguard_configured_peers", len(normalized_clients)
            ),
            "wireguard_enabled_peers": base_payload.get(
                "wireguard_enabled_peers",
                sum(1 for client in normalized_clients if client["enabled"]),
            ),
            "wireguard_connected_peers": base_payload.get(
                "wireguard_connected_peers",
                sum(
                    1
                    for client in normalized_clients
                    if client["latestHandshakeAt"] is not None
                ),
            ),
        }

    def _remove_stale_devices(self, current_client_keys: set[str]) -> None:
        stale_client_keys = self._known_client_keys - current_client_keys
        if not stale_client_keys:
            self._known_client_keys = current_client_keys
            return

        device_registry = dr.async_get(self.hass)

        for client_key in stale_client_keys:
            device = device_registry.async_get_device(identifiers={(DOMAIN, client_key)})
            if device is not None:
                device_registry.async_update_device(
                    device_id=device.id,
                    remove_config_entry_id=self.config_entry_id,
                )
            self._previous_counters.pop(client_key, None)

        self._known_client_keys = current_client_keys
