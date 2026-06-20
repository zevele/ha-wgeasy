from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_URL
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr

from .const import DEFAULT_POLL_INTERVAL, DOMAIN, PLATFORMS
from .coordinator import WGEasyCoordinator


type WGEasyConfigEntry = ConfigEntry[WGEasyCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: WGEasyConfigEntry) -> bool:
    coordinator = WGEasyCoordinator(
        hass,
        config_entry_id=entry.entry_id,
        url=entry.data[CONF_URL],
        password=entry.data[CONF_PASSWORD],
        poll_interval=entry.options.get("poll_interval", DEFAULT_POLL_INTERVAL),
    )

    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception as err:
        raise ConfigEntryNotReady(f"Unable to connect to WG Easy: {err}") from err

    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: WGEasyConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_config_entry_device(
    hass: HomeAssistant,
    entry: WGEasyConfigEntry,
    device_entry: dr.DeviceEntry,
) -> bool:
    coordinator = entry.runtime_data
    active_client_keys = {
        client["publicKey"] for client in coordinator.data.get("clients", [])
    }

    return not any(
        identifier
        for identifier in device_entry.identifiers
        if identifier[0] == DOMAIN and identifier[1] in active_client_keys
    )
