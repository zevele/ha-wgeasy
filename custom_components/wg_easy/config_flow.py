from __future__ import annotations

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_TOKEN, CONF_URL
from homeassistant.core import callback

from .const import DEFAULT_ONLINE_TIMEOUT_SECONDS, DEFAULT_POLL_INTERVAL, DOMAIN


class WGEasyConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 2

    async def async_step_user(self, user_input=None):
        errors = {}

        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_URL])
            self._abort_if_unique_id_configured()

            return self.async_create_entry(
                title="WG Easy",
                data=user_input,
            )

        return self.async_show_form(
            step_id="user",
            data_schema=self._build_schema(),
            errors=errors,
        )

    async def async_step_reconfigure(self, user_input=None):
        entry = self._get_reconfigure_entry()

        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_URL])
            self._abort_if_unique_id_mismatch(reason="wrong_account")

            return self.async_update_reload_and_abort(
                entry,
                unique_id=user_input[CONF_URL],
                data_updates={
                    CONF_URL: user_input[CONF_URL],
                    CONF_TOKEN: user_input[CONF_TOKEN],
                },
            )

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self._build_schema(entry.data),
        )

    def _build_schema(self, data=None):
        data = data or {}
        return vol.Schema(
            {
                vol.Required(CONF_URL, default=data.get(CONF_URL, "")): str,
                vol.Required(CONF_TOKEN, default=data.get(CONF_TOKEN, "")): str,
            }
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return WGEasyOptionsFlow(config_entry)


class WGEasyOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, config_entry):
        self._config_entry = config_entry

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        data_schema = vol.Schema(
            {
                vol.Required(
                    "poll_interval",
                    default=self._config_entry.options.get(
                        "poll_interval", DEFAULT_POLL_INTERVAL
                    ),
                ): vol.All(vol.Coerce(int), vol.Range(min=5)),
                vol.Required(
                    "online_timeout_seconds",
                    default=self._config_entry.options.get(
                        "online_timeout_seconds", DEFAULT_ONLINE_TIMEOUT_SECONDS
                    ),
                ): vol.All(vol.Coerce(int), vol.Range(min=1)),
            }
        )

        return self.async_show_form(step_id="init", data_schema=data_schema)
