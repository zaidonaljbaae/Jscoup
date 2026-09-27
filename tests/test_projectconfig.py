# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Tests for jscoup.projectconfig — the config file that drives JSCoup.from_config_file()."""

import json

from jscoup import projectconfig


def test_creates_file_with_generated_password_on_first_load(tmp_path):
    path = str(tmp_path / ".jscoup.config.json")
    assert not (tmp_path / ".jscoup.config.json").exists()

    config = projectconfig.load_or_create(path)

    assert (tmp_path / ".jscoup.config.json").exists()
    assert config.dashboard_username == "admin"
    assert config.dashboard_password  # a real, non-empty generated password
    assert config.database_url is None  # SQLite fallback, not a real DB
    assert config.features["gateway"] is False


def test_reload_returns_the_same_settings(tmp_path):
    path = str(tmp_path / ".jscoup.config.json")
    first = projectconfig.load_or_create(path)

    second = projectconfig.load_or_create(path)

    assert second.dashboard_password == first.dashboard_password
    assert second.service_name == first.service_name


def test_existing_file_is_never_overwritten(tmp_path):
    path = str(tmp_path / ".jscoup.config.json")
    projectconfig.load_or_create(path)
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    data["service_name"] = "hand-edited-name"
    data["database_url"] = "postgresql+psycopg://user:pass@host/db"
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)

    config = projectconfig.load_or_create(path)

    assert config.service_name == "hand-edited-name"
    assert config.database_url == "postgresql+psycopg://user:pass@host/db"


def test_from_dict_fills_in_missing_features_with_defaults():
    config = projectconfig.ProjectConfig.from_dict({"service_name": "x", "features": {"gateway": True}})

    assert config.service_name == "x"
    assert config.features["gateway"] is True
    assert config.features["live_tester"] is True  # default, not present in the input dict
