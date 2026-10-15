from backend.app.ingester import WazuhIndexerClient, normalize_wazuh_alert


def test_wazuh_indexer_client_searches_alert_index(monkeypatch):
    captured = {}

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "hits": {
                    "hits": [
                        {
                            "_id": "indexer-document-id",
                            "_source": {"id": "source-alert-id", "rule": {"id": "5710"}},
                        }
                    ]
                }
            }

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr("backend.app.ingester.httpx.post", fake_post)
    alerts = WazuhIndexerClient().get_alerts(limit=7)

    assert captured["url"].endswith("/wazuh-alerts-*/_search")
    assert captured["json"]["size"] == 7
    assert captured["json"]["sort"] == [{"timestamp": {"order": "desc"}}]
    assert alerts == [
        {"id": "source-alert-id", "rule": {"id": "5710"}, "_id": "indexer-document-id"}
    ]


def test_wazuh_normalization_produces_stable_reference():
    source_alert = {
        "id": "source-alert-id",
        "timestamp": "2026-10-15T12:00:00Z",
        "agent": {"name": "web-01", "ip": "10.0.0.8", "os": {"name": "Ubuntu"}},
        "rule": {"id": "5710", "level": 10, "description": "SSH authentication failure"},
        "full_log": "Failed SSH login",
    }

    first = normalize_wazuh_alert(source_alert)
    second = normalize_wazuh_alert(source_alert)

    assert first["alert_ref"] == second["alert_ref"]
    assert first["alert_ref"].startswith("AL-")
    assert len(first["alert_ref"]) == 32
    assert first["source"] == "wazuh"
    assert first["agent_name"] == "web-01"
    assert first["wazuh_rule_id"] == "5710"