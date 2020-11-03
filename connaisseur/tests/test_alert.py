import pytest
from datetime import datetime, timedelta
import json
from connaisseur.alert import Alert, send_alerts
from connaisseur.exceptions import AlertSendingError
from connaisseur.policy import ImagePolicy

with open("tests/data/ad_request_deployments.json", "r") as readfile:
    admission_request_deployment = json.load(readfile)

with open("tests/data/ad_request_init_allowlisted.json", "r") as readfile:
    admission_request_allowlisted = json.load(readfile)

opsgenie_receiver_config_throw = {
    "custom_headers": '{"Authorization": "GenieKey 12345678-abcd-2222-3333-1234567890ef"}',
    "fail_if_alert_sending_fails": True,
    "payload_fields": {
        "responders": [{"type": "user", "username": "testuser@testcompany.de"}],
        "tags": ["image_deployed"],
        "visibleTo": [{"type": "user", "username": "testuser@testcompany.de"}],
    },
    "priority": 4,
    "receiver_url": "https://api.eu.opsgenie.com/v2/alerts",
    "template": "opsgenie_template",
}

opsgenie_receiver_config_reject = {
    "custom_headers": '{"Authorization": "GenieKey 12345678-abcd-2222-3333-1234567890ef"}',
    "fail_if_alert_sending_fails": False,
    "payload_fields": {
        "responders": [{"type": "user", "username": "testuser@testcompany.de"}],
        "tags": ["image_rejected"],
        "visibleTo": [{"type": "user", "username": "testuser@testcompany.de"}],
    },
    "priority": 4,
    "receiver_url": "https://api.eu.opsgenie.com/v2/alerts",
    "template": "opsgenie_template",
}

slack_receiver_config = {
    "fail_if_alert_sending_fails": False,
    "priority": 3,
    "receiver_url": "https://hooks.slack.com/services/A0123456789/ABCDEFGHIJ/HFb3Gs7FFscjQNJYWHGY7GPV",
    "template": "slack_template",
}

keybase_receiver_config = {
    "custom_headers": "{'Content-Language': 'de-DE'}",
    "fail_if_alert_sending_fails": True,
    "priority": 3,
    "receiver_url": "https://bots.keybase.io/webhookbot/IFP--tpV2wBxEP3ArYx4gVS_B-0",
    "template": "keybase_template",
}

alert_headers = {
    "Content-Type": "application/json",
    "Authorization": "GenieKey 12345678-abcd-2222-3333-1234567890ef",
}

alert_payload_deployment = {
    "message": "CONNAISSEUR admitted a request",
    "alias": "CONNAISSEUR admitted a request to deploy the images ['securesystemsengineering/alice-image:test'].",
    "description": "CONNAISSEUR admitted a request to deploy the following images:\n ['securesystemsengineering/alice-image:test'] \n\n Please check the logs of the `connaisseur-pod-123` for more details.",
    "responders": [{"type": "user", "username": "testuser@testcompany.de"}],
    "visibleTo": [{"type": "user", "username": "testuser@testcompany.de"}],
    "actions": [],
    "tags": ["image_deployed"],
    "details": {
        "pod": "connaisseur-pod-123",
        "cluster": "minikube",
        "alert_created": datetime.now(),
        "request_id": "3a3a7b38-5512-4a85-94bb-3562269e0a6a",
    },
    "entity": "Connaisseur",
    "priority": "P4",
}


@pytest.fixture
def mock_env_vars(monkeypatch):
    monkeypatch.setenv("ALERT_CONFIG_DIR", "tests/data/alerting")
    monkeypatch.setenv("POD_NAME", "connaisseur-pod-123")


@pytest.fixture
def mock_image_policy(monkeypatch):
    def read_policy():
        with open("tests/data/imagepolicy.json") as readfile:
            policy = json.load(readfile)
            return policy["spec"]

    monkeypatch.setattr(ImagePolicy, "JSON_SCHEMA_PATH", "res/policy_schema.json")
    monkeypatch.setattr(ImagePolicy, "get_image_policy", read_policy)


@pytest.mark.parametrize(
    "message, receiver_config, admission_request, alert_payload",
    [
        (
            "CONNAISSEUR admitted a request",
            opsgenie_receiver_config_throw,
            admission_request_deployment,
            alert_payload_deployment,
        ),
    ],
)
def test_alert(
    mock_env_vars,
    message: str,
    receiver_config: dict,
    admission_request: dict,
    alert_payload: dict,
):
    alert = Alert(message, receiver_config, admission_request)
    assert alert.throw_if_alert_sending_fails is True
    assert alert.receiver_url == "https://api.eu.opsgenie.com/v2/alerts"
    assert alert.headers == alert_headers
    payload = json.loads(alert.payload)
    assert payload["details"]["alert_created"] is not None
    assert datetime.strptime(
        payload["details"]["alert_created"], "%Y-%m-%d %H:%M:%S.%f"
    ) > datetime.now() - timedelta(seconds=30)
    payload["details"].pop("alert_created")
    alert_payload["details"].pop("alert_created")
    assert payload == alert_payload


@pytest.mark.parametrize(
    "message, receiver_config, admission_request",
    [
        (
            "CONNAISSEUR admitted a request",
            opsgenie_receiver_config_throw,
            admission_request_deployment,
        ),
        (
            "CONNAISSEUR admitted a request",
            opsgenie_receiver_config_reject,
            admission_request_deployment,
        ),
    ],
)
def test_alert_sending_error(
    requests_mock,
    capfd,
    caplog,
    mock_env_vars,
    mock_image_policy,
    message: str,
    receiver_config: dict,
    admission_request: dict,
):
    requests_mock.post(
        "https://api.eu.opsgenie.com/v2/alerts",
        text="401 Client Error: Unauthorized for url: https://api.eu.opsgenie.com/v2/alerts",
        status_code=401,
    )
    alert = Alert(message, receiver_config, admission_request)
    with pytest.raises(Exception):
        alert.send_alert()
        if alert.throw_if_alert_sending_fails is True:
            out, err = capfd.readouterr()
            with pytest.raises(AlertSendingError) as alert_error:
                assert (
                    "401 Client Error: Unauthorized for url: https://api.eu.opsgenie.com/v2/alerts"
                    in str(alert_error)
                )
                assert AlertSendingError(alert_error) == err
        else:
            assert (
                "401 Client Error: Unauthorized for url: https://api.eu.opsgenie.com/v2/alerts"
                in caplog.text
            )


@pytest.mark.parametrize(
    "message, receiver_config, admission_request",
    [
        (
            "CONNAISSEUR admitted a request",
            opsgenie_receiver_config_reject,
            admission_request_deployment,
        )
    ],
)
def test_alert_sending(
    requests_mock,
    caplog,
    mock_env_vars,
    mock_image_policy,
    message: str,
    receiver_config: dict,
    admission_request: dict,
):
    requests_mock.post(
        "https://api.eu.opsgenie.com/v2/alerts",
        json={
            "result": "Request will be processed",
            "took": 0.302,
            "requestId": "43a29c5c-3dbf-4fa4-9c26-f4f71023e120",
        },
        status_code=200,
    )
    alert = Alert(message, receiver_config, admission_request)
    with pytest.raises(Exception):
        response = alert.send_alert()
        assert "sent alert to opsgenie" in caplog.text
        assert response.status_code == 200
        assert response.json.result == "Request will be processed"


@pytest.mark.parametrize(
    "message, receiver_config, admission_request",
    [
        (
            "CONNAISSEUR admitted a request",
            opsgenie_receiver_config_throw,
            admission_request_allowlisted,
        ),
    ],
)
def test_alert_sending_bypass_for_only_whitelisted_images(
    mock_env_vars,
    mock_image_policy,
    message: str,
    receiver_config: dict,
    admission_request: dict,
):
    alert = Alert(message, receiver_config, admission_request)
    assert alert.send_alert() is None


@pytest.mark.parametrize(
    "event_category, admission_request",
    [
        ("admit_request", admission_request_deployment),
        ("reject_request", admission_request_deployment),
    ],
)
def test_send_alerts(
    mock_env_vars, mocker, event_category: str, admission_request: dict
):
    mock_alert = mocker.patch("connaisseur.alert.Alert")
    send_alerts(event_category, admission_request)
    admit_calls = [
        mocker.call(
            "CONNAISSEUR admitted a request",
            opsgenie_receiver_config_throw,
            admission_request_deployment,
        ),
        mocker.call(
            "CONNAISSEUR admitted a request",
            slack_receiver_config,
            admission_request_deployment,
        ),
    ]
    reject_calls = [
        mocker.call(
            "CONNAISSEUR rejected a request",
            opsgenie_receiver_config_reject,
            admission_request_deployment,
        ),
        mocker.call(
            "CONNAISSEUR rejected a request",
            keybase_receiver_config,
            admission_request_deployment,
        ),
    ]
    if event_category == "admit_request":
        assert mock_alert.has_calls(admit_calls)
    elif event_category == "reject_request":
        assert mock_alert.has_calls(reject_calls)

    mocker.resetall()

    mock_alert_sending = mocker.patch(
        "connaisseur.alert.Alert.send_alert", return_value=True
    )
    send_alerts(event_category, admission_request)
    assert mock_alert_sending.has_calls([mocker.call(), mocker.call()])
