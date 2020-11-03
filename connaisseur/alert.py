import os
import json
import logging
from datetime import datetime
from string import Template
from enum import Enum
import requests
from connaisseur.exceptions import AlertSendingError
from connaisseur.mutate import get_container_specs
from connaisseur.policy import ImagePolicy
from connaisseur.image import Image


class Alert:
    """
    Class to store image information about an alert as attributes and a sending functionality as method.
    Alert Sending can, depending on the configuration, throw an AlertSendingError causing Connaisseur
    responding with status code 500 to the request that was sent for admission control,
    causing a Kubernetes Error event.
    """

    connaisseur_pod_id: str
    cluster: str
    timestamp: int

    request_id: str
    images: list

    template: str
    receiver_url: str
    payload: dict
    headers: dict

    alert_message: str
    priority: int

    def __init__(self, alert_message, receiver_config, admission_request):
        self.alert_message = alert_message
        self.admission_request = admission_request
        self.receiver_url = receiver_config["receiver_url"]
        self.throw_if_alert_sending_fails = receiver_config[
            "fail_if_alert_sending_fails"
        ]
        self.payload = self._construct_payload(receiver_config)
        self.headers = get_headers(receiver_config)
        self.template = receiver_config["template"]

    def _construct_payload(self, receiver_config):
        with open(
            "{}/{}".format(os.getenv("ALERT_CONFIG_DIR"), receiver_config["template"]),
            "r",
        ) as templatefile:
            template = str(templatefile.read())
            payload = json.loads(template)
            if receiver_config.get("payload_fields") is not None:
                payload.update(receiver_config.get("payload_fields"))
            payload = json.dumps(payload)
            payload = Template(payload).substitute(
                alert_message=self.alert_message,
                priority=str(receiver_config["priority"]),
                connaisseur_pod_id=os.getenv("POD_NAME"),
                cluster=load_config()["cluster_name"],
                timestamp=datetime.now(),
                request_id=self.admission_request["request"]["uid"],
                images=str(get_images(self.admission_request)),
            )
        return payload

    def send_alert(self):
        policy = ImagePolicy()
        if not any(
            [
                policy.get_matching_rule(Image(image)).get("verify", True)
                for image in get_images(self.admission_request)
            ]
        ):
            return
        try:
            response = requests.post(
                self.receiver_url, data=self.payload, headers=self.headers
            )
            response.raise_for_status()
            logging.info("sent alert to %s", self.template.split("_")[0])
        except Exception as err:
            if self.throw_if_alert_sending_fails:
                raise AlertSendingError(str(err))
            logging.error(err)
        return response


class AlertCategories(Enum):
    admitted = "admit_request"
    rejected = "reject_request"


def load_config():
    with open(
        "{}/alertconfig.json".format(os.getenv("ALERT_CONFIG_DIR")), "r"
    ) as configfile:
        config = json.loads(configfile.read())
    return config


def get_images(admission_request):
    relevant_spec = get_container_specs(admission_request["request"]["object"])
    images = [container["image"] for container in relevant_spec]
    return images


def get_headers(receiver_config):
    headers = {"Content-Type": "application/json"}
    additional_headers = receiver_config.get("custom_headers")
    if additional_headers is not None:
        headers.update(json.loads(additional_headers))
    return headers


def send_alerts(event_category, admission_request):
    alert_config = load_config()
    if alert_config.get(event_category) is not None:
        for receiver in alert_config[event_category]["templates"]:
            alert = Alert(
                alert_config[event_category]["message"], receiver, admission_request
            )
            alert.send_alert()
