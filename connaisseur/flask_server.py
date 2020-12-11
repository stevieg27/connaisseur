import os
import traceback
import logging
from flask import Flask, request, jsonify
from requests.exceptions import HTTPError
from connaisseur.exceptions import (
    BaseConnaisseurException,
    UnknownVersionError,
    AlertSendingError,
)
from connaisseur.mutate import admit, validate
from connaisseur.notary_api import health_check
from connaisseur.admission_review import get_admission_review
import connaisseur.kube_api as api
from connaisseur.alert import send_alerts, AlertCategories

DETECTION_MODE = os.environ.get("DETECTION_MODE", "0") == "1"

APP = Flask(__name__)
"""
Flask Server that admits the request send to the k8s cluster, validates it and
sends its response back.
"""


@APP.errorhandler(AlertSendingError)
def handle_alert_sending_failure(err):
    logging.error(err.message)
    return err.message, 500


@APP.route("/mutate", methods=["POST"])
def mutate():
    """
    Handles the '/mutate' path and accepts CREATE and UPDATE requests.
    Sends its response back, which either denies or allows the request.
    """

    admission_request = request.json
    try:
        validate(admission_request)
        response = admit(admission_request)
    except BaseConnaisseurException as err:
        send_alerts(AlertCategories.rejected.value, admission_request)
        logging.error(str(err))
        return jsonify(
            get_admission_review(
                admission_request["request"]["uid"],
                False,
                msg=err.user_msg,
                detection_mode=DETECTION_MODE,
            )
        )
    except UnknownVersionError as err:
        send_alerts(AlertCategories.rejected.value, admission_request)
        logging.error(str(err))
        return jsonify(
            get_admission_review(
                admission_request["request"]["uid"],
                False,
                msg=str(err),
                detection_mode=DETECTION_MODE,
            )
        )
    except Exception:
        send_alerts(AlertCategories.rejected.value, admission_request)
        logging.error(traceback.format_exc())
        return jsonify(
            get_admission_review(
                admission_request["request"]["uid"],
                False,
                msg="unknown error. please check the logs.",
                detection_mode=DETECTION_MODE,
            )
        )
    send_alerts(AlertCategories.admitted.value, admission_request)
    return jsonify(response)


# health probe
@APP.route("/health", methods=["GET", "POST"])
def healthz():
    """
    Handles the '/health' endpoint and checks the health status of the flask
    server. Sends back either '200' for a healthy status or '500'
    otherwise.
    """
    return ("", 200)


# readiness probe
@APP.route("/ready", methods=["GET", "POST"])
def readyz():
    """
    Handles the '/ready' endpoint and checks the health status of the configured notary
    server and whether the webhook is installed or not. If the notary is available and the
    webhook is installed it returns a 200 status code. Otherwise should one of them not be
    reachable, 500 is returned. For installation purposes, the readiness probe first
    checks whether a specific bootstrap pod (called sentinel) is running in the namespace.
    If this pod can be found and is still running, the readiness probe automatically
    returns 200. This bootstrap pod will only run for the first 30 seconds after
    installation or until the webhook is installed, after which the pod gets immediately
    deleted. From there on the readiness probe checks the notary server and webhook as
    usual.
    """
    sentinel = os.environ.get("CONNAISSEUR_SENTINEL")
    sentinel_ns = os.environ.get("CONNAISSEUR_NAMESPACE")
    sentinel_path = "api/v1/namespaces/{ns}/pods/{name}".format(
        ns=sentinel_ns, name=sentinel
    )

    try:
        sentinel_response = api.request_kube_api(sentinel_path)
    except HTTPError:
        sentinel_response = {}

    sentinel_running = sentinel_response.get("status", {}).get("phase") == "Running"

    # create api path for the webhook configuration
    webhook = os.environ.get("CONNAISSEUR_WEBHOOK")
    webhook_path = (
        "apis/admissionregistration.k8s.io/v1beta1/mutatingwebhookconfigurations/{name}"
    ).format(name=webhook)

    try:
        webhook_response = api.request_kube_api(webhook_path)
    except HTTPError:
        webhook_response = None

    notary_health = health_check(os.environ.get("NOTARY_SERVER"))

    return (
        ("", 200)
        if ((webhook_response or sentinel_running) and notary_health)
        else ("", 500)
    )
