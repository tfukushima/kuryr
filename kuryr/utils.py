# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from flask import Flask, jsonify
from neutronclient.common.exceptions import NeutronClientException
from werkzeug.exceptions import default_exceptions
from werkzeug.exceptions import HTTPException


# Return all errors as JSON. From http://flask.pocoo.org/snippets/83/
def make_json_app(import_name, **kwargs):
    """Creates a JSON-oriented Flask app.

    All error responses that you don't specifically manage yourself will have
    application/json content type, and will contain JSON that follows the
    libnetwork remote driver protocol.


    { "Err": "405: Method Not Allowed" }


    See:
      - https://github.com/docker/libnetwork/blob/3c8e06bc0580a2a1b2440fe0792fbfcd43a9feca/docs/remote.md#errors  # noqa
    """
    def make_json_error(ex):
        response = jsonify({"Err": str(ex)})
        response.status_code = (ex.code if isinstance(ex, HTTPException)
                                else ex.status_code
                                if isinstance(ex, NeutronClientException)
                                else 500)
        content_type = 'application/vnd.docker.plugins.v1+json; charset=utf-8'
        response.headers['Content-Type'] = content_type
        return response

    app = Flask(import_name, **kwargs)

    for code in default_exceptions.iterkeys():
        app.error_handler_spec[None][code] = make_json_error

    return app


class KuryrException(Exception):
    """Default Kuryr exception"""

    def __init__(self, msg):
        """
        :param msg: the message for the cause of the exception
        """
        self.msg = msg

    def __repr__(self):
        return repr(self.msg)


class DuplicatedResourceException(KuryrException):
    """Exception represents there're multiple resources for the ID.

    This exception is thrown when you query the Neutron resouce associated with
    the ID and you get multiple resources.
    """
