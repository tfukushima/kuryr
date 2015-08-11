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

import os

import docker
from docker.utils import check_resource
from flask import jsonify
from flask import request
from neutronclient.common.exceptions import NeutronClientException
from neutronclient.neutron import client

from kuryr import app
from kuryr.constants import SCHEMA
from kuryr.utils import DuplicatedResourceException


OS_URL = os.environ.get('OS_URL', 'http://127.0.0.1:9696/')
OS_TOKEN = os.environ.get('OS_TOKEN', '9999888877776666')

# TODO(tfukushima): Retrieve configuration info from a config file.
app.neutron = client.Client('2.0', endpoint_url=OS_URL, token=OS_TOKEN)
app.neutron.format = 'json'


class ExtendedDockerClient(docker.Client):
    @check_resource
    def inspect_network(self, network):
        return self._result(self._get(
            self._url("/networks/{0}".format(network))), True)

    @check_resource
    def inspect_service(self, service):
        return self._result(self._get(
            self._url("/services/{0}".format(service))), True)

    @check_resource
    def inspect_service_backend(self, service):
        return self._result(self._get(
            self._url("/services/{0}/backend".format(service))), True)


app.docker = ExtendedDockerClient(base_url='unix:///var/run/docker.sock')


@app.route('/Plugin.Activate', methods=['POST'])
def plugin_activate():
    return jsonify(SCHEMA['PLUGIN_ACTIVATE'])


@app.route('/NetworkDriver.CreateNetwork', methods=['POST'])
def network_driver_create_network():
    """Creates a new Neutron Network which name is the given NetworkID.

    This function takes the following JSON data and delegates the actual
    network creation to the Neutron client. libnetwork's NetworkID is used as
    the name of Network in Neutron. ::

        {
            "NetworkID": string,
            "Options": {
                ...
            }
        }

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#create-network  # noqa
    """
    json_data = request.get_json(force=True)

    app.logger.debug("Received JSON data {0} for /NetworkDriver.CreateNetwork"
                     .format(json_data))
    # TODO(tfukushima): Add a validation of the JSON data for the network.
    neutron_network_name = json_data['NetworkID']

    r = app.docker.inspect_network(neutron_network_name)
    app.logger.info("Network info from the Docker daemon: {0}".format(r))

    network = app.neutron.create_network(
        {'network': {'name': neutron_network_name, "admin_state_up": True}})

    app.logger.info("Created a new network with name {0} successfully: {1}"
                    .format(neutron_network_name, network))
    return jsonify(SCHEMA['SUCCESS'])


@app.route('/NetworkDriver.DeleteNetwork', methods=['POST'])
def network_driver_delete_network():
    """Deletes the Neutron Network which name is the given NetworkID.

    This function takes the following JSON data and delegates the actual
    network deletion to the Neutron client. ::

        {
            "NetworkID": string
        }

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#delete-network  # noqa
    """
    json_data = request.get_json(force=True)

    app.logger.debug("Received JSON data {0} for /NetworkDriver.DeleteNetwork"
                     .format(json_data))
    # TODO(tfukushima): Add a validation of the JSON data for the network.
    neutron_network_name = json_data['NetworkID']

    filtered_networks = app.neutron.list_networks(name=neutron_network_name)

    # We assume Neutron's Network names are not conflicted in Kuryr because
    # they are Docker IDs, 256 bits hashed values, which are rarely conflicted.
    # However, if there're multiple networks associated with the single
    # NetworkID, it raises DuplicatedResourceException and stops processes.
    # See the following doc for more details about Docker's IDs:
    #   https://github.com/docker/docker/blob/master/docs/terms/container.md#container-ids  # noqa
    if len(filtered_networks) > 1:
        raise DuplicatedResourceException(
            "Multiple Neutron Networks exist for NetworkID {0}"
            .format(neutron_network_name))
    else:
        neutron_network_id = filtered_networks['networks'][0]['id']
        app.neutron.delete_network(neutron_network_id)
        app.logger.info("Deleted the network with ID {} successfully"
                        .format(neutron_network_id))
        return jsonify(SCHEMA['SUCCESS'])


@app.route('/NetworkDriver.CreateEndpoint', methods=['POST'])
def network_driver_create_endpoint():
    """Creates new Neutron Subnets and a Port with the given EndpointID.

    This function takes the following JSON data and delegates the actual
    endpoint creation to the Neutron client mapping it into Subnet and Port. ::

        {
            "NetworkID": string,
            "EndpointID": string,
            "Options": {
                ...
            },
            "Interfaces": [{
                "ID": int,
                "Address": string,
                "AddressIPv6": string,
                "MacAddress": string
            }, ...]
        }

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#create-endpoint  # noqa
    """
    json_data = request.get_json(force=True)

    app.logger.debug("Received JSON data {0} for /NetworkDriver.CreateEndpoint"
                     .format(json_data))
    # TODO(tfukushima): Add a validation of the JSON data for the subnet.
    neutron_network_name = json_data['NetworkID']
    endpoint_id = json_data['EndpointID']

    filtered_networks = app.neutron.list_networks(name=neutron_network_name)

    if len(filtered_networks) > 1:
        raise DuplicatedResourceException(
            "Multiple Neutron Networks exist for NetworkID {0}"
            .format(neutron_network_name))
    else:
        neutron_network_id = filtered_networks['networks'][0]['id']

        interfaces = json_data['Interfaces']

        response_interfaces = []

        for interface in interfaces:
            # v4 and v6 Subnets for bulk creation.
            subnets = []

            interface_id = interface['ID']
            interface_ipv4 = interface.get('Address', '')
            interface_ipv6 = interface.get('AddressIPv6', '')
            interface_mac = interface['MacAddress']
            if interface_ipv4:
                subnets.append({
                    'name': '-'.join([endpoint_id, str(interface_id), 'v4']),
                    'network_id': neutron_network_id,
                    'ip_version': 4,
                    'cidr': interface_ipv4,
                })
            if interface_ipv6:
                subnets.append({
                    'name': '-'.join([endpoint_id, str(interface_id), 'v6']),
                    'network_id': neutron_network_id,
                    'ip_version': 6,
                    'cidr': interface_ipv6,
                })
            # Bulk create operation of subnets
            created_subnets = app.neutron.create_subnet({'subnets': subnets})

            try:
                port = {
                    'name': '-'.join([endpoint_id, str(interface_id), 'port']),
                    'admin_state_up': True,
                    'mac_address': interface_mac,
                    'network_id': neutron_network_id,
                }
                app.neutron.create_port({'port': port})

                response_interfaces.append({
                    'ID': interface_id,
                    'Address': interface_ipv4,
                    'AddressIPv6': interface_ipv6,
                    'MacAddress': interface_mac
                })
            except NeutronClientException:
                # Rollback the subnets creation
                for subnet in created_subnets['subnets']:
                    app.neutron.delete_subnet(subnet['id'])
                raise

        return jsonify({'Interfaces': response_interfaces})


@app.route('/NetworkDriver.EndpointOperInfo', methods=['POST'])
def network_driver_endpoint_operational_info():
    return jsonify(SCHEMA['ENDPOINT_OPER_INFO'])


@app.route('/NetworkDriver.DeleteEndpoint', methods=['POST'])
def network_driver_delete_endpoint():
    """Deletes Neutron Subnets and a Port with the given EndpointID.

    This function takes the following JSON data and delegates the actual
    endpoint deletion to the Neutron client mapping it into Subnet and Port. ::

        {
            "NetworkID": string,
            "EndpointID": string
        }

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#delete-endpoint  # noqa
    """
    json_data = request.get_json(force=True)
    # TODO(tfukushima): Add a validation of the JSON data for the subnet.
    app.logger.debug("Received JSON data {0} for /NetworkDriver.DeleteEndpoint"
                     .format(json_data))

    neutron_network_name = json_data['NetworkID']
    endpoint_id = json_data['EndpointID']

    filtered_networks = app.neutron.list_networks(name=neutron_network_name)

    if len(filtered_networks) > 1:
        raise DuplicatedResourceException(
            "Multiple Neutron Networks exist for NetworkID {0}"
            .format(neutron_network_name))
    else:
        neutron_network_id = filtered_networks['networks'][0]['id']

        filtered_subnets = app.neutron.list_subnets(
            network_id=neutron_network_id)
        filtered_subnets = [subnet for subnet in filtered_subnets['subnets']
                            if endpoint_id in subnet['name']]
        for subnet in filtered_subnets:
            app.neutron.delete_subnet(subnet['id'])

        try:
            filtered_ports = app.neutron.list_ports(
                network_id=neutron_network_id)
            filtered_ports = [port for port in filtered_ports['ports']
                              if endpoint_id in port['name']]
            for port in filtered_ports:
                app.neutron.delete_port(port['id'])
        except NeutronClientException:
            # Rollback the subnet deletion
            app.neutron.create_subnet(subnet)
            raise

        return jsonify(SCHEMA['SUCCESS'])


@app.route('/NetworkDriver.Join', methods=['POST'])
def network_driver_join():
    return jsonify(SCHEMA['JOIN'])


@app.route('/NetworkDriver.Leave', methods=['POST'])
def network_driver_leave():
    return jsonify(SCHEMA['SUCCESS'])
