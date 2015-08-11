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

import hashlib
import random

from ddt import ddt, data, unpack
from oslo_serialization import jsonutils

from kuryr import app
from kuryr.constants import SCHEMA
from kuryr.tests import base


@ddt
class TestKuryr(base.TestCase):
    """Basic unitests for libnetwork remote driver URI endpoints.

    This test class covers the following HTTP methods and URIs as described in
    the remote driver specification as below:

      https://github.com/docker/libnetwork/blob/3c8e06bc0580a2a1b2440fe0792fbfcd43a9feca/docs/remote.md  # noqa

    - POST /Plugin.Activate
    - POST /NetworkDriver.CreateNetwork
    - POST /NetworkDriver.DeleteNetwork
    - POST /NetworkDriver.CreateEndpoint
    - POST /NetworkDriver.EndpointOperInfo
    - POST /NetworkDriver.DeleteEndpoint
    - POST /NetworkDriver.Join
    - POST /NetworkDriver.Leave
    """
    def setUp(self):
        super(TestKuryr, self).setUp()
        self.app.neutron.format = 'json'

    def tearDown(self):
        super(TestKuryr, self).tearDown()
        self.mox.VerifyAll()
        self.mox.UnsetStubs()

    @data(('/Plugin.Activate', SCHEMA['PLUGIN_ACTIVATE']),
        ('/NetworkDriver.EndpointOperInfo', SCHEMA['ENDPOINT_OPER_INFO']),
        ('/NetworkDriver.DeleteEndpoint', SCHEMA['SUCCESS']),
        ('/NetworkDriver.Join', SCHEMA['JOIN']),
        ('/NetworkDriver.Leave', SCHEMA['SUCCESS']))
    @unpack
    def test_remote_driver_endpoint(self, endpoint, expected):
        response = self.app.post(endpoint)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(expected, decoded_json)

    def test_network_driver_create_network(self):
        docker_network_id = hashlib.sha256(
            str(random.getrandbits(256))).hexdigest()
        self.mox.StubOutWithMock(app.neutron, "create_network")
        fake_request = {
            "network": {
                "name": docker_network_id,
                "admin_state_up": True
            }
        }
        # The following fake response is retrieved from the Neutron doc:
        #   http://developer.openstack.org/api-ref-networking-v2.html#createNetwork  # noqa
        fake_response = {
            "network": {
                "status": "ACTIVE",
                "subnets": [],
                "name": docker_network_id,
                "admin_state_up": True,
                "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
                "router:external": False,
                "segments": [],
                "shared": False,
                "id": "4e8e5957-649f-477b-9e5b-f1f75b21c03c"
            }
        }
        app.neutron.create_network(fake_request).AndReturn(fake_response)

        self.mox.ReplayAll()

        data = {'NetworkID': docker_network_id, 'Options': {}}
        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(SCHEMA['SUCCESS'], decoded_json)

    def test_network_driver_delete_network(self):
        docker_network_id = hashlib.sha256(
            str(random.getrandbits(256))).hexdigest()
        fake_neutron_network_id = "4e8e5957-649f-477b-9e5b-f1f75b21c03c"
        fake_list_response = {
            "networks": [{
                "status": "ACTIVE",
                "subnets": [],
                "name": docker_network_id,
                "admin_state_up": True,
                "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
                "router:external": False,
                "segments": [],
                "shared": False,
                "id": fake_neutron_network_id
            }]
        }

        self.mox.StubOutWithMock(app.neutron, 'list_networks')
        app.neutron.list_networks(
            name=docker_network_id).AndReturn(fake_list_response)
        self.mox.StubOutWithMock(app.neutron, 'delete_network')
        app.neutron.delete_network(fake_neutron_network_id).AndReturn(None)
        self.mox.ReplayAll()

        data = {'NetworkID': docker_network_id}
        response = self.app.post('/NetworkDriver.DeleteNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(SCHEMA['SUCCESS'], decoded_json)

    def _mock_out_network(self, docker_network_id):
        fake_neutron_network_id = "4e8e5957-649f-477b-9e5b-f1f75b21c03c"
        fake_list_response = {
            "networks": [{
                "status": "ACTIVE",
                "subnets": [],
                "name": docker_network_id,
                "admin_state_up": True,
                "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
                "router:external": False,
                "segments": [],
                "shared": False,
                "id": fake_neutron_network_id
            }]
        }
        self.mox.StubOutWithMock(app.neutron, 'list_networks')
        app.neutron.list_networks(
            name=docker_network_id).AndReturn(fake_list_response)
        return fake_neutron_network_id

    def test_network_driver_create_endpoint(self):
        docker_network_id = hashlib.sha256(
            str(random.getrandbits(256))).hexdigest()
        docker_endpoint_id = hashlib.sha256(
            str(random.getrandbits(256))).hexdigest()

        fake_neutron_network_id = self._mock_out_network(docker_network_id)

        self.mox.StubOutWithMock(app.neutron, 'create_subnet')
        fake_subnet_request = {
            "subnets": [{
                'name': '-'.join([docker_endpoint_id, '0', 'v4']),
                'network_id': fake_neutron_network_id,
                'ip_version': 4,
                "cidr": '192.168.1.2/24'
            }, {
                'name': '-'.join([docker_endpoint_id, '0', 'v6']),
                'network_id': fake_neutron_network_id,
                'ip_version': 6,
                "cidr": 'fe80::f816:3eff:fe20:57c4/64'
            }]
        }
        # The following fake response is retrieved from the Neutron doc:
        #   http://developer.openstack.org/api-ref-networking-v2.html#createSubnet  # noqa
        fake_subnet_response = {
            "subnets": [{
                "name": '-'.join([docker_endpoint_id, '0', 'v4']),
                "network_id": docker_network_id,
                "tenant_id": "c1210485b2424d48804aad5d39c61b8f",
                "allocation_pools": [{"start": "192.168.1.2",
                                      "end": "192.168.1.254"}],
                "gateway_ip": "192.168.1.1",
                "ip_version": 4,
                "cidr": "192.168.1.2/24",
                "id": "9436e561-47bf-436a-b1f1-fe23a926e031",
                "enable_dhcp": True
            }, {
                "name": '-'.join([docker_endpoint_id, '0', 'v6']),
                "network_id": docker_network_id,
                "tenant_id": "c1210485b2424d48804aad5d39c61b8f",
                "allocation_pools": [{"start": "fe80::f816:3eff:fe20:57c4",
                                      "end": "fe80::ffff:ffff:ffff:ffff"}],
                "gateway_ip": "fe80::f816:3eff:fe20:57c3",
                "ip_version": 6,
                "cidr": "fe80::f816:3eff:fe20:57c3/64",
                "id": "64dd4a98-3d7a-4bfd-acf4-91137a8d2f51",
                "enable_dhcp": True
            }]
        }
        app.neutron.create_subnet(
            fake_subnet_request).AndReturn(fake_subnet_response)

        self.mox.StubOutWithMock(app.neutron, 'create_port')
        fake_port_request = {
            'port': {
                'name': '-'.join([docker_endpoint_id, '0', 'port']),
                'admin_state_up': True,
                'mac_address': "fa:16:3e:20:57:c3",
                'network_id': fake_neutron_network_id
            }
        }
        # The following fake response is retrieved from the Neutron doc:
        #   http://developer.openstack.org/api-ref-networking-v2.html#createPort  # noqa
        fake_port = {
            "port": {
                "status": "DOWN",
                "name": '-'.join([docker_endpoint_id, '0', 'port']),
                "allowed_address_pairs": [],
                "admin_state_up": True,
                "network_id": fake_neutron_network_id,
                "tenant_id": "d6700c0c9ffa4f1cb322cd4a1f3906fa",
                "device_owner": "",
                "mac_address": "fa:16:3e:20:57:c3",
                "fixed_ips": [{
                    "subnet_id": "9436e561-47bf-436a-b1f1-fe23a926e031",
                    "ip_address": "192.168.1.2"
                }],
                "id": "65c0ee9f-d634-4522-8954-51021b570b0d",
                "security_groups": [],
                "device_id": ""
            }
        }
        app.neutron.create_port(fake_port_request).AndReturn(fake_port)
        self.mox.ReplayAll()

        data = {
            'NetworkID': docker_network_id,
            'EndpointID': docker_endpoint_id,
            'Options': {},
            'Interfaces': [{
                'ID': 0,
                'Address': '192.168.1.2/24',
                'AddressIPv6': 'fe80::f816:3eff:fe20:57c4/64',
                'MacAddress': "fa:16:3e:20:57:c3"
            }]
        }
        response = self.app.post('/NetworkDriver.CreateEndpoint',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        expected = {'Interfaces': data['Interfaces']}
        self.assertEqual(expected, decoded_json)
