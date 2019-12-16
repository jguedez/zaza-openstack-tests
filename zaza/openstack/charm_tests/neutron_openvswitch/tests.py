#!/usr/bin/env python3

# Copyright 2018 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Encapsulating `neutron-openvswitch` testing."""

import json
import logging
import unittest

import zaza
import zaza.model as model
import zaza.openstack.utilities.openstack as openstack_utils
import zaza.openstack.charm_tests.test_utils as test_utils


class NeutronOpenvSwitchTest(test_utils.OpenStackBaseTest):
    """Test basic Neutron Gateway Charm functionality."""

    @classmethod
    def setUpClass(cls):
        """Run class setup for running Neutron Gateway tests."""
        super(NeutronOpenvSwitchTest, cls).setUpClass()
        cls.current_os_release = openstack_utils.get_os_release()
        cls.services = ['neutron-openvswitch-agent']

        bionic_stein = openstack_utils.get_os_release('bionic_stein')

        cls.pgrep_full = (True if cls.current_os_release >= bionic_stein
                          else False)

        # workaround due to bug in libjuju setting lead_unit to None in
        # subordinate charms in test_utils.OpenStackBaseTest
        # https://github.com/juju/python-libjuju/issues/374
        cls.lead_unit = model.get_first_unit_name(cls.application_name)
        logging.debug('Leader unit is {}'.format(cls.lead_unit))

    def test_900_restart_on_config_change(self):
        """Checking restart happens on config change.

        Change debug logging and assert that services are restarted as a result
        """
        # Expected default and alternate values
        current_value = zaza.model.get_application_config(
            self.application_name)['debug']['value']
        new_value = str(not bool(current_value)).title()
        current_value = str(current_value).title()

        set_default = {'debug': current_value}
        set_alternate = {'debug': new_value}
        default_entry = {'DEFAULT': {'debug': [current_value]}}
        alternate_entry = {'DEFAULT': {'debug': [new_value]}}

        # Config file affected by juju set config change
        conf_file = '/etc/neutron/neutron.conf'

        # Make config change, check for service restarts
        logging.info(
            'Setting verbose on {} {}'.format(self.application_name,
                                              set_alternate))
        self.restart_on_changed(
            conf_file,
            set_default,
            set_alternate,
            default_entry,
            alternate_entry,
            self.services,
            pgrep_full=self.pgrep_full)

    def test_910_pause_and_resume(self):
        """Run pause and resume tests.

        Pause service and check services are stopped then resume and check
        they are started
        """
        # libjuju status for subordinate charms has issues (reports no units)
        # meaning that the pause_resume support in test_utils.OpenStackBaseTest
        # does not work properly, the block comment below should be all we need
        # when this is fixed: https://github.com/juju/python-libjuju/issues/374

        # with self.pause_resume(
        #         self.services,
        #         pgrep_full=self.pgrep_full):
        #     logging.info("Testing pause resume")

        # as a workaround we are checking that we can pause/resume directly
        unit = model.get_unit_from_name(self.lead_unit)
        self.assertEqual(unit.workload_status, "active")

        model.run_action(self.lead_unit, "pause")
        unit = model.get_unit_from_name(self.lead_unit)
        self.assertEqual(unit.workload_status, "maintenance")

        model.run_action(self.lead_unit, "resume")
        unit = model.get_unit_from_name(self.lead_unit)
        self.assertEqual(unit.workload_status, "active")


class NeutronOpenvSwitchOverlayTest(unittest.TestCase):
    """Class for `neutron-openvswitch` tests."""

    @classmethod
    def setUpClass(cls):
        """Run class setup for `neutron-openvswitch` tests."""
        super(NeutronOpenvSwitchOverlayTest, cls).setUpClass()

    def test_tunnel_datapath(self):
        """From ports list, connect to unit in one end, ping other end(s)."""
        keystone_session = openstack_utils.get_overcloud_keystone_session()
        neutron_client = openstack_utils.get_neutron_session_client(
            keystone_session)

        resp = neutron_client.list_ports()
        ports = resp['ports']
        host_port = {}
        for port in ports:
            if (port['device_owner'].startswith('network:') or
                    port['device_owner'].startswith('compute:')):
                continue
            host_port[port['binding:host_id']] = port

        for unit in zaza.model.get_units('neutron-openvswitch'):
            result = zaza.model.run_on_unit(unit.entity_id, 'hostname')
            hostname = result['Stdout'].rstrip()
            if hostname not in host_port:
                # no port bound to this host, skip
                continue
            # get interface name from unit OVS data
            ovs_interface = json.loads(zaza.model.run_on_unit(
                unit.entity_id, 'ovs-vsctl -f json find Interface '
                                'external_ids:iface-id={}'
                                .format(host_port[hostname]['id']))['Stdout'])
            for (idx, heading) in enumerate(ovs_interface['headings']):
                if heading == 'name':
                    break
            else:
                raise Exception('Unable to find interface name from OVS')
            interface_name = ovs_interface['data'][0][idx]

            ip_unit = zaza.model.run_on_unit(
                unit.entity_id, 'ip addr show dev {}'
                                .format(interface_name))
            for other_host in (set(host_port) - set([hostname])):
                for ip_info in host_port[other_host]['fixed_ips']:
                    logging.info('Local IP info: "{}"'.format(ip_unit))
                    logging.info('PING "{}" --> "{}"...'
                                 .format(hostname, other_host))
                    result = zaza.model.run_on_unit(
                        unit.entity_id,
                        'ping -c 3 {}'.format(ip_info['ip_address']))
                    logging.info(result['Stdout'])
                    if result['Code'] == '1':
                        raise Exception('FAILED')
