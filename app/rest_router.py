# coding=utf-8
# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import datetime
import logging
import numbers
import random
import shlex
import socket
import struct
import time
import json

import etcd3

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.exception import OFPUnknownVersion
from ryu.exception import RyuException
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.lib import mac as mac_lib
from ryu.lib import addrconv
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import packet_base
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import vlan
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import nicira_ext

import requests
import json
import netaddr
import xml.etree.ElementTree as ET
import os
import netaddr
import subprocess
# =============================
#          REST API
# =============================
#
#  Note: specify switch and vlan group, as follows.
#   {switch_id} : 'all' or switchID
#   {vlan_id}   : 'all' or vlanID
#

# 1. get address data and routing data.
#
# * get data of no vlan
# GET /router/{switch_id}
#
# * get data of specific vlan group
# GET /router/{switch_id}/{vlan_id}
#

# 2. set address data or routing data.
#
# * set data of no vlan
# POST /router/{switch_id}
#
# * set data of specific vlan group
# POST /router/{switch_id}/{vlan_id}
#
#  case1: set address data.
#    parameter = {"address": "A.B.C.D/M"}
#  case2-1: set static route.
#    parameter = {"destination": "A.B.C.D/M", "gateway": "E.F.G.H"}
#  case2-2: set default route.
#    parameter = {"gateway": "E.F.G.H"}
#

# 3. delete address data or routing data.
#
# * delete data of no vlan
# DELETE /router/{switch_id}
#
# * delete data of specific vlan group
# DELETE /router/{switch_id}/{vlan_id}
#
#  case1: delete address data.
#    parameter = {"address_id": "<int>"} or {"address_id": "all"}
#  case2: delete routing data.
#    parameter = {"route_id": "<int>"} or {"route_id": "all"}
#
#


UINT16_MAX = 0xffff
UINT32_MAX = 0xffffffff
UINT64_MAX = 0xffffffffffffffff

ETHERNET = ethernet.ethernet.__name__
VLAN = vlan.vlan.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__

MAX_SUSPENDPACKETS = 50  # Threshold of the packet suspends thread count.

ARP_REPLY_TIMER = 2  # sec
OFP_REPLY_TIMER = 1.0  # sec
CHK_ROUTING_TBL_INTERVAL = 1800  # sec
DP_PORT_TIMER = 2

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'
VLANID_PATTERN = r'[0-9]{1,4}|all'

VLANID_NONE = 0
VLANID_MIN = 2
VLANID_MAX = 4094

COOKIE_DEFAULT_ID = 0
COOKIE_SHIFT_VLANID = 32
COOKIE_SHIFT_ROUTEID = 16
COOKIE_SHIFT_FW = 10

DEFAULT_ROUTE = '0.0.0.0/0'
# IDLE_TIMEOUT = 1800  # sec
IDLE_TIMEOUT = 180
DEFAULT_TTL = 64

REST_COMMAND_RESULT = 'command_result'
REST_RESULT = 'result'
REST_DETAILS = 'details'
REST_OK = 'success'
REST_NG = 'failure'
REST_ALL = 'all'
REST_SWITCHID = 'switch_id'
REST_VLANID = 'vlan_id'
REST_NW = 'internal_network'
REST_FIREWALL = "firwalls"
REST_ADDRESSID = 'address_id'
REST_ADDRESS = 'address'
REST_ROUTEID = 'route_id'
REST_ROUTE = 'route'
REST_DESTINATION = 'destination'
REST_GATEWAY = 'gateway'
REST_FWID = "rule_id"


PRIORITY_VLAN_SHIFT = 1000
PRIORITY_NETMASK_SHIFT = 32

PRIORITY_NORMAL = 0
PRIORITY_ARP_HANDLING = 2
PRIORITY_DEFAULT_ROUTING = 1
PRIORITY_MAC_LEARNING = 2
PRIORITY_STATIC_ROUTING = 2
PRIORITY_IMPLICIT_ROUTING = 3
PRIORITY_L2_SWITCHING = 4
PRIORITY_IP_HANDLING = 5
PRIORITY_INGRESS = 5

PRIORITY_EX = 10

PRIORITY_TYPE_ROUTE = 'priority_route'

ex_port = 1
MONITOR_PORT = 3

EX_TABLE = 10
INGRESS_SECURE_TABLE = 20

L2_LOOKUP_TABLE = 30
EGRESS_SECURE_TABLE = 40
L3_LOOKUP_TABLE = 50
INGRESS_DNAT_TABLE = 45
EGRESS_SNAT_TABLE = 60

L3_LOOKUP_TABLE2 = 52

NW_PROTO = {
"ICMP": 1,
"TCP": 6,
"UDP": 17,
}


GATEWAY_MAC_ADDRESS = "38:ad:8e:df:a0:65"
#
# TABLE_LIST = [
#     EX_TABLE,
#     INGRESS_SECURE_TABLE,
#     INGRESS_DISPATCH_TABLE,
#     L2_LOOKUP_TABLE,
#     EGRESS_SECURE_TABLE,
#     L3_LOOKUP_TABLE,
#     INGRESS_DNAT_TABLE,
#     INGRESS_SNAT_TABLE,
# ]


FIREWALL_FILE_PATH = "/var/tmp/firewall.xml"
NETWORK_FILE_PATH = "/var/tmp/network.xml"

VLAN_HEADER = '<vlan id="%s" >\n'
VLAN_END = "</vlan>\n"
NETWORK = "<network>%s</network>\n"
FIREWALL_RULE_HEADER = "<rule id=\"%s\" >\n"
FIREWALL_RULE_END = "</rule>\n"
RULE_TEMPLATE = "<%s>%s</%s>\n"


FIPS_URL = 'http://219.245.185.226:8088/get_fips'
FIP_URL = 'http://219.245.185.226:8088/show_fip'
POD_URL = 'http://219.245.186.55:8070/pods/list'

# ovs-ofctl add-flow fptest-br table=45,priority=30,ip,
# in_port=$ex_port,nw_dst=$fip,actions=mod_dl_dst:$pod_mac,
# mod_dl_src:$veth_mac,Dec_TTL,mod_nw_dst=$pod_ip,resubmit\(,40\)
#
# ovs-ofctl add-flow fptest-br table=50,priority=30,
# ip,in_port=$ex_port,nw_dst=$pod_ip,actions=output:$veth_num
#
# ovs-ofctl add-flow fptest-br table=60,priority=30,
# ip,nw_src=$pod_ip,actions=mod_dl_src:$fip_mac,
# mod_dl_dst:38:ad:8e:df:a0:65,dec_ttl,mod_nw_src:$fip,resubmit\(,40\)
#
#
# ovs-ofctl add-flow fptest-br table=50,
# priority=30,ip,nw_src=$fip,actions=output:$ex_port



def get_priority(priority_type, vid=0, route=None):
    log_msg = None
    priority = priority_type

    if priority_type == PRIORITY_TYPE_ROUTE:
        assert route is not None
        if route.dst_ip:
            priority_type = PRIORITY_STATIC_ROUTING
            priority = priority_type + route.netmask
            log_msg = 'static routing'
        else:
            priority_type = PRIORITY_DEFAULT_ROUTING
            priority = priority_type
            log_msg = 'default routing'

    if vid or priority_type == PRIORITY_IP_HANDLING:
        priority += PRIORITY_VLAN_SHIFT

    if priority_type > PRIORITY_STATIC_ROUTING:
        priority += PRIORITY_NETMASK_SHIFT

    if log_msg is None:
        return priority
    else:
        return priority, log_msg


def get_priority_type(priority, vid):
    if vid:
        priority -= PRIORITY_VLAN_SHIFT
    return priority

def is_public_ip(value):
    ip = netaddr.IPAddress(value)
    if ip.is_unicast() and not ip.is_private():
        return True
    else:
        return False

def delete_all_flows():
    cmd = "ovs-ofctl del-flows fptest-br"
    os.system(cmd)

class NotFoundError(RyuException):
    message = 'Router SW is not connected. : switch_id=%(switch_id)s'


class CommandFailure(RyuException):
    pass


class RestRouterAPI(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):

        # print "RestRouterAPI"

        super(RestRouterAPI, self).__init__(*args, **kwargs)

        # logger configure
        RouterController.set_logger(self.logger)

        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {'waiters': self.waiters}

        mapper = wsgi.mapper
        wsgi.registory['RouterController'] = self.data
        requirements = {'switch_id': SWITCHID_PATTERN,
                        'vlan_id': VLANID_PATTERN}

        # For no vlan data
        path = '/router/{switch_id}'
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='get_data',
                       conditions=dict(method=['GET']))
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='set_data',
                       conditions=dict(method=['POST']))
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='delete_data',
                       conditions=dict(method=['DELETE']))
        # For vlan data
        path = '/router/{switch_id}/{vlan_id}'
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='get_vlan_data',
                       conditions=dict(method=['GET']))
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='set_vlan_data',
                       conditions=dict(method=['POST']))
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='delete_vlan_data',
                       conditions=dict(method=['DELETE']))

        path = '/router/{switch_id}/pod'
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='get_fip',
                       conditions=dict(method=['GET']))
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='bind_fip',
                       conditions=dict(method=['POST']))
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='unbind_fip',
                       conditions=dict(method=['DELETE']))

        path = '/router/{switch_id}/firewall'
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='get_firewall_rules',
                       conditions=dict(method=['GET']))
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='add_firewall_rules',
                       conditions=dict(method=['POST']))
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='delete_firewall_rule',
                       conditions=dict(method=['DELETE']))

        # TODO
        path = '/router/{switch_id}/xml'
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='add_xml_request',
                       conditions=dict(method=['POST']))


    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_handler(self, ev):
        if ev.enter:
            RouterController.register_router(ev.dp)
        else:
            RouterController.unregister_router(ev.dp)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        RouterController.packet_in_handler(ev.msg)

    def _stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if (dp.id not in self.waiters
                or msg.xid not in self.waiters[dp.id]):
            return
        event, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        if ofproto_v1_3.OFP_VERSION == dp.ofproto.OFP_VERSION:
            more = dp.ofproto.OFPMPF_REPLY_MORE
        else:
            more = dp.ofproto.OFPSF_REPLY_MORE
        if msg.flags & more:
            return
        del self.waiters[dp.id][msg.xid]
        event.set()

    # for OpenFlow version1.0
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_0(self, ev):
        self._stats_reply_handler(ev)

    # for OpenFlow version1.2/1.3
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        self._stats_reply_handler(ev)

    def set_xml(self):
        RouterController.set_xml_file()

    # TODO: Update routing table when port status is changed.



# REST command template
def rest_command(func):
    def _rest_command(*args, **kwargs):
        try:
            msg = func(*args, **kwargs)
            return Response(content_type='application/json',
                            body=json.dumps(msg))

        except SyntaxError as e:
            status = 400
            print e
            details = e.msg
        except (ValueError, NameError) as e:
            status = 400
            print e
            details = e.message

        except NotFoundError as msg:
            status = 404
            details = str(msg)

        msg = {REST_RESULT: REST_NG,
               REST_DETAILS: details}
        return Response(status=status, body=json.dumps(msg))

    return _rest_command


class RouterController(ControllerBase):

    _ROUTER_LIST = {}
    _LOGGER = None

    def __init__(self, req, link, data, **config):
        super(RouterController, self).__init__(req, link, data, **config)
        self.waiters = data['waiters']

    @classmethod
    def set_logger(cls, logger):
        cls._LOGGER = logger
        cls._LOGGER.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[RT][%(levelname)s] switch_id=%(sw_id)s: %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        cls._LOGGER.addHandler(hdlr)

    @classmethod
    def set_xml_file(cls):
        for dp_id in cls._ROUTER_LIST:
            router = cls._ROUTER_LIST[dp_id]
            router.set_xml_file()

    @classmethod
    def register_router(cls, dp):
        dpid = {'sw_id': dpid_lib.dpid_to_str(dp.id)}
        try:
            router = Router(dp, cls._LOGGER)
        except OFPUnknownVersion as message:
            cls._LOGGER.error(str(message), extra=dpid)
            return
        cls._ROUTER_LIST.setdefault(dp.id, router)
        cls._LOGGER.info('Join as router.', extra=dpid)

    @classmethod
    def unregister_router(cls, dp):
        if dp.id in cls._ROUTER_LIST:
            cls._ROUTER_LIST[dp.id].delete()
            del cls._ROUTER_LIST[dp.id]

            dpid = {'sw_id': dpid_lib.dpid_to_str(dp.id)}
            cls._LOGGER.info('Leave router.+', extra=dpid)

    @classmethod
    def packet_in_handler(cls, msg):
        dp_id = msg.datapath.id
        if dp_id in cls._ROUTER_LIST:
            router = cls._ROUTER_LIST[dp_id]
            router.packet_in_handler(msg)

    # GET /router/{switch_id}
    @rest_command
    def get_data(self, req, switch_id, **_kwargs):
        return self._access_router(switch_id, VLANID_NONE,
                                   'get_data', req)

    # GET /router/{switch_id}/{vlan_id}
    @rest_command
    def get_vlan_data(self, req, switch_id, vlan_id, **_kwargs):
        return self._access_router(switch_id, vlan_id,
                                   'get_data', req)

    # POST /router/{switch_id}
    @rest_command
    def set_data(self, req, switch_id, **_kwargs):
        # print "set_normal_data"
        return self._access_router(switch_id, VLANID_NONE,
                                   'set_data', req)

    # POST /router/{switch_id}/{vlan_id}
    @rest_command
    def set_vlan_data(self, req, switch_id, vlan_id, **_kwargs):
        # print "set_vlan_data"
        return self._access_router(switch_id, vlan_id,
                                   'set_data', req)

    # DELETE /router/{switch_id}
    @rest_command
    def delete_data(self, req, switch_id, **_kwargs):
        return self._access_router(switch_id, VLANID_NONE,
                                   'delete_data', req)

    # DELETE /router/{switch_id}/{vlan_id}
    @rest_command
    def delete_vlan_data(self, req, switch_id, vlan_id, **_kwargs):
        return self._access_router(switch_id, vlan_id,
                                   'delete_data', req)

    # TODO
    @rest_command
    def get_fip(self, req, switch_id, **kwargs):
        return self._access_router1(switch_id,
                                    'get_fip', req)

    @rest_command
    def bind_fip(self, req, switch_id, **kwargs):
        return self._access_router1(switch_id,
                                   'bind_fip', req)

    @rest_command
    def unbind_fip(self, req, switch_id, **_kwargs):
        return self._access_router1(switch_id,
                                   'unbind_fip', req)

    @rest_command
    def get_firewall_rules(self, req, switch_id, **_kwargs):
        return self._access_router(switch_id, VLANID_NONE,
                                   'get_firewall_rules', req)

    @rest_command
    def add_firewall_rules(self, req, switch_id, **kwargs):
        return self._access_router(switch_id, VLANID_NONE,
                                   'add_firewall_rules', req)

    @rest_command
    def delete_firewall_rule(self, req, switch_id, **kwargs):
        return self._access_router(switch_id, VLANID_NONE,
                                   'delete_firewall_rule', req)

    @rest_command
    def add_xml_request(self, req, switch_id, **kwargs):
        return self._access_router1(switch_id,
                                    'add_xml_request', req)

    def _access_router1(self, switch_id, func, req):
        rest_message = []
        routers = self._get_router(switch_id)
        try:
            param = req.json if req.body else {}
        except ValueError:
            raise SyntaxError('invalid syntax %s', req.body)
        for router in routers.values():
            function = getattr(router, func)
            # print "function is %s" % function
            data = function(param, self.waiters)
            rest_message.append(data)

        return rest_message

    def _access_router(self, switch_id, vlan_id, func, req):
        rest_message = []
        routers = self._get_router(switch_id)
        try:
            param = req.json if req.body else {}
            # print "param is %s" % param
        except ValueError:
            raise SyntaxError('invalid syntax %s', req.body)
        for router in routers.values():
            # print "router is %s, func is %s" % (router, func)
            function = getattr(router, func)
            data = function(vlan_id, param, self.waiters)
            rest_message.append(data)

        return rest_message

    def _get_router(self, switch_id):
        routers = {}

        if switch_id == REST_ALL:
            routers = self._ROUTER_LIST
        else:
            sw_id = dpid_lib.str_to_dpid(switch_id)
            if sw_id in self._ROUTER_LIST:
                routers = {sw_id: self._ROUTER_LIST[sw_id]}

        if routers:
            return routers
        else:
            raise NotFoundError(switch_id=switch_id)


class Router(dict):
    def __init__(self, dp, logger):
        super(Router, self).__init__()
        self.dp = dp
        self.dpid_str = dpid_lib.dpid_to_str(dp.id)
        self.sw_id = {'sw_id': self.dpid_str}
        self.logger = logger

        self.port_data = PortData(dp.ports)

        ofctl = OfCtl.factory(dp, logger)
        cookie = COOKIE_DEFAULT_ID

        delete_all_flows()

        # Set SW config: TTL error packet in (for OFPv1.2/1.3)
        ofctl.set_sw_config_for_ttl()

        # Set flow: ARP handling (packet in)
        priority = get_priority(PRIORITY_ARP_HANDLING)
        ofctl.set_packetin_flow(cookie, priority, dl_type=ether.ETH_TYPE_ARP)
        self.logger.info('Set ARP handling (packet in) flow [cookie=0x%x]',
                         cookie, extra=self.sw_id)

        # Set flow: L2 switching (normal)
        priority = get_priority(PRIORITY_NORMAL)
        ofctl.set_normal_flow(cookie, priority)
        self.logger.info('Set L2 switching (normal) flow [cookie=0x%x]',
                         cookie, extra=self.sw_id)


        priority = PRIORITY_EX
        ofctl.set_resubmit_flow(cookie, priority, in_port=ex_port, new_table_id=EX_TABLE)

        # set ex_port arp handling
        priority = get_priority(PRIORITY_ARP_HANDLING)
        ofctl.set_packetin_flow(cookie, priority, dl_type=ether.ETH_TYPE_ARP, table_id=EX_TABLE)

        priority = get_priority(PRIORITY_NORMAL)
        outport = None  # for drop
        ofctl.set_routing_flow1(cookie, priority, outport, table_id=EX_TABLE)

        priority = get_priority(PRIORITY_NORMAL)
        outport = None  # for drop
        ofctl.set_routing_flow1(cookie, priority, outport, table_id=INGRESS_DNAT_TABLE)


        priority = get_priority(PRIORITY_NORMAL)
        outport = None  # for drop
        ofctl.set_routing_flow1(cookie, priority, outport, table_id=EGRESS_SNAT_TABLE)

        priority = get_priority(PRIORITY_IP_HANDLING)
        ofctl.set_floatingip_ingress_flow(cookie, priority, 0, dl_type=ether.ETH_TYPE_IP,
                                          new_table_id=INGRESS_SECURE_TABLE, table_id=EX_TABLE)

        priority = get_priority(PRIORITY_NORMAL) + 2
        ofctl.set_resubmit_flow(cookie, priority, 0, metadata=3, new_table_id=INGRESS_DNAT_TABLE, table_id=L2_LOOKUP_TABLE)

        priority = get_priority(PRIORITY_NORMAL)
        ofctl.set_resubmit_flow(cookie, priority, 0, new_table_id=L2_LOOKUP_TABLE, table_id=INGRESS_SECURE_TABLE)

        # priority = get_priority(PRIORITY_NORMAL)
        # ofctl.set_normal_flow(cookie, priority, table_id=L3_LOOKUP_TABLE)

        # Set VlanRouter for vid=None.
        vlan_router = VlanRouter(VLANID_NONE, dp, self.port_data, logger)
        self[VLANID_NONE] = vlan_router

        priority = get_priority(PRIORITY_NORMAL)
        ofctl.set_resubmit_flow(cookie, priority, 0, new_table_id=L3_LOOKUP_TABLE, table_id=EGRESS_SECURE_TABLE)

        # L2_LOOKUP_TABLE
        priority = get_priority(PRIORITY_NORMAL)
        ofctl.set_resubmit_flow(cookie, priority, 0,
                                new_table_id=EGRESS_SNAT_TABLE,
                                table_id=L2_LOOKUP_TABLE)

        # Start cyclic routing table check.s
        self.thread = hub.spawn(self._cyclic_update_routing_tbl)
        self.logger.info('Start cyclic routing table update.',
                         extra=self.sw_id)



    def delete(self):
        hub.kill(self.thread)
        self.thread.wait()
        self.logger.info('Stop cyclic routing table update.',
                         extra=self.sw_id)

    def set_xml_file(self, vlan_id=VLANID_NONE):
        vlan_routers = self._get_vlan_router(vlan_id)
        if vlan_routers:
            for vlan_router in vlan_routers:
                vlan_router.set_xml()
        else:
            msgs = [{REST_VLANID: vlan_id}]

        return {REST_SWITCHID: self.dpid_str}

    def _get_vlan_router(self, vlan_id):
        vlan_routers = []

        if vlan_id == REST_ALL:
            vlan_routers = list(self.values())
        else:
            vlan_id = int(vlan_id)
            if (vlan_id != VLANID_NONE and
                    (vlan_id < VLANID_MIN or VLANID_MAX < vlan_id)):
                msg = 'Invalid {vlan_id} value. Set [%d-%d]'
                raise ValueError(msg % (VLANID_MIN, VLANID_MAX))
            elif vlan_id in self:
                vlan_routers = [self[vlan_id]]

        return vlan_routers

    def _add_vlan_router(self, vlan_id):
        vlan_id = int(vlan_id)
        if vlan_id not in self:
            vlan_router = VlanRouter(vlan_id, self.dp, self.port_data,
                                     self.logger)
            self[vlan_id] = vlan_router
        return self[vlan_id]

    def _del_vlan_router(self, vlan_id, waiters):
        #  Remove unnecessary VlanRouter.
        if vlan_id == VLANID_NONE:
            return

        vlan_router = self[vlan_id]
        if (len(vlan_router.address_data) == 0
                and len(vlan_router.routing_tbl) == 0):
            vlan_router.delete(waiters)
            del self[vlan_id]

    def get_data(self, vlan_id, dummy1, dummy2):
        vlan_routers = self._get_vlan_router(vlan_id)
        if vlan_routers:
            msgs = [vlan_router.get_data() for vlan_router in vlan_routers]
        else:
            msgs = [{REST_VLANID: vlan_id}]

        return {REST_SWITCHID: self.dpid_str,
                REST_NW: msgs}

    def get_firewall_rules(self, vlan_id, dummy1, dummy2):
        vlan_routers = self._get_vlan_router(vlan_id)
        if vlan_routers:
            msgs = [vlan_router.get_firewall_rules() for vlan_router in vlan_routers]
        else:
            msgs = [{REST_VLANID: vlan_id}]

        return {REST_SWITCHID: self.dpid_str,
                REST_NW: msgs}

    # TODO
    def get_fip(self, param, waiters):
        vlan_routers = self._get_vlan_router(VLANID_NONE)
        if vlan_routers:
            msgs = [vlan_router.get_fip() for vlan_router in vlan_routers]
        else:
            msgs = "Cannont get floating ips"

        return {REST_SWITCHID: self.dpid_str,
                REST_NW: msgs}

    # TODO
    def add_xml_request(self, param, waiters):
        vlan_routers = self._get_vlan_router(VLANID_NONE)

        # msgs = []
        for vlan_router in vlan_routers:

            msg = vlan_router.add_xml_request()

        return {REST_SWITCHID: self.dpid_str,
                REST_COMMAND_RESULT: msg}

    def bind_fip(self, param, waiters):
        vlan_routers = self._get_vlan_router(VLANID_NONE)

        # msgs = []
        for vlan_router in vlan_routers:
            try:
                msg = vlan_router.bind_fip(param)
                # msgs.append(msg)
                # if msg[REST_RESULT] == REST_NG:
                if msg == REST_NG:
                    # Data setting is failure.
                    self._del_vlan_router(vlan_router.vlan_id, waiters)
            except ValueError as err_msg:
                # Data setting is failure.
                self._del_vlan_router(vlan_router.vlan_id, waiters)
                raise err_msg

        return {REST_SWITCHID: self.dpid_str,
                REST_COMMAND_RESULT: msg}

    def unbind_fip(self, param, waiters):
        vlan_routers = self._get_vlan_router(VLANID_NONE)

        # msgs = []
        for vlan_router in vlan_routers:
            try:
                msg = vlan_router.unbind_fip(param)
                # msgs.append(msg)
                # if msg[REST_RESULT] == REST_NG:
                if msg == REST_NG:
                    # Data setting is failure.
                    self._del_vlan_router(vlan_router.vlan_id, waiters)
            except ValueError as err_msg:
                # Data setting is failure.
                self._del_vlan_router(vlan_router.vlan_id, waiters)
                raise err_msg

        return {REST_SWITCHID: self.dpid_str,
                REST_COMMAND_RESULT: msg}

    def add_firewall_rules(self, vlan_id, param, waiters):
        vlan_routers = self._get_vlan_router(vlan_id)

        msgs = []
        for vlan_router in vlan_routers:
            try:
                msg = vlan_router.add_firewall_rules(param)
                msgs.append(msg)
                if msg[REST_RESULT] == REST_NG:
                    # Data setting is failure.
                    self._del_vlan_router(vlan_router.vlan_id, waiters)
            except ValueError as err_msg:
                # Data setting is failure.
                self._del_vlan_router(vlan_router.vlan_id, waiters)
                raise err_msg

        return {REST_SWITCHID: self.dpid_str,
                REST_COMMAND_RESULT: msgs}


    def delete_firewall_rule(self, vlan_id, param, waiters):
        vlan_routers = self._get_vlan_router(vlan_id)

        msgs = []
        for vlan_router in vlan_routers:
            try:
                rule_id = param["rule_id"]
                # print "param is %s" % rule_id
                msg = vlan_router.delete_firewall_rule(rule_id, waiters)
                msgs.append(msg)
                if msg[REST_RESULT] == REST_NG:
                    # Data setting is failure.
                    self._del_vlan_router(vlan_router.vlan_id, waiters)
            except ValueError as err_msg:
                # Data setting is failure.
                self._del_vlan_router(vlan_router.vlan_id, waiters)
                raise err_msg

        return {REST_SWITCHID: self.dpid_str,
                REST_COMMAND_RESULT: msgs}

    def set_data(self, vlan_id, param, waiters):
        vlan_routers = self._get_vlan_router(vlan_id)
        if not vlan_routers:
            vlan_routers = [self._add_vlan_router(vlan_id)]

        msgs = []
        for vlan_router in vlan_routers:
            try:
                # print "vlan_router set_data"
                msg = vlan_router.set_data(param)
                msgs.append(msg)
                if msg[REST_RESULT] == REST_NG:
                    # Data setting is failure.
                    self._del_vlan_router(vlan_router.vlan_id, waiters)
            except ValueError as err_msg:
                # Data setting is failure.
                self._del_vlan_router(vlan_router.vlan_id, waiters)
                raise err_msg

        return {REST_SWITCHID: self.dpid_str,
                REST_COMMAND_RESULT: msgs}

    def delete_data(self, vlan_id, param, waiters):
        msgs = []
        print "param is %s" % param
        # waiters is {}
        vlan_routers = self._get_vlan_router(vlan_id)
        if vlan_routers:
            for vlan_router in vlan_routers:
                msg = vlan_router.delete_data(param, waiters)
                if msg:
                    msgs.append(msg)
                # Check unnecessary VlanRouter.
                self._del_vlan_router(vlan_router.vlan_id, waiters)
        if not msgs:
            msgs = [{REST_RESULT: REST_NG,
                     REST_DETAILS: 'Data is nothing.'}]

        return {REST_SWITCHID: self.dpid_str,
                REST_COMMAND_RESULT: msgs}

    def packet_in_handler(self, msg):
        pkt = packet.Packet(msg.data)
        # TODO: Packet library convert to string

        # self.logger.info('Packet in = %s', str(pkt), self.sw_id)

        # print "Router, msg.data"

        header_list = dict((p.protocol_name, p)
                           for p in pkt.protocols
                           if isinstance(p, packet_base.PacketBase))
        if header_list:
            # Check vlan-tag
            vlan_id = VLANID_NONE
            if VLAN in header_list:
                vlan_id = header_list[VLAN].vid

            # Event dispatch
            if vlan_id in self:
                self[vlan_id].packet_in_handler(msg, header_list)
            else:
                self.logger.debug('Drop unknown vlan packet. [vlan_id=%d]',
                                  vlan_id, extra=self.sw_id)

    def _cyclic_update_routing_tbl(self):
        while True:
            # send ARP to all gateways.
            for vlan_router in self.values():
                vlan_router.send_arp_all_gw()
                hub.sleep(1)

            hub.sleep(CHK_ROUTING_TBL_INTERVAL)





class VlanRouter(object):
    def __init__(self, vlan_id, dp, port_data, logger):
        super(VlanRouter, self).__init__()
        self.vlan_id = vlan_id
        self.dp = dp
        self.sw_id = {'sw_id': dpid_lib.dpid_to_str(dp.id)}
        self.logger = logger

        self.port_data = port_data
        self.port_map = self._get_port_map()

        self.address_data = AddressData()
        self.routing_tbl = RoutingTable()
        self.packet_buffer = SuspendPacketList(self.send_icmp_unreach_error)
        self.ofctl = OfCtl.factory(dp, logger)



        # Set flow: default route (drop)
        # self.delete_all_flows()

        self._set_defaultroute_drop()
        self.fw_rules = {}
        self.vlan_groups = {}

        self._parse_xml()
        # etcd client
        self.client = etcd3.client(host='219.245.186.55', port=12379)


        time_stamp = '{0:%Y-%m-%d-%H-%M}'.format(datetime.datetime.now())
        tcpdump_split = shlex.split(("tcpdump -i monitor ip -w /var/pcaps/monitor-%s.pcap") % time_stamp)
        subprocess.Popen(tcpdump_split)

        # mac地址的第二位是偶数
        self.fip_set = set(["202.117.54.233",
                            "202.117.54.234",
                            "202.117.54.235",
                            "219.245.185.210",
                            "219.245.185.211",
                            "219.245.185.212",
                            "219.245.185.213",
                            "219.245.185.214",
                            "219.245.185.215",
                            "219.245.185.216",
                            ]) # 从neutron同步到的数据

        self.fip_map = {
            "202.117.54.233": "02:c4:b5:80:fc:23",
            "202.117.54.234": "02:c4:b5:80:fc:24",
            "202.117.54.235": "02:c4:b5:80:fc:25",

            "219.245.185.210": "04:c4:b5:80:fc:00",
            "219.245.185.211": "04:c4:b5:80:fc:01",
            "219.245.185.212": "04:c4:b5:80:fc:02",
            "219.245.185.213": "04:c4:b5:80:fc:03",
            "219.245.185.214": "04:c4:b5:80:fc:04",
            "219.245.185.215": "04:c4:b5:80:fc:05",
            "219.245.185.216": "04:c4:b5:80:fc:06",
        }
        self.used_fip_set = set()
        # self.pods = {}
        # self._get_pods()


        self.arp_list = {}
        self.mac_no_list = {}

        self.count = 0
        self.thread = hub.spawn(self.send_arp)

        self.dp_thread = hub.spawn(self.sync_datapath_ports)

    def sync_datapath_ports(self):
        while True:
            self.port_data = PortData(self.dp.ports)
            hub.sleep(DP_PORT_TIMER)

    # get floatingip set from etcd
    def get_floatingip_set(self):
        fip_list = []
        for data, meta in self.client.get_prefix('/ipam/fip'):
            fip = str(meta.key.decode()).split('/')[3]
            fip_list.append(fip)
        return set(fip_list)

    # get random mac addresses for floatingips
    def get_random_mac(self):
        macstring = "0123456789abcdef" * 12
        macstringlist = random.sample(macstring, 12)
        # set the second position an event num
        macstringlist[1] = '2'
        data = "{0[0]}{0[1]}:{0[2]}{0[3]}:{0[4]}{0[5]}:{0[6]}{0[7]}:{0[8]}{0[9]}:{0[10]}{0[11]}".format(macstringlist)
        return str(data)

    def floatingip_watcher(self):
        pass


    def _get_port_map(self):
        port_map = {}
        for portno, port in self.dp.ports.items():
            port_map[port.hw_addr] = portno
        return port_map

    def send_arp(self):
        # src_mac = "06:c4:b5:80:fc:24"  # 浮动ip的mac
        while True:
            # send ARP to all gateways.
            for floating_ip_address in self.fip_set:
                gw_ip_address = self._get_floatingip_gw(floating_ip_address)
                # print "floating_ip_address is %s, gw_ip_address is %s" % (floating_ip_address, gw_ip_address)
                src_mac = self.fip_map[floating_ip_address]
                self._send_floatingip_arp_req(src_mac, floating_ip_address, gw_ip_address)
                hub.sleep(1)
            # hub.sleep(CHK_ROUTING_TBL_INTERVAL)

    def _parse_firewall_rules(self):
        tree = ET.parse(FIREWALL_FILE_PATH)
        root = tree.getroot()
        index = 0
        for child in root:
            tmpdict = dict()
            for i in child:
                tmpdict[i.tag] = i.text
            self.fw_rules[index] = tmpdict
            index += 1

        self._add_firewall_rules_init(self.fw_rules)

    def _parse_network_from_file(self):
        tree = ET.parse(NETWORK_FILE_PATH)
        root = tree.getroot()
        topos = []
        for child in root:
            for i in child:
                topos.append((i.text, child.attrib["id"]))

        data = {}
        for item in topos:
            ip = item[0]
            vlanid = int(item[1])
            if vlanid not in data.keys():
                data[vlanid] = [ip]
            else:
                data[vlanid].append(ip)

        self._add_network_topology_init(data)

    def _add_network_topology_init(self, vlan_groups):
        for k, v in vlan_groups.items():
            # print "_add_network_topology_init, k = %s, v = %s" % (k, v)
            self._set_address_data(k, v)

    def _parse_xml(self, status_code=0):
        st = time.time()
        if status_code == 0:
            self._parse_firewall_rules()
            self._parse_network_from_file()
        elif status_code == 1:
            self._parse_network_from_html()
            return
        # print "parse time is %s " % (time.time() - st)

    def _parse_network_from_html(self):
        pass

    def _reset(self):
        self.vlan_groups = {}
        self.address_data = {}

    def _set_vlan_groups_xml(self):
        with open(NETWORK_FILE_PATH, "w") as f:
            f.write("<root>\n")
            dd = {}
            for network, id in self.vlan_groups.items():
                if id not in dd.keys():
                    dd[id] = [network]
                else:
                    dd[id].append(network)
            for id, networks in dd.items():
                f.write(VLAN_HEADER % id)
                for network in networks:
                    ip = netaddr.IPNetwork(network)
                    gw_ip_address = str(ip[1]) + "/24"
                    f.write(NETWORK % gw_ip_address)
                f.write(VLAN_END)
            f.write("</root>\n")

    def _set_rule_chain(self, rules):
        if not isinstance(rules, dict):
            raise Exception("rule must be a dict")
        res = ""

        for k, v in rules.items():
            res += RULE_TEMPLATE % (k, v, k)

        return res

    def _set_firewall_xml(self):
        with open(FIREWALL_FILE_PATH, "w") as f:
            f.write("<root>\n")
            for id, rules in self.fw_rules.items():
                f.write(FIREWALL_RULE_HEADER % id)
                f.write(self._set_rule_chain(rules))
                f.write(FIREWALL_RULE_END)
            f.write("</root>\n")

    def set_xml(self):
        try:
            self._set_vlan_groups_xml()
        except Exception as e:
            print "set vlan groups xml failed"
            raise e

        try:
            self._set_firewall_xml()
        except Exception as e:
            print "set firewall xml failed"
            raise e


    def _generate_firewall_rules(self):
        priority = get_priority(PRIORITY_DEFAULT_ROUTING)
        cookie = self._id_to_cookie(REST_VLANID, self.vlan_id)


    def _get_mac(self, dst_ip):
        if not self.arp_list.has_key(dst_ip):
            address = self.address_data.get_data(ip=dst_ip)
            src_ip = address.default_gw
            self.send_arp_request(src_ip, dst_ip)
        return self.arp_list.get(dst_ip, None)

    def _get_floatingip_gw(self, floating_ip_address):
        net = floating_ip_address + "/24"
        ip = netaddr.IPNetwork(net)
        gw_ip_address = str(ip[1])
        return gw_ip_address

    def _add_nat_rules(self, fip, veth_mac, pod_mac, veth_index, pod_ip, fip_mac):

        # print "veth_index is %s" % veth_index
        self.ofctl.set_floatingip_ingress_dnat_flow(0, priority=30, in_port=ex_port, nw_dst=fip, new_dl_dst=pod_mac,
                                                    new_nw_dst=pod_ip, new_dl_src=veth_mac,
                                                    goto_table_id=EGRESS_SECURE_TABLE,
                                                    dl_type=ether.ETH_TYPE_IP,
                                                    table_id=INGRESS_DNAT_TABLE)

        self.ofctl.set_floatingip_ingress_l3_flow(0, priority=30, in_port=ex_port,
                                                  port_index=veth_index,
                                                  nw_dst=pod_ip,
                                                  dl_type=ether.ETH_TYPE_IP,
                                                  table_id=L3_LOOKUP_TABLE2)

        self.ofctl.set_floatingip_egress_l3_flow(0, priority=30, nw_src=fip,
                                                 dl_type=ether.ETH_TYPE_IP,
                                                 table_id=L3_LOOKUP_TABLE)

        self.ofctl.set_floatingip_engress_snat_flow(0, priority=30, nw_src=pod_ip, new_dl_dst=GATEWAY_MAC_ADDRESS,
                                                    new_nw_src=fip, new_dl_src=fip_mac, goto_table_id=EGRESS_SECURE_TABLE,
                                                    dl_type=ether.ETH_TYPE_IP, table_id=EGRESS_SNAT_TABLE)

    def _del_nat_rules(self, fip, pod_ip):
        pass

    def bind_fip(self, data):
        floating_ip_address = data["floatingip"]
        # use etcd data instead of self.fip_set
        fip_set_etcd = self.get_floatingip_set()

        if floating_ip_address not in fip_set_etcd:
            return self._response({"error": {"floating ip is invalid"}})

        if floating_ip_address in self.used_fip_set:
            return self._response({"error": {"floating ip is in use"}})

        self.port_map = self._get_port_map()

        pod_name = data["pod_name"]
        # fip_mac = self.fip_map[floating_ip_address]
        fip_mac = self.get_random_mac()
        pods_dict = json.loads(requests.get(POD_URL).content)
        pods_datas = pods_dict["data"]["pods"]
        pod_mac = None
        veth_mac = None
        pod_ip = None
        for pod in pods_datas:
            if pod["name"] == pod_name:
                pod_mac = pod["potMac"]
                veth_mac = pod["hostMac"]
                pod_ip = pod["ip"]
                break

        if pod_mac is None or veth_mac is None or pod_ip is None:
            return self._response({"error": {"pod name is invalid"}})

        # if pod_ip not in cidr, cannont bin floatingip
        # pod_ip_cidr = str(IPy.IP(pod_ip).make_net("255.255.255.0"))
        # print pod_ip_cidr
        # if pod_ip_cidr not in self.vlan_groups.keys():
        #     return self._response("error: no router for pod")
        veth_index = self.port_map[veth_mac]
        self._add_nat_rules(floating_ip_address, veth_mac, pod_mac, veth_index, pod_ip, fip_mac)
        self.used_fip_set.add(floating_ip_address)
        # return self._response(
        #     {
        #         "result":
        #             {
        #                 "floating_ip_address": floating_ip_address,
        #                 "pod_ip": pod_ip
        #             }
        #     })
        return "success"

    def unbind_fip(self, data):
        fip = data["floatingip"]
        pod_ip = data["pod_ip"]
        if fip not in self.used_fip_set:
            return "fail"
        self.used_fip_set.remove(fip)
        cmd1 = "ovs-ofctl del-flows fptest-br table=45,ip,in_port=%s,nw_dst=%s" % (ex_port, fip)
        os.system(cmd1)
        print cmd1

        cmd2 = "ovs-ofctl del-flows fptest-br table=%s," \
               "ip,in_port=%s,nw_dst=%s" % (L3_LOOKUP_TABLE2, ex_port, pod_ip)
        os.system(cmd2)
        print cmd2

        cmd3 = "ovs-ofctl del-flows fptest-br table=50,ip,nw_src=%s" % fip
        os.system(cmd3)
        print cmd3

        cmd4 = "ovs-ofctl del-flows fptest-br table=60,ip,nw_src=%s" % pod_ip
        os.system(cmd4)
        print cmd4
        # return self._response({"result": "OK"})
        return "success"

    #  get an empty post request, changes the network.xml configuration and parses
    def _clear_L2_table(self, cidr):
        cmd = "ovs-ofctl del-flows fptest-br " \
              "table=%s,ip,nw_src=%s" % (L2_LOOKUP_TABLE, cidr)
        os.system(cmd)

        cmd = "ovs-ofctl del-flows fptest-br " \
              "table=%s,ip,nw_dst=%s" % (L2_LOOKUP_TABLE, cidr)
        os.system(cmd)

    def _clear_L2_table2(self, cidr):
        cmd = "ovs-ofctl del-flows fptest-br " \
              "table=%s,ip,nw_dst=%s" % (L2_LOOKUP_TABLE, cidr)
        os.system(cmd)
        # cmd4 = "ovs-ofctl del-flows fptest-br table=60,ip,nw_src=%s" % cidr
        # os.system(cmd4)


    def _clear_L3_table(self, cidr):

        cmd2 = "ovs-ofctl del-flows fptest-br " \
               "table=%s,ip,nw_dst=%s" % (L3_LOOKUP_TABLE, cidr)
        os.system(cmd2)

        cmd = "ovs-ofctl del-flows fptest-br " \
              "table=%s,ip,nw_src=%s" % (L3_LOOKUP_TABLE, cidr)
        os.system(cmd)

    def add_xml_request(self):
        print "get the post from smartkeeper"
        #print self.vlan_groups
        for cidr, vlan_id in self.vlan_groups.items():
            self._clear_L2_table(cidr)
            self._clear_L3_table(cidr)

        self.vlan_groups = {}

        self._parse_network_from_file()
        return "success"

    def _get_pods(self):
        f = open("/var/tmp/pod.txt")
        for line in f.readlines():
            line = line.strip()
            items = line.split()
            pod_name = items[0]
            ip_address = items[1]
            self.pods[pod_name] = ip_address
            # print "pod_name is %s, ip_address is %s" % (pod_name, ip_address)
        f.close()

    def _get_fip_addresses(self, url):
        resp = requests.post(url)
        fips = json.loads(resp.content)
        fips = fips["floatingips"]
        res = {}
        for ip in fips:
            if ip["fixed_ip_address"] is None:
                res[ip["id"]] = ip["ip_address"]
        return res


    def delete(self, waiters):
        # Delete flow.
        msgs = self.ofctl.get_all_flow(waiters)
        for msg in msgs:
            for stats in msg.body:
                vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
                if vlan_id == self.vlan_id:
                    self.ofctl.delete_flow(stats)

        assert len(self.packet_buffer) == 0

    @staticmethod
    def _cookie_to_id(id_type, cookie):
        if id_type == REST_VLANID:
            rest_id = cookie >> COOKIE_SHIFT_VLANID
        elif id_type == REST_ADDRESSID:
            rest_id = cookie & UINT32_MAX
        elif id_type == REST_FWID:
            rest_id = (cookie & UINT32_MAX) >> COOKIE_SHIFT_FW
        else:
            assert id_type == REST_ROUTEID
            rest_id = (cookie & UINT32_MAX) >> COOKIE_SHIFT_ROUTEID

        return rest_id

    def _id_to_cookie(self, id_type, rest_id):
        vid = self.vlan_id << COOKIE_SHIFT_VLANID

        if id_type == REST_VLANID:
            cookie = rest_id << COOKIE_SHIFT_VLANID
        elif id_type == REST_ADDRESSID:
            cookie = vid + int(rest_id)
        elif id_type == REST_FWID:
            cookie = vid + (rest_id << COOKIE_SHIFT_FW)
        else:
            assert id_type == REST_ROUTEID
            cookie = vid + (rest_id << COOKIE_SHIFT_ROUTEID)

        return cookie

    def _get_priority(self, priority_type, route=None):
        return get_priority(priority_type, vid=self.vlan_id, route=route)

    def _response(self, msg):
        if msg and self.vlan_id:
            msg.setdefault(REST_VLANID, self.vlan_id)
        return msg

    # TODO
    def get_fip(self):
        unused_fip_list = list(self.get_floatingip_set() - self.used_fip_set)
        unused_fip_dict = {"floating_ip": unused_fip_list}
        print unused_fip_dict
        return unused_fip_dict

    def get_firewall_rules(self):
        return self._response(self.fw_rules)

    def get_data(self):
        # print self.vlan_groups
        data = {}
        # print self.vlan_groups.keys()
        for ip, vlan in self.vlan_groups.items():
            if vlan not in data.keys():
                data[vlan] = []
                data[vlan].append(ip)
            else:
                data[vlan].append(ip)

        return self._response(data)

    def _get_address_data(self):
        address_data = []
        for value in self.address_data.values():
            default_gw = ip_addr_ntoa(value.default_gw)
            address = '%s/%d' % (default_gw, value.netmask)
            data = {REST_ADDRESSID: value.address_id,
                    REST_ADDRESS: address}
            address_data.append(data)
        return {REST_ADDRESS: address_data}

    def _get_routing_data(self):
        routing_data = []
        for key, value in self.routing_tbl.items():
            if value.gateway_mac is not None:
                gateway = ip_addr_ntoa(value.gateway_ip)
                data = {REST_ROUTEID: value.route_id,
                        REST_DESTINATION: key,
                        REST_GATEWAY: gateway}
                routing_data.append(data)
        return {REST_ROUTE: routing_data}

    def set_data(self, data):
        details = None
        try:
            # Set address data
            if REST_ADDRESS in data:
                addresses = data[REST_ADDRESS]
                # address_id = self._set_address_data(address)
                for k, v in addresses.items():
                    self._set_address_data(k, v)
                # details = 'Add address [address_id=%d]' %
                details = 'Add new address'
            # Set routing data
            elif REST_GATEWAY in data:
                gateway = data[REST_GATEWAY]
                if REST_DESTINATION in data:
                    destination = data[REST_DESTINATION]
                else:
                    destination = DEFAULT_ROUTE
                route_id = self._set_routing_data(destination, gateway)
                details = 'Add route [route_id=%d]' % route_id


        except CommandFailure as err_msg:
        # except Exception as err_msg:
            msg = {REST_RESULT: REST_NG, REST_DETAILS: str(err_msg)}
            return self._response(msg)
        # print "\nself.vlan_groups is %s\n" % self.vlan_groups

        if details is not None:
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}
            return self._response(msg)
        else:
            raise ValueError('Invalid parameter.')

    def _send_floatingip_arp_req(self, src_mac, floatingip_address, gw):
        dst_mac = mac_lib.BROADCAST_STR
        arp_target_mac = mac_lib.DONTCARE_STR
        inport = self.ofctl.dp.ofproto.OFPP_CONTROLLER
        output = ex_port
        src_ip = floatingip_address
        dst_ip = gw
        self.ofctl.send_arp(arp.ARP_REQUEST, self.vlan_id,
                            src_mac, dst_mac, src_ip, dst_ip,
                            arp_target_mac, inport, output)

    def _set_address_data(self, index, addresses):
        # self._send_floatingip_req()
        index = int(index)
        for address in addresses:
            if address in self.vlan_groups:
                continue
            a, b, c = nw_addr_aton(address)
            nw_addr_mask = "%s/%s" % (a, b)
            self.vlan_groups[nw_addr_mask] = index
            # print "address is %s" % address
            # notice: This is myadd
            address = self.address_data.myadd(address, index)
            # print "address.address_id is %s " % address.address_id
            # cookie = self._id_to_cookie(REST_ADDRESSID, address.address_id)
            # # This is original
            # print type(address.address_id)
            cookie = self._id_to_cookie(REST_ADDRESSID, address.address_id)

            # Set flow: host MAC learning (packet in)

            # priority = self._get_priority(PRIORITY_MAC_LEARNING)
            #
            # self.ofctl.set_packetin_flow(cookie, priority,
            #                              dl_type=ether.ETH_TYPE_IP,
            #                              dl_vlan=self.vlan_id,
            #                              dst_ip=address.nw_addr,
            #                              dst_mask=address.netmask, table_id=L2_LOOKUP_TABLE)
            # priority=2,ip,nw_dst=192.168.0.0/24 actions=CONTROLLER:65535
            # log_msg = 'Set host MAC learning (packet in) flow [cookie=0x%x]'
            # self.logger.info(log_msg, cookie, extra=self.sw_id)

            # set Flow: IP handling(PacketIn)
            priority = self._get_priority(PRIORITY_IP_HANDLING)
            # print address.default_gw
            self.ofctl.set_packetin_flow(cookie, priority,
                                         dl_type=ether.ETH_TYPE_IP,
                                         dl_vlan=self.vlan_id,
                                         dst_ip=address.default_gw, table_id=L2_LOOKUP_TABLE)
            # self.logger.info('Set IP handling (packet in) flow [cookie=0x%x]',
            #                  cookie, extra=self.sw_id)

            # self.logger.info('Set IP handling (packet in) flow [cookie=0x%x]',
                             # cookie, extra=self.sw_id)

            # Set flow: L2 switching (normal)

            outport = self.ofctl.dp.ofproto.OFPP_NORMAL
            priority = self._get_priority(PRIORITY_L2_SWITCHING)
            self.ofctl.set_l2_lookup_flow(
                cookie, priority, outport, dl_vlan=self.vlan_id,
                nw_src=address.nw_addr, src_mask=address.netmask,
                nw_dst=address.nw_addr, dst_mask=address.netmask, table_id=L2_LOOKUP_TABLE)


            priority = self._get_priority(PRIORITY_L2_SWITCHING)
            self.ofctl.set_l2_lookup_flow(
                cookie, priority, outport, dl_vlan=self.vlan_id,
                nw_src=address.nw_addr, src_mask=address.netmask,
                nw_dst=address.nw_addr, dst_mask=address.netmask, table_id=L3_LOOKUP_TABLE)

            priority = self._get_priority(PRIORITY_L2_SWITCHING) - 5
            self.ofctl.set_packetin_flow_l3(cookie, priority,
                                            dl_type=ether.ETH_TYPE_IP, dl_vlan=self.vlan_id,
                                            nw_dst=address.nw_addr, dst_mask=address.netmask, table_id=L2_LOOKUP_TABLE)

            # priority = get_priority(PRIORITY_NORMAL)
            # self.ofctl.set_resubmit_flow(cookie, priority, 0,nw_dst=address.default_gw,
            #                                 new_table_id=EGRESS_SNAT_TABLE,
            #                              table_id=L2_LOOKUP_TABLE)

            actions = [self.ofctl.dp.ofproto_parser.NXActionResubmitTable(table_id=L3_LOOKUP_TABLE2)]
            self.ofctl.set_flow(cookie, 30, in_port=ex_port, actions=actions,
                                nw_dst=address.nw_addr, dst_mask=address.netmask,
                                dl_type=ether.ETH_TYPE_IP, table_id=L3_LOOKUP_TABLE)


    def _set_routing_data(self, destination, gateway):
        err_msg = 'Invalid [%s] value.' % REST_GATEWAY
        dst_ip = ip_addr_aton(gateway, err_msg=err_msg)
        address = self.address_data.get_data(ip=dst_ip)
        if address is None:
            msg = 'Gateway=%s\'s address is not registered.' % gateway
            raise CommandFailure(msg=msg)
        elif dst_ip == address.default_gw:
            msg = 'Gateway=%s is used as default gateway of address_id=%d'\
                % (gateway, address.address_id)
            raise CommandFailure(msg=msg)
        else:
            src_ip = address.default_gw
            route = self.routing_tbl.add(destination, gateway)
            self._set_route_packetin(route)
            self.send_arp_request(src_ip, dst_ip)
            return route.route_id

    def _set_defaultroute_drop(self):
        cookie = self._id_to_cookie(REST_VLANID, self.vlan_id)
        priority = self._get_priority(PRIORITY_DEFAULT_ROUTING)
        outport = None  # for drop
        # self.ofctl.set_routing_flow(cookie, priority, outport,
        #                             dl_vlan=self.vlan_id)
        self.ofctl.set_resubmit_flow(cookie, priority, in_port=0, new_table_id=INGRESS_SECURE_TABLE)
        self.logger.info('Set default route (resubmit to ingress) flow [cookie=0x%x]',
                         cookie, extra=self.sw_id)

    def _set_route_packetin(self, route):
        cookie = self._id_to_cookie(REST_ROUTEID, route.route_id)
        priority, log_msg = self._get_priority(PRIORITY_TYPE_ROUTE,
                                               route=route)
        self.ofctl.set_packetin_flow(cookie, priority,
                                     dl_type=ether.ETH_TYPE_IP,
                                     dl_vlan=self.vlan_id,
                                     dst_ip=route.dst_ip,
                                     dst_mask=route.netmask)
        self.logger.info('Set %s (packet in) flow [cookie=0x%x]', log_msg,
                         cookie, extra=self.sw_id)


    def delete_ingress_flow(self, data, waiters):
        if REST_FWID in data:
            fw_id = data[REST_FWID]
            msg = self._delete_firewall_rule(fw_id)
        else:
            raise ValueError("Invalid Parameter")

        return self._response(msg)

    def _delete_ingress_flow(self, fw_id):
        delete_list = []
        msgs = self.ofctl.get_all_flow(waiters, table_id=INGRESS_SECURE_TABLE)
        max_id = UINT16_MAX
        for msg in msgs:
            for stats in msg.body:
                vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
                # print "vlan_id is %s" % vlan_id
                if vlan_id != self.vlan_id:
                    continue
                addr_id = VlanRouter._cookie_to_id(REST_ADDRESSID,
                                                   stats.cookie)
                # print "addr_id is %s" % addr_id
                if addr_id in skip_ids:
                    continue
                elif address_id == REST_ALL:
                    if addr_id <= COOKIE_DEFAULT_ID or max_id < addr_id:
                    #     print "HaHa"
                    # if max_id < addr_id:
                        continue
                elif address_id != addr_id:
                    continue
                delete_list.append(stats)

        delete_ids = []

        # print "delete_list is %s" % delete_list

        for flow_stats in delete_list:
            # Delete flow
            self.ofctl.delete_flow(flow_stats, table_id=L2_LOOKUP_TABLE)
            address_id = VlanRouter._cookie_to_id(REST_ADDRESSID,
                                                  flow_stats.cookie)

            del_address = self.address_data.get_data(addr_id=address_id)
            if del_address is not None:
                del_address_mask = "%s/%s" % (del_address.nw_addr, del_address.netmask)
                self.vlan_groups.pop(del_address_mask)

            if del_address is not None:
                # Clean up suspend packet threads.
                self.packet_buffer.delete(del_addr=del_address)

                # Delete data.
                self.address_data.delete(address_id)
                if address_id not in delete_ids:
                    delete_ids.append(address_id)

        msg = {}
        if delete_ids:
            delete_ids = ','.join(str(addr_id) for addr_id in delete_ids)
            details = 'Delete address [address_id=%s]' % delete_ids
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}

        if skip_ids:
            skip_ids = ','.join(str(addr_id) for addr_id in skip_ids)
            details = 'Skip delete (related route exist) [address_id=%s]'\
                % skip_ids
            if msg:
                msg[REST_DETAILS] += ', %s' % details
            else:
                msg = {REST_RESULT: REST_NG, REST_DETAILS: details}

        return msg

    def mod_flow(self, cookie=0, cookie_mask=0, table_id=0,
                 command=None, idle_timeout=0, hard_timeout=0,
                 priority=0xff, buffer_id=0xffffffff, match=None,
                 actions=None, inst_type=None, out_port=None,
                 out_group=None, flags=0, inst=None):

        datapath = self.dp

        if command is None:
            command = datapath.ofproto.OFPFC_ADD

        if inst is None:
            if inst_type is None:
                inst_type = datapath.ofproto.OFPIT_APPLY_ACTIONS

            inst = []
            if actions is not None:
                inst = [datapath.ofproto_parser.OFPInstructionActions(
                    inst_type, actions)]

        if out_port is None:
            out_port = datapath.ofproto.OFPP_ANY

        if out_group is None:
            out_group = datapath.ofproto.OFPG_ANY

        cookie, cookie_mask = cookies.apply_global_cookie_modifiers(
            cookie, cookie_mask, self)

        message = datapath.ofproto_parser.OFPFlowMod(datapath, cookie,
                                                     cookie_mask,
                                                     table_id, command,
                                                     idle_timeout,
                                                     hard_timeout,
                                                     priority,
                                                     buffer_id,
                                                     out_port,
                                                     out_group,
                                                     flags,
                                                     match,
                                                     inst)

        datapath.send_msg(message)

    def _get_firewall_rule_match(self, index, **kwargs):
        return self.dp.ofproto_parser.OFPMatch(
            cookie=self._id_to_cookie(REST_FWID, index),
            **kwargs
        )

    def _add_firewall_rules_init(self, datas):

        dup_list = []
        for index, data in datas.items():
            # 198 {'action': 'drop', 'nw_proto': 'icmp', 'nw_src': '219.245.185.225'}; index,data
            self.add_firewall_rule(index, data)

        if len(dup_list) == 0:
            details = "all fw_id inserted"
        else:
            fw_ids = ','.join(str(id) for id in dup_list)
            details = "fw_id %s is already in rules" % fw_ids
        msg = {REST_RESULT: REST_OK, REST_DETAILS: details}
        return msg

    def add_firewall_rules(self, datas):

        dup_list = []
        for data in datas:
            index = data["rule_id"]
            if index in self.fw_rules.keys():
                dup_list.append(index)
                continue
            rules = data["rules"]
            self.add_firewall_rule(index, rules)

        if len(dup_list) == 0:
            details = "all fw_id inserted"
        else:
            fw_ids = ','.join(str(id) for id in dup_list)
            details = "fw_id %s is already in rules" % fw_ids
        msg = {REST_RESULT: REST_OK, REST_DETAILS: details}
        # print "firewall add"
        # for id, rules in self.fw_rules.items():
        #     print id, rules
        # self._set_firewall_xml()
        return msg

    def add_firewall_rule(self, index, rules):
        priority = get_priority(PRIORITY_INGRESS)
        cookie = self._id_to_cookie(REST_FWID, index)
        # print "rules is %s" % rules
        self.fw_rules[index] = rules
        self.ofctl.set_firewall_flow(cookie, priority, **rules)

    def delete_firewall_rule(self, fw_id, waiters):
        if fw_id != REST_ALL:
            try:
                fw_id = int(fw_id)
            except ValueError as e:
                err_msg = 'Invalid [%s] value. %s'
                raise ValueError(err_msg % (REST_ADDRESSID, e.message))

        # Get all flow.
        if fw_id not in self.fw_rules.keys():
            details = 'rule [id=%s] not in current rules' % fw_id
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}
            return msg

        table_id = EGRESS_SECURE_TABLE
        if "nw_src" in self.fw_rules[fw_id]:
            table_id = INGRESS_SECURE_TABLE

        delete_list = []
        msgs = self.ofctl.get_all_flow(waiters, table_id=table_id)
        max_id = UINT16_MAX
        for msg in msgs:
            for stats in msg.body:
                vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
                # print "vlan_id is %s" % vlan_id
                if vlan_id != self.vlan_id:
                    continue
                firewall_id = VlanRouter._cookie_to_id(REST_FWID,
                                                   stats.cookie)

                if fw_id == REST_ALL:
                    if firewall_id <= COOKIE_DEFAULT_ID or max_id < addr_id:
                    #     print "HaHa"
                    # if max_id < addr_id:
                        continue
                elif firewall_id != fw_id:
                    continue
                delete_list.append(stats)

        for flow_stats in delete_list:
            # Delete flow
            self.ofctl.delete_flow(flow_stats, table_id=table_id)
            firewall_id = VlanRouter._cookie_to_id(REST_FWID,
                                                  flow_stats.cookie)

            del self.fw_rules[firewall_id]


        details = 'Delete firwall rule [id=%s]' % fw_id
        msg = {REST_RESULT: REST_OK, REST_DETAILS: details}
        # self._set_firewall_xml()
        return msg

    def delete_data(self, data, waiters):
        if REST_ROUTEID in data:
            route_id = data[REST_ROUTEID]
            msg = self._delete_routing_data(route_id, waiters)
        elif REST_ADDRESSID in data:
            address_id = data[REST_ADDRESSID]
            address_cidr = str(data['cidr'])
            # if address_id == REST_ALL:
            #     print "REST_ALL"
            #     msg = self._delete_all_address_data(address_id, waiters)
            # else:
            # msg = self._delete_address_data(address_id, waiters)
            # self._clear_L2_table2(address_cidr)

            self._clear_L2_table(address_cidr)
            self._clear_L3_table(address_cidr)
            self.vlan_groups.pop(address_cidr)

            # msg = self._delete_address_data(address_id, address_cidr, waiters)
            msg = {REST_RESULT: REST_OK, REST_DETAILS: "success"}
            print "clear_l2_table2"
        else:
            raise ValueError('Invalid parameter.')

        return self._response(msg)
        # return msg

    def _delete_address_data(self, address_id, waiters):
        if address_id != REST_ALL:
            try:
                address_id = int(address_id)
            except ValueError as e:
                err_msg = 'Invalid [%s] value. %s'
                raise ValueError(err_msg % (REST_ADDRESSID, e.message))
        # else:
        #     self.vlan_groups = {}

        skip_ids = self._chk_addr_relation_route(address_id)

        # print "address_id is %s" % address_id

        # Get all flow.
        delete_list = []
        msgs = self.ofctl.get_all_flow(waiters, table_id=L2_LOOKUP_TABLE)
        max_id = UINT16_MAX
        # for * 3
        for msg in msgs:
            for stats in msg.body:
                vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
                # print "vlan_id is %s" % vlan_id

                if vlan_id != self.vlan_id:
                    continue
                addr_id = VlanRouter._cookie_to_id(REST_ADDRESSID,
                                                   stats.cookie)
                # print "in for msg in msgs, addr_id is %s" % addr_id

                if addr_id in skip_ids:
                    continue
                elif address_id == REST_ALL:
                    if addr_id <= COOKIE_DEFAULT_ID or max_id < addr_id:
                    #     print "HaHa"
                    # if max_id < addr_id:
                        continue
                elif address_id != addr_id:
                    continue
                delete_list.append(stats)

        delete_ids = []

        for flow_stats in delete_list:
            # Delete flow
            self.ofctl.delete_flow(flow_stats, table_id=L2_LOOKUP_TABLE)

            address_id = VlanRouter._cookie_to_id(REST_ADDRESSID,
                                                  flow_stats.cookie)
            # print address_id
            #
            # for k, address in self.address_data.items():
            #     print "self.address_data is %s, %s" % (k, address.address_id)

            del_address = self.address_data.get_data(addr_id=address_id)
            # print "del_address is %s" % del_address

            if del_address is not None:
                del_address_mask = "%s/%s" % (del_address.nw_addr, del_address.netmask)

                self.vlan_groups.pop(del_address_mask)

            if del_address is not None:
                # Clean up suspend packet threads.
                self.packet_buffer.delete(del_addr=del_address)

                # Delete data.
                self.address_data.delete(address_id)
                if address_id not in delete_ids:
                    delete_ids.append(address_id)

        msg = {}
        if delete_ids:
            delete_ids = ','.join(str(addr_id) for addr_id in delete_ids)
            details = 'Delete address [address_id=%s]' % delete_ids
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}

        if skip_ids:
            skip_ids = ','.join(str(addr_id) for addr_id in skip_ids)
            details = 'Skip delete (related route exist) [address_id=%s]'\
                % skip_ids
            if msg:
                msg[REST_DETAILS] += ', %s' % details
            else:
                msg = {REST_RESULT: REST_NG, REST_DETAILS: details}

        return msg

    # def _delete_address_data(self, address_id, address_cidr, waiters):
    #     # print "_delete_address_data"
    #     if address_id != REST_ALL:
    #         try:
    #             address_id = int(address_id)
    #         except ValueError as e:
    #             err_msg = 'Invalid [%s] value. %s'
    #             raise ValueError(err_msg % (REST_ADDRESSID, e.message))
    #     # else:
    #     #     self.vlan_groups = {}
    #
    #     # empty []
    #     skip_ids = self._chk_addr_relation_route(address_id)
    #     # print "address_id is %s" % address_id
    #
    #     # Get all flow, OFPFlowStats() *3
    #     delete_list = []
    #     msgs = self.ofctl.get_all_flow(waiters, table_id=L2_LOOKUP_TABLE)
    #     max_id = UINT16_MAX
    #     # for * 3
    #     for msg in msgs:
    #         for stats in msg.body:
    #             # vlan_id = 0
    #             vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
    #             # print "vlan_id is %s" % vlan_id
    #
    #             if vlan_id != self.vlan_id:
    #                 continue
    #             addr_id = VlanRouter._cookie_to_id(REST_ADDRESSID,
    #                                                stats.cookie)
    #
    #             # print "in for msg in msgs, addr_id is %s" % addr_id
    #
    #             if addr_id in skip_ids:
    #                 continue
    #             elif address_id == REST_ALL:
    #                 if addr_id <= COOKIE_DEFAULT_ID or max_id < addr_id:
    #                 #     print "HaHa"
    #                 # if max_id < addr_id:
    #                      continue
    #             elif address_id != addr_id:
    #                 continue
    #             elif address_cidr[:-4] not in str(stats):
    #                 continue
    #             delete_list.append(stats)
    #
    #     delete_ids = []
    #     print delete_list
    #
    #     for flow_stats in delete_list:
    #         # Delete flow
    #         self.ofctl.delete_flow(flow_stats, table_id=L2_LOOKUP_TABLE)
    #
    #     # execute delete once
    #     address_id = VlanRouter._cookie_to_id(REST_ADDRESSID,
    #                                           flow_stats.cookie)
    #     for k, address in self.address_data.items():
    #         print "self.address_data is %s, %s" % (k, address.address_id)
    #
    #     del_address = self.address_data.get_data(addr_id=address_id)
    #     print "del_address is %s" % del_address
    #
    #     if del_address is not None:
    #         del_address_mask = "%s/%s" % (del_address.nw_addr, del_address.netmask)
    #
    #         self.vlan_groups.pop(del_address_mask)
    #
    #     if del_address is not None:
    #         # Clean up suspend packet threads.
    #         self.packet_buffer.delete(del_addr=del_address)
    #
    #         # Delete data.
    #         self.address_data.delete(address_id)
    #         if address_id not in delete_ids:
    #             delete_ids.append(address_id)
    #     # execute delete once
    #
    #     msg = {}
    #     if delete_ids:
    #         delete_ids = ','.join(str(addr_id) for addr_id in delete_ids)
    #         details = 'Delete address [address_id=%s]' % delete_ids
    #         msg = {REST_RESULT: REST_OK, REST_DETAILS: details}
    #
    #     if skip_ids:
    #         skip_ids = ','.join(str(addr_id) for addr_id in skip_ids)
    #         details = 'Skip delete (related route exist) [address_id=%s]'\
    #             % skip_ids
    #         if msg:
    #             msg[REST_DETAILS] += ', %s' % details
    #         else:
    #             msg = {REST_RESULT: REST_NG, REST_DETAILS: details}
    #
    #     return msg

    def _delete_routing_data(self, route_id, waiters):

        if route_id != REST_ALL:
            try:
                route_id = int(route_id)
            except ValueError as e:
                err_msg = 'Invalid [%s] value. %s'
                raise ValueError(err_msg % (REST_ROUTEID, e.message))

        # Get all flow.
        # waiters is {}
        msgs = self.ofctl.get_all_flow(waiters)

        delete_list = []
        for msg in msgs:
            for stats in msg.body:
                vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
                if vlan_id != self.vlan_id:
                    continue
                rt_id = VlanRouter._cookie_to_id(REST_ROUTEID, stats.cookie)
                if route_id == REST_ALL:
                    if rt_id == COOKIE_DEFAULT_ID:
                        continue
                elif route_id != rt_id:
                    continue
                delete_list.append(stats)

        # Delete flow.
        delete_ids = []
        for flow_stats in delete_list:
            self.ofctl.delete_flow(flow_stats)
            route_id = VlanRouter._cookie_to_id(REST_ROUTEID,
                                                flow_stats.cookie)
            self.routing_tbl.delete(route_id)
            if route_id not in delete_ids:
                delete_ids.append(route_id)

            # case: Default route deleted. -> set flow (drop)
            route_type = get_priority_type(flow_stats.priority,
                                           vid=self.vlan_id)
            if route_type == PRIORITY_DEFAULT_ROUTING:
                self._set_defaultroute_drop()

        msg = {}
        if delete_ids:
            delete_ids = ','.join(str(route_id) for route_id in delete_ids)
            details = 'Delete route [route_id=%s]' % delete_ids
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}

        return msg

    def _chk_addr_relation_route(self, address_id):
        # Check exist of related routing data.
        relate_list = []
        gateways = self.routing_tbl.get_gateways()
        for gateway in gateways:
            address = self.address_data.get_data(ip=gateway)
            if address is not None:
                if (address_id == REST_ALL
                        and address.address_id not in relate_list):
                    relate_list.append(address.address_id)
                elif address.address_id == address_id:
                    relate_list = [address_id]
                    break
        return relate_list

    def packet_in_handler(self, msg, header_list): # 最重要的一段代码
        # Check invalid TTL (for OpenFlow V1.2/1.3)

        # print "VlanRouter, packet_in_handler!, header_list is %s" % header_list

        ofproto = self.dp.ofproto
        in_port = self.ofctl.get_packetin_inport(msg)

        if ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION or \
                ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            if msg.reason == ofproto.OFPR_INVALID_TTL:
                self._packetin_invalid_ttl(msg, header_list)
                return

        # Analyze event type.
        if ARP in header_list:
            # print header_list[ARP].dst_ip
            dst_ip = header_list[ARP].dst_ip
            src_ip = header_list[ARP].src_ip

            # print "ARP, ip address is %s, count is %s" % (dst_sip, self.count)

            # if header_list[ARP].dst_ip in self.fip_set:
            if header_list[ARP].dst_ip in self.get_floatingip_set():
                print "receive, arp, %s in fip_maps.keys()" % dst_ip
                dst_mac = header_list[ARP].src_mac
                in_port = self.ofctl.dp.ofproto.OFPP_CONTROLLER
                # src_mac = self._get_mac(self.fip_maps[dst_ip])
                fip = header_list[ARP].dst_ip
                src_mac = self.fip_map[fip]

                self.ofctl.send_arp(arp.ARP_REPLY, self.vlan_id,
                                    src_mac, dst_mac, dst_ip, src_ip,
                                    dst_mac, in_port, ex_port)

            self._packetin_arp(msg, header_list)
            return

        if IPV4 in header_list:
            rt_ports = self.address_data.get_default_gw() # 这个是网关的ip
            if header_list[IPV4].dst in rt_ports:
                # Packet to router's port.
                if ICMP in header_list:
                    if header_list[ICMP].type == icmp.ICMP_ECHO_REQUEST:
                        self._packetin_icmp_req(msg, header_list)
                        return
                elif TCP in header_list or UDP in header_list:
                    self._packetin_tcp_udp(msg, header_list)
                    return
            elif header_list[IPV4].dst in self.fip_set:
                dst_ip = header_list[IPV4].dst
                print "IPV4, %s in self.fip_map.keys()" % dst_ip

                # if self.fip_maps.get(dst_ip, None):
                #     fix_ip = self.fip_maps[dst_ip]
                # else:
                #     print "dst_ip not in fip_maps"
                #     return

                # dst_mac = "16:8c:09:b3:0b:68"
                #
                # self.ofctl.set_packetin_flow_output(priority=100,
                #                              dl_type=ether.ETH_TYPE_IP,
                #                              dl_vlan=self.vlan_id,
                #                              dst_ip=dst_ip, new_eth_dst=dst_mac,
                #                                     new_nw_dst=fix_ip,
                #                                     out_port=1025)
                # self.ofctl.set_packetin_flow_output(priority=100,
                #                              dl_type=ether.ETH_TYPE_IP,
                #                              dl_vlan=self.vlan_id,
                #                              src_ip=fix_ip, new_nw_src=dst_ip,
                #                                     new_eth_dst="38:ad:8e:df:a0:65",
                #                                     out_port=2037)

            else:
                # Packet to internal host or gateway router.
                self._packetin_to_node(msg, header_list)
                return

    def _get_portno_by_peermac(self, mac):
        for k, v in self.port_data.items():
            if v == mac:
                return k
        return None

    def _packetin_arp(self, msg, header_list):
        src_addr = self.address_data.get_data(ip=header_list[ARP].src_ip)

        if src_addr is None:
            return

        # case: Receive ARP from the gateway
        #  Update routing table.
        # case: Receive ARP from an internal host
        #  Learning host MAC.
        # gw_flg = self._update_routing_tbl(msg, header_list)
        # if gw_flg is False:
        # #     self._learning_host_mac(msg, header_list)


        # ARP packet handl ing.
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = header_list[ARP].src_ip
        dst_ip = header_list[ARP].dst_ip
        srcip = ip_addr_ntoa(src_ip)
        dstip = ip_addr_ntoa(dst_ip)
        rt_ports = self.address_data.get_default_gw()

        # print "src_ip is %s, dst_ip is %s, rt_ports is %s" % (src_ip, dst_ip, rt_ports)

        if src_ip == dst_ip:
            # GARP -> packet forward (normal)
            output = self.ofctl.dp.ofproto.OFPP_NORMAL
            self.ofctl.send_packet_out(in_port, output, msg.data)

            self.logger.info('Receive GARP from [%s].', srcip,
                             extra=self.sw_id)
            self.logger.info('Send GARP (normal).', extra=self.sw_id)

        elif dst_ip not in rt_ports:
            dst_addr = self.address_data.get_data(ip=dst_ip)
            if (dst_addr is not None and
                    src_addr.address_id == dst_addr.address_id):
                # ARP from internal host -> packet forward (normal)
                output = self.ofctl.dp.ofproto.OFPP_NORMAL
                self.ofctl.send_packet_out(in_port, output, msg.data)

                self.logger.info('Receive ARP from an internal host [%s].',
                                 srcip, extra=self.sw_id)
                self.logger.info('Send ARP (normal)', extra=self.sw_id)
        else:
            if header_list[ARP].opcode == arp.ARP_REQUEST:
                # ARP request to router port -> send ARP reply
                src_mac = self.port_data[in_port].mac
                dst_mac = header_list[ARP].src_mac
                arp_target_mac = dst_mac
                output = in_port
                in_port = self.ofctl.dp.ofproto.OFPP_CONTROLLER

                if self.arp_list.get(src_ip) is None:
                    self.arp_list[src_ip] = dst_mac
                    self.mac_no_list[dst_mac] = in_port

                self.ofctl.send_arp(arp.ARP_REPLY, self.vlan_id,
                                    src_mac, dst_mac, dst_ip, src_ip,
                                    arp_target_mac, in_port, output)

                log_msg = 'Receive ARP request from [%s] to router port [%s].'
                self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
                self.logger.info('Send ARP reply to [%s]', srcip,
                                 extra=self.sw_id)

            elif header_list[ARP].opcode == arp.ARP_REPLY:
                #  ARP reply to router port -> suspend packets forward
                log_msg = 'Receive ARP reply from [%s] to router port [%s].'
                self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)

                if self.arp_list.get(src_ip) is None:
                    self.arp_list[src_ip] = header_list[ARP].src_mac
                    dst_mac = header_list[ARP].src_mac
                    self.mac_no_list[dst_mac] = in_port

                packet_list = self.packet_buffer.get_data(src_ip) # 缓存的包
                if packet_list:
                    # stop ARP reply wait thread.
                    for suspend_packet in packet_list:
                        self.packet_buffer.delete(pkt=suspend_packet)

                    # send suspend packet.
                    output = self.ofctl.dp.ofproto.OFPP_TABLE
                    for suspend_packet in packet_list:
                        source_port = suspend_packet.header_list[IPV4].src
                        self._learning_host_mac1(msg, header_list, source_port)
                        self.ofctl.send_packet_out(suspend_packet.in_port,
                                                   output,
                                                   suspend_packet.data)
                        # print "in _packetin_arp, suspend_packet src is %s" % suspend_packet.header_list[IPV4].src
                        # self.logger.info('Send suspend packet to [%s].', srcip, extra=self.sw_id)


    def _packetin_icmp_req(self, msg, header_list):
        # Send ICMP echo reply.
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                             icmp.ICMP_ECHO_REPLY,
                             icmp.ICMP_ECHO_REPLY_CODE,
                             icmp_data=header_list[ICMP].data)

        srcip = ip_addr_ntoa(header_list[IPV4].src)
        dstip = ip_addr_ntoa(header_list[IPV4].dst)
        log_msg = 'Receive ICMP echo request from [%s] to router port [%s].'
        self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
        self.logger.info('Send ICMP echo reply to [%s].', srcip,
                         extra=self.sw_id)

    def _packetin_tcp_udp(self, msg, header_list):
        # Send ICMP port unreach error.
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                             icmp.ICMP_DEST_UNREACH,
                             icmp.ICMP_PORT_UNREACH_CODE,
                             msg_data=msg.data)

        srcip = ip_addr_ntoa(header_list[IPV4].src)
        dstip = ip_addr_ntoa(header_list[IPV4].dst)
        self.logger.info('Receive TCP/UDP from [%s] to router port [%s].',
                         srcip, dstip, extra=self.sw_id)
        self.logger.info('Send ICMP destination unreachable to [%s].', srcip,
                         extra=self.sw_id)

    # 跨网段的转发
    def _packetin_to_node(self, msg, header_list):
        if len(self.packet_buffer) >= MAX_SUSPENDPACKETS:
            self.logger.info('Packet is dropped, MAX_SUSPENDPACKETS exceeded.',
                             extra=self.sw_id)
            return

        # Send ARP request to get node MAC address.
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = None
        dst_ip = header_list[IPV4].dst # 192.168.0.3
        srcip = ip_addr_ntoa(header_list[IPV4].src)
        dstip = ip_addr_ntoa(dst_ip)

        address = self.address_data.get_data(ip=dst_ip)
        if address is not None:
            log_msg = 'Receive IP packet from [%s] to an internal host [%s].'
            self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
            src_ip = address.default_gw  # 192.168.1.2 ping 192.168.0.3, 结果是192.168.0.1
            src_net = "%s/%s" % (ipv4_apply_mask(srcip, address.netmask), address.netmask)
            dst_net = "%s/%s" % (ipv4_apply_mask(dstip, address.netmask), address.netmask)
            if src_net not in self.vlan_groups.keys() or dst_net not in self.vlan_groups.keys():
                self.logger.debug("src_net %s or dst_net %s not in self.vlan_groups" % (src_net, dst_net))
                return
            if self.vlan_groups[src_net] != self.vlan_groups[dst_net]:
                self.logger.debug("src_net %s and dst_net %s are not in the same net" % (src_net, dst_net))
                return
        else:
            route = self.routing_tbl.get_data(dst_ip=dst_ip)
            if route is not None:
                log_msg = 'Receive IP packet from [%s] to [%s].'
                self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
                gw_address = self.address_data.get_data(ip=route.gateway_ip)
                if gw_address is not None:
                    src_ip = gw_address.default_gw
                    dst_ip = route.gateway_ip

            # if is_public_ip(dst_ip):
            #     address = self.address_data.get_data(ip=srcip)
            #     if address is not None:
            #         self.packet_buffer.add(in_port, header_list, msg.data)
            #         cookie = self._id_to_cookie(REST_ADDRESSID, address.address_id)
            #         priority = self._get_priority(PRIORITY_L2_SWITCHING)
            #         self.ofctl.set_resubmit_flow(cookie, priority, 0, table_id=L2_LOOKUP_TABLE, new_table_id=L3_LOOKUP_TABLE,
            #                                  nw_src=srcip, nw_dst=dstip, dl_type=ether.ETH_TYPE_IP)


        if src_ip is not None:
            self.packet_buffer.add(in_port, header_list, msg.data)
            self.send_arp_request(src_ip, dst_ip, in_port=in_port) # src_ip 192.168.0.1 dst_ip 192.168.0.3
            self.logger.info('Send ARP request (flood)', extra=self.sw_id)

            # self.send_arp_request(src_ip, "192.168.0.233", in_port=in_port) # src_ip 192.168.0.1 dst_ip 192.168.0.3
            # ARP, Request who-has 192.168.0.233 tell 192.168.0.1, length 46

    def _packetin_invalid_ttl(self, msg, header_list):
        # Send ICMP TTL error.
        srcip = ip_addr_ntoa(header_list[IPV4].src)
        self.logger.info('Receive invalid ttl packet from [%s].', srcip,
                         extra=self.sw_id)

        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = self._get_send_port_ip(header_list)
        if src_ip is not None:
            self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                                 icmp.ICMP_TIME_EXCEEDED,
                                 icmp.ICMP_TTL_EXPIRED_CODE,
                                 msg_data=msg.data, src_ip=src_ip)
            self.logger.info('Send ICMP time exceeded to [%s].', srcip,
                             extra=self.sw_id)

    def send_arp_all_gw(self):
        gateways = self.routing_tbl.get_gateways()
        for gateway in gateways:
            address = self.address_data.get_data(ip=gateway)
            self.send_arp_request(address.default_gw, gateway)

    def send_arp_request(self, src_ip, dst_ip, in_port=None):
        # Send ARP request from all ports.

        for send_port in self.port_data.values():
            if in_port is None or in_port != send_port.port_no:
                src_mac = send_port.mac
                dst_mac = mac_lib.BROADCAST_STR
                arp_target_mac = mac_lib.DONTCARE_STR
                inport = self.ofctl.dp.ofproto.OFPP_CONTROLLER
                output = send_port.port_no

                self.ofctl.send_arp(arp.ARP_REQUEST, self.vlan_id,
                                    src_mac, dst_mac, src_ip, dst_ip,
                                    arp_target_mac, inport, output)

    # def get_port_list(self):
    #     ports = requests.get(POD_URL)
    #     return [{'name': port["name"], "ip": port["ip"]} for port in ports]
    #
    #
    # def get_veth_mac(self):
    #     ports_dict = get_port_list()
    #     ip_list = [port["ip"] for port in ports_dict]



    def send_icmp_unreach_error(self, packet_buffer):
        # Send ICMP host unreach error.
        self.logger.info('ARP reply wait timer was timed out.',
                         extra=self.sw_id)
        src_ip = self._get_send_port_ip(packet_buffer.header_list)
        if src_ip is not None:
            self.ofctl.send_icmp(packet_buffer.in_port,
                                 packet_buffer.header_list,
                                 self.vlan_id,
                                 icmp.ICMP_DEST_UNREACH,
                                 icmp.ICMP_HOST_UNREACH_CODE,
                                 msg_data=packet_buffer.data,
                                 src_ip=src_ip)

            dstip = ip_addr_ntoa(packet_buffer.dst_ip)
            self.logger.info('Send ICMP destination unreachable to [%s].',
                             dstip, extra=self.sw_id)

    def _update_routing_tbl(self, msg, header_list):
        # Set flow: routing to gateway.
        out_port = self.ofctl.get_packetin_inport(msg)
        src_mac = header_list[ARP].src_mac
        dst_mac = self.port_data[out_port].mac
        src_ip = header_list[ARP].src_ip

        gateway_flg = False
        for key, value in self.routing_tbl.items():
            if value.gateway_ip == src_ip:
                gateway_flg = True
                if value.gateway_mac == src_mac:
                    continue
                self.routing_tbl[key].gateway_mac = src_mac

                cookie = self._id_to_cookie(REST_ROUTEID, value.route_id)
                priority, log_msg = self._get_priority(PRIORITY_TYPE_ROUTE,
                                                       route=value)
                self.ofctl.set_routing_flow(cookie, priority, out_port,
                                            dl_vlan=self.vlan_id,
                                            src_mac=dst_mac,
                                            dst_mac=src_mac,
                                            nw_dst=value.dst_ip,
                                            dst_mask=value.netmask,
                                            dec_ttl=True)
                self.logger.info('Set %s flow [cookie=0x%x]', log_msg, cookie,
                                 extra=self.sw_id)
        return gateway_flg

    def _learning_host_mac1(self, msg, header_list, source_ip):
        # Set flow: routing to internal Host. 直接转发到对应的port
        out_port = self.ofctl.get_packetin_inport(msg)
        src_mac = header_list[ARP].src_mac
        dst_mac = self.port_data[out_port].mac
        src_ip = header_list[ARP].src_ip

        gateways = self.routing_tbl.get_gateways()
        if src_ip not in gateways:
            address = self.address_data.get_data(ip=src_ip)
            if address is not None:
                cookie = self._id_to_cookie(REST_ADDRESSID, address.address_id)
                priority = self._get_priority(PRIORITY_IMPLICIT_ROUTING)
                self.ofctl.set_routing_flow(cookie, priority,
                                            out_port, dl_vlan=self.vlan_id,
                                            src_mac=dst_mac, dst_mac=src_mac,
                                            nw_dst=src_ip,
                                            nw_src=source_ip,
                                            idle_timeout=IDLE_TIMEOUT,
                                            dec_ttl=True, table_id=L3_LOOKUP_TABLE)
                # self.logger.info('Set implicit routing flow [cookie=0x%x]',
                #                  cookie, extra=self.sw_id)
                address0 = self.address_data.get_data(ip=source_ip)
                priority = self._get_priority(PRIORITY_L2_SWITCHING)
                outport = self.ofctl.dp.ofproto.OFPP_NORMAL
                self.ofctl.set_l2_lookup_flow(
                    cookie, priority, outport, dl_vlan=self.vlan_id,
                    nw_src=source_ip,
                    idle_timeout=IDLE_TIMEOUT,
                    nw_dst=src_ip, table_id=L2_LOOKUP_TABLE)


    def _learning_host_mac(self, msg, header_list):
        # Set flow: routing to internal Host. 直接转发到对应的port
        out_port = self.ofctl.get_packetin_inport(msg)
        src_mac = header_list[ARP].src_mac
        dst_mac = self.port_data[out_port].mac
        src_ip = header_list[ARP].src_ip

        gateways = self.routing_tbl.get_gateways()
        if src_ip not in gateways:
            address = self.address_data.get_data(ip=src_ip)
            if address is not None:
                cookie = self._id_to_cookie(REST_ADDRESSID, address.address_id)
                priority = self._get_priority(PRIORITY_IMPLICIT_ROUTING)
                self.ofctl.set_routing_flow(cookie, priority,
                                            out_port, dl_vlan=self.vlan_id,
                                            src_mac=dst_mac, dst_mac=src_mac,
                                            nw_dst=src_ip,
                                            idle_timeout=IDLE_TIMEOUT,
                                            dec_ttl=True)
                self.logger.info('Set implicit routing flow [cookie=0x%x]',
                                 cookie, extra=self.sw_id)

    def _get_send_port_ip(self, header_list):
        try:
            src_mac = header_list[ETHERNET].src
            if IPV4 in header_list:
                src_ip = header_list[IPV4].src
            else:
                src_ip = header_list[ARP].src_ip
        except KeyError:
            self.logger.debug('Receive unsupported packet.', extra=self.sw_id)
            return None

        address = self.address_data.get_data(ip=src_ip)
        if address is not None:
            return address.default_gw
        else:
            route = self.routing_tbl.get_data(gw_mac=src_mac)
            if route is not None:
                address = self.address_data.get_data(ip=route.gateway_ip)
                if address is not None:
                    return address.default_gw

        self.logger.debug('Receive packet from unknown IP[%s].',
                          ip_addr_ntoa(src_ip), extra=self.sw_id)
        return None


class PortData(dict):
    def __init__(self, ports):
        super(PortData, self).__init__()
        for port in ports.values():
            data = Port(port.port_no, port.hw_addr)
            self[port.port_no] = data


class Port(object):
    def __init__(self, port_no, hw_addr):
        super(Port, self).__init__()
        self.port_no = port_no
        self.mac = hw_addr


class AddressData(dict):
    def __init__(self):
        super(AddressData, self).__init__()
        self.address_id = 1

    def add(self, address):
        err_msg = 'Invalid [%s] value.' % REST_ADDRESS
        nw_addr, mask, default_gw = nw_addr_aton(address, err_msg=err_msg)

        # Check overlaps
        for other in self.values():
            other_mask = mask_ntob(other.netmask)
            add_mask = mask_ntob(mask, err_msg=err_msg)
            if (other.nw_addr == ipv4_apply_mask(default_gw, other.netmask) or
                    nw_addr == ipv4_apply_mask(other.default_gw, mask,
                                               err_msg)):
                msg = 'Address overlaps [address_id=%d]' % other.address_id
                raise CommandFailure(msg=msg)

        address = Address(self.address_id, nw_addr, mask, default_gw)
        ip_str = ip_addr_ntoa(nw_addr)
        key = '%s/%d' % (ip_str, mask)
        self[key] = address

        self.address_id += 1
        self.address_id &= UINT32_MAX
        if self.address_id == COOKIE_DEFAULT_ID:
            self.address_id = 1

        return address

    def _get_gateway(self, address):
        return str(list(netaddr.IPNetwork(address))[1]) + "/24"

    def myadd(self, address, index):
        err_msg = 'Invalid [%s] value.' % REST_ADDRESS
        ip = address.split("/")[0]

        address = self._get_gateway(address)
        nw_addr, mask, default_gw = nw_addr_aton(address, err_msg=err_msg)

        # Check overlaps
        # for other in self.values():
        #     other_mask = mask_ntob(other.netmask)
        #     add_mask = mask_ntob(mask, err_msg=err_msg)
        #     if (other.nw_addr == ipv4_apply_mask(default_gw, other.netmask) or
        #             nw_addr == ipv4_apply_mask(other.default_gw, mask,
        #                                        err_msg)):
        #         msg = 'Address overlaps [address_id=%d]' % other.address_id
        #         raise CommandFailure(msg=msg)


        ## look here, self.address_id -> index
        address = Address(index, nw_addr, mask, default_gw)
        ip_str = ip_addr_ntoa(nw_addr)
        key = '%s/%d' % (ip_str, mask)
        self[key] = address

        # self.address_id += 1
        # self.address_id &= UINT32_MAX
        # if self.address_id == COOKIE_DEFAULT_ID:
        #     self.address_id = 1

        return address

    def delete(self, address_id):
        for key, value in self.items():
            if value.address_id == address_id:
                del self[key]
                return

    def get_default_gw(self):
        return [address.default_gw for address in self.values()]

    def get_data(self, addr_id=None, ip=None):
        for address in self.values():
            if addr_id is not None:
                if addr_id == address.address_id:
                    return address
            else:
                assert ip is not None
                if ipv4_apply_mask(ip, address.netmask) == address.nw_addr:
                    return address
        return None


class Address(object):
    def __init__(self, address_id, nw_addr, netmask, default_gw):
        super(Address, self).__init__()
        self.address_id = address_id
        self.nw_addr = nw_addr
        self.netmask = netmask
        self.default_gw = default_gw

    def __contains__(self, ip):
        return bool(ipv4_apply_mask(ip, self.netmask) == self.nw_addr)


class RoutingTable(dict):
    def __init__(self):
        super(RoutingTable, self).__init__()
        self.route_id = 1

    def add(self, dst_nw_addr, gateway_ip):
        err_msg = 'Invalid [%s] value.'

        if dst_nw_addr == DEFAULT_ROUTE:
            dst_ip = 0
            netmask = 0
        else:
            dst_ip, netmask, dummy = nw_addr_aton(
                dst_nw_addr, err_msg=err_msg % REST_DESTINATION)

        gateway_ip = ip_addr_aton(gateway_ip, err_msg=err_msg % REST_GATEWAY)

        # Check overlaps
        overlap_route = None
        if dst_nw_addr == DEFAULT_ROUTE:
            if DEFAULT_ROUTE in self:
                overlap_route = self[DEFAULT_ROUTE].route_id
        elif dst_nw_addr in self:
            overlap_route = self[dst_nw_addr].route_id

        if overlap_route is not None:
            msg = 'Destination overlaps [route_id=%d]' % overlap_route
            raise CommandFailure(msg=msg)

        routing_data = Route(self.route_id, dst_ip, netmask, gateway_ip)
        ip_str = ip_addr_ntoa(dst_ip)
        key = '%s/%d' % (ip_str, netmask)
        self[key] = routing_data

        self.route_id += 1
        self.route_id &= UINT32_MAX
        if self.route_id == COOKIE_DEFAULT_ID:
            self.route_id = 1

        return routing_data

    def delete(self, route_id):
        for key, value in self.items():
            if value.route_id == route_id:
                del self[key]
                return

    def get_gateways(self):
        return [routing_data.gateway_ip for routing_data in self.values()]

    def get_data(self, gw_mac=None, dst_ip=None):
        if gw_mac is not None:
            for route in self.values():
                if gw_mac == route.gateway_mac:
                    return route
            return None

        elif dst_ip is not None:
            get_route = None
            mask = 0
            for route in self.values():
                if ipv4_apply_mask(dst_ip, route.netmask) == route.dst_ip:
                    # For longest match
                    if mask < route.netmask:
                        get_route = route
                        mask = route.netmask

            if get_route is None:
                get_route = self.get(DEFAULT_ROUTE, None)
            return get_route
        else:
            return None


class Route(object):
    def __init__(self, route_id, dst_ip, netmask, gateway_ip):
        super(Route, self).__init__()
        self.route_id = route_id
        self.dst_ip = dst_ip
        self.netmask = netmask
        self.gateway_ip = gateway_ip
        self.gateway_mac = None


class SuspendPacketList(list):
    def __init__(self, timeout_function):
        super(SuspendPacketList, self).__init__()
        self.timeout_function = timeout_function

    def add(self, in_port, header_list, data):
        suspend_pkt = SuspendPacket(in_port, header_list, data,
                                    self.wait_arp_reply_timer)
        self.append(suspend_pkt)

    def delete(self, pkt=None, del_addr=None):
        if pkt is not None:
            del_list = [pkt]
        else:
            assert del_addr is not None
            del_list = [pkt for pkt in self if pkt.dst_ip in del_addr]

        for pkt in del_list:
            self.remove(pkt)
            hub.kill(pkt.wait_thread)
            pkt.wait_thread.wait()

    def get_data(self, dst_ip):
        return [pkt for pkt in self if pkt.dst_ip == dst_ip]

    def wait_arp_reply_timer(self, suspend_pkt):
        hub.sleep(ARP_REPLY_TIMER)
        if suspend_pkt in self:
            self.timeout_function(suspend_pkt)
            self.delete(pkt=suspend_pkt)

    def get_data2(self, in_port, dst_ip):
        return [pkt for pkt in self if pkt.dst_ip == dst_ip and pkg.in_port == in_port]

class SuspendPacket(object):
    def __init__(self, in_port, header_list, data, timer):
        super(SuspendPacket, self).__init__()
        self.in_port = in_port
        self.dst_ip = header_list[IPV4].dst
        self.header_list = header_list
        self.data = data
        # Start ARP reply wait timer.
        self.wait_thread = hub.spawn(timer, self)


class OfCtl(object):
    _OF_VERSIONS = {}

    @staticmethod
    def register_of_version(version):
        def _register_of_version(cls):
            OfCtl._OF_VERSIONS.setdefault(version, cls)
            return cls
        return _register_of_version

    @staticmethod
    def factory(dp, logger):
        of_version = dp.ofproto.OFP_VERSION
        if of_version in OfCtl._OF_VERSIONS:
            ofctl = OfCtl._OF_VERSIONS[of_version](dp, logger)
        else:
            raise OFPUnknownVersion(version=of_version)

        return ofctl

    def __init__(self, dp, logger):
        super(OfCtl, self).__init__()
        self.dp = dp
        self.sw_id = {'sw_id': dpid_lib.dpid_to_str(dp.id)}
        self.logger = logger

    def set_sw_config_for_ttl(self):
        # OpenFlow v1_2/1_3.
        pass

    def set_flow(self, cookie, priority, dl_type=0, dl_dst=0, dl_vlan=0,
                 nw_src=0, src_mask=32, nw_dst=0, dst_mask=32, in_port=0,
                 nw_proto=0, idle_timeout=0, actions=None, table_id=0, metadata=0):
        # Abstract method
        raise NotImplementedError()

    def send_arp(self, arp_opcode, vlan_id, src_mac, dst_mac,
                 src_ip, dst_ip, arp_target_mac, in_port, output):
        # Generate ARP packet
        if vlan_id != VLANID_NONE:
            ether_proto = ether.ETH_TYPE_8021Q
            pcp = 0
            cfi = 0
            vlan_ether = ether.ETH_TYPE_ARP
            v = vlan.vlan(pcp, cfi, vlan_id, vlan_ether)
        else:
            ether_proto = ether.ETH_TYPE_ARP
        hwtype = 1
        arp_proto = ether.ETH_TYPE_IP
        hlen = 6
        plen = 4

        pkt = packet.Packet()
        e = ethernet.ethernet(dst_mac, src_mac, ether_proto)
        a = arp.arp(hwtype, arp_proto, hlen, plen, arp_opcode,
                    src_mac, src_ip, arp_target_mac, dst_ip)
        pkt.add_protocol(e)
        if vlan_id != VLANID_NONE:
            pkt.add_protocol(v)
        pkt.add_protocol(a)
        pkt.serialize()

        # Send packet out
        # print "send_arp, send packet out"

        self.send_packet_out(in_port, output, pkt.data, data_str=str(pkt))

    def send_icmp(self, in_port, protocol_list, vlan_id, icmp_type,
                  icmp_code, icmp_data=None, msg_data=None, src_ip=None):
        # Generate ICMP reply packet
        csum = 0
        offset = ethernet.ethernet._MIN_LEN

        if vlan_id != VLANID_NONE:
            ether_proto = ether.ETH_TYPE_8021Q
            pcp = 0
            cfi = 0
            vlan_ether = ether.ETH_TYPE_IP
            v = vlan.vlan(pcp, cfi, vlan_id, vlan_ether)
            offset += vlan.vlan._MIN_LEN
        else:
            ether_proto = ether.ETH_TYPE_IP

        eth = protocol_list[ETHERNET]
        e = ethernet.ethernet(eth.src, eth.dst, ether_proto)

        ip = protocol_list[IPV4]

        if icmp_data is None and msg_data is not None:
            # RFC 4884 says that we should send "at least 128 octets"
            # if we are using the ICMP Extension Structure.
            # We're not using the extension structure, but let's send
            # up to 128 bytes of the original msg_data.
            #
            # RFC 4884 also states that the length field is interpreted in
            # 32 bit units, so the length calculated in bytes needs to first
            # be divided by 4, then increased by 1 if the modulus is non-zero.
            #
            # Finally, RFC 4884 says, if we're specifying the length, we MUST
            # zero pad to the next 32 bit boundary.
            end_of_data = offset + len(ip) + 128
            ip_datagram = bytearray()
            ip_datagram += msg_data[offset:end_of_data]
            data_len = int(len(ip_datagram) / 4)
            length_modulus = int(len(ip_datagram) % 4)
            if length_modulus:
                data_len += 1
                ip_datagram += bytearray([0] * (4 - length_modulus))
            if icmp_type == icmp.ICMP_DEST_UNREACH:
                icmp_data = icmp.dest_unreach(data_len=data_len,
                                              data=ip_datagram)
            elif icmp_type == icmp.ICMP_TIME_EXCEEDED:
                icmp_data = icmp.TimeExceeded(data_len=data_len,
                                              data=ip_datagram)

        ic = icmp.icmp(icmp_type, icmp_code, csum, data=icmp_data)

        if src_ip is None:
            src_ip = ip.dst
        ip_total_length = ip.header_length * 4 + ic._MIN_LEN
        if ic.data is not None:
            ip_total_length += ic.data._MIN_LEN
            if ic.data.data is not None:
                ip_total_length += + len(ic.data.data)
        i = ipv4.ipv4(ip.version, ip.header_length, ip.tos,
                      ip_total_length, ip.identification, ip.flags,
                      ip.offset, DEFAULT_TTL, inet.IPPROTO_ICMP, csum,
                      src_ip, ip.src)

        pkt = packet.Packet()
        pkt.add_protocol(e)
        if vlan_id != VLANID_NONE:
            pkt.add_protocol(v)
        pkt.add_protocol(i)
        pkt.add_protocol(ic)
        pkt.serialize()

        # Send packet out
        self.send_packet_out(in_port, self.dp.ofproto.OFPP_IN_PORT,
                             pkt.data, data_str=str(pkt))

    def send_packet_out(self, in_port, output, data, data_str=None):
        actions = [self.dp.ofproto_parser.OFPActionOutput(output, 0)]
        self.dp.send_packet_out(buffer_id=UINT32_MAX, in_port=in_port,
                                actions=actions, data=data)
        # TODO: Packet library convert to string
        # if data_str is None:
        #     data_str = str(packet.Packet(data))
        # self.logger.debug('Packet out = %s', data_str, extra=self.sw_id)

    def set_floatingip_ingress_flow(self, cookie, priority, in_port, new_table_id, dl_type=0, table_id=0, metadata=0):
        actions = [
            self.dp.ofproto_parser.OFPActionSetField(metadata=3),
            self.dp.ofproto_parser.NXActionResubmitTable(table_id=new_table_id)]
        self.set_flow(cookie, priority, in_port=in_port, actions=actions, dl_type=dl_type, table_id=table_id, metadata=metadata)

    def set_resubmit_flow(self, cookie, priority, in_port, new_table_id, dl_type=0, table_id=0,
                          metadata=0, dl_vlan=0, nw_src=0, nw_dst=0, nw_proto=0):
        actions = [self.dp.ofproto_parser.NXActionResubmitTable(table_id=new_table_id)]
        self.set_flow(cookie, priority, in_port=in_port, actions=actions, dl_type=dl_type, table_id=table_id, metadata=metadata,
                      dl_vlan=dl_vlan, nw_src=nw_src, nw_dst=nw_dst, nw_proto=nw_proto)

    def set_normal_flow(self, cookie, priority, table_id=0):
        out_port = self.dp.ofproto.OFPP_NORMAL
        actions = [self.dp.ofproto_parser.OFPActionOutput(out_port, 0)]
        self.set_flow(cookie, priority, actions=actions, table_id=table_id)

    def set_test_flow(self, cookie, priority, table_id=0):
        parser = self.dp.ofproto_parser

        actions = [
            parser.OFPActionSetField(reg6=2),
            parser.OFPActionSetField(metadata=234),
            parser.NXActionRegLoad(
                dst='in_port',
                value=0,
                ofs_nbits=nicira_ext.ofs_nbits(0, 31),
            ),
            parser.NXActionResubmit(),
        ]
        self.set_flow(cookie, priority, in_port=3, actions=actions, table_id=table_id)

    def set_packetin_flow(self, cookie, priority, dl_type=0, dl_dst=0,in_port=0, nw_src=0, nw_dst=0,
                          dl_vlan=0, dst_ip=0, src_mask=32, dst_mask=32, nw_proto=0, table_id=0):
        miss_send_len = UINT16_MAX
        actions = [self.dp.ofproto_parser.OFPActionOutput(
            self.dp.ofproto.OFPP_CONTROLLER, miss_send_len)]
        # print "self.dp.ofproto_parser: %s" % self.dp.ofproto_parser
        # print "set_packetin_flow, priority is %s" % priority
        self.set_flow(cookie, priority, dl_type=dl_type, dl_dst=dl_dst,
                      dl_vlan=dl_vlan, nw_dst=dst_ip, dst_mask=dst_mask,
                      in_port=in_port,
                      nw_proto=nw_proto, actions=actions, table_id=table_id)

    def set_packetin_flow_l3(self, cookie, priority, dl_type=0, dl_dst=0,in_port=0, nw_dst=0,
                             dl_vlan=0, dst_mask=32, nw_proto=0, table_id=0):
        miss_send_len = UINT16_MAX
        actions = [self.dp.ofproto_parser.OFPActionOutput(
            self.dp.ofproto.OFPP_CONTROLLER, miss_send_len)]
        # print "self.dp.ofproto_parser: %s" % self.dp.ofproto_parser
        # print "set_packetin_flow, priority is %s" % priority
        self.set_flow(cookie, priority, dl_type=dl_type, dl_dst=dl_dst,
                      dl_vlan=dl_vlan, nw_dst=nw_dst, dst_mask=dst_mask,
                      in_port=in_port,
                      nw_proto=nw_proto, actions=actions, table_id=table_id)

    def set_metadata_flow(self, cookie, priority, dl_type=0, dl_dst=0,in_port=0,
                          dl_vlan=0, dst_ip=0, dst_mask=32, nw_proto=0, table_id=0, metadata=0):
        out_port = self.dp.ofproto.OFPP_NORMAL
        actions = [self.dp.ofproto_parser.OFPActionOutput(out_port, 0)]
        # print "self.dp.ofproto_parser: %s" % self.dp.ofproto_parser
        # print "set_packetin_flow, priority is %s" % priority
        self.set_flow(cookie, priority, dl_type=dl_type, dl_dst=dl_dst,
                      dl_vlan=dl_vlan, nw_dst=dst_ip, dst_mask=dst_mask,
                      in_port=in_port,
                      nw_proto=nw_proto, actions=actions, table_id=table_id, metadata=metadata)

    def set_packetin_flow_output(self, priority, dl_type=0, dl_dst=0,src_ip=0,in_port=0,
                          dl_vlan=0, dst_ip=0, dst_mask=32, nw_proto=0, new_eth_src=None,
                                 new_eth_dst=None, new_nw_src=None, new_nw_dst=None, out_port=None):
        miss_send_len = UINT16_MAX
        # actions = [self.dp.ofproto_parser.OFPActionOutput(
        #     self.dp.ofproto.OFPP_CONTROLLER, miss_send_len)]
        actions = []
        if new_eth_src:
            actions.append(self.dp.ofproto_parser.OFPActionSetField(eth_src=new_eth_src))
        if new_eth_dst:
            actions.append(self.dp.ofproto_parser.OFPActionSetField(eth_dst=new_eth_dst))
        if new_nw_src:
            actions.append(self.dp.ofproto_parser.OFPActionSetField(ipv4_src=new_nw_src))
        if new_nw_dst:
            actions.append(self.dp.ofproto_parser.OFPActionSetField(ipv4_dst=new_nw_dst))
        if out_port:
            actions.append(self.dp.ofproto_parser.OFPActionOutput(out_port, miss_send_len))

        # print "set_packetin_flow, priority is %s" % priority
        self.set_flow(0, priority, dl_type=dl_type, dl_dst=dl_dst, in_port=in_port,
                      dl_vlan=dl_vlan, nw_dst=dst_ip, dst_mask=dst_mask,nw_src=src_ip,
                      nw_proto=nw_proto, actions=actions)

    def send_stats_request(self, stats, waiters):
        self.dp.set_xid(stats)
        waiters_per_dp = waiters.setdefault(self.dp.id, {})
        event = hub.Event()
        msgs = []
        waiters_per_dp[stats.xid] = (event, msgs)
        self.dp.send_msg(stats)

        try:
            event.wait(timeout=OFP_REPLY_TIMER)
        except hub.Timeout:
            del waiters_per_dp[stats.xid]

        return msgs

    def set_floatingip_ingress_dnat_flow(self, cookie, priority, in_port, nw_dst, new_dl_dst, new_nw_dst,
                                         new_dl_src, goto_table_id, dl_type=ether.ETH_TYPE_IP,
                                         table_id=INGRESS_DNAT_TABLE):
        actions = []
        # actions.append(self.dp.ofproto_parser.OFPActionDecNwTtl())
        if new_dl_src:
            actions.append(self.dp.ofproto_parser.OFPActionSetField(eth_src=new_dl_src))
        if new_dl_dst:
            actions.append(self.dp.ofproto_parser.OFPActionSetField(eth_dst=new_dl_dst))
        if new_nw_dst:
            actions.append(self.dp.ofproto_parser.OFPActionSetField(ipv4_dst=new_nw_dst))
        if goto_table_id:
            actions.append(self.dp.ofproto_parser.NXActionResubmitTable(table_id=goto_table_id))
        self.set_flow(cookie, priority, in_port=in_port, nw_dst=nw_dst,
                      actions=actions, dl_type=dl_type, table_id=table_id)


    def set_floatingip_ingress_l3_flow(self, cookie, priority, in_port, port_index, nw_dst, dl_type=ether.ETH_TYPE_IP, table_id=L3_LOOKUP_TABLE):
        actions = [self.dp.ofproto_parser.OFPActionOutput(port_index)]
        actions.append(self.dp.ofproto_parser.OFPActionOutput(MONITOR_PORT))
        self.set_flow(cookie, priority, in_port=in_port, actions=actions,
                      nw_dst=nw_dst, dl_type=dl_type, table_id=table_id)


    def set_floatingip_ingress_l3_flow2(self, cookie, priority, in_port, nw_dst, dl_type=ether.ETH_TYPE_IP, table_id=L3_LOOKUP_TABLE):
        # actions = [self.dp.ofproto_parser.OFPActionOutput(port_index)]
        actions.append(self.dp.ofproto_parser.NXActionResubmitTable(table_id=L3_LOOKUP_TABLE2))
        self.set_flow(cookie, priority, in_port=in_port, actions=actions,
                      nw_dst=nw_dst, dl_type=dl_type, table_id=table_id)

    def set_floatingip_egress_l3_flow(self, cookie, priority, nw_src, dl_type=ether.ETH_TYPE_IP, table_id=L3_LOOKUP_TABLE):
        actions = [self.dp.ofproto_parser.OFPActionOutput(ex_port)]
        # actions.append(self.dp.ofproto_parser.OFPActionDecNwTtl())
        self.set_flow(cookie, priority, actions=actions,
                      nw_src=nw_src, dl_type=dl_type, table_id=table_id)


    def set_floatingip_engress_snat_flow(self, cookie, priority, nw_src, new_dl_dst, new_dl_src,
                                         goto_table_id, dl_type=ether.ETH_TYPE_IP,
                                         new_nw_src=GATEWAY_MAC_ADDRESS,table_id=INGRESS_DNAT_TABLE):
        actions = [self.dp.ofproto_parser.OFPActionOutput(MONITOR_PORT)]
        if new_dl_src:
            actions.append(self.dp.ofproto_parser.OFPActionSetField(eth_src=new_dl_src))
        if new_dl_dst:
            actions.append(self.dp.ofproto_parser.OFPActionSetField(eth_dst=new_dl_dst))
        if new_nw_src:
            actions.append(self.dp.ofproto_parser.OFPActionSetField(ipv4_src=new_nw_src))
        if goto_table_id:
            actions.append(self.dp.ofproto_parser.NXActionResubmitTable(table_id=goto_table_id))
        self.set_flow(cookie, priority, nw_src=nw_src,
                      actions=actions, dl_type=dl_type, table_id=table_id)


@OfCtl.register_of_version(ofproto_v1_0.OFP_VERSION)
class OfCtl_v1_0(OfCtl):

    def __init__(self, dp, logger):
        super(OfCtl_v1_0, self).__init__(dp, logger)

    def get_packetin_inport(self, msg):
        return msg.in_port

    def get_all_flow(self, waiters):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        match = ofp_parser.OFPMatch(ofp.OFPFW_ALL, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0)
        stats = ofp_parser.OFPFlowStatsRequest(self.dp, 0, match,
                                               0xff, ofp.OFPP_NONE)
        return self.send_stats_request(stats, waiters)

    def set_flow(self, cookie, priority, dl_type=0, dl_dst=0, dl_vlan=0,
                 nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                 nw_proto=0, idle_timeout=0, actions=None):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser
        cmd = ofp.OFPFC_ADD

        # Match
        wildcards = ofp.OFPFW_ALL
        if dl_type:
            wildcards &= ~ofp.OFPFW_DL_TYPE
        if dl_dst:
            wildcards &= ~ofp.OFPFW_DL_DST
        if dl_vlan:
            wildcards &= ~ofp.OFPFW_DL_VLAN
        if nw_src:
            v = (32 - src_mask) << ofp.OFPFW_NW_SRC_SHIFT | \
                ~ofp.OFPFW_NW_SRC_MASK
            wildcards &= v
            nw_src = ipv4_text_to_int(nw_src)
        if nw_dst:
            v = (32 - dst_mask) << ofp.OFPFW_NW_DST_SHIFT | \
                ~ofp.OFPFW_NW_DST_MASK
            wildcards &= v
            nw_dst = ipv4_text_to_int(nw_dst)
        if nw_proto:
            wildcards &= ~ofp.OFPFW_NW_PROTO

        match = ofp_parser.OFPMatch(wildcards, 0, 0, dl_dst, dl_vlan, 0,
                                    dl_type, 0, nw_proto,
                                    nw_src, nw_dst, 0, 0)
        actions = actions or []

        m = ofp_parser.OFPFlowMod(self.dp, match, cookie, cmd,
                                  idle_timeout=idle_timeout,
                                  priority=priority, actions=actions)
        self.dp.send_msg(m)

    def set_routing_flow(self, cookie, priority, outport, dl_vlan=0,
                         nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                         src_mac=0, dst_mac=0, idle_timeout=0, **dummy):
        ofp_parser = self.dp.ofproto_parser
        if nw_src or dst_src:
            dl_type = ether.ETH_TYPE_IP
        # print "execute ovs1.0 set_routing_flow"

        # Decrement TTL value is not supported at OpenFlow V1.0
        actions = []
        if src_mac:
            actions.append(ofp_parser.OFPActionSetDlSrc(
                           mac_lib.haddr_to_bin(src_mac)))
        if dst_mac:
            actions.append(ofp_parser.OFPActionSetDlDst(
                           mac_lib.haddr_to_bin(dst_mac)))
        if outport is not None:
            actions.append(ofp_parser.OFPActionOutput(outport))

        self.set_flow(cookie, priority, dl_type=dl_type, dl_vlan=dl_vlan,
                      nw_src=nw_src, src_mask=src_mask,
                      nw_dst=nw_dst, dst_mask=dst_mask,
                      idle_timeout=idle_timeout, actions=actions)

    def delete_flow(self, flow_stats):
        match = flow_stats.match
        cookie = flow_stats.cookie
        cmd = self.dp.ofproto.OFPFC_DELETE_STRICT
        priority = flow_stats.priority
        actions = []

        flow_mod = self.dp.ofproto_parser.OFPFlowMod(
            self.dp, match, cookie, cmd, priority=priority, actions=actions)
        self.dp.send_msg(flow_mod)
        self.logger.info('Delete flow [cookie=0x%x]', cookie, extra=self.sw_id)


class OfCtl_after_v1_2(OfCtl):

    def __init__(self, dp, logger):
        super(OfCtl_after_v1_2, self).__init__(dp, logger)

    def set_sw_config_for_ttl(self):
        pass

    def get_packetin_inport(self, msg):
        in_port = self.dp.ofproto.OFPP_ANY
        for match_field in msg.match.fields:
            if match_field.header == self.dp.ofproto.OXM_OF_IN_PORT:
                in_port = match_field.value
                break
        return in_port

    def get_all_flow(self, waiters):
        pass




    def set_firewall_flow(self, cookie, priority, dl_type=0, dl_dst=0, dl_vlan=0, dl_src=0,
                          nw_src=0, src_mask=32, nw_dst=0, dst_mask=32, in_port=0,
                          nw_proto="", action=None, **kwargs):

        actions = []
        table_id = EGRESS_SECURE_TABLE
        goto_table = L3_LOOKUP_TABLE
        if nw_src or nw_dst:
            dl_type = ether.ETH_TYPE_IP
        if nw_src:
            table_id = INGRESS_SECURE_TABLE
            goto_table = L2_LOOKUP_TABLE

        ofp_parser = self.dp.ofproto_parser
        if action == "accept":
            actions.append(ofp_parser.NXActionResubmitTable(table_id=goto_table))
        elif action == "drop":
            actions = []
        else:
            raise Exception("firewall rule action is neither accept nor drop")

        if nw_proto:
            nw_proto = self._get_nw_proto(nw_proto)
            # print nw_proto

        self.set_flow(cookie, priority, dl_type=dl_type, dl_dst=dl_dst, dl_vlan=dl_vlan, dl_src=dl_src,
                     nw_src=nw_src, src_mask=src_mask, nw_dst=nw_dst, dst_mask=dst_mask, in_port=in_port,
                     nw_proto=nw_proto, idle_timeout=0, actions=actions, table_id=table_id, **kwargs)

    def _get_nw_proto(self, nw_proto):
        if str.isdigit(str(nw_proto)):
            return int(nw_proto)
        nw_proto = nw_proto.upper()
        proto = NW_PROTO.get(nw_proto, None)
        if proto is None:
            raise Exception("protocol %s is invalid" % proto)
        return proto

    def set_flow(self, cookie, priority, dl_type=0, dl_dst=0, dl_vlan=0, dl_src=0,
                 nw_src=0, src_mask=32, nw_dst=0, dst_mask=32, in_port=0,
                 nw_proto=0, idle_timeout=0, actions=None, table_id=0, metadata=0,
                 tp_src=0, tp_dst=0, **kwargs):

        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser
        cmd = ofp.OFPFC_ADD

        # Match
        match = ofp_parser.OFPMatch()
        if in_port:
            match.set_in_port(in_port)
        if metadata:
            match.set_metadata(metadata)
        if dl_type:
            match.set_dl_type(dl_type)
        if dl_src:
            match.set_dl_src(dl_src)
        if dl_dst:
            match.set_dl_dst(dl_dst)
        if dl_vlan:
            match.set_vlan_vid(dl_vlan)
        if nw_src:
            match.set_ipv4_src_masked(ipv4_text_to_int(str(nw_src)),
                                      mask_ntob(src_mask))
        if nw_dst:
            match.set_ipv4_dst_masked(ipv4_text_to_int(str(nw_dst)),
                                      mask_ntob(dst_mask))
        if nw_proto:
            if dl_type == ether.ETH_TYPE_IP:
                match.set_ip_proto(nw_proto)
                if nw_proto == ether.TCP:
                    if tp_src:
                        match.set_tcp_src(int(tp_src))
                    if tp_dst:
                        match.set_tcp_dst(int(tp_dst))
                elif nw_proto == ether.UDP:
                    if tp_src:
                        match.set_udp_src(int(tp_src))
                    if tp_dst:
                        match.set_udp_dst(int(tp_dst))
            elif dl_type == ether.ETH_TYPE_ARP:
                match.set_arp_opcode(nw_proto)


        # Instructions
        actions = actions or []
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        #
        # m = ofp_parser.OFPFlowMod(self.dp, cookie, 0, 0, cmd, idle_timeout,
        #                           0, priority, UINT32_MAX, ofp.OFPP_ANY,
        #                           ofp.OFPG_ANY, 0, match, inst)

        m = ofp_parser.OFPFlowMod(self.dp, cookie, 0, table_id, cmd, idle_timeout,
                                  0, priority, UINT32_MAX, ofp.OFPP_ANY,
                                  ofp.OFPG_ANY, 0, match, inst)

        self.dp.send_msg(m)

    def set_l2_lookup_flow(self, cookie, priority, outport, dl_vlan=0,
                         nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                         src_mac=0, dst_mac=0, idle_timeout=0, dec_ttl=False, table_id=0):

        # print "execute ovs1.3 set_routing_flow"

        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        dl_type = ether.ETH_TYPE_IP

        actions = []
        # actions = [ofp_parser.OFPActionSetField(metadata=1)]
        if dec_ttl:
            actions.append(ofp_parser.OFPActionDecNwTtl())
        if src_mac:
            actions.append(ofp_parser.OFPActionSetField(eth_src=src_mac))
        if dst_mac:
            actions.append(ofp_parser.OFPActionSetField(eth_dst=dst_mac))
        # if outport is not None:
        #     actions.append(ofp_parser.OFPActionOutput(outport, 0))
        actions += [self.dp.ofproto_parser.NXActionResubmitTable(table_id=EGRESS_SECURE_TABLE)]

        self.set_flow(cookie, priority, dl_type=dl_type, dl_vlan=dl_vlan,
                      nw_src=nw_src, src_mask=src_mask,
                      nw_dst=nw_dst, dst_mask=dst_mask,
                      idle_timeout=idle_timeout, actions=actions, table_id=table_id)

    def set_routing_flow(self, cookie, priority, outport, dl_vlan=0,
                         nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                         src_mac=0, dst_mac=0, idle_timeout=0, dec_ttl=False, table_id=0):

        # print "execute ovs1.3 set_routing_flow"

        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser
        dl_type = ether.ETH_TYPE_IP

        actions = []
        if dec_ttl:
            actions.append(ofp_parser.OFPActionDecNwTtl())
        if src_mac:
            actions.append(ofp_parser.OFPActionSetField(eth_src=src_mac))
        if dst_mac:
            actions.append(ofp_parser.OFPActionSetField(eth_dst=dst_mac))
        if outport is not None:
            actions.append(ofp_parser.OFPActionOutput(outport, 0))
        # actions += [ofp_parser.OFPActionSetField(metadata=1)]

        self.set_flow(cookie, priority, dl_type=dl_type, dl_vlan=dl_vlan,
                      nw_src=nw_src, src_mask=src_mask,
                      nw_dst=nw_dst, dst_mask=dst_mask,
                      idle_timeout=idle_timeout, actions=actions, table_id=table_id)

    def set_routing_flow1(self, cookie, priority, outport, dl_vlan=0,
                         nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                         src_mac=0, dst_mac=0, idle_timeout=0, dec_ttl=False, table_id=0):

        # print "execute ovs1.3 set_routing_flow"

        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        actions = []
        if dec_ttl:
            actions.append(ofp_parser.OFPActionDecNwTtl())
        if src_mac:
            actions.append(ofp_parser.OFPActionSetField(eth_src=src_mac))
        if dst_mac:
            actions.append(ofp_parser.OFPActionSetField(eth_dst=dst_mac))
        if outport is not None:
            actions.append(ofp_parser.OFPActionOutput(outport, 0))
        # actions += [ofp_parser.OFPActionSetField(metadata=1)]

        self.set_flow(cookie, priority, dl_vlan=dl_vlan,
                      nw_src=nw_src, src_mask=src_mask,
                      nw_dst=nw_dst, dst_mask=dst_mask,
                      idle_timeout=idle_timeout, actions=actions, table_id=table_id)

    def delete_flow(self, flow_stats, table_id=0):
        # print "ofctl after v12"
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        cmd = ofp.OFPFC_DELETE
        cookie = flow_stats.cookie
        cookie_mask = UINT64_MAX
        match = ofp_parser.OFPMatch()
        inst = []

        flow_mod = ofp_parser.OFPFlowMod(self.dp, cookie, cookie_mask, table_id, cmd,
                                         0, 0, 0, UINT32_MAX, ofp.OFPP_ANY,
                                         ofp.OFPG_ANY, 0, match, inst)
        self.dp.send_msg(flow_mod)

        # self.logger.info('Delete flow [cookie=0x%x]', cookie, extra=self.sw_id)
    def _delete_flow(self, table_id):
        # print "ofctl after v12"
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        cmd = ofp.OFPFC_DELETE
        # cookie = flow_stats.cookie
        cookie = 0
        cookie_mask = UINT64_MAX
        match = ofp_parser.OFPMatch()
        inst = []

        flow_mod = ofp_parser.OFPFlowMod(self.dp, cookie, cookie_mask, table_id, cmd,
                                         0, 0, 0, UINT32_MAX, ofp.OFPP_ANY,
                                         ofp.OFPG_ANY, 0, match, inst)
        self.dp.send_msg(flow_mod)

@OfCtl.register_of_version(ofproto_v1_2.OFP_VERSION)
class OfCtl_v1_2(OfCtl_after_v1_2):

    def __init__(self, dp, logger):
        super(OfCtl_v1_2, self).__init__(dp, logger)

    def set_sw_config_for_ttl(self):
        flags = self.dp.ofproto.OFPC_INVALID_TTL_TO_CONTROLLER
        miss_send_len = UINT16_MAX
        m = self.dp.ofproto_parser.OFPSetConfig(self.dp, flags,
                                                miss_send_len)
        self.dp.send_msg(m)
        self.logger.info('Set SW config for TTL error packet in.',
                         extra=self.sw_id)

    def get_all_flow(self, waiters):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        match = ofp_parser.OFPMatch()
        stats = ofp_parser.OFPFlowStatsRequest(self.dp, 0, ofp.OFPP_ANY,
                                               ofp.OFPG_ANY, 0, 0, match)
        return self.send_stats_request(stats, waiters)


@OfCtl.register_of_version(ofproto_v1_3.OFP_VERSION)
class OfCtl_v1_3(OfCtl_after_v1_2):

    def __init__(self, dp, logger):
        super(OfCtl_v1_3, self).__init__(dp, logger)

    def set_sw_config_for_ttl(self):
        packet_in_mask = (1 << self.dp.ofproto.OFPR_ACTION |
                          1 << self.dp.ofproto.OFPR_INVALID_TTL)
        port_status_mask = (1 << self.dp.ofproto.OFPPR_ADD |
                            1 << self.dp.ofproto.OFPPR_DELETE |
                            1 << self.dp.ofproto.OFPPR_MODIFY)
        flow_removed_mask = (1 << self.dp.ofproto.OFPRR_IDLE_TIMEOUT |
                             1 << self.dp.ofproto.OFPRR_HARD_TIMEOUT |
                             1 << self.dp.ofproto.OFPRR_DELETE)
        m = self.dp.ofproto_parser.OFPSetAsync(
            self.dp, [packet_in_mask, 0], [port_status_mask, 0],
            [flow_removed_mask, 0])
        self.dp.send_msg(m)
        self.logger.info('Set SW config for TTL error packet in.',
                         extra=self.sw_id)

    def get_all_flow(self, waiters, table_id=0):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        match = ofp_parser.OFPMatch()
        stats = ofp_parser.OFPFlowStatsRequest(self.dp, 0, table_id, ofp.OFPP_ANY,
                                               ofp.OFPG_ANY, 0, 0, match)
        return self.send_stats_request(stats, waiters)


def ip_addr_aton(ip_str, err_msg=None):
    try:
        return addrconv.ipv4.bin_to_text(socket.inet_aton(ip_str))
    except (struct.error, socket.error) as e:
        if err_msg is not None:
            e.message = '%s %s' % (err_msg, e.message)
        raise ValueError(e.message)


def ip_addr_ntoa(ip):
    return socket.inet_ntoa(addrconv.ipv4.text_to_bin(ip))


def mask_ntob(mask, err_msg=None):
    try:
        return (UINT32_MAX << (32 - mask)) & UINT32_MAX
    except ValueError:
        msg = 'illegal netmask'
        if err_msg is not None:
            msg = '%s %s' % (err_msg, msg)
        raise ValueError(msg)


def ipv4_apply_mask(address, prefix_len, err_msg=None):
    import itertools

    assert isinstance(address, str)
    address_int = ipv4_text_to_int(address)
    return ipv4_int_to_text(address_int & mask_ntob(prefix_len, err_msg))


def ipv4_int_to_text(ip_int):
    assert isinstance(ip_int, numbers.Integral)
    return addrconv.ipv4.bin_to_text(struct.pack('!I', ip_int))


def ipv4_text_to_int(ip_text):
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]


def nw_addr_aton(nw_addr, err_msg=None):
    ip_mask = nw_addr.split('/')
    default_route = ip_addr_aton(ip_mask[0], err_msg=err_msg)
    netmask = 32
    if len(ip_mask) == 2:
        try:
            netmask = int(ip_mask[1])
        except ValueError as e:
            if err_msg is not None:
                e.message = '%s %s' % (err_msg, e.message)
            raise ValueError(e.message)
    if netmask < 0:
        msg = 'illegal netmask'
        if err_msg is not None:
            msg = '%s %s' % (err_msg, msg)
        raise ValueError(msg)
    nw_addr = ipv4_apply_mask(default_route, netmask, err_msg)
    return nw_addr, netmask, default_route
