# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2018 Red Hat, Inc.
#
# Authors:
# Eric Garver <egarver@redhat.com>

import os

from firewall import config
from firewall.errors import FirewallError

from firewall.core.fw_config import FirewallConfig
from firewall.core.io.zone import zone_reader
from firewall.core.io.service import service_reader
from firewall.core.io.ipset import ipset_reader
from firewall.core.io.icmptype import icmptype_reader
from firewall.core.io.helper import helper_reader
from firewall.core.io.policy import policy_reader
from firewall.core.io.direct import Direct
from firewall.core.io.firewalld_conf import firewalld_conf


def list_xml_files(_dir):
    if not os.path.isdir(_dir):
        return []
    return [name for name in sorted(os.listdir(_dir)) if name.endswith(".xml")]


def list_zone_files(_dir):
    if not os.path.isdir(_dir):
        return []
    result = list_xml_files(_dir)
    if _dir.startswith(config.ETC_FIREWALLD):
        # Add zone files that should be combined
        result.extend(
            [
                os.path.join(zone, file)
                for zone in sorted(os.listdir(_dir))
                for file in list_xml_files(os.path.join(_dir, zone))
            ]
        )
    return result


def check_on_disk_config(fw):
    fw_config = FirewallConfig(fw)

    try:
        _firewalld_conf = firewalld_conf(config.FIREWALLD_CONF)
        _firewalld_conf.read()
    except FirewallError as error:
        raise FirewallError(error.code, "'%s': %s" % (config.FIREWALLD_CONF, error.msg))
    except IOError:
        # defaults will be filled
        pass
    except Exception as msg:
        raise Exception("'%s': %s" % (config.FIREWALLD_CONF, msg))
    fw_config.set_firewalld_conf(_firewalld_conf)

    readers = {
        "ipset": {
            "reader": ipset_reader,
            "add": fw_config.add_ipset,
            "dirs": [config.FIREWALLD_IPSETS, config.ETC_FIREWALLD_IPSETS],
            "select": list_xml_files,
        },
        "helper": {
            "reader": helper_reader,
            "add": fw_config.add_helper,
            "dirs": [config.FIREWALLD_HELPERS, config.ETC_FIREWALLD_HELPERS],
            "select": list_xml_files,
        },
        "icmptype": {
            "reader": icmptype_reader,
            "add": fw_config.add_icmptype,
            "dirs": [config.FIREWALLD_ICMPTYPES, config.ETC_FIREWALLD_ICMPTYPES],
            "select": list_xml_files,
        },
        "service": {
            "reader": service_reader,
            "add": fw_config.add_service,
            "dirs": [config.FIREWALLD_SERVICES, config.ETC_FIREWALLD_SERVICES],
            "select": list_xml_files,
        },
        "zone": {
            "reader": zone_reader,
            "add": fw_config.add_zone,
            "dirs": [config.FIREWALLD_ZONES, config.ETC_FIREWALLD_ZONES],
            "select": list_zone_files,
        },
        "policy": {
            "reader": policy_reader,
            "add": fw_config.add_policy_object,
            "dirs": [config.FIREWALLD_POLICIES, config.ETC_FIREWALLD_POLICIES],
            "select": list_xml_files,
        },
    }
    for reader in readers.keys():
        for _dir in readers[reader]["dirs"]:
            for selected in readers[reader]["select"](_dir):
                obj = readers[reader]["reader"](selected, _dir)
                readers[reader]["add"](obj)
    fw_config.full_check_config()

    if os.path.isfile(config.FIREWALLD_DIRECT):
        try:
            obj = Direct(config.FIREWALLD_DIRECT)
            obj.read()
            obj.check_config(obj.export_config())
        except FirewallError as error:
            raise FirewallError(
                error.code, "'%s': %s" % (config.FIREWALLD_DIRECT, error.msg)
            )
        except Exception as msg:
            raise Exception("'%s': %s" % (config.FIREWALLD_DIRECT, msg))
