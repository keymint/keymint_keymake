# Copyright 2014 Open Source Robotics Foundation, Inc.
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

import xml.etree.ElementTree as ElementTree

from copy import deepcopy

import xmlschema

from .exceptions import InvalidGovernanceXML
from .namespace import DDSNamespaceHelper
from .schemas import get_dds_schema_path


from .utils import pretty_xml, tidy_xml


class AccessRuleHelper:
    """Help build access rule into artifacts."""

    def __init__(self):
        pass


class DDSAccessRuleHelper(AccessRuleHelper):
    """Help build access rule into artifacts."""

    def __init__(self):
        self.dds_namespaces_helper = DDSNamespaceHelper()

    def ros_topic_rule(self, context, access_rule):
        dds_access_rule = ElementTree.Element('topic_rule')
        dds_topic_expression = ElementTree.Element('topic_expression')

        topic_expression = access_rule.find('topic_expression')
        access_rule.remove(topic_expression)

        dds_topic_expression.text = self.dds_namespaces_helper.topic(topic_expression.text)
        dds_access_rule.append(dds_topic_expression)
        dds_access_rule.extend(access_rule.getchildren())
        return [dds_access_rule]

    def ros_service_rule(self, context, access_rule):
        # TODO
        return []

    def ros_action_rule(self, context, access_rule):
        # TODO
        return []

    def ros_parameter_rule(self, context, access_rule):
        # TODO
        return []


class GovernanceHelper:
    """Help build governance into artifacts."""

    def __init__(self):
        pass

    def build(self, context):
        raise NotImplementedError


class DDSGovernanceHelper(GovernanceHelper):
    """Help build governance into artifacts."""

    _dds_access_rule_types = ['topic_rule']

    def __init__(self):
        self.dds_access_rule_helper = DDSAccessRuleHelper()

    def _build_access_rules(self, context, access_rule):
        formater = getattr(self.dds_access_rule_helper, access_rule.tag)
        return formater(context, access_rule)

    def _build_domain_rule(self, context, domain_rule):

        dds_domain_rule = ElementTree.Element('domain_rule')
        dds_access_rules = ElementTree.Element('topic_access_rules')

        access_rules = domain_rule.find('topic_access_rules')
        domain_rule.remove(access_rules)
        dds_domain_rule.extend(domain_rule.getchildren())

        for access_rule in access_rules.getchildren():
            if access_rule.tag in self._dds_access_rule_types:
                dds_access_rules.append(access_rule)
            else:
                _dds_access_rules = self._build_access_rules(context, access_rule)
                dds_access_rules.extend(_dds_access_rules)

        dds_domain_rule.append(dds_access_rules)
        return dds_domain_rule

    def build(self, context):
        governance = deepcopy(context.package_manifest.governance)
        dds_governance = ElementTree.Element('domain_access_rules')

        for domain_rule in governance.findall('domain_rule'):
            dds_domain_rule = self._build_domain_rule(context, domain_rule)
            dds_governance.append(dds_domain_rule)

        dds_root = ElementTree.Element('dds')
        dds_root.append(dds_governance)
        dds_root = tidy_xml(dds_root)
        return pretty_xml(dds_root)

    def test(self, dds_root_str, filename):
        governance_xsd_path = get_dds_schema_path('governance.xsd')
        governance_schema = xmlschema.XMLSchema(governance_xsd_path)
        if not governance_schema.is_valid(dds_root_str):
            try:
                governance_schema.validate(dds_root_str)
            except Exception as ex:
                if filename is not None:
                    msg = "The governance file '%s' contains invalid XML:\n" % filename
                else:
                    msg = 'The governance file contains invalid XML:\n'
                raise InvalidGovernanceXML(msg + str(ex))
