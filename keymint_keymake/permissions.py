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

from xml.etree import cElementTree as ElementTree

from copy import deepcopy

import xmlschema

from keymint_keymake.pki.certificate import get_ca

from .exceptions import InvalidPermissionsXML
from .namespace import DDSNamespaceHelper
from .schemas import get_dds_schema_path
from .smime.sign import sign_data

from keymint_package.xml.utils import pretty_xml, tidy_xml

def _compatible_criteria(dds_criteria, criteria):
    partitions = criteria.find('partitions')
    dds_partitions = dds_criteria.find('partitions')
    if not partitions == dds_partitions:
        if partitions is None:
            return False
        else:
            partitions = [i.text for i in partitions.iter()]
            dds_partitions = [i.text for i in dds_partitions.iter()]
            if not set(partitions) == set(dds_partitions):
                return False

    data_tags = criteria.find('data_tags')
    dds_data_tags = dds_criteria.find('data_tags')
    if not data_tags == dds_data_tags:
        if data_tags is None:
            return False
        else:
            data_tags = [i.text for i in data_tags.iter()]
            dds_data_tags = [i.text for i in dds_data_tags.iter()]
            if not set(data_tags) == set(dds_data_tags):
                return False
    return True


class CriteriasHelpter:
    """Help build criteria into artifacts."""

    def __init__(self):
        pass


class DDSCriteriasHelper(CriteriasHelpter):
    """Help build permission into artifacts."""

    _dds_expressions_types = ['partition', 'tag']
    _dds_expression_list_types = ['partitions', 'data_tags']

    def __init__(self):
        self.dds_namespaces_helper = DDSNamespaceHelper()

    def _dds_criteria(self, context, expression, expression_list, dds_criteria_kind, partitions, data_tags):
        dds_criteria = ElementTree.Element(dds_criteria_kind)
        dds_expression_list = ElementTree.Element(expression_list.tag)
        dds_expression = ElementTree.Element(expression.tag)

        formater = getattr(self.dds_namespaces_helper, expression.tag)
        dds_topics, dds_partitions, dds_data_tags = formater(expression, partitions, data_tags, dds_criteria_kind)

        if dds_topics is not None:
            dds_criteria.append(dds_topics)
        if dds_partitions is not None:
            dds_criteria.append(dds_partitions)
        if dds_data_tags is not None:
            dds_criteria.append(dds_data_tags)
        return dds_criteria

    def ros_topic(self, context, expression, expression_list, dds_criteria_kind, partitions, data_tags):
        return self._dds_criteria(context, expression, expression_list, dds_criteria_kind, partitions, data_tags)

    def ros_service(self, context, expression, expression_list, dds_criteria_kind, partitions, data_tags):
        return self._dds_criteria(context, expression, expression_list, dds_criteria_kind, partitions, data_tags)

    def _dds_criterias(self, context, criteria, dds_criteria_kind):
        dds_criterias = []
        partitions = criteria.find('partitions')
        if partitions:
            criteria.remove(partitions)
        data_tags = criteria.find('data_tags')
        if data_tags:
            criteria.remove(data_tags)
        for expression_list in list(criteria):
            for expression in list(expression_list):
                if hasattr(self, expression.tag):
                    formater = getattr(self, expression.tag)
                    dds_criteria = formater(context, expression, expression_list, dds_criteria_kind, partitions, data_tags)
                    dds_criterias.append(dds_criteria)
                else:
                    dds_criteria = ElementTree.Element(dds_criteria_kind)
                    dds_expression_list = ElementTree.Element(expression_list.tag)
                    dds_expression_list.append(expression)
                    dds_criteria.append(dds_expression_list)
                    if partitions:
                        dds_criteria.append(partitions)
                    if data_tags:
                        dds_criteria.append(data_tags)
                    dds_criterias.append(dds_criteria)
        return dds_criterias

    def ros_publish(self, context, criteria):
        return self._dds_criterias(context, criteria, 'publish')

    def ros_subscribe(self, context, criteria):
        return self._dds_criterias(context, criteria, 'subscribe')

    def ros_relay(self, context, criteria):
        return self._dds_criterias(context, criteria, 'relay')

    def ros_call(self, context, criteria):
        dds_criterias = []
        dds_criterias.extend(self._dds_criterias(context, criteria, 'publish'))
        dds_criterias.extend(self._dds_criterias(context, criteria, 'subscribe'))
        return dds_criterias

    def ros_execute(self, context, criteria):
        # TODO
        return []

    def ros_request(self, context, criteria):
        # TODO
        return []

    def ros_operate(self, context, criteria):
        # TODO
        return []

    def ros_read(self, context, criteria):
        # TODO
        return []

    def ros_write(self, context, criteria):
        # TODO
        return []


class PermissionsHelper:
    """Help build permission into artifacts."""

    def __init__(self):
        pass

    def build(self, context):
        raise NotImplementedError


class DDSPermissionsHelper(PermissionsHelper):
    """Help build permission into artifacts."""

    def __init__(self):
        self.dds_criterias_helper = DDSCriteriasHelper()

    def _build_criterias(self, context, criteria):
        formater = getattr(self.dds_criterias_helper, criteria.tag)
        return formater(context, criteria)

    def _compress_rule(self, context, rule):
        dds_rule = ElementTree.Element(rule.tag)

        domains = rule.find('domains')
        dds_rule.append(domains)
        rule.remove(domains)

        for criteria in list(rule):
            dds_criterias = dds_rule.findall(criteria.tag)
            if dds_criterias is None:
                dds_rule.append(criteria)
            else:
                for dds_criteria in dds_criterias:
                    if _compatible_criteria(dds_criteria, criteria):
                        topics = criteria.find('topics')
                        dds_topics = dds_criteria.find('topics')
                        dds_topics.extend(topics)
                        break
                else:
                    dds_rule.append(criteria)
        return dds_rule

    def _build_rule(self, context, rule):
        dds_rule = ElementTree.Element(rule.tag)

        domains = rule.find('domains')
        dds_rule.append(domains)
        rule.remove(domains)

        for criteria in list(rule):
            if hasattr(self.dds_criterias_helper, criteria.tag):
                dds_criterias = self._build_criterias(context, criteria)
                dds_rule.extend(dds_criterias)
            else:
                dds_rule.append(criteria)
        # TODO Should we attempt to sort dds_criterias as expected in DDS schema

        dds_rule = self._compress_rule(context, dds_rule)

        return dds_rule

    def _build_grant(self, context, grant):

        dds_grant = ElementTree.Element('grant')

        name = grant.get('name')
        dds_grant.set('name', name)

        subject_name = grant.find('subject_name')
        subject_name.text = subject_name.text.format(**grant.attrib)
        dds_grant.append(subject_name)
        grant.remove(subject_name)

        validity = grant.find('validity')
        dds_grant.append(validity)
        grant.remove(validity)

        default = grant.find('default')
        grant.remove(default)

        for rule in grant.getchildren():
            dds_rule = self._build_rule(context, rule)
            dds_grant.append(dds_rule)

        dds_grant.append(default)

        return dds_grant

    def build(self, context):
        permissions = deepcopy(context.package_manifest.permissions)
        dds_permissions = ElementTree.Element('permissions')

        for grant in permissions.findall('grant'):
            dds_grant = self._build_grant(context, grant)
            dds_permissions.append(dds_grant)

        dds_root = ElementTree.Element('dds')
        dds_root.append(dds_permissions)
        dds_root = tidy_xml(dds_root)
        return pretty_xml(dds_root)

    def test(self, context, dds_root_str, filename):
        permissions_xsd_path = get_dds_schema_path('permissions.xsd')
        permissions_schema = xmlschema.XMLSchema(permissions_xsd_path)
        if not permissions_schema.is_valid(dds_root_str):
            try:
                permissions_schema.validate(dds_root_str)
            except Exception as ex:
                if filename is not None:
                    msg = "The permissions file '%s' contains invalid XML:\n" % filename
                else:
                    msg = 'The permissions file contains invalid XML:\n'
                raise InvalidPermissionsXML(msg + str(ex))

    def install(self, context, dds_permissions_bytes):
        issuer_name = context.package_manifest.permissions_ca.text
        ca_key, ca_cert = get_ca(context=context, issuer_name=issuer_name)
        dds_permissions_bytes_singed = sign_data(dds_permissions_bytes, ca_key, ca_cert)
        return dds_permissions_bytes_singed
