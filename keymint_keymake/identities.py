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

import os
import datetime

import xml.etree.ElementTree as ElementTree

from copy import deepcopy

import xmlschema

from .exceptions import InvalidPermissionsXML
from .namespace import DDSNamespaceHelper
from .schemas import get_dds_schema_path

from keymint_keymake.pki.asymmetric import AsymmetricHelper
from keymint_keymake.pki.certificate import CertificateHelper

from cryptography import x509
from cryptography.hazmat.backends import default_backend


class IdentitiesHelper:
    """Help build identities into artifacts."""

    def __init__(self):
        pass

    def build(self, context):
        raise NotImplementedError


class DDSIdentitiesHelper(IdentitiesHelper):
    """Help build identities into artifacts."""

    def __init__(self):
        self.dds_asymmetric_helper = AsymmetricHelper()
        self.dds_certificate_helper = CertificateHelper()

    def _build_key(self, context, key):
        asymmetric_types = key.find('asymmetric_type')
        asymmetric_type = asymmetric_types.getchildren()[0]
        generator = getattr(self.dds_asymmetric_helper, asymmetric_type.tag)
        dds_key = generator(context, asymmetric_type)
        return dds_key

    def _build_csr(self, context, identity, csr, dds_key):
        dds_csr = self.dds_certificate_helper.build_csr(context, identity, csr, dds_key)
        return dds_csr

    def _build_identity(self, context, identity):

        dds_identity = {}
        dds_identity['name'] = identity.get('name')

        key = identity.find('key')
        dds_key = self._build_key(context, key)
        dds_key_bytes = self.dds_asymmetric_helper.serialize(context, key, dds_key)

        csr = identity.find('cert')
        dds_csr = self._build_csr(context, identity, csr, dds_key)
        dds_csr_bytes = self.dds_certificate_helper.serialize(context, csr, dds_csr)

        dds_identity['dds_key'] = {'object': dds_key, 'bytes': dds_key_bytes}
        dds_identity['dds_csr'] = {'object': dds_csr, 'bytes': dds_csr_bytes}

        return dds_identity

    def build(self, context):
        identities = deepcopy(context.package_manifest.identities)
        dds_identities = []

        for identity in identities.findall('identity'):
            dds_identity = self._build_identity(context, identity)
            dds_identities.append(dds_identity)

        return dds_identities

    def _install_identity(self, context, identity, dds_identity):
        cert = identity.find('cert')

        dds_csr_bytes = dds_identity['dds_csr']['bytes']
        dds_csr = x509.load_pem_x509_csr(dds_csr_bytes, default_backend())

        dds_cert = self.dds_certificate_helper.install_cert(context, cert, dds_csr)
        dds_cert_bytes = self.dds_certificate_helper.serialize(context, cert, dds_cert)

        dds_identity['dds_csr'] = {'object': dds_csr, 'bytes': dds_csr_bytes}
        dds_identity['dds_cert'] = {'object': dds_cert, 'bytes': dds_cert_bytes}

        return dds_identity

    def install(self, context, dds_identity):
        identity = deepcopy(context.package_manifest.identities.findall('identity')[0])
        dds_identity = self._install_identity(context, identity, dds_identity)
        return dds_identity

    # def test(self, dds_root_str, filename):
    #     permissions_xsd_path = get_dds_schema_path('permissions.xsd')
    #     permissions_schema = xmlschema.XMLSchema(permissions_xsd_path)
    #     if not permissions_schema.is_valid(dds_root_str):
    #         try:
    #             permissions_schema.validate(dds_root_str)
    #         except Exception as ex:
    #             if filename is not None:
    #                 msg = "The permissions file '%s' contains invalid XML:\n" % filename
    #             else:
    #                 msg = 'The permissions file contains invalid XML:\n'
    #             raise InvalidPermissionsXML(msg + str(ex))
