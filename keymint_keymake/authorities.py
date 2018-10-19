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

# import os
# import datetime

from copy import deepcopy

# from xml.etree import cElementTree as ElementTree


# import xmlschema

# from .exceptions import InvalidPermissionsXML
# from .namespace import DDSNamespaceHelper
# from .schemas import get_dds_schema_path

from keymint_keymake.pki.asymmetric import AsymmetricHelper
from keymint_keymake.pki.certificate import CertificateHelper
from keymint_keymake.pki.certificate import get_ca_csr, get_ca_key

# from cryptography import x509
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization


class AuthoritiesHelper:
    """Help build authorities into artifacts."""

    def __init__(self):
        pass

    def init(self, context):
        raise NotImplementedError


class DDSAuthoritiesHelper(AuthoritiesHelper):
    """Help build authorities into artifacts."""

    def __init__(self):
        self.dds_asymmetric_helper = AsymmetricHelper()
        self.dds_certificate_helper = CertificateHelper()

    def _build_key(self, context, key):
        asymmetric_types = key.find('asymmetric_type')
        asymmetric_type = asymmetric_types.getchildren()[0]
        generator = getattr(self.dds_asymmetric_helper, asymmetric_type.tag)
        dds_key = generator(context, asymmetric_type)
        return dds_key

    def _build_csr(self, context, authority, csr, dds_key):
        dds_csr = self.dds_certificate_helper.build_csr(context, authority, csr, dds_key)
        return dds_csr

    def _build_authority(self, context, authority):

        dds_authority = {}
        dds_authority['name'] = authority.get('name')

        key = authority.find('key')
        dds_key = self._build_key(context, key)
        dds_key_bytes = self.dds_asymmetric_helper.serialize(context, key, dds_key)

        csr = authority.find('cert')
        dds_csr = self._build_csr(context, authority, csr, dds_key)
        dds_csr_bytes = self.dds_certificate_helper.serialize(context, csr, dds_csr)

        dds_authority['dds_key'] = {'object': dds_key, 'bytes': dds_key_bytes}
        dds_authority['dds_csr'] = {'object': dds_csr, 'bytes': dds_csr_bytes}

        return dds_authority

    def build_iter(self, context):
        authorities = deepcopy(context.profile_manifest.authorities)

        for authority in authorities.findall('authority'):
            dds_authority = self._build_authority(context, authority)
            yield dds_authority

        return

    def _install_authority(self, context, authority):

        dds_authority = {}
        dds_authority['name'] = authority.get('name')

        cert = authority.find('cert')

        dds_csr = get_ca_csr(context, dds_authority['name'])
        dds_key = get_ca_key(context, dds_authority['name'])

        dds_cert = self.dds_certificate_helper.install_cert(context, cert, dds_csr, dds_key)
        dds_cert_bytes = self.dds_certificate_helper.serialize(context, cert, dds_cert)

        dds_authority['dds_cert'] = {'object': dds_cert, 'bytes': dds_cert_bytes}

        return dds_authority

    def install_iter(self, context):
        authorities = deepcopy(context.profile_manifest.authorities)

        for authority in authorities.findall('authority'):
            dds_authority = self._install_authority(context, authority)
            yield dds_authority

        return
