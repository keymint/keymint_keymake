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


from cryptography import hazmat, x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes


def parse_dn(dn):
    """Simple 'Distinguished Name' or RDN parser"""
    # Other examples
    # https://github.com/cannatag/ldap3/blob/681e4d8f80032437d4937f29e83f18f6740e6e37/ldap3/utils/dn.py#L274
    # https://stackoverflow.com/questions/23715944/parsing-x509-distinguished-name
    parts = []
    for i in dn.split('/'):
        for j in i.split(','):
            if '=' in j:
                [key, value] = j.split('=', 1)
                key = key.strip()
                parts.append([key, value])
    return dict(parts)


class CertificateHelper:
    """Help build certificate into artifacts."""

    def __init__(self):
        pass


class DDSCertificateHelper:
    """Help build certificate into artifacts."""

    # https://tools.ietf.org/html/rfc4514#page-7
    _attribute_dict = {
    'CN': ObjectIdentifier('2.5.4.3'),  # COMMON_NAME
    'L': ObjectIdentifier('2.5.4.7'),  # LOCALITY_NAME
    'ST': ObjectIdentifier('2.5.4.8'),  # STATE_OR_PROVINCE_NAME
    'O': ObjectIdentifier('2.5.4.10'),  # ORGANIZATION_NAME
    'OU': ObjectIdentifier('2.5.4.11'),  # ORGANIZATION_UNIT_NAME
    'C': ObjectIdentifier('2.5.4.6'),  # COUNTRY_NAME
    'STREET': ObjectIdentifier('2.5.4.9'),  # STREET_ADDRESS
    'DC': ObjectIdentifier('0.9.2342.19200300.100.1.25'),  # DOMAIN_COMPONENT
    'UID': ObjectIdentifier('0.9.2342.19200300.100.1.1'),  # USER_ID
    }
    # https://github.com/pyca/cryptography/blob/master/src/cryptography/x509/oid.py
    _NAMES_OID = {v: k for k, v in x509.oid._OID_NAMES.items()}

    def dn_dict_to_attributes(self, dn_dict):
        attributes = []
        for key, value in dn_dict.items():
            if key in self._attribute_dict:
                attribute = x509.NameAttribute(self._attribute_dict[key], value)
                attributes.append(attribute)
            else:
                attribute = x509.NameAttribute(self._NAMES_OID[key], value)
                attributes.append(attribute)
        return attributes


    def build_csr(self, context, csr, dds_key):
        # OMG Secure DDS 9.4.1.3.2.1 Subject name Section
        # https://tools.ietf.org/html/rfc4514
        hash_algorithm = getattr(hashes, csr.find('hash_algorithm').text)
        subject_name = csr.find('subject_name').text
        dn_dict = parse_dn(subject_name)
        attributes = self.dn_dict_to_attributes(dn_dict)

        dds_csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(attributes)
            # Sign the CSR with our private key.
            ).sign(dds_key, hash_algorithm(), default_backend())
        return dds_csr

    def get_ca(self, context, issuer_name):
        # TODO conceder getting ca password from context
        issuer_name = os.path.normpath(issuer_name)
        ca_key_path = os.path.join(context.private_space, issuer_name + '.key.pem')
        ca_cert_path = os.path.join(context.public_space, issuer_name + '.cert.pem')

        with open(ca_key_path, 'rb') as f:
            ca_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend())

        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        return ca_key, ca_cert

    def install_cert(self, context, cert, dds_csr):
        # TODO shouldn't choice of ca hash_algorithm come from ca context?
        hash_algorithm = getattr(hashes, cert.find('hash_algorithm').text)()

        subject = dds_csr.subject

        validity = cert.find('validity')
        not_before = validity.find('not_before').text
        not_before_datetime = datetime.datetime.strptime(not_before, '%Y-%m-%dT%H:%M:%S')
        not_after = validity.find('not_after').text
        not_after_datetime = datetime.datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%S')

        serial_number = int(cert.find('serial_number').text)
        issuer_name = cert.find('issuer_name').text
        ca_key, ca_cert = self.get_ca(context, issuer_name)

        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject
            ).serial_number(serial_number
            ).not_valid_before(not_before_datetime
            ).not_valid_after(not_after_datetime
            ).public_key(dds_csr.public_key()
            ).issuer_name(ca_cert.subject)
        dds_cert = cert_builder.sign(ca_key, hash_algorithm, default_backend())
        return dds_cert

    def serialize(self, context, cert, dds_certificate):
        dds_certificate_bytes = dds_certificate.public_bytes(
                encoding=serialization.Encoding.PEM)
        return dds_certificate_bytes


class AsymmetricHelper:
    """Help build key into artifacts."""

    def __init__(self):
        pass


class DDSAsymmetricHelper(AsymmetricHelper):
    """Help build asymmetric keys into artifacts."""

    def serialize(self, context, key, dds_key):
        encryption_algorithm = key.find('encryption_algorithm').text
        if encryption_algorithm == 'NoEncryption':
            encryption_algorithm = serialization.NoEncryption()
        else:
            password = bytes(os.environ[key.find('password_env').text], 'utf-8')
            encryption_algorithm = getattr(serialization, encryption_algorithm)(password)

        dds_key_bytes = dds_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption_algorithm)
        return dds_key_bytes

    def rsa(self, context, asymmetric_type):
        dds_key = asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=int(asymmetric_type.find('key_size').text),
            backend=default_backend())
        return dds_key

    def dsa(self, context, asymmetric_type):
        dds_key = asymmetric.dsa.generate_private_key(
            key_size=int(asymmetric_type.find('key_size').text),
            backend=default_backend())
        return dds_key

    def ec(self, context, asymmetric_type):
        dds_key = asymmetric.ec.generate_private_key(
            curve=getattr(asymmetric.ec, asymmetric_type.find('curve').text)(),
            backend=default_backend())
        return dds_key


class IdentitiesHelper:
    """Help build identities into artifacts."""

    def __init__(self):
        pass

    def build(self, context):
        raise NotImplementedError


class DDSIdentitiesHelper(IdentitiesHelper):
    """Help build identities into artifacts."""

    def __init__(self):
        self.dds_asymmetric_helper = DDSAsymmetricHelper()
        self.dds_certificate_helper = DDSCertificateHelper()

    def _build_key(self, context, key):
        asymmetric_types = key.find('asymmetric_type')
        asymmetric_type = asymmetric_types.getchildren()[0]
        generator = getattr(self.dds_asymmetric_helper, asymmetric_type.tag)
        dds_key = generator(context, asymmetric_type)
        return dds_key

    def _build_csr(self, context, csr, dds_key):
        dds_csr = self.dds_certificate_helper.build_csr(context, csr, dds_key)
        return dds_csr

    def _build_identity(self, context, identity):

        dds_identity = {}
        dds_identity['name'] = identity.get('name')

        key = identity.find('key')
        dds_key = self._build_key(context, key)
        dds_key_bytes = self.dds_asymmetric_helper.serialize(context, key, dds_key)

        csr = identity.find('cert')
        dds_csr = self._build_csr(context, csr, dds_key)
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
