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

# import xml.etree.ElementTree as ElementTree

from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class AsymmetricHelper:
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
