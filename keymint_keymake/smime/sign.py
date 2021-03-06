# Copyright 2017 Open Source Robotics Foundation, Inc.
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

# Stuck with M2Crypto until somthing better comes along
# https://github.com/pyca/cryptography/issues/1621

import logging

# from cryptography import hazmat, x509
from cryptography.hazmat.primitives.serialization import Encoding

from keymint_keymake import pki

from M2Crypto import BIO, SMIME


class BadPKCS7Format(BaseException):
    pass


class BadKeySource(BaseException):
    pass


def _load_key(smime, key, cert, source_type):
    if source_type is 'file':
        smime.load_key(keyfile=key, certfile=cert)
    elif source_type is 'bio':
        smime.load_key_bio(keybio=key, certbio=cert)
    elif source_type is 'pkcs11':
        smime.pkey = key
        smime.x509 = cert
    else:
        msg = 'unknown source type: ' + source_type + \
            '; possible values: file, bio, pkcs11'
        logging.error(msg=msg)
        raise BadKeySource(msg)


def _sign_bio(data_bio, key, cert, source_type,
              source_format='PEM', flags=None, algo='sha256'):
    smime = SMIME.SMIME()
    _load_key(smime=smime, key=key, cert=cert, source_type=source_type)
    if flags is None:
        flags = SMIME.PKCS7_DETACHED
        flags |= SMIME.PKCS7_TEXT
    try:
        if source_format == 'PEM':
            pkcs7 = smime.sign(data_bio=data_bio, flags=flags, algo=algo)
        elif source_format == 'DER':
            pkcs7 = smime.sign(data_bio=data_bio, algo=algo)
        else:
            msg = 'Unknown format: ' + source_format + \
                '; Possible formats: [PEM, DER]'
            logging.error(msg='pkcs7 format error: unknown format')
            raise BadPKCS7Format(msg)
    except SMIME.SMIME_Error as e:
        logging.error(msg='smime error: ' + str(e))
        raise
    except SMIME.PKCS7_Error as e:
        logging.error(msg='pkcs7 error: ' + str(e))
        raise
    return pkcs7, smime, flags


def _sign_data(data_bytes, key, cert,
               source_type='file', source_format='PEM'):

    out_bio = BIO.MemoryBuffer()

    data_bio = BIO.MemoryBuffer(data=data_bytes)
    pkcs7, smime, flags = _sign_bio(
        data_bio=data_bio, key=key, cert=cert,
        source_type=source_type, source_format=source_format)

    data_bio = BIO.MemoryBuffer(data=data_bytes)
    smime.write(out_bio=out_bio, pkcs7=pkcs7, data_bio=data_bio, flags=flags)
    out_data = out_bio.read()

    return out_data


def sign_data(data, key, cert, source_format='PEM'):
    if isinstance(data, (bytes, bytearray)):
        data_bytes = data
    else:
        with open(data, mode='rb') as data_fd:
            data_bytes = data_fd.read()

    if source_format is 'PEM':
        encoding = Encoding.PEM
    if source_format is 'DER':
        encoding = Encoding.DER
    key_dump = pki.utils._dump_key(key=key, encoding=encoding)
    key_bio = BIO.MemoryBuffer(data=key_dump)
    cert_dump = pki.utils._dump_cert(cert=cert, encoding=encoding)
    cert_bio = BIO.MemoryBuffer(data=cert_dump)
    signed_data = _sign_data(data_bytes=data_bytes, key=key_bio, cert=cert_bio,
                             source_type='bio', source_format=source_format)
    return signed_data


def sign_file(file_path, key, cert, out_path, source_format='PEM'):
    with open(file_path, mode='rb') as data_fd:
        data_bytes = data_fd.read()

    out_data = _sign_data(
        data_bytes=data_bytes,
        key=key,
        cert=cert,
        source_format=source_format)

    try:
        with open(out_path, mode='wb') as out_fd:
            out_fd.write(out_data)
    except IOError as e:
        msg = 'IOError in writing signed file: ' + str(e)
        logging.error(msg=msg)
        raise
