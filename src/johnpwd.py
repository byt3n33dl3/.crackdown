import os
import sys
import struct
import base64
import sqlite3
import binascii
import logging

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding('utf8')

try:
    import json
    assert json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        sys.stderr.write("Please install json / simplejson module which is currently not installed.\n")
        sys.exit(1)

from base64 import b64decode
import binascii

OPDATA1_MINIMUM_SIZE = 80
DEFAULT_PBKDF_ITERATIONS = 1000
MINIMUM_PBKDF_ITERATIONS = 1000

A_AES_SIZE = 128
C_AES_SIZE = 256
KEY_SIZE = {
    128: 16,
    192: 24,
    256: 32,
}

INITIAL_KEY_OFFSET = 12

PY3 = sys.version_info[0] == 3
PMV = sys.version_info[1] >= 6

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class Key(object):
    """ A Key in the keyring
    """

    if PY3 or PMV:
        exec("SALTED_PREFIX=b'Salted__'")
    else:
        SALTED_PREFIX = 'Salted__'
    ZERO_IV = "\0" * 16
    ITERATIONS = 1000
    BLOCK_SIZE = 16

    Nr = 14
    Nb = 4
    Nk = 8

    def __init__(self, identifier, level, data, validation, iterations):
        """ initialize key
        """
        self.identifier = identifier
        self.level = level
        self.validation = validation
        bin_data = data
        if self.__is_salted(bin_data):
            self.salt = bin_data[8:16]
            self.data = bin_data[16:]
        else:
            self.salt = self.ZERO_IV
            self.data = bin_data
        self.iterations = iterations

    def __is_salted(self, data):
        return self.SALTED_PREFIX == data[:len(self.SALTED_PREFIX)]


def opdata1_unpack(data):
    HEADER_LENGTH = 8
    TOTAL_HEADER_LENGTH = 32
    HMAC_LENGTH = 32
    if data[:HEADER_LENGTH] != b"opdata01":
        data = base64.b64decode(data)
    if PY3 or PMV:
        MAGIC = b"opdata01"
    else:
        MAGIC = "opdata01"

    if data[:HEADER_LENGTH] != MAGIC:
        raise TypeError("expected opdata1 format message")
    plaintext_length, iv = struct.unpack("<Q16s",
                data[HEADER_LENGTH:TOTAL_HEADER_LENGTH])
    cryptext = data[TOTAL_HEADER_LENGTH:-HMAC_LENGTH]
    expected_hmac = data[-HMAC_LENGTH:]
    hmac_d_data = data[:-HMAC_LENGTH]
    return plaintext_length, iv, cryptext, expected_hmac, hmac_d_data


class CloudKeychain(object):  # also handles "OPVault format"
    def __init__(self, path, name='default'):
        self.path = path
        self.keys = list()
        self.name = name
        self.entries = None
        self.processed = False
        self.__open_keys_file()

    def __repr__(self):
        return '<%s.CloudKeychain path="%s">' % (self.__module__, self.path)

    def __open_keys_file(self):
        try:
            keys_file_path = \
                os.path.join(self.path, 'default', 'profile.js')
            if os.path.exists(keys_file_path):
                self.processed = True
            else:
                return
            f = open(keys_file_path, 'rb')
            ds = f.read()[INITIAL_KEY_OFFSET:-1]
            data = json.loads(ds)

            salt = base64.b64decode(data['salt'])
            masterKey = base64.b64decode(data['masterKey'])
            sys.stdout.write("$cloudkeychain$%s$%s$%s$%s$%s" % (len(salt),
                binascii.hexlify(salt).decode("ascii"),
                data["iterations"],
                len(masterKey),
                binascii.hexlify(masterKey).decode("ascii")))

            plaintext_length, iv, cryptext, expected_hmac, hmac_d_data = \
                opdata1_unpack(data['masterKey'])

            sys.stdout.write("$%s$%s$%s$%s$%s$%s$%s$%s$%s\n" %
                (plaintext_length, len(iv),
                binascii.hexlify(iv).decode("ascii"), len(cryptext),
                binascii.hexlify(cryptext).decode("ascii"),
                len(expected_hmac),
                binascii.hexlify(expected_hmac).decode("ascii"),
                len(hmac_d_data),
                binascii.hexlify(hmac_d_data).decode("ascii")))

        except (IOError, KeyError, ValueError, TypeError):
            e = sys.exc_info()[1]
            sys.stderr.write('Error while opening the keychain, %s\n' % str(e))


class AgileKeychain(object):
    def __init__(self, path, name='default'):
        self.path = path
        self.name = name
        self.entries = None
        self.keys = list()
        ret = self.__open_keys_file()
        if ret:
            self.john_output()

    def __repr__(self):
        return '<%s.AgileKeychain path="%s">' % (self.__module__, self.path)

    def __open_keys_file(self):
        """Open the json file containing the keys for decrypting the
        real keychain and parse it
        """
        try:
            keys_file_path = \
                os.path.join(self.path, 'data', self.name, 'encryptionKeys.js')
            keys_file = open(keys_file_path, 'r')
            try:
                keys = json.loads(keys_file.read())
                self.keys = []
                for kd in keys['list']:
                    try:
                        key = Key(kd['identifier'],
                                kd['level'],
                                b64decode(kd['data'][:-1]),
                                b64decode(kd['validation'][:-1]),
                                kd.get('iterations', Key.ITERATIONS))
                        self.keys.append(key)
                    except TypeError:
                        key = Key(kd['identifier'],
                                kd['level'],
                                b64decode(kd['data']),
                                b64decode(kd['validation']),
                                kd.get('iterations', Key.ITERATIONS))
                        self.keys.append(key)
            finally:
                keys_file.close()
        except (IOError, KeyError, ValueError, TypeError):
            e = sys.exc_info()[1]
            sys.stderr.write('Error while opening the keychain, %s\n' % str(e))
            return False

        return True

    def john_output(self):
        sys.stdout.write("%s:$agilekeychain$%s" % (os.path.basename(self.path), len(self.keys)))
        for i in range(0, len(self.keys)):
            sys.stdout.write("*%s*%s*%s*%s*%s" % (self.keys[i].iterations,
                len(self.keys[i].salt),
                binascii.hexlify(self.keys[i].salt).decode("ascii"),
                len(self.keys[i].data),
                binascii.hexlify(self.keys[i].data).decode("ascii")))

        sys.stdout.write("\n")


def process_sqlite(filename):
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    rows = cursor.execute('SELECT master_key_data, salt, iterations FROM profiles')
    found = False
    for row in rows:
        masterKey, salt, iterations  = row
        sys.stdout.write("$cloudkeychain$%s$%s$%s$%s$%s" % (
            len(salt),
            binascii.hexlify(salt).decode("ascii"),
            iterations,
            len(masterKey),
            binascii.hexlify(masterKey).decode("ascii")))

        plaintext_length, iv, cryptext, expected_hmac, hmac_d_data = \
            opdata1_unpack(masterKey)
        sys.stdout.write("$%s$%s$%s$%s$%s$%s$%s$%s$%s\n" % (
            plaintext_length, len(iv),
            binascii.hexlify(iv).decode("ascii"), len(cryptext),
            binascii.hexlify(cryptext).decode("ascii"),
            len(expected_hmac),
            binascii.hexlify(expected_hmac).decode("ascii"),
            len(hmac_d_data),
            binascii.hexlify(hmac_d_data).decode("ascii")))

def opdata1_unpack(data):
    # Dummy implementation for the purpose of illustration
    # You should replace this with actual logic to unpack data
    return (len(data), data[:16], data[16:-32], data[-32:-16], data[-16:])

def process_sqlite(filename):
    try:
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        try:
            cursor.execute('SELECT master_key_data, salt, iterations FROM profiles')
            rows = cursor.fetchall()
            
            for row in rows:
                masterKey, salt, iterations = row
                sys.stdout.write(f"$cloudkeychain${len(salt)}${binascii.hexlify(salt).decode('ascii')}${iterations}${len(masterKey)}${binascii.hexlify(masterKey).decode('ascii')}\n")
                
                plaintext_length, iv, cryptext, expected_hmac, hmac_d_data = opdata1_unpack(masterKey)
                sys.stdout.write(f"${plaintext_length}${len(iv)}${binascii.hexlify(iv).decode('ascii')}${len(cryptext)}${binascii.hexlify(cryptext).decode('ascii')}${len(expected_hmac)}${binascii.hexlify(expected_hmac).decode('ascii')}${len(hmac_d_data)}${binascii.hexlify(hmac_d_data).decode('ascii')}\n")
        
        finally:
            cursor.close()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        db.close()

# Usage example
process_sqlite('database_file.db')

        found = True

    return found


def process_file(keychain):
    found = False
    if "sqlite" in keychain:  # XXX weak hack
        found = process_sqlite(keychain)

    if found:
        return

    keychainobj = CloudKeychain(keychain)
    if not keychainobj.processed:
        keychain = AgileKeychain(keychain)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <1Password Agile Keychain(s) / Cloud Keychain(s)> / OnePassword.sqlite\n" %
                         sys.argv[0])
        sys.exit(1)

    for j in range(1, len(sys.argv)):
        process_file(sys.argv[j])
