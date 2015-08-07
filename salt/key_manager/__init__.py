# -*- coding: utf-8 -*-
'''
The key_manager package implements a pluggable system for storing and
retrieving various asymetric keys used by the rest of Salt.
'''
from __future__ import absolute_import
# Import Python Libs

try:
    import importlib
    HAS_IMPORTLIB = True
except ImportError:
    HAS_IMPORTLIB = False

from salt import exceptions
from salt.crypt import Crypticle


class BaseKeyManager(object):
    """
    Provides a skeleton API for Key Managers. Keys are classified by type
    and stored by name. Names must be unique within a type.
    """
    def __init__(self, opts):
        self.opts = opts
        if 'encrypt_private_keys' in opts and opts['encrypt_private_keys']:
            try:
                self.crypt = Crypticle(opts, opts['keystore_secret'])
            except KeyError:
                raise exceptions.KeyManagerConfigError('keystore_secret must be set \
                        when private key encryption is enabled.')
        else:
            self.crypt = None
        self.initialize()

    def _encrypt_priv_key(self, priv_key):
        """
        Perform AES encryption of the private key using keystore_secret.
        """
        if self.crypt:
            return self.crypt.encrypt(priv_key)
        else:
            # Encryption is disabled, store the plain text.
            return priv_key

    def _decrypt_priv_key(self, crypted_key):
        """
        Perform AES decryption of the private key using keystore_secret.
        """
        if self.crypt:
            return self.crypt.decrypt(crypted_key)
        else:
            # Encryption is disabled, assume the key was stored in clear text
            return crypted_key

    def initialize(self):
        """
        Perform any actions required to initialize the keystore.
        """
        pass

    def save(self, key_type, key_name, pub_key, priv_key=None):
        """
        Save the key to the keystore. It is recommended to encrypt priv_key
        before storing in a remote store.
        """
        pass

    def get(self, key_type, key_name, decrypt_priv=True):
        """
        Retrieve the key from the keystore. decrypt_priv may be set to False
        to reduce loading time by not decrypting the private key.
        """
        pass

    def remove(self, key_type, key_name):
        """
        Remove the key from the keystore.
        """
        pass

def get_key_manager(opts):
    """
    Load and return the proper key manager for provided options.
    """
    try:
        manager_mod_name = opts['keystore_module']
    except KeyError:
        raise exceptions.KeyManagerConfigError('No keystore_module was provided.')

    try:
        if HAS_IMPORTLIB:
            manager_mod = importlib.import_module(manager_mod_name)
        else:
            manager_mod = getattr(__import__("salt.modules.inspectlib", globals(),
                locals(), fromlist=[str(manager_mod_name)]), manager_mod_name)
    except ImportError:
        import traceback
        raise exceptions.KeyManagerConfigError('Unable to import module for keystore %s. \
                The exception was %s' % (manager_mod_name, traceback.format_exc()))

    return manager_mod.MANAGER(opts)
