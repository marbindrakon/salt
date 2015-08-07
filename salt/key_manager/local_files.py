from salt import exceptions
from salt.key_manager import BaseKeyManager
from salt.utils import fopen

import os


class LocalFileKeyManager(BaseKeyManager):
    """
    A key manager which stores files in the local pki_dir.
    Key types correspond to directories within pki_dir.
    """
    def initialize(self):
        try:
            self.base_dir = self.opts['pki_dir']
        except KeyError:
            raise exceptions.SaltMasterError(
                    'LocalFileKeyManager requires pki_dir to be set.')


    def _get_key_path(self, key_type, key_name, private):
        """
        Get the filesystem path for a key.
        """
        if private:
            suffix = 'pem'
        else:
            suffix = 'pub'
        file_name = "{0}.{1}".format(key_name, suffix)
        type_dir = os.path.join(self.base_dir, key_type)
        if not os.path.exists(type_dir):
            os.makedirs(type_dir)
        return os.path.join(type_dir, file_name)


    def save(self, key_type, key_name, pub_key, priv_key=None):
        """
        Save the key pair to the local filesystem.
        """
        if priv_key:
            priv_key_to_store = self._encrypt_priv_key(priv_key)
        else:
            priv_key_to_store = None

        pub_key_path = self._get_key_path(key_type, key_name, False)
        priv_key_path = self._get_key_path(key_type, key_name, True)
        if os.path.isfile(pub_key_path):
            raise exceptions.KeyExists('A public key for %s already exists in the store.' % key_name)
        if priv_key and os.path.isfile(priv_key_path):
            raise exceptions.KeyExists('A private key for %s already exists in the store.' % key_name)
        cumask = os.umask(191)
        with fopen(pub_key_path, 'wb+') as pub_key_file:
            pub_key_file.write(pub_key)
        if priv_key_to_store:
            with fopen(priv_key_path, 'wb+') as priv_key_file:
                priv_key_file.write(priv_key_to_store)
        os.chmod(priv_key_path, 256)


    def get(self, key_type, key_name, decrypt_priv=True):
        """
        Get a key pair form the local filesystem.
        """
        pub_key_path = self._get_key_path(key_type, key_name, False)
        priv_key_path = self._get_key_path(key_type, key_name, True)

        if os.path.isfile(pub_key_path):
            with fopen(pub_key_path) as pub_key_file:
                pub_key = pub_key_file.read()
        else:
            raise exceptions.KeyNotFound('No public key was found for %s' % key_name)

        if os.path.isfile(priv_key_path):
            with fopen(priv_key_path) as priv_key_file:
                priv_key = self._decrypt_priv_key(priv_key_file.read())
        else:
            priv_key = None

        return (pub_key, priv_key)


    def remove(self, key_type, key_name):
        """
        Delete a key pair form the local filesystem.
        """
        pub_key_path = self._get_key_path(key_type, key_name, False)
        priv_key_path = self._get_key_path(key_type, key_name, True)

        if os.path.isfile(pub_key_path):
            os.remove(pub_key_path)

        if os.path.isfile(priv_key_path):
            os.remove(priv_key_path)

MANAGER = LocalFileKeyManager
