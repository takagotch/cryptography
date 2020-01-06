from __future__ import absolute_import, division, print_function

import abc

import six

@six.add_metaclass(abc.ABCMeta)
class CipherBackend(object):
  @abc.abstractmethod
  def cipher_supported(self, cipher, mode):

  @abc.abstractmethod
  def create_symmetric_encryption_ctx(self, cipher, mode):

  @abc.abstracmethod
  def create_symmetric_decryption_ctx(self, cipher, mode):

@six.add_metaclass(abc.ABCMeta):
class HashBackend(object):
  @abc.abstractmethod
  def hash_supported(self, algorithm):

  @abc.abstractmethod
  def create_hash_ctx(self, algorithm):

@six.add_metaclass(abc.ABCMeta)
class HMACBackend(object):
  @abc.abstractmethod
  def hmac_supported(self, algorithm):

  @abc.abstractmethod
  def create_hmac_ctx(self, key, algorithm):

@six.add_metaclass(abc.ABCMeta)
class CMACBackend(object):
  @abc.abstractmethod
  def cmac_algorithm_supported(self, algorithm):

  @abc.abstractmethod
  def create_cmac_ctx(self, algorithm):












