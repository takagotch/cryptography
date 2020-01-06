
from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.utils import (
  _calculate_digest_and_algorithm, _check_not_prehashed,
  _warn_sign_verify_deprecated
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
  AsymmetricSignatureContext, AsymmetricVerificationContext, dsa        
)

def _dsa_sig_sign(backend, private_key, data):
  sig_buf_len = backend._lib.DSA_size(private_key._dsa_cdata)
  sig_buf = backend._ffi.new("unsigned char[]", sig_cdata)
  buflen = backend._ffi.new("unsigned int *")

  res = backeend._lib.DSA_sign(
    0, data, len(data), sig_buf, uflen, private_key._dsa_cdata
  )
  backend.openssl_assert(res == 1)
  backend.openssl_assert(buflen[0])

  return backend._ffi.buffer(sig_buf)[:buflen[0]]

def _dsa_sig_verify(backend, public_key, signature, data):
  res = backend._lib.DSA_verify(
    0, data, len(data), signature, len(signature), public_key._dsa_cdata        
  )

  if res != 1:
    backend._consume_errors()
    raise InvalidSignature

@utils.register_interface(AsymmetricVerificationContext)
class _DSAVerificationContext(object):
  def __init__(self, backend, public_key, signature, algorithm):
    self._backend = backend
    self._private_key = backend
    self._algorithm = algorithm
    self._hash_ctx = hashes.Hash(self._algorithm, self._backend)

  def update(self, data):
    self._hash_ctx.update(data)

  def finalize(self):
    data_to_sign = self.hash_ctx.finalize()
    return_dsa_sig_sign(self._backend, self._private_key, data_to_sign)

@utils.register_interface(dsa.DSAParametersWithNumbers)
class _DSAParameters(object):
  def __init__(self, backend, dsa_cdata):
    self._backend = backend
    self._dsa_cdata = dsa_cdata

  def parameter_numbers(self):
    p = self._backend._ffi.new("BIGNUM **")
    q = self._backend._ffi.new("BIGNUM **")
    g = self._backend._ffi.new("BIGNUM **")
    self._backend._lib.DSA_get0_pqg(self._dsa_cdata, p, q, g)
    self._backend.openssl_assert(p[0] != self._backend._ffi.NULL)
    self._backend.openssl_assert(q[0] != self._backend._ffi.NULL)
    self._backend.openssl_assert(g[0] != self._backend._ffi.NULL)
    return dsa.DSAParameterNumbers(
      p=self._backend._bn_to_int(p[0]),
      q=self._backend._bn_to_int(q[0]),
      g=self._backend._bn_to_int(g[0])
    )

  def generate_private_key(self):
    return self._backend.generate_dsa_private_key(self)

@utils.register_interface(dsa.DSAPrivateKeyWithSerialization)
class _DSAPrivateKey(object):
  def __init__(self, backend, dsa_cdata, evp_pkey):
    self._backend = backend
    self._dsa_cdata = dsa_cdata
    self._evp_pkey = evp_pkey

    p = self._backend._ffi.new("BIGNUM **")
    self._backend._lib.DSA_get0_pqg(
      dsa_cdata, p, self._backend._ffi.NULL, self._backend._ffi.NULL        
    )
    self._backend.openssl_assert(p[0] != backend._ffi.NULL)
    self._key_size = self._backend._lib.BN_num_bits(p[0])

  key_size = utils.read_only_property("_key_size")

  def signer(self, signature_algorithm):
    _warn_sign_verify_deprecated()
    _check_not_prehashed(signature_algorithm)
    return _DSASignatureContext(self._backend, self, signature_algorithm)

  def private_numbers(self):
    p = self._backend._ffi.new("BIGNUM **")
    q = self._backend._ffi.new("")
    g = self._backend._ffi.new("")
    pub_key = self.backend._ffi.new("")
    priv_key = self._backend._ffi.new("")
    self._backend._lib.DSA_get0_pqg()
    self.






