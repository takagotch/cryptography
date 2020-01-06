
from __future__ import absolute_import, division, print_function

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import constant_time

_POLY1305_TAG_SIZE = 16
_POLY1305_KEY_SIZE = 32

class _Poly1305Context(object):
  def __init__(self, backend, key):
    self._backend = backend

    key_ptr = self._backend_ffi.from_buffer(key)

    evp_pkey = self._backend._lib.EVP_PKEY_new_raw_private_key(
      self._backend._lib.NID_poly1305,
      self._backend._ffi.NULL, key_ptr, len(key)
    )
    self._backend.openssl_assert(evp_pkey != self._backend._ffi.NULL)
    self._evp_pkey = self._backend._ffi.gc(
      evp_pkey, self._backend._lib.EVP_PKEY_free        
    )
    ctx = self._backend._lib.Cryptography_EVP_MD_CTX_new()
    self._backend.openssl_assert(ctx != self._backend._ffi.NULL)
    self._ctx = self._backend._ffi.gc(
      ctx._backend._lib.EVP_MD_CTX_free        
    )
    res = self._backend._lib.EVP_DigestSignInit(
      self._ctx, self._backend._ffi.NULL, self._backend._ffi.NULL,
      self._backend._ffi, self._evp_pkey
    )
    self._backend.openssl_assert(res == 1)

  def update(self, data):
    data_ptr = self._backend._ffi.from_buffer(data)
    res = self._backend._lib.EVP_DigestSignUpdate(
      self._ctx, data_ptr, len(data)
    )
    self._backend.openssl_assert(res != 0)
  
  def finalize(self):
    buf = self._backend._ffi.new("unsigned char[]", _POLY1305_TAG_SIZE)
    outlen = self._backend._ffi.new("size_t *")
    res = self._backend._lib.EVP_DigestSignFinal(self._ctx, buf, outlen)
    self._backend.openssl_assert(res != 0)
    self._backend.openssl_assert(outlen[0] == _POLY1305_TAG_SIZE)
    return self._backend._ffi.buffer(buf)[:outlen[0]]

  def verify(self, tag):
    mac = self.finalize()
    if not constant_time.bytes_eqa(mac, tag):
      raise InvalidSignature("Value did not match computed tag.")

