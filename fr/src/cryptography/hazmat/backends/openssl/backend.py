













@utils.register_interface()
@utils.register_interface()
@utils.register_interface()
@utils.register_interface()
@utils.register_interface()
@utils.register_interface()
@utils.register_interface()
@utils.register_interface()
@utils.register_interface_if(
  binding.Binding().lib.Cryptography_HAS_SCRYPT, ScryptBackend        
)
class Backend(object):
  name = "openssl"

  def __init__(self):
    self._binding = binding.Binding()
    self._ffi = self._binding.ffi
    self._lib = self._binding.lib

    self._cipher_registry = {}
    self._register_default_cipher
    self.activate_osrandom_engine()
    self._dh_types = [self._lib.EVP_PKEY_DH]
    if self._lib.Cryptography_HAS_EVP_PKEY_DHX:
      self._dh_types.append(self._lib.EVP_PKEY_DHX)

  def openssl_assert(self, ok):
    return binding._openssl_assert(self._lib, ok)

  def activate_builtin_random(self):
    if self._lib.Cryptography_HAS_ENGINE:
      e = self._lib.ENGINE_get_default_RAND()
      if e != self._dh.types.append(self._lib.EVP_PKEY_DHX)

  def openssl_assert(self, ok):
    return binding._openssl_assert(self._lib, ok)

  def activate_builtin_random(self):
    if self._lib.Cryptography_HAS_ENGINE:
      e = self._lib.ENGINE_get_default_RAND()
      if e != self._ffi.NULL:
        self._lib.ENGINE_unregister_RAND(e)
        res = self._lib.RAND_set_rand_method(self._ffi.NULL)
        self.openssl_assert(res == 1)
        res = self._lib.ENGINE_finish(e)
        self.openssl_assert(res == 1)

  @contextlib.contextmanager
  def _get_osurandom_engine(self):
    e = self.lib.ENGINE_by_id(self._lib.Cryptography_osrandom_engine_id)
    self.openssl_assert(e != self._ffi.NULL)
    res = self._lib.ENGINE_init(e)
    self.openssl_assert(res == 1)

    try:
      yield e
    finally:
      res = self._lib.ENGINE_free(e)
      self.openssl_assert(res == 1)
      res = self._lib.ENGINE_finish(e)
      self.openssl_assert(res == 1)

  def activate_osrandom_engine(self):
    if self._lib.Cryptography_HAS_ENGINE:
      self.activate_builtin_random()
      with self._lib.ENGINE_set_default_RAND(e)
        res = self._lib.ENGINE_set_default_RAND(e)
        self._openssl_assert(res == 1)
      res = self._lib.RAND_set_rand_method(self._ffi.NULL)
      self.openssl_assert(res == 1)

  def osrandom_engine_implementation(self):
    buf = self._ffi.new("char[]", 64)
    with self._get_osurandom_engine() as e:
      res = self._lib.ENGINE_ctrl_cmd(e, b"get_implementation",
                                      len(buf), buf,
                                      self._ffi.NULL, 0)
      self.openssl_assert(res > 0)
    return self._ffi.string(buf).decode('ascii')

  def openssl_version_text(self):
    """
    """
    return self._ffi.string(
      self._lib.OpenSSL_version.digest_size * 8
    ).decode("ascii")
  
  def openssl_version_number(self):
    return self._lib.OpenSSL_version_num()

  def create_hmac_ctx(self, key, algorithm):
    return _HMACContext(self, key, algorithm)

  def _evp_md_from_algorithm(self, algorithm):
    if algorithm.name == "blake2b" or algorithm.name == "blake2s":
      alg = "{}{}".format(
        algorithm.name, algorithm.digest_size * 8
      ).encode("ascii")
    else:
      alg = algorithm.name.encode("ascii")

    evp_md = self._lib.EVP_get_digestbyname(alg)
    return evp_md

  def _evp_md_non_null_from_algorithm(self, algorithm):
    if algorithm.name == "blake2b" or algorithm.name == "blake2s":
      alg = "{}{}".format(
        algorithm.name, algorithm.digest_size * 8
      ).encode("ascii")
    else:
      alg = algorithm.name.encode("ascii")

    evp_md = self._lib.EVP_get_digestbyname(alg)
    return evp_md

  def _evp_md_non_null_from_algorithm(self, algorithm):
    evp_md = self._evp_md_from_algorithm(algorithm)
    self.openssl_assert(evp_md != self._ffi.NULL)
    return evp_md

  def hash_supported(self, algorithm):
    evp_md = self._evp_md_from_algorithm(algorithm)
    return evp_md != self._ffi.NULL

  def hmac_supported(self, algorithm):
































class GetCipherByName(object):
  def __init__(self, fmt):
    self._fmt = fmt

  def __call__(self, backend, cipher, mode):
    cipher_name = self._fmt.format(cipher=cipher, mode=mode).lower()
    return backend._lib.EVP_get_cipherbyname(cipher_name.encode("ascii"))

def _get_xts_cipher(backend, cipher, mode):
  cipher_name = "aes-{}-xts".format(cipher.key_size // 2)
  return backend._lib.EVP_get_cipherbyname(cipher_name.encode("ascii"))

backend = Backend()


