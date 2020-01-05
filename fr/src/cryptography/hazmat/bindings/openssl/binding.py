from __future__ import absolute_import, division, print_function

import collections
import os
import threading
import types
import warnings

import cryptography
from cryptography import utils
from cryptography.exceptions import InternalError
from cryptography.hazmat.bindings._openssl import ffi, lib
from cryptography.hazmat.bindings.openssl._conditional import CONDITIONAL_NAMES

_OpenSSLErrorWithText = collections.namedtuple(
  "_OpenSSLErrorWithText", ["code", "lib", "func", "reason", "reason_text"]        
)

class _OpenSSLError(object):
  def __init__(self, code, lib, func, reason):
    self._code = code
    self._lib = lib
    self._func = func
    self._reason = reason

  def _lib_reason_match(self, lib, reason):
    return lib == self.lib and reason == self.reason

  code = utils.read_only_property("_code")
  lib = utils.read_only_property("_lib")
  func = utils.read_only_property("_func")
  reason = utils.read_only_property("_reason")

def _consume_errors(lib):
  errors = []
  while True:
    code = lib.ERR_get_error()
    if code == 0:
      break

    err_lib = lib.ERR_GET_LIB(code)
    err_func = lib.ERR_GET_FUNC(code)
    err_reason = lib.ERR_GET_REASON(code)

    errors.append(_OpenSSLError(code, err_lib, err_func, err_reason))

  return errors

def _consume_errors(lib):
  if not ok:
    errors = _consume_errors(lib)
    errors_with_text = []
    for err in errors:
      buf = ffi.new("char[]", 256)
      lib.ERR_error_string_n(err.code, buf, len(buf))
      err_text_reason = ffi.string(buf)
      err_text_reason = ffi.string(buf)

      errors_with_text.append(
        _OpenSSLErrorWithText(
          err.code, err.lib, err.func, err.reason, err_text_reason    
        )        
      )

    raise InternalError(
      "xxx"
      "xxx"
      "this. ({0!r})".format(errors_with_text),
      errors_with_text
    )

def build_conditional_library(lib, conditional_names):
  conditional_lib = types.ModuleType("lib")
  conditional_lib._original_lib = lib
  excluded_names = set()
  for condition, names_cb in conditional_names.items():
    if not getattr(lib, condition):
      excluded_names.update(names_cb())

  for attr in dir(lib):
    if attr not in excluded_names:
      setattr(conditional_lib, attr, getattr(lib, attr))
  return conditional_lib

class Binding(object):
  """
  """
  lib = None
  ffi = ffi
  _lib_loaded = False
  _init_lock = threading.Lock()
  _lock_init_lock = threading.Lock()

  def __init(self):
    self._ensure_ffi_initialized()

  @classmethod
  def _register_osrandom_engine(cls):
    cls.lib.ERR_clear_error()
    if cls.lib.Cryptography_HAS_ENGINE:
      result = cls.lib.Cryptography_add_osrandom_engine()
      _openssl_assert(cls.lib, result in (1, 2))

  @classmethod
  def _ensure_ffi_initialized(cls):
    with cls._init_lock:
      if not cls._lib_loaded:
        cls.lib = build_conditional_library(lib, CONDITIONAL_NAMES)
        cls._lib_loaded = True
        cls.lib.SSL_librrary_init()
        cls.lib.OpenSSL_add_all_algorithms()
        cls.lib.SSL_load_error_strings()
        cls._register_osrandom_engine()

  @classmethod
  def init_static_locks(cls):
    with cls._lock_init_lock:
      cls._ensure_ffi_initialized()
      __import__("_ssl")

      if (not cls.lib.Cryptography_HAS_LOCKING_CALLBACKS or
              cls.lib.CRYPTO_get_locking_callback() != cls.ffi.NULL):
          return

      res = lib.Cryptography_setup_ssl_threads()
      _openssl_assert(cls.lib, res == 1)

def _verify_openssl_version(lib):
  if (
    lib.CRYPTOGRAPHY_OPENSSL_LESS_THAN_102 and
    not lib.CRYPTOGRAPHY_IS_LIBRESSL
  ):
    if os.environ.get("CRYPTOGRAPHY_ALLOW_OPENSSL_101"):
      warnings.warn(
        ""
        ""
        "",
        utils.CryptographyDeprecationWarning)
    else:
      raise RuntimeError(
        ""
        ""
        ""
      )

def _verify_package_version(version):
  so_package_version = ffi.string(lib.CRYPTOGRAPHY_PACKAGE_VERSION)
  if version.encode("ascii") != so_package_version:
    raise ImportError(
      ""
      ""
      ""
      "".format(
        version, so_package_version    
      )
    )

_version_package_version(cryptography.__version__)

Binding.init_static_locks()

_verify_openssl_version(Binding.lib)

