"""Selective Disclosure for JSON Web Tokens (SD-JWT).

This module implements the compact serialization defined in RFC 9901.
Issuer signatures and Key Binding JWTs are regular JWS/JWT objects created
through :mod:`jwcrypto.jwt`, so they can also be handled by the existing
JWS and JWE APIs.
"""

import copy
import hashlib
import hmac
import json
import secrets
import time

from jwcrypto.common import JWException
from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import json_encode
from jwcrypto.jwk import JWK, JWKSet
from jwcrypto.jws import JWS
from jwcrypto.jwt import JWT, JWTExpired, JWTInvalidClaimFormat
from jwcrypto.jwt import JWTInvalidClaimValue, JWTMissingClaim
from jwcrypto.jwt import JWTNotYetValid


_HASH_ALGORITHMS = {
    'sha-256': 'sha256',
    'sha-384': 'sha384',
    'sha-512': 'sha512',
    'sha3-256': 'sha3_256',
    'sha3-384': 'sha3_384',
    'sha3-512': 'sha3_512',
}

_DEFAULT_HASH_ALG = 'sha-256'
_RESERVED_CLAIMS = ('_sd', '...')


class SDJWTException(JWException):
    """Base exception for SD-JWT processing errors."""


class InvalidSDJWT(SDJWTException):
    """The SD-JWT is malformed or its signature is invalid."""


class InvalidSDJWTDisclosure(SDJWTException):
    """A Disclosure is malformed or not referenced by the SD-JWT."""


class InvalidSDJWTKeyBinding(SDJWTException):
    """The Key Binding JWT is missing or invalid."""


class SDJWTSelectionError(SDJWTException):
    """A requested selectively disclosable claim cannot be selected."""


class Disclosure:
    """A parsed RFC 9901 Disclosure."""

    def __init__(self, serialized, hash_alg=_DEFAULT_HASH_ALG):
        if not isinstance(serialized, str) or not serialized:
            raise InvalidSDJWTDisclosure(
                'Disclosure must be a non-empty string')
        self.serialized = serialized
        self.hash_alg = _check_hash_alg(hash_alg)
        try:
            decoded = base64url_decode(serialized).decode('utf-8')
            value = _json_decode(decoded)
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidSDJWTDisclosure(
                'Disclosure is not valid base64url-encoded JSON') from e

        if not isinstance(value, list) or len(value) not in (2, 3):
            raise InvalidSDJWTDisclosure(
                'Disclosure must contain two or three elements')
        if not isinstance(value[0], str):
            raise InvalidSDJWTDisclosure('Disclosure salt must be a string')

        self.salt = value[0]
        if len(value) == 3:
            if not isinstance(value[1], str):
                raise InvalidSDJWTDisclosure(
                    'Disclosure claim name must be a string')
            self.claim_name = value[1]
            self.value = value[2]
            self.is_array_element = False
        else:
            self.claim_name = None
            self.value = value[1]
            self.is_array_element = True

        self.digest = _hash_value(
            serialized.encode('ascii'), self.hash_alg)
        self.path = None
        self.parent = None

    def __repr__(self):
        return 'Disclosure(claim_name={!r}, array_element={!r})'.format(
            self.claim_name, self.is_array_element)


class SDJWT:
    """An SD-JWT or SD-JWT+KB in compact serialization."""

    def __init__(self, issuer_jwt=None, disclosures=None, kb_jwt=None):
        """Create an SD-JWT object.

        :param issuer_jwt: The compact issuer-signed JWT as a string, or a
         :class:`jwcrypto.jwt.JWT` object.
        :param disclosures: An optional list of serialized Disclosures.
        :param kb_jwt: An optional serialized Key Binding JWT.
        """
        if issuer_jwt is None:
            self.issuer_jwt = None
        elif isinstance(issuer_jwt, JWT):
            self.issuer_jwt = issuer_jwt.serialize()
        elif isinstance(issuer_jwt, str):
            self.issuer_jwt = issuer_jwt
        else:
            raise TypeError('issuer_jwt must be a string or JWT')

        self.disclosures = list(disclosures or [])
        if any(not isinstance(d, str) for d in self.disclosures):
            raise TypeError('Disclosures must be strings')

        if isinstance(kb_jwt, JWT):
            self.kb_jwt = kb_jwt.serialize()
        elif kb_jwt is not None and not isinstance(kb_jwt, str):
            raise TypeError('kb_jwt must be a string or JWT')
        else:
            self.kb_jwt = kb_jwt

    @classmethod
    def issue(cls, claims, key, header=None, alg=None, holder_key=None,
              disclosable=None, hash_alg=_DEFAULT_HASH_ALG, decoys=0,
              algs=None):
        """Issue a signed SD-JWT.

        ``disclosable`` contains paths to claims that are selectively
        disclosable. A path is a claim name, a dot-separated path such as
        ``"address.street"``, a JSON Pointer such as ``"/address/street"``,
        or a tuple/list of object names and array indices.

        If ``holder_key`` is provided, its public key is included in the
        ``cnf`` claim for holder binding. The issuer key signs the inner
        JWT; the holder key signs the optional Key Binding JWT later.
        """
        if not isinstance(key, JWK):
            raise TypeError('key must be a JWK object')
        if algs is not None and not isinstance(algs, list):
            raise TypeError('algs must be a list')

        hash_alg = _check_hash_alg(hash_alg)
        claims = _read_json_object(claims, 'claims')
        _check_claims_for_issuance(claims)

        if holder_key is not None:
            if not isinstance(holder_key, JWK):
                raise TypeError('holder_key must be a JWK object')
            try:
                holder_jwk = holder_key.export_public(as_dict=True)
            except Exception as e:  # pylint: disable=broad-except
                raise ValueError(
                    'holder_key must contain an asymmetric public key') from e
            cnf = claims.get('cnf')
            if cnf is None:
                claims['cnf'] = {'jwk': holder_jwk}
            else:
                if not isinstance(cnf, dict) or cnf.get('jwk') != holder_jwk:
                    raise ValueError(
                        'claims cnf does not match the holder_key')

        header = _prepare_issuer_header(header, key, alg)
        paths = _normalize_disclosable(disclosable)
        payload, disclosures = _build_sd_payload(
            claims, paths, hash_alg, decoys)

        token = JWT(header=header, claims=payload, algs=algs)
        token.make_signed_token(key)
        return cls(token.serialize(), disclosures)

    @classmethod
    def from_serialized(cls, serialized):
        """Deserialize an SD-JWT or SD-JWT+KB compact string."""
        issuer_jwt, disclosures, kb_jwt = _split_serialized(serialized)
        return cls(issuer_jwt, disclosures, kb_jwt)

    @classmethod
    def from_jose_token(cls, token):
        """Alias for :meth:`from_serialized`."""
        return cls.from_serialized(token)

    @property
    def serialized(self):
        return self.serialize()

    @property
    def is_key_binding(self):
        return self.kb_jwt is not None

    def serialize(self, compact=True):
        """Serialize the SD-JWT or SD-JWT+KB.

        :param compact: Must be True. The parameter mirrors the JWT, JWS
         and JWE APIs.
        """
        if not compact:
            raise ValueError('Only the compact serialization is supported')
        if self.issuer_jwt is None:
            raise ValueError('SD-JWT has no issuer-signed JWT')

        serialized = self.issuer_jwt + '~'
        for disclosure in self.disclosures:
            serialized += disclosure + '~'
        if self.kb_jwt is not None:
            serialized += self.kb_jwt
        return serialized

    def present(self, claims_to_disclose=None, holder_key=None, nonce=None,
                aud=None, alg=None, kb_header=None, issued_at=None,
                disclose_all=False):
        """Create a presentation, optionally adding holder key binding."""
        holder = SDJWTHolder(self)
        return holder.present(
            claims_to_disclose=claims_to_disclose,
            holder_key=holder_key,
            nonce=nonce,
            aud=aud,
            alg=alg,
            kb_header=kb_header,
            issued_at=issued_at,
            disclose_all=disclose_all)

    def verify(self, key, **kwargs):
        """Verify the presentation and return processed claims."""
        return SDJWTVerifier(key=key, **kwargs).verify(self)

    def __str__(self):
        try:
            return self.serialize()
        except Exception:  # pylint: disable=broad-except
            return self.__repr__()

    def __repr__(self):
        return 'SDJWT(issuer_jwt={!r}, disclosures={!r}, kb_jwt={!r})'.format(
            self.issuer_jwt, self.disclosures, self.kb_jwt)


class SDJWTIssuer:
    """Convenience wrapper for issuing an SD-JWT."""

    def __init__(self, claims, key, header=None, alg=None, holder_key=None,
                 disclosable=None, hash_alg=_DEFAULT_HASH_ALG, decoys=0,
                 algs=None):
        self.sd_jwt = SDJWT.issue(
            claims=claims,
            key=key,
            header=header,
            alg=alg,
            holder_key=holder_key,
            disclosable=disclosable,
            hash_alg=hash_alg,
            decoys=decoys,
            algs=algs)
        self.sd_jwt_serialized = self.sd_jwt.serialize()
        self.issuer_jwt = self.sd_jwt.issuer_jwt
        self.disclosures = self.sd_jwt.disclosures

    def serialize(self, compact=True):
        return self.sd_jwt.serialize(compact=compact)

    def __str__(self):
        return self.serialize()


class SDJWTHolder:
    """Holder-side selection and presentation of an issued SD-JWT."""

    def __init__(self, sd_jwt):
        if isinstance(sd_jwt, str):
            sd_jwt = SDJWT.from_serialized(sd_jwt)
        if not isinstance(sd_jwt, SDJWT):
            raise TypeError('sd_jwt must be a string or SDJWT')
        if sd_jwt.kb_jwt is not None:
            raise InvalidSDJWT('The Holder cannot receive an SD-JWT+KB')
        self.sd_jwt = sd_jwt
        self.sd_jwt_presentation = None

    def present(self, claims_to_disclose=None, holder_key=None, nonce=None,
                aud=None, alg=None, kb_header=None, issued_at=None,
                disclose_all=False):
        """Select Disclosures and optionally create an SD-JWT+KB.

        When ``holder_key``, ``nonce`` and ``aud`` are all provided, a
        Key Binding JWT is created. All three are required together.
        """
        issuer_token, payload, all_disclosures = _inspect_issued(
            self.sd_jwt)
        hash_alg = _payload_hash_alg(payload)

        selected = _select_disclosures(
            all_disclosures, claims_to_disclose, disclose_all)
        selected_raw = [d.serialized for d in selected]

        signing_requested = any(
            value is not None for value in (holder_key, nonce, aud))
        if not signing_requested:
            presentation = SDJWT(
                self.sd_jwt.issuer_jwt, selected_raw, None)
            self.sd_jwt_presentation = presentation.serialize()
            return presentation

        if holder_key is None or nonce is None or aud is None:
            raise InvalidSDJWTKeyBinding(
                'holder_key, nonce and aud are required for key binding')
        if not isinstance(holder_key, JWK):
            raise TypeError('holder_key must be a JWK object')
        if not isinstance(nonce, str):
            raise InvalidSDJWTKeyBinding('nonce must be a string')
        if not isinstance(aud, str):
            raise InvalidSDJWTKeyBinding('aud must be a string')

        holder_jwk = _holder_key_from_cnf(payload)
        _check_holder_key(holder_key, holder_jwk)

        if issued_at is None:
            issued_at = int(time.time())
        if isinstance(issued_at, bool) or not isinstance(issued_at, int):
            raise InvalidSDJWTKeyBinding('issued_at must be an integer')

        sd_jwt_for_hash = issuer_token + '~'
        for disclosure in selected_raw:
            sd_jwt_for_hash += disclosure + '~'
        sd_hash = _hash_value(
            sd_jwt_for_hash.encode('ascii'), hash_alg)

        kb_payload = {
            'aud': aud,
            'iat': issued_at,
            'nonce': nonce,
            'sd_hash': sd_hash,
        }
        kb_claims = _read_json_object(
            json_encode(kb_payload), 'Key Binding claims')
        kb_header = _prepare_kb_header(kb_header, holder_key, alg)

        token = JWT(header=kb_header, claims=kb_claims)
        token.make_signed_token(holder_key)
        kb_jwt = token.serialize()

        presentation = SDJWT(
            self.sd_jwt.issuer_jwt, selected_raw, kb_jwt)
        self.sd_jwt_presentation = presentation.serialize()
        return presentation

    def create_presentation(self, claims_to_disclose=None, holder_key=None,
                            nonce=None, aud=None, alg=None, kb_header=None,
                            issued_at=None, disclose_all=False):
        """Create and return the serialized presentation."""
        presentation = self.present(
            claims_to_disclose=claims_to_disclose,
            holder_key=holder_key,
            nonce=nonce,
            aud=aud,
            alg=alg,
            kb_header=kb_header,
            issued_at=issued_at,
            disclose_all=disclose_all)
        return presentation.serialize()


class SDJWTVerifier:
    """Verify an SD-JWT or SD-JWT+KB and process its Disclosures."""

    def __init__(self, sd_jwt=None, key=None, algs=None, check_claims=None,
                 leeway=60, max_age=300, allowed_hash_algs=None,
                 expected_typ=None, expected_aud=None,
                 expected_nonce=None, require_key_binding=False,
                 holder_key=None):
        if key is None and isinstance(sd_jwt, (JWK, JWKSet)):
            key, sd_jwt = sd_jwt, None
        elif isinstance(sd_jwt, (JWK, JWKSet)) and \
                isinstance(key, (str, SDJWT)):
            sd_jwt, key = key, sd_jwt
        if key is None:
            raise TypeError('key is required')
        if not isinstance(key, (JWK, JWKSet)):
            raise TypeError('key must be a JWK or JWKSet object')
        if algs is not None and not isinstance(algs, list):
            raise TypeError('algs must be a list')

        self.key = key
        self.sd_jwt = sd_jwt
        self.algs = algs
        self.check_claims = check_claims
        self.leeway = int(leeway)
        self.max_age = max_age
        if max_age is not None:
            self.max_age = int(max_age)
        self.allowed_hash_algs = allowed_hash_algs
        self.expected_typ = expected_typ
        self.expected_aud = expected_aud
        self.expected_nonce = expected_nonce
        self.require_key_binding = require_key_binding
        self.holder_key = holder_key

        self.claims = None
        self.payload = None
        self.issuer_jwt = None
        self.disclosures = None
        self.kb_jwt = None

    def verify(self, sd_jwt=None, expected_aud=None, expected_nonce=None,
               require_key_binding=False, holder_key=None):
        """Verify a presentation and return the processed claims."""
        if sd_jwt is None:
            sd_jwt = self.sd_jwt
        if sd_jwt is None:
            raise ValueError('No SD-JWT provided')
        if isinstance(sd_jwt, str):
            sd_jwt = SDJWT.from_serialized(sd_jwt)
        if not isinstance(sd_jwt, SDJWT):
            raise TypeError('sd_jwt must be a string or SDJWT')

        if expected_aud is None:
            expected_aud = self.expected_aud
        if expected_nonce is None:
            expected_nonce = self.expected_nonce
        if not require_key_binding:
            require_key_binding = self.require_key_binding
        if holder_key is None:
            holder_key = self.holder_key

        self.sd_jwt = sd_jwt
        self.issuer_jwt = sd_jwt.issuer_jwt
        self.disclosures = list(sd_jwt.disclosures)
        self.kb_jwt = sd_jwt.kb_jwt

        try:
            issuer = JWT(
                jwt=sd_jwt.issuer_jwt,
                key=self.key,
                algs=self.algs,
                check_claims=False,
                expected_type='JWS')
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidSDJWT('Issuer-signed JWT verification failed') from e

        header = _json_decode(issuer.header)
        if not isinstance(header, dict):
            raise InvalidSDJWT('Issuer-signed JWT header is not an object')
        if header.get('alg') == 'none':
            raise InvalidSDJWT('The none algorithm is not allowed')
        self._check_typ(header, self.expected_typ, 'issuer-signed JWT')

        payload = _json_decode(issuer.claims)
        if not isinstance(payload, dict):
            raise InvalidSDJWT('SD-JWT payload is not a JSON object')

        hash_alg = _payload_hash_alg(payload)
        if self.allowed_hash_algs is not None:
            if hash_alg not in self.allowed_hash_algs:
                raise InvalidSDJWT(
                    'Hash algorithm {!r} is not allowed'.format(hash_alg))

        try:
            processed, _, _ = _process_sd_payload(
                payload, sd_jwt.disclosures, hash_alg)
        except SDJWTException:
            raise
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidSDJWTDisclosure(
                'Disclosure processing failed') from e

        self._validate_claims(processed)

        if require_key_binding and sd_jwt.kb_jwt is None:
            raise InvalidSDJWTKeyBinding(
                'Key binding is required but no Key Binding JWT was provided')

        if sd_jwt.kb_jwt is not None:
            self._verify_key_binding(
                sd_jwt,
                processed,
                hash_alg,
                expected_aud=expected_aud,
                expected_nonce=expected_nonce,
                holder_key=holder_key)
        elif holder_key is not None:
            raise InvalidSDJWTKeyBinding(
                'holder_key was provided but no Key Binding JWT was found')

        self.claims = processed
        self.payload = processed
        return processed

    validate = verify

    @property
    def verified_claims(self):
        return self.claims

    def _validate_claims(self, claims):
        if self.check_claims is False:
            return

        now = time.time()
        if 'exp' in claims:
            self._check_time_claim('exp', claims['exp'], now)
        if 'nbf' in claims:
            self._check_time_claim('nbf', claims['nbf'], now)

        if not self.check_claims:
            return

        for name, expected in self.check_claims.items():
            if name not in claims:
                raise JWTMissingClaim('Claim {} is missing'.format(name))
            actual = claims[name]

            if name == 'aud':
                actual_values = (
                    actual if isinstance(actual, list) else [actual])
                expected_values = (
                    expected if isinstance(expected, list) else [expected])
                if not any(value in actual_values
                           for value in expected_values):
                    raise JWTInvalidClaimValue(
                        "Invalid 'aud' value. Expected {!r} in {!r}".format(
                            expected, actual))
            elif name == 'exp':
                self._check_time_claim('exp', actual, expected)
            elif name == 'nbf':
                self._check_time_claim('nbf', actual, expected)
            elif name == 'scope':
                if not isinstance(actual, str):
                    raise JWTInvalidClaimFormat(
                        'Claim scope must be a string')
                if expected is not None and expected not in actual.split():
                    raise JWTInvalidClaimValue(
                        "Invalid 'scope' value. {!r} is missing".format(
                            expected))
            elif expected is not None and expected != actual:
                raise JWTInvalidClaimValue(
                    "Invalid '{}' value. Expected {!r} got {!r}".format(
                        name, expected, actual))

    def _check_time_claim(self, name, value, limit):
        if isinstance(value, bool) or not isinstance(value, int):
            raise JWTInvalidClaimFormat(
                'Claim {} is not an integer'.format(name))
        if name == 'exp' and value < limit - self.leeway:
            raise JWTExpired(
                'Expired at {}, time: {}(leeway: {})'.format(
                    value, limit, self.leeway))
        if name == 'nbf' and value > limit + self.leeway:
            raise JWTNotYetValid(
                'Valid from {}, time: {}(leeway: {})'.format(
                    value, limit, self.leeway))

    def _verify_key_binding(self, sd_jwt, claims, hash_alg, expected_aud,
                            expected_nonce, holder_key):
        holder_jwk = _holder_key_from_cnf(claims)
        if holder_key is not None:
            if not isinstance(holder_key, JWK):
                raise TypeError('holder_key must be a JWK object')
            _check_holder_key(holder_key, holder_jwk)

        try:
            kb = JWT(
                jwt=sd_jwt.kb_jwt,
                key=holder_jwk,
                algs=self.algs,
                check_claims=False,
                expected_type='JWS')
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidSDJWTKeyBinding(
                'Key Binding JWT signature verification failed') from e

        header = _json_decode(kb.header)
        if not isinstance(header, dict):
            raise InvalidSDJWTKeyBinding(
                'Key Binding JWT header is not an object')
        if header.get('alg') == 'none':
            raise InvalidSDJWTKeyBinding(
                'The none algorithm is not allowed')
        self._check_typ(header, 'kb+jwt', 'Key Binding JWT', required=True)

        kb_claims = _json_decode(kb.claims)
        if not isinstance(kb_claims, dict):
            raise InvalidSDJWTKeyBinding(
                'Key Binding JWT payload is not an object')

        for name in ('iat', 'aud', 'nonce', 'sd_hash'):
            if name not in kb_claims:
                raise InvalidSDJWTKeyBinding(
                    'Key Binding JWT is missing {!r}'.format(name))

        iat = kb_claims['iat']
        if isinstance(iat, bool) or not isinstance(iat, int):
            raise InvalidSDJWTKeyBinding('Key Binding iat must be an integer')
        now = int(time.time())
        if iat > now + self.leeway:
            raise InvalidSDJWTKeyBinding(
                'Key Binding JWT is not yet valid')
        if self.max_age is not None and iat < now - self.max_age:
            raise InvalidSDJWTKeyBinding('Key Binding JWT is too old')

        aud = kb_claims['aud']
        nonce = kb_claims['nonce']
        sd_hash = kb_claims['sd_hash']
        if not isinstance(aud, str):
            raise InvalidSDJWTKeyBinding('Key Binding aud must be a string')
        if not isinstance(nonce, str):
            raise InvalidSDJWTKeyBinding('Key Binding nonce must be a string')
        if not isinstance(sd_hash, str):
            raise InvalidSDJWTKeyBinding(
                'Key Binding sd_hash must be a string')
        if expected_aud is not None and aud != expected_aud:
            raise InvalidSDJWTKeyBinding('Key Binding aud does not match')
        if expected_nonce is not None and nonce != expected_nonce:
            raise InvalidSDJWTKeyBinding('Key Binding nonce does not match')

        sd_jwt_for_hash = sd_jwt.issuer_jwt + '~'
        for disclosure in sd_jwt.disclosures:
            sd_jwt_for_hash += disclosure + '~'
        expected_hash = _hash_value(
            sd_jwt_for_hash.encode('ascii'), hash_alg)
        if not hmac.compare_digest(sd_hash, expected_hash):
            raise InvalidSDJWTKeyBinding(
                'Key Binding sd_hash does not match the presentation')

    def _check_typ(self, header, expected, description, required=False):
        actual = header.get('typ')
        if actual is None:
            if required:
                raise InvalidSDJWT(
                    '{} is missing the typ header'.format(description))
            return
        if not isinstance(actual, str):
            raise InvalidSDJWT(
                '{} has an invalid typ header'.format(description))
        if expected is None:
            return
        expected_values = (
            expected if isinstance(expected, (list, tuple)) else [expected])
        if _normalize_typ(actual) not in [
                _normalize_typ(value) for value in expected_values]:
            raise InvalidSDJWT(
                '{} has unexpected typ {!r}'.format(description, actual))


def _json_decode(value):
    def reject_duplicates(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError('Duplicate JSON object member')
            result[key] = item
        return result

    if isinstance(value, bytes):
        value = value.decode('utf-8')

    def reject_constant(constant):
        raise ValueError('Invalid JSON constant {}'.format(constant))

    return json.loads(
        value,
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant)


def _read_json_object(value, description):
    try:
        if isinstance(value, dict):
            result = copy.deepcopy(value)
        else:
            result = _json_decode(value)
    except Exception as e:  # pylint: disable=broad-except
        raise ValueError('{} must be a JSON object'.format(description)) from e
    if not isinstance(result, dict):
        raise ValueError('{} must be a JSON object'.format(description))
    return result


def _check_hash_alg(hash_alg):
    if hash_alg not in _HASH_ALGORITHMS:
        raise InvalidSDJWT(
            'Unsupported SD-JWT hash algorithm {!r}'.format(hash_alg))
    return hash_alg


def _hash_value(value, hash_alg):
    digest = hashlib.new(_HASH_ALGORITHMS[hash_alg])
    digest.update(value)
    return base64url_encode(digest.digest())


def _make_disclosure(disclosure, hash_alg):
    serialized = base64url_encode(json_encode(disclosure))
    return serialized, _hash_value(serialized.encode('ascii'), hash_alg)


def _random_salt():
    return secrets.token_urlsafe(16)


def _check_claims_for_issuance(claims):
    for reserved in _RESERVED_CLAIMS:
        if reserved in claims:
            raise ValueError(
                'Claim {!r} is reserved by SD-JWT'.format(reserved))
    if '_sd_alg' in claims:
        raise ValueError("Claim '_sd_alg' is set by the issuer")


def _default_alg(key):
    if 'alg' in key:
        return key['alg']
    kty = key.get('kty')
    if kty == 'EC':
        algorithms = {
            'P-256': 'ES256',
            'P-384': 'ES384',
            'P-521': 'ES512',
            'secp256k1': 'ES256K',
            'P-256K': 'ES256K',
        }
        if key.get('crv') in algorithms:
            return algorithms[key.get('crv')]
    elif kty == 'RSA':
        return 'RS256'
    elif kty == 'OKP' and key.get('crv') in ('Ed25519', 'Ed448'):
        return 'EdDSA'
    elif kty == 'oct':
        return 'HS256'
    raise ValueError('Unable to determine a signing algorithm for the key')


def _prepare_issuer_header(header, key, alg):
    if header is None:
        result = {}
    elif isinstance(header, dict):
        result = copy.deepcopy(header)
    elif isinstance(header, str):
        result = _read_json_object(header, 'header')
    else:
        raise TypeError('header must be a dict or JSON string')

    if alg is not None:
        if 'alg' in result and result['alg'] != alg:
            raise ValueError('Conflicting alg values in header and argument')
        result['alg'] = alg
    if 'alg' not in result:
        result['alg'] = _default_alg(key)
    if result['alg'] == 'none':
        raise ValueError('The none algorithm is not allowed')
    if 'typ' not in result:
        result['typ'] = 'sd+jwt'
    if result.get('b64') is False:
        raise ValueError('SD-JWT payloads must use base64url encoding')
    return result


def _prepare_kb_header(header, key, alg):
    if header is None:
        result = {}
    elif isinstance(header, dict):
        result = copy.deepcopy(header)
    elif isinstance(header, str):
        result = _read_json_object(header, 'kb_header')
    else:
        raise TypeError('kb_header must be a dict or JSON string')

    if alg is not None:
        if 'alg' in result and result['alg'] != alg:
            raise ValueError('Conflicting alg values in header and argument')
        result['alg'] = alg
    if 'alg' not in result:
        result['alg'] = _default_alg(key)
    if result['alg'] == 'none':
        raise ValueError('The none algorithm is not allowed')
    if 'typ' in result and _normalize_typ(result['typ']) != \
            _normalize_typ('kb+jwt'):
        raise ValueError("Key Binding JWT typ must be 'kb+jwt'")
    result['typ'] = 'kb+jwt'
    if result.get('b64') is False:
        raise ValueError('Key Binding JWT payloads must be base64url encoded')
    return result


def _normalize_typ(value):
    if not isinstance(value, str):
        return value
    value = value.lower()
    if '/' not in value:
        return 'application/' + value
    return value


def _normalize_disclosable(disclosable):
    if disclosable is None:
        return set()
    if disclosable is True:
        return True
    if isinstance(disclosable, (str, int, tuple)):
        disclosable = [disclosable]
    if not isinstance(disclosable, (list, set, frozenset)):
        raise TypeError('disclosable must be a path or a list of paths')
    return {_normalize_path(path) for path in disclosable}


def _normalize_path(path):
    if isinstance(path, tuple):
        parts = path
    elif isinstance(path, list):
        parts = tuple(path)
    elif isinstance(path, str):
        if path.startswith('/'):
            if path == '/':
                parts = ()
            else:
                parts = tuple(
                    part.replace('~1', '/').replace('~0', '~')
                    for part in path[1:].split('/'))
        else:
            parts = tuple(path.split('.'))
    else:
        raise TypeError('Claim paths must be strings, tuples or lists')
    if not parts:
        raise ValueError('The root object cannot be selectively disclosed')
    for part in parts:
        if isinstance(part, bool) or not isinstance(part, (str, int)):
            raise TypeError('Claim path elements must be strings or integers')
    return tuple(parts)


def _paths_equal(left, right):
    if len(left) != len(right):
        return False
    for lpart, rpart in zip(left, right):
        if lpart == rpart:
            continue
        if str(lpart) == str(rpart):
            continue
        return False
    return True


def _is_selected(path, selected):
    if selected is True:
        return True
    return any(_paths_equal(path, candidate) for candidate in selected)


def _build_sd_payload(claims, paths, hash_alg, decoys):
    disclosures = []
    seen_paths = set()

    def process_object(obj, path):
        result = {}
        for key, value in obj.items():
            if key in _RESERVED_CLAIMS or key == '_sd_alg':
                raise ValueError(
                    'Claim {!r} is reserved by SD-JWT'.format(key))
            child_path = path + (key,)
            seen_paths.add(child_path)
            processed = process_value(value, child_path)
            if _is_selected(child_path, paths):
                serialized, digest = _make_disclosure(
                    [_random_salt(), key, processed], hash_alg)
                disclosures.append(serialized)
                result.setdefault('_sd', []).append(digest)
            else:
                result[key] = processed
        if '_sd' in result:
            result['_sd'].sort()
        return result

    def process_array(array, path):
        result = []
        for index, value in enumerate(array):
            child_path = path + (index,)
            seen_paths.add(child_path)
            processed = process_value(value, child_path)
            if _is_selected(child_path, paths):
                serialized, digest = _make_disclosure(
                    [_random_salt(), processed], hash_alg)
                disclosures.append(serialized)
                result.append({'...': digest})
            else:
                result.append(processed)
        return result

    def process_value(value, path):
        if isinstance(value, dict):
            return process_object(value, path)
        if isinstance(value, list):
            return process_array(value, path)
        return copy.deepcopy(value)

    result = process_object(claims, ())
    result['_sd_alg'] = hash_alg

    if decoys:
        if isinstance(decoys, bool) or not isinstance(decoys, int) or \
                decoys < 0:
            raise ValueError('decoys must be a non-negative integer')
        result.setdefault('_sd', [])
        for _ in range(decoys):
            result['_sd'].append(
                _hash_value(secrets.token_bytes(32), hash_alg))
        result['_sd'].sort()

    if paths is not True:
        for requested in paths:
            if not any(_paths_equal(requested, seen)
                       for seen in seen_paths):
                raise ValueError(
                    'Disclosable claim path {!r} does not exist'.format(
                        requested))
    return result, disclosures


def _payload_hash_alg(payload):
    hash_alg = payload.get('_sd_alg', _DEFAULT_HASH_ALG)
    if not isinstance(hash_alg, str):
        raise InvalidSDJWT('_sd_alg must be a string')
    return _check_hash_alg(hash_alg)


def _parse_disclosures(disclosures, hash_alg):
    by_digest = {}
    salts = set()
    parsed = []
    for serialized in disclosures:
        try:
            disclosure = Disclosure(serialized, hash_alg)
        except InvalidSDJWTDisclosure:
            raise
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidSDJWTDisclosure(
                'Unable to parse Disclosure') from e
        if disclosure.salt in salts:
            raise InvalidSDJWTDisclosure(
                'Disclosure salts must be unique')
        salts.add(disclosure.salt)
        if disclosure.digest in by_digest:
            raise InvalidSDJWTDisclosure(
                'Duplicate Disclosure digest')
        by_digest[disclosure.digest] = disclosure
        parsed.append(disclosure)
    return by_digest, parsed


def _process_sd_payload(payload, disclosures, hash_alg):
    by_digest, parsed = _parse_disclosures(disclosures, hash_alg)
    seen_digests = set()
    used_disclosures = set()

    def check_digest(digest):
        if not isinstance(digest, str):
            raise InvalidSDJWTDisclosure('Digest must be a string')
        try:
            decoded = base64url_decode(digest)
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidSDJWTDisclosure(
                'Digest is not canonical base64url') from e
        expected_size = hashlib.new(
            _HASH_ALGORITHMS[hash_alg]).digest_size
        if len(decoded) != expected_size:
            raise InvalidSDJWTDisclosure(
                'Digest has the wrong length for {}'.format(hash_alg))
        if digest in seen_digests:
            raise InvalidSDJWTDisclosure('Duplicate digest in SD-JWT')
        seen_digests.add(digest)

    def process_value(value, path, parent=None):
        if isinstance(value, dict):
            return process_object(value, path, parent)
        if isinstance(value, list):
            return process_array(value, path, parent)
        return copy.deepcopy(value)

    def process_object(obj, path, parent=None):
        result = {}
        for key, value in obj.items():
            if key == '_sd':
                continue
            if key == '...':
                raise InvalidSDJWTDisclosure(
                    "'...' is only valid in an array element")
            if key == '_sd_alg':
                if path:
                    raise InvalidSDJWT(
                        '_sd_alg is only allowed at the top level')
                continue
            result[key] = process_value(value, path + (key,), None)

        if '_sd' in obj:
            sd_list = obj['_sd']
            if not isinstance(sd_list, list):
                raise InvalidSDJWTDisclosure('_sd must be an array')
            for digest in sd_list:
                check_digest(digest)
                disclosure = by_digest.get(digest)
                if disclosure is None:
                    continue
                if disclosure.is_array_element:
                    raise InvalidSDJWTDisclosure(
                        'Object digest points to an array Disclosure')
                name = disclosure.claim_name
                if name in _RESERVED_CLAIMS:
                    raise InvalidSDJWTDisclosure(
                        'Disclosure uses a reserved claim name')
                if name == '_sd_alg':
                    raise InvalidSDJWTDisclosure(
                        'Disclosure uses the reserved _sd_alg claim')
                if name in result:
                    raise InvalidSDJWTDisclosure(
                        'Disclosed claim conflicts with an existing claim')
                disclosure.path = path + (name,)
                disclosure.parent = parent
                used_disclosures.add(disclosure.serialized)
                result[name] = process_value(
                    disclosure.value, disclosure.path, disclosure)
        return result

    def process_array(array, path, parent=None):
        result = []
        for index, item in enumerate(array):
            if isinstance(item, dict) and '...' in item:
                if len(item) != 1:
                    raise InvalidSDJWTDisclosure(
                        "Array placeholder must contain only '...'")
                digest = item['...']
                check_digest(digest)
                disclosure = by_digest.get(digest)
                if disclosure is None:
                    continue
                if not disclosure.is_array_element:
                    raise InvalidSDJWTDisclosure(
                        'Array digest points to an object Disclosure')
                disclosure.path = path + (index,)
                disclosure.parent = parent
                used_disclosures.add(disclosure.serialized)
                result.append(process_value(
                    disclosure.value, disclosure.path, disclosure))
            else:
                if isinstance(item, dict) and not item:
                    result.append({})
                else:
                    result.append(process_value(
                        item, path + (index,), None))
        return result

    processed = process_object(payload, ())

    unused = [
        disclosure for disclosure in parsed
        if disclosure.serialized not in used_disclosures
    ]
    if unused:
        raise InvalidSDJWTDisclosure(
            'A Disclosure is not referenced by the SD-JWT')
    return processed, parsed, by_digest


def _inspect_issued(sd_jwt):
    try:
        JWS().deserialize(sd_jwt.issuer_jwt)
    except Exception as e:  # pylint: disable=broad-except
        raise InvalidSDJWT('Issuer-signed JWT is malformed') from e
    try:
        encoded_payload = sd_jwt.issuer_jwt.split('.')[1]
        payload = _json_decode(base64url_decode(encoded_payload))
    except Exception as e:  # pylint: disable=broad-except
        raise InvalidSDJWT('SD-JWT payload is not valid JSON') from e
    if not isinstance(payload, dict):
        raise InvalidSDJWT('SD-JWT payload is not a JSON object')
    hash_alg = _payload_hash_alg(payload)
    _, parsed, _ = _process_sd_payload(
        payload, sd_jwt.disclosures, hash_alg)
    return sd_jwt.issuer_jwt, payload, parsed


def _select_disclosures(disclosures, requested, disclose_all):
    if disclose_all:
        return list(disclosures)
    if not requested:
        return []
    if isinstance(requested, (str, int, tuple)):
        requested = [requested]
    if not isinstance(requested, (list, set, frozenset)):
        raise TypeError('claims_to_disclose must be a list of paths')

    selected = []
    selected_raw = set()
    by_raw = {d.serialized: d for d in disclosures}

    def add_with_ancestors(disclosure):
        chain = []
        current = disclosure
        while current is not None:
            chain.append(current)
            current = current.parent
        for item in reversed(chain):
            if item.serialized not in selected_raw:
                selected_raw.add(item.serialized)
                selected.append(item)

    for item in requested:
        if isinstance(item, str) and item in by_raw:
            add_with_ancestors(by_raw[item])
            continue

        path = _normalize_path(item)
        matches = [
            d for d in disclosures
            if d.path is not None and _paths_equal(d.path, path)
        ]
        if not matches:
            last = path[-1]
            matches = [
                d for d in disclosures
                if d.path is not None and d.path[-1] == last
            ]
        if not matches:
            raise SDJWTSelectionError(
                'No selectively disclosable claim matches {!r}'.format(item))
        if len(matches) > 1:
            raise SDJWTSelectionError(
                'Multiple selectively disclosable claims match {!r}; '
                'use a fully qualified path'.format(item))
        add_with_ancestors(matches[0])

    return [d for d in disclosures if d.serialized in selected_raw]


def _holder_key_from_cnf(claims):
    cnf = claims.get('cnf')
    if not isinstance(cnf, dict) or 'jwk' not in cnf:
        raise InvalidSDJWTKeyBinding(
            'SD-JWT does not contain a cnf.jwk holder key')
    jwk_data = cnf['jwk']
    try:
        if isinstance(jwk_data, dict):
            return JWK.from_json(json_encode(jwk_data))
        if isinstance(jwk_data, str):
            return JWK.from_json(jwk_data)
    except Exception as e:  # pylint: disable=broad-except
        raise InvalidSDJWTKeyBinding(
            'SD-JWT cnf.jwk is not a valid JWK') from e
    raise InvalidSDJWTKeyBinding('SD-JWT cnf.jwk is not a JWK')


def _check_holder_key(private_key, public_key):
    try:
        private_thumbprint = private_key.thumbprint()
        public_thumbprint = public_key.thumbprint()
    except Exception as e:  # pylint: disable=broad-except
        raise InvalidSDJWTKeyBinding(
            'Unable to compare holder keys') from e
    if private_thumbprint != public_thumbprint:
        raise InvalidSDJWTKeyBinding(
            'holder_key does not match the SD-JWT cnf.jwk')


def _split_serialized(serialized):
    if not isinstance(serialized, str):
        raise TypeError('serialized SD-JWT must be a string')
    if '~' not in serialized:
        raise InvalidSDJWT(
            'SD-JWT compact serialization must contain a tilde')

    parts = serialized.split('~')
    issuer_jwt = parts[0]
    if not _is_compact_jws(issuer_jwt):
        raise InvalidSDJWT('Issuer-signed JWT is not a compact JWS')

    if parts[-1] == '':
        kb_jwt = None
        disclosures = parts[1:-1]
    else:
        kb_jwt = parts[-1]
        disclosures = parts[1:-1]
        if not _is_compact_jws(kb_jwt):
            raise InvalidSDJWT('Key Binding JWT is not a compact JWS')

    if any(disclosure == '' for disclosure in disclosures):
        raise InvalidSDJWT('Empty Disclosure in SD-JWT')
    return issuer_jwt, disclosures, kb_jwt


def _is_compact_jws(value):
    return isinstance(value, str) and value.count('.') == 2


def issue(claims, key, **kwargs):
    """Issue an SD-JWT.

    This is a module-level convenience function for
    :meth:`SDJWT.issue`.
    """
    return SDJWT.issue(claims, key, **kwargs)


def verify(sd_jwt, key, **kwargs):
    """Verify an SD-JWT presentation and return processed claims."""
    return SDJWTVerifier(key=key, **kwargs).verify(sd_jwt)
