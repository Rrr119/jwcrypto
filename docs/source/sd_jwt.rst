Selective Disclosure JWT (SD-JWT)
=================================

The sd_jwt Module implements `RFC 9901`_.
An SD-JWT is an issuer-signed JWT whose payload can contain digests of
Disclosures. A Holder can send only the Disclosures the Verifier is allowed
to see. The Holder can also attach a Key Binding JWT (KB-JWT) to prove
possession of the key referenced by the ``cnf`` claim.

The issuer-signed JWT and the KB-JWT are ordinary JWS objects, created with
the existing :class:`jwcrypto.jwt.JWT` API. This means they can also be
inspected with :class:`jwcrypto.jws.JWS`, and the complete SD-JWT compact
presentation can be encrypted with :class:`jwcrypto.jwe.JWE`.

.. _RFC 9901: https://www.rfc-editor.org/rfc/rfc9901

Classes
-------

.. autoclass:: jwcrypto.sd_jwt.SDJWT
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.sd_jwt.SDJWTIssuer
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.sd_jwt.SDJWTHolder
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.sd_jwt.SDJWTVerifier
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.sd_jwt.Disclosure
   :members:
   :show-inheritance:

Functions
---------

.. autofunction:: jwcrypto.sd_jwt.issue

.. autofunction:: jwcrypto.sd_jwt.verify

Exceptions
----------

.. autoclass:: jwcrypto.sd_jwt.SDJWTException
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.sd_jwt.InvalidSDJWT
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.sd_jwt.InvalidSDJWTDisclosure
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.sd_jwt.InvalidSDJWTKeyBinding
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.sd_jwt.SDJWTSelectionError
   :members:
   :show-inheritance:

Examples
--------

Issue an SD-JWT with holder binding. ``disclosable`` selects the claims that
can later be omitted. Paths can name object properties, nested properties, or
array elements::

    from jwcrypto import jwk, sd_jwt

    issuer_key = jwk.JWK.generate(kty='EC', crv='P-256')
    holder_key = jwk.JWK.generate(kty='EC', crv='P-256')

    issued = sd_jwt.SDJWT.issue(
        claims={
            'iss': 'https://issuer.example',
            'given_name': 'Alice',
            'family_name': 'Smith',
            'address': {'street': 'Main Street', 'city': 'Springfield'},
        },
        key=issuer_key,
        holder_key=holder_key,
        disclosable=['given_name', 'family_name', 'address.street'],
    )
    issued_token = issued.serialize()

Create a presentation and a KB-JWT. The ``nonce`` and ``aud`` values are
chosen by the Verifier and must be checked during verification::

    holder = sd_jwt.SDJWTHolder(issued_token)
    presentation = holder.present(
        claims_to_disclose=['given_name', 'address.street'],
        holder_key=holder_key,
        nonce='verifier-nonce',
        aud='https://verifier.example',
    ).serialize()

Verify the issuer signature, Disclosures, and holder binding::

    verifier = sd_jwt.SDJWTVerifier(
        key=issuer_key,
        require_key_binding=True,
        expected_nonce='verifier-nonce',
        expected_aud='https://verifier.example',
    )
    claims = verifier.verify(presentation)

The resulting ``claims`` contain ``given_name``, the disclosed
``address.street`` value, and permanently disclosed claims. ``family_name``
is absent because its Disclosure was not selected.

Without key binding, omit the holder arguments::

    presentation = holder.present(['given_name']).serialize()
    claims = sd_jwt.SDJWTVerifier(issuer_key).verify(presentation)

To encrypt the presentation for transport, pass the SD-JWT string as the JWE
plaintext. After decryption, call
:meth:`jwcrypto.sd_jwt.SDJWTVerifier.verify` on the decrypted string.
