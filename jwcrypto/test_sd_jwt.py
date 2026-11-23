import json
import time
import unittest

from jwcrypto import jwe, jwk, jws, jwt, sd_jwt
from jwcrypto.common import base64url_decode, base64url_encode, json_encode


class TestSDJWT(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.issuer_key = jwk.JWK.generate(kty='EC', crv='P-256')
        cls.holder_key = jwk.JWK.generate(kty='EC', crv='P-256')

    def _claims(self):
        now = int(time.time())
        return {
            'iss': 'https://issuer.example',
            'iat': now,
            'exp': now + 600,
            'given_name': 'Alice',
            'family_name': 'Smith',
            'address': {
                'street': 'Main Street',
                'city': 'Springfield',
            },
            'nationalities': ['DE', 'FR', 'US'],
        }

    def _issue(self, **kwargs):
        return sd_jwt.SDJWT.issue(
            self._claims(),
            self.issuer_key,
            holder_key=self.holder_key,
            **kwargs)

    def test_issue_present_verify_full_chain(self):
        issued = self._issue(disclosable=[
            'given_name',
            'family_name',
            'address.street',
            'nationalities.0',
            'nationalities.1',
            'nationalities.2',
        ])
        self.assertTrue(issued.serialize().endswith('~'))
        self.assertEqual(len(issued.disclosures), 6)

        issued_claims = sd_jwt.SDJWTVerifier(
            self.issuer_key).verify(issued)
        self.assertEqual(issued_claims['family_name'], 'Smith')
        self.assertEqual(issued_claims['nationalities'], ['DE', 'FR', 'US'])

        holder = sd_jwt.SDJWTHolder(issued.serialize())
        presentation = holder.present(
            ['given_name', 'address.street', 'nationalities.1'],
            holder_key=self.holder_key,
            nonce='nonce-123',
            aud='https://verifier.example')

        verified = sd_jwt.SDJWTVerifier(
            self.issuer_key,
            require_key_binding=True,
            expected_aud='https://verifier.example',
            expected_nonce='nonce-123').verify(presentation)

        self.assertEqual(verified['given_name'], 'Alice')
        self.assertNotIn('family_name', verified)
        self.assertEqual(
            verified['address'],
            {'city': 'Springfield', 'street': 'Main Street'})
        self.assertEqual(verified['nationalities'], ['FR'])
        self.assertNotIn('_sd', verified)
        self.assertNotIn('_sd_alg', verified)

    def test_create_presentation_returns_compact_sd_jwt(self):
        issued = self._issue(disclosable=['given_name', 'family_name'])
        holder = sd_jwt.SDJWTHolder(issued.serialize())
        presentation = holder.create_presentation(
            ['given_name'],
            holder_key=self.holder_key,
            nonce='nonce',
            aud='verifier')
        self.assertIsInstance(presentation, str)
        self.assertEqual(presentation, holder.sd_jwt_presentation)
        self.assertEqual(
            sd_jwt.SDJWTVerifier(
                self.issuer_key,
                expected_aud='verifier',
                expected_nonce='nonce').verify(
                    presentation)['given_name'],
            'Alice')

    def test_sd_jwt_without_key_binding(self):
        issued = self._issue(disclosable=['given_name', 'family_name'])
        presentation = issued.present(['given_name'])
        self.assertFalse(presentation.is_key_binding)
        self.assertTrue(presentation.serialize().endswith('~'))
        claims = sd_jwt.SDJWTVerifier(self.issuer_key).verify(presentation)
        self.assertEqual(claims['given_name'], 'Alice')
        self.assertNotIn('family_name', claims)

    def test_sha512_disclosures(self):
        issued = self._issue(
            hash_alg='sha-512', disclosable=['given_name', 'address.city'])
        presentation = issued.present(
            ['given_name', 'address.city'],
            holder_key=self.holder_key,
            nonce='nonce',
            aud='verifier')
        claims = sd_jwt.SDJWTVerifier(
            self.issuer_key,
            expected_aud='verifier',
            expected_nonce='nonce',
            require_key_binding=True).verify(presentation)
        self.assertEqual(claims['given_name'], 'Alice')
        self.assertEqual(
            claims['address'],
            {'city': 'Springfield', 'street': 'Main Street'})

    def test_recursive_disclosure_includes_parent(self):
        issued = self._issue(
            disclosable=['address', 'address.street'])
        presentation = issued.present(['address.street'])
        self.assertEqual(len(presentation.disclosures), 2)
        claims = sd_jwt.SDJWTVerifier(self.issuer_key).verify(presentation)
        self.assertEqual(
            claims['address'],
            {'city': 'Springfield', 'street': 'Main Street'})

    def test_decoy_digests_are_ignored(self):
        issued = self._issue(disclosable=['given_name'], decoys=3)
        payload = self._payload(issued.issuer_jwt)
        self.assertEqual(len(payload['_sd']), 4)
        claims = sd_jwt.SDJWTVerifier(self.issuer_key).verify(issued)
        self.assertEqual(claims['given_name'], 'Alice')

    def test_tampered_disclosure_is_rejected(self):
        issued = self._issue(disclosable=['given_name'])
        presentation = issued.present(['given_name'])
        parts = presentation.serialize().split('~')
        disclosure = json.loads(
            base64url_decode(parts[1]).decode('utf-8'))
        disclosure[2] = 'Mallory'
        parts[1] = base64url_encode(json_encode(disclosure))
        tampered = '~'.join(parts)

        with self.assertRaises(sd_jwt.InvalidSDJWTDisclosure):
            sd_jwt.SDJWTVerifier(self.issuer_key).verify(tampered)

    def test_wrong_issuer_key_is_rejected(self):
        issued = self._issue(disclosable=['given_name'])
        with self.assertRaises(sd_jwt.InvalidSDJWT):
            sd_jwt.SDJWTVerifier(
                jwk.JWK.generate(kty='EC', crv='P-256')).verify(issued)

    def test_duplicate_and_unreferenced_disclosures_are_rejected(self):
        issued = self._issue(disclosable=['given_name'])
        duplicate = sd_jwt.SDJWT(
            issued.issuer_jwt,
            issued.disclosures + issued.disclosures)
        with self.assertRaises(sd_jwt.InvalidSDJWTDisclosure):
            sd_jwt.SDJWTVerifier(self.issuer_key).verify(duplicate)

        extra = sd_jwt.Disclosure(
            base64url_encode(json_encode(
                ['extra-salt', 'extra_claim', 'unexpected'])))
        unreferenced = sd_jwt.SDJWT(
            issued.issuer_jwt, issued.disclosures + [extra.serialized])
        with self.assertRaises(sd_jwt.InvalidSDJWTDisclosure):
            sd_jwt.SDJWTVerifier(self.issuer_key).verify(unreferenced)

    def test_holder_binding_rejects_wrong_key_nonce_and_audience(self):
        issued = self._issue(disclosable=['given_name'])

        with self.assertRaises(sd_jwt.InvalidSDJWTKeyBinding):
            issued.present(
                ['given_name'],
                holder_key=jwk.JWK.generate(kty='EC', crv='P-256'),
                nonce='nonce',
                aud='verifier')

        presentation = issued.present(
            ['given_name'],
            holder_key=self.holder_key,
            nonce='nonce',
            aud='verifier')
        verifier = sd_jwt.SDJWTVerifier(self.issuer_key)
        with self.assertRaises(sd_jwt.InvalidSDJWTKeyBinding):
            verifier.verify(
                presentation, expected_aud='other', expected_nonce='nonce')
        with self.assertRaises(sd_jwt.InvalidSDJWTKeyBinding):
            verifier.verify(
                presentation, expected_aud='verifier', expected_nonce='other')
        with self.assertRaises(sd_jwt.InvalidSDJWTKeyBinding):
            verifier.verify(
                presentation,
                expected_aud='verifier',
                expected_nonce='nonce',
                holder_key=jwk.JWK.generate(kty='EC', crv='P-256'))

    def test_key_binding_detects_disclosure_changes(self):
        issued = self._issue(disclosable=['given_name', 'family_name'])
        presentation = issued.present(
            ['given_name', 'family_name'],
            holder_key=self.holder_key,
            nonce='nonce',
            aud='verifier')
        parts = presentation.serialize().split('~')
        parts[1], parts[2] = parts[2], parts[1]
        changed = '~'.join(parts)
        no_disclosure = '~'.join([parts[0], parts[-1]])

        verifier = sd_jwt.SDJWTVerifier(
            self.issuer_key,
            expected_aud='verifier',
            expected_nonce='nonce',
            require_key_binding=True)
        with self.assertRaises(sd_jwt.InvalidSDJWTKeyBinding):
            verifier.verify(changed)
        with self.assertRaises(sd_jwt.InvalidSDJWTKeyBinding):
            verifier.verify(no_disclosure)

    def test_key_binding_required(self):
        issued = self._issue(disclosable=['given_name'])
        presentation = issued.present(['given_name'])
        with self.assertRaises(sd_jwt.InvalidSDJWTKeyBinding):
            sd_jwt.SDJWTVerifier(
                self.issuer_key,
                require_key_binding=True).verify(presentation)

    def test_issuer_jwt_is_compatible_with_jws_and_jwt(self):
        issued = self._issue(disclosable=['given_name'])

        signature = jws.JWS()
        signature.deserialize(issued.issuer_jwt, self.issuer_key)
        self.assertTrue(signature.is_valid)

        token = jwt.JWT(
            jwt=issued.issuer_jwt,
            key=self.issuer_key,
            check_claims=False)
        payload = json.loads(token.claims)
        self.assertIn('_sd', payload)
        self.assertEqual(payload['_sd_alg'], 'sha-256')

    def test_presentation_can_be_wrapped_in_jwe(self):
        issued = self._issue(disclosable=['given_name'])
        presentation = issued.present(
            ['given_name'],
            holder_key=self.holder_key,
            nonce='nonce',
            aud='verifier')

        encryption_key = jwk.JWK.generate(kty='oct', size=256)
        encrypted = jwe.JWE(
            presentation.serialize().encode('utf-8'),
            json_encode({'alg': 'A256KW', 'enc': 'A256CBC-HS512'}))
        encrypted.add_recipient(encryption_key)

        decrypted = jwe.JWE()
        decrypted.deserialize(
            encrypted.serialize(compact=True), encryption_key)
        claims = sd_jwt.SDJWTVerifier(
            self.issuer_key,
            expected_aud='verifier',
            expected_nonce='nonce',
            require_key_binding=True).verify(
                decrypted.payload.decode('utf-8'))
        self.assertEqual(claims['given_name'], 'Alice')

    def test_invalid_serializations(self):
        issued = self._issue(disclosable=['given_name'])
        without_tilde = issued.issuer_jwt
        with self.assertRaises(sd_jwt.InvalidSDJWT):
            sd_jwt.SDJWT.from_serialized(without_tilde)
        with self.assertRaises(sd_jwt.InvalidSDJWT):
            sd_jwt.SDJWT.from_serialized(issued.issuer_jwt + '~~')

    def test_rfc9901_disclosure_vector(self):
        disclosure = sd_jwt.Disclosure(
            'WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJN'
            'w7ZiaXVzIl0')
        self.assertEqual(disclosure.claim_name, 'family_name')
        self.assertEqual(disclosure.value, 'Möbius')
        self.assertEqual(
            disclosure.digest,
            'X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0')

    def test_missing_disclosable_path(self):
        with self.assertRaises(ValueError):
            self._issue(disclosable=['does_not_exist'])

    @staticmethod
    def _payload(compact_jws):
        encoded = compact_jws.split('.')[1]
        return json.loads(base64url_decode(encoded).decode('utf-8'))


if __name__ == '__main__':
    unittest.main()
