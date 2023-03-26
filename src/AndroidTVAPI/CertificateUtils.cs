using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;

namespace AndroidTVAPI
{
    public class GeneratedCertificate
    {
        public byte[] Certificate;
        public byte[] PrivateKey;
    }

    internal class CertificateUtils
    {
        internal static GeneratedCertificate GenerateCertificate(
            string name,
            string country,
            string state,
            string locality,
            string organisation,
            string organisationUnit,
            string email,
            DateTime notBefore,
            DateTime notAfter,
            bool exClientAuth = true,
            int keyStrength = 2048,
            string signatureAlgorithm = "SHA256WITHRSA")
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            AsymmetricCipherKeyPair subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            AsymmetricCipherKeyPair issuerKeyPair = subjectKeyPair;
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerKeyPair.Private, random);

            var certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            var nameOids = new List<DerObjectIdentifier>
            {
                X509Name.CN,
                X509Name.O,
                X509Name.OU,
                X509Name.ST,
                X509Name.C,
                X509Name.L,
                X509Name.E
            };

            var nameValues = new Dictionary<DerObjectIdentifier, string>()
            {
                { X509Name.CN, name },
                { X509Name.O, organisation },
                { X509Name.OU, organisationUnit },
                { X509Name.ST, state },
                { X509Name.C, country },
                { X509Name.L, locality },
                { X509Name.E, email }
            };

            var subjectDN = new X509Name(nameOids, nameValues);
            var issuerDN = subjectDN;

            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);
            certificateGenerator.SetPublicKey(issuerKeyPair.Public);

            if (exClientAuth)
            {
                var keyUsage = new KeyUsage(KeyUsage.KeyEncipherment);
                certificateGenerator.AddExtension(X509Extensions.KeyUsage, false, keyUsage.ToAsn1Object());

                // add client authentication extended key usage
                var extendedKeyUsage = new ExtendedKeyUsage(new[] { KeyPurposeID.id_kp_clientAuth });
                certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true, extendedKeyUsage.ToAsn1Object());
            }

            // serial number is required, generate it randomly
            byte[] serial = new byte[20];
            random.NextBytes(serial);
            serial[0] = 1;
            certificateGenerator.SetSerialNumber(new Org.BouncyCastle.Math.BigInteger(serial));

            var certificate = certificateGenerator.Generate(signatureFactory);

            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(issuerKeyPair.Private);

            var ret = new GeneratedCertificate()
            {
                Certificate = certificate.GetEncoded(),
                PrivateKey = info.ToAsn1Object().GetEncoded()
            };

            return ret;
        }
    }
}
