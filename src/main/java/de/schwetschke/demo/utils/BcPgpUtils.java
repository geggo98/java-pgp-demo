package de.schwetschke.demo.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.util.Date;
import java.util.UUID;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class BcPgpUtils {

    public static PGPKeyPair generateEd25519KeyPair() throws PGPException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PublicKey pubKey = keyPair.getPublic();
        PrivateKey privKey = keyPair.getPrivate();

        if (!(pubKey instanceof EdDSAKey) || !(pubKey instanceof BCEdDSAPublicKey)) {
            throw new IllegalArgumentException("Public key must be an instance of EdDSAKey and BCEdDSAPublicKey.");
        }
        if (!(privKey instanceof EdECPrivateKey) || !(privKey instanceof BCEdDSAPrivateKey)) {
            throw new IllegalArgumentException("Private key must be an instance of EdDSAKey or BCEdDSAPrivateKey.");
        }

        // Convert to PGP key pair
        // EDDSA is the OpenPGP curve25519 equivalent. The gpg command line tool uses the same key type for Curve25519 keys:
        // ```
        // $ gpg --quick-generate-key \
        //          'ED25519 Example Key <your.email@example.com> (optional comment)' \
        //          ed25519 cert never
        // $ gpg --export-secret-keys --armor 5829E0C168AE16FA93ACB124AAF45D40A01E3222 | gpg --list-packets
        // # version 4, algo 22, created 1707206527, expires 0 <-- algo 22 is EDDSA
        // ```
        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.EDDSA, keyPair, new Date());
        return pgpKeyPair;
    }

    public static PasswordProtectedPgpKeyPair generatePgpKeyPair(final String keyOwnerMailAddress) throws NoSuchAlgorithmException, NoSuchProviderException, PGPException {
        PGPKeyPair pgpKeyPair = generateEd25519KeyPair();

        // Key ring generator
        final PGPDigestCalculator digestCalculator = new JcaPGPDigestCalculatorProviderBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build()
            .get(HashAlgorithmTags.SHA1);

        final String passphrase = UUID.randomUUID().toString();

        final int algorithm = pgpKeyPair.getPublicKey().getAlgorithm();
        final PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            pgpKeyPair,
            keyOwnerMailAddress,
            digestCalculator,
            null,
            null,
            new JcaPGPContentSignerBuilder(algorithm, HashAlgorithmTags.SHA1),
            new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, digestCalculator).setProvider("BC").build(passphrase.toCharArray())
        );

        // Generate the key rings
        final PGPPublicKeyRing pkr = keyRingGen.generatePublicKeyRing();
        final PGPSecretKeyRing skr = keyRingGen.generateSecretKeyRing();
        return new PasswordProtectedPgpKeyPair(pkr, skr, passphrase);
    }

}
