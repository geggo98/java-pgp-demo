package de.schwetschke.demo;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
    import java.util.Date;

public class Curve25519PgpKeyExample {

    public static PGPKeyPair generateEd25519KeyPair() throws PGPException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PublicKey pubKey = keyPair.getPublic();
        PrivateKey privKey = keyPair.getPrivate();

        if (!(pubKey instanceof EdDSAKey) || !(pubKey instanceof BCEdDSAPublicKey)) {
            throw new IllegalArgumentException("Public key must be an instance of EdDSAKey and BCEdDSAPublicKey.");
        }

        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.EDDSA, keyPair, new Date());
        return pgpKeyPair;
    }
    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Generate a Curve25519 key pair
        PGPKeyPair pgpKeyPair = generateEd25519KeyPair();
        // Write public key to ASCII armored format
        String publicKeyArmored = exportKey(pgpKeyPair.getPublicKey());
        System.out.println("Public Key:\n" + publicKeyArmored);

        // Write private key to ASCII armored format
        String privateKeyArmored = exportKey(pgpKeyPair.getPrivateKey());
        System.out.println("Private Key:\n" + privateKeyArmored);

        // Read public key from ASCII armored string
        PGPPublicKey publicKey = readPublicKey(new ByteArrayInputStream(publicKeyArmored.getBytes()));

        // Read private key from ASCII armored string
        PGPPrivateKey privateKey = readPrivateKey(new ByteArrayInputStream(privateKeyArmored.getBytes()));
    }

    private static String exportKey(PGPPublicKey key) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOut = new ArmoredOutputStream(out);
        key.encode(armoredOut);
        armoredOut.close();
        return out.toString();
    }

    private static String exportKey(PGPPrivateKey key) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOut = new ArmoredOutputStream(out);
        final byte[] encoded = key.getPrivateKeyDataPacket().getEncoded();
        armoredOut.write(encoded);
        armoredOut.close();
        return out.toString();
    }

    private static PGPPublicKey readPublicKey(ByteArrayInputStream in) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in), new BcKeyFingerprintCalculator());
        return pgpPub.getKeyRings().next().getPublicKey();
    }

    private static PGPPrivateKey readPrivateKey(ByteArrayInputStream in) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(in), new BcKeyFingerprintCalculator());
        PGPSecretKey secretKey = pgpSec.getKeyRings().next().getSecretKey();
        PBESecretKeyDecryptor decryptorFactory = null; // Implement as needed for encrypted keys
        return secretKey.extractPrivateKey(decryptorFactory);
    }
}
