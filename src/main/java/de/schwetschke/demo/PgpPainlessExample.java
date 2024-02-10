package de.schwetschke.demo;

import static java.lang.StringTemplate.STR;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.UUID;
import java.util.stream.StreamSupport;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

import de.schwetschke.demo.utils.BcPgpUtils;
import de.schwetschke.demo.utils.PasswordProtectedPgpKeyPair;

public class PgpPainlessExample {
    public static void main(String[] args) throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        final String userId = "Test PgPainless <pgpainless@schwetschke.de>";

        // EdDSA primary key with EdDSA signing- and XDH encryption subkeys
        final String password = UUID.randomUUID().toString();
        final PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
            .modernKeyRing(userId, password);
        final PasswordProtectedPgpKeyPair passwordProtectedPgpKeyPair = new PasswordProtectedPgpKeyPair(secretKeys, password);
        // Write public key to ASCII armored format to the file public-key.asc
        try (java.io.FileWriter fileWriter = new java.io.FileWriter("public-key.pgpainless.asc")) {
            fileWriter.write(passwordProtectedPgpKeyPair.exportPublicKeyRing());
        }
        // Write private key to ASCII armored format to the file private-key.asc
        try (java.io.FileWriter fileWriter = new java.io.FileWriter("private-key.pgpainless.asc")) {
            fileWriter.write(passwordProtectedPgpKeyPair.exportSecretKeyRing());
        }
        System.out.println("Passphrase for secret key: " + passwordProtectedPgpKeyPair.secretKeyPassphrase());

        final String secretText = "This is a secret message: Lore ipsum dolor sit amet.";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (final EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
            .onOutputStream(bos)
            .withOptions(ProducerOptions.encrypt(
                EncryptionOptions
                    .encryptCommunications()
                    .addRecipient(passwordProtectedPgpKeyPair.publicKeyRing()))
                .setAsciiArmor(false)
                .overrideCompressionAlgorithm(CompressionAlgorithm.UNCOMPRESSED))) {
            encryptionStream.write(secretText.getBytes(StandardCharsets.UTF_8));
        }
        try (FileOutputStream fileOutputStream = new FileOutputStream("secret-message.pgpainless.pgp")) {
            bos.writeTo(fileOutputStream);
        }

        final ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        String decryptedText;
        try(final DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
            .onInputStream(bis)
            .withOptions(
                ConsumerOptions.get()
                    .addDecryptionKey(passwordProtectedPgpKeyPair.secretKeyRing(), SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(passwordProtectedPgpKeyPair.secretKeyPassphrase()))))){
            final byte[] decrypted = Streams.readAll(decryptionStream);
            decryptedText = new String(decrypted, StandardCharsets.UTF_8);
        }
        System.out.println("Decrypted message: " + decryptedText);
    }
}
