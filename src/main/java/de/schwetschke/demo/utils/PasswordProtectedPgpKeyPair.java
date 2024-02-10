package de.schwetschke.demo.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public record PasswordProtectedPgpKeyPair(PGPPublicKeyRing publicKeyRing, PGPSecretKeyRing secretKeyRing, String secretKeyPassphrase) {
    public PasswordProtectedPgpKeyPair(PGPSecretKeyRing secretKeyRing, String secretKeyPassphrase) {
        this(extractPublicKeys(secretKeyRing), secretKeyRing, secretKeyPassphrase);
    }

    public List<PGPPublicKey> getPublicKeys() {
        final Iterator<PGPPublicKey> publicKeyIterator = publicKeyRing.getPublicKeys();
        return Stream
            .generate(() -> publicKeyIterator)
            .takeWhile(Iterator::hasNext)
            .map(Iterator::next)
            .toList();
    }

    public String exportPublicKeyRing() throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final OutputStream out = new ArmoredOutputStream(baos)) {
            publicKeyRing.encode(out);
        }
        baos.close();
        return baos.toString();
    }

    public String exportSecretKeyRing() throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final OutputStream out = new ArmoredOutputStream(baos)) {
            secretKeyRing.encode(out);
        }
        baos.close();
        return baos.toString();
    }

    private static PGPPublicKeyRing extractPublicKeys(PGPSecretKeyRing secretKeyRing) {
        final Iterator<PGPPublicKey> publicKeyIterator = secretKeyRing.getPublicKeys();
        final List<PGPPublicKey> publicKeysList = Stream
            .generate(() -> publicKeyIterator)
            .takeWhile(Iterator::hasNext)
            .map(Iterator::next)
            .toList();
        return new PGPPublicKeyRing(publicKeysList);
    }
}
