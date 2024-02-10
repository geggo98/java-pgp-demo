package de.schwetschke.demo;

import java.security.Security;

import de.schwetschke.demo.utils.BcPgpUtils;
import de.schwetschke.demo.utils.PasswordProtectedPgpKeyPair;

public class PgpBouncyCastleExample {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        final PasswordProtectedPgpKeyPair passwordProtectedPgpKeyPair = BcPgpUtils.generatePgpKeyPair("Test BouncyCastle <bouncycastle@schwetschke.de>");
        // Write public key to ASCII armored format to the file public-key.asc
        try (java.io.FileWriter fileWriter = new java.io.FileWriter("public-key-bc.asc")) {
            fileWriter.write(passwordProtectedPgpKeyPair.exportPublicKeyRing());
        }
        // Write private key to ASCII armored format to the file private-key.asc
        try (java.io.FileWriter fileWriter = new java.io.FileWriter("private-key-bc.asc")) {
            fileWriter.write(passwordProtectedPgpKeyPair.exportSecretKeyRing());
        }
        System.out.println("Passphrase for secret key: " + passwordProtectedPgpKeyPair.secretKeyPassphrase());
    }

}