package de.schwetschke.demo;

import java.security.Security;
import java.util.UUID;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;

public class BouncyGpgLibraryExample {
    public static void main(String[] args) throws Exception {
        final String secretKeyPassphrase = UUID.randomUUID().toString();

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        InMemoryKeyring keyring = KeyringConfigs.forGpgExportedKeys((keyId) -> secretKeyPassphrase.toCharArray());
        
    }
}

