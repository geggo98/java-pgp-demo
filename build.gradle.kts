plugins {
    id("java")
}

group = "de.schwetschke.demo"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    // https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk18on
    implementation("org.bouncycastle:bcprov-jdk18on:1.77")

    // https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk18on
    implementation("org.bouncycastle:bcpg-jdk18on:1.77")

    // https://mvnrepository.com/artifact/name.neuhalfen.projects.crypto.bouncycastle.openpgp/bouncy-gpg
    implementation("name.neuhalfen.projects.crypto.bouncycastle.openpgp:bouncy-gpg:2.3.0")

    // https://mvnrepository.com/artifact/org.pgpainless/pgpainless-core
    implementation("org.pgpainless:pgpainless-core:1.6.6")

    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}