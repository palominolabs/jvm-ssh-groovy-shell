package com.palominolabs.ssh.auth.publickey.rsa;

import com.google.common.io.BaseEncoding;
import com.google.common.io.Resources;
import com.palominolabs.ssh.auth.publickey.PublicKeyMatcher;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

public final class SshRsaPublicKeyLoaderTest {
    @Test
    public void testParseValidLine() throws IOException {
        PublicKeyMatcher key = getRsaKey(Resources.getResource(getClass(), "rsa1.pub"));

        RSAPublicKey publicKey = ((RsaPublicKeyMatcher) key).getKey();
        assertEquals(new BigInteger("65537"), publicKey.getPublicExponent());
        assertEquals(new BigInteger(
            "27679173740107051800604399652522847883587117239557177378544541890699251505571288795048579079765660286792511596146621782589040679877973810882435783313994503748393255613924122826862068608069317089328777316645487020243362970123613989271775304846563211128430829355349205874653495780499559657058025994818219715030951371452974614968387511646356998307813676166778382397605524622857929399449075377700152249256465252669347842580616508276793619630763300771813210436404128239279675457217765046021369448478717197912270485603345892056313526039388787296681305504184029135731917840368838154999322211043881505119264561688266440872681"),
            publicKey.getModulus());
    }

    static PublicKeyMatcher getRsaKey(URL keyUrl) throws IOException {
        String[] chunks = Resources.toString(keyUrl, UTF_8).split(" ");
        String base64 = chunks[1];

        byte[] bytes = BaseEncoding.base64().decode(base64);

        return new SshRsaPublicKeyLoader().buildMatcher(bytes, chunks[1]);
    }
}
