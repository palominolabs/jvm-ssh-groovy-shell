package com.palominolabs.ssh.auth.publickey.rfc4253;

import com.google.common.io.BaseEncoding;
import com.google.common.io.Resources;
import com.palominolabs.ssh.auth.publickey.rsa.RsaPublicKeyMatcherFactoryTest;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import static com.google.common.io.Resources.getResource;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

public final class RsaSshPublicKeyParserTest {
    @Test
    public void testParseValidKey() throws IOException, InvalidKeySpecException {
        String[] chunks =
            Resources.toString(getResource(RsaPublicKeyMatcherFactoryTest.class, "rsa1.pub"), UTF_8).split(" ");
        byte[] bytes = BaseEncoding.base64().decode(chunks[1]);

        RSAPublicKey key = new RsaSshPublicKeyParser(bytes).getKey();

        assertEquals(new BigInteger("65537"), key.getPublicExponent());
        assertEquals(new BigInteger(
            "27679173740107051800604399652522847883587117239557177378544541890699251505571288795048579079765660286792511596146621782589040679877973810882435783313994503748393255613924122826862068608069317089328777316645487020243362970123613989271775304846563211128430829355349205874653495780499559657058025994818219715030951371452974614968387511646356998307813676166778382397605524622857929399449075377700152249256465252669347842580616508276793619630763300771813210436404128239279675457217765046021369448478717197912270485603345892056313526039388787296681305504184029135731917840368838154999322211043881505119264561688266440872681"),
            key.getModulus());
        assertEquals("RSA", key.getAlgorithm());
    }
}
