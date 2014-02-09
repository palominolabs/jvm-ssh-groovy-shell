package com.palominolabs.ssh.auth.publickey.rfc4253;

import com.google.common.io.BaseEncoding;
import com.google.common.io.Resources;
import com.palominolabs.ssh.auth.publickey.dsa.DsaPublicKeyMatcherFactoryTest;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import static com.google.common.io.Resources.getResource;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;

public final class DsaSshPublicKeyParserTest {
    @Test
    public void testParseValidKey() throws IOException, InvalidKeySpecException {
        String[] chunks =
            Resources.toString(getResource(DsaPublicKeyMatcherFactoryTest.class, "dsa1.pub"), UTF_8).split(" ");
        byte[] bytes = BaseEncoding.base64().decode(chunks[1]);

        DSAPublicKey key = new DsaSshPublicKeyParser(bytes).getKey();

        assertEquals(new BigInteger(
            "19243293393629472680101195172811065621541133739983495485464409305213695636136546201296069469801275547885234663376246515754854830504065379514297947315218078755563633063448817268790336318680074288423642113762022718208286220435476487086939745746007597423930974265532105923541694052881038362381112297302909866791"),
            key.getY());
        assertEquals(new BigInteger(
            "141540177250299575203409317531960105681920855160429040016859638265487307321729536068685059990256418289212062487493063056644903441756692040977350398345034535604141184842461808540689753175943984495293694655605208290731147338796305208765057884191860082044297661171444943969366180926056906842817679915972030722053"),
            key.getParams().getP());
        assertEquals(new BigInteger(
            "46887515648774416508024875968742533826778451490302210254766020436110510995721460509613190241189769660148202050490984963477640708710842181007562821740569806451429776426913614804332776809801906323682066633230206514681361515336630979812334270542881934298360274401509727012680464082281689791880811924483143081839"),
            key.getParams().getG());
        assertEquals(new BigInteger("1035488456611306799546464428508766441880259252349"), key.getParams().getQ());
        assertEquals("DSA", key.getAlgorithm());
    }
}
