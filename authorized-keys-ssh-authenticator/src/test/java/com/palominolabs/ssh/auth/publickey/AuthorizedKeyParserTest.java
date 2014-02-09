package com.palominolabs.ssh.auth.publickey;

import com.google.common.io.BaseEncoding;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public final class AuthorizedKeyParserTest {

    private AuthorizedKeyParser authorizedKeyParser;

    @Before
    public void setUp() {
        authorizedKeyParser =
            new AuthorizedKeyParser(
            );
    }

    @Test
    public void testParseValidLine() throws IOException {
        List<AuthorizedKey> keys = getKeys("dummy aaa comment1\ndummy bbb comment2");

        assertEquals(2, keys.size());

        assertKey(keys.get(0), "aaa", "comment1");
        assertKey(keys.get(1), "bbb", "comment2");
    }

    @Test
    public void testSkipsInvalidLines() throws IOException {
        List<AuthorizedKey> keys = getKeys("asdf\ndummy bbb comment2\nfoo");

        assertEquals(1, keys.size());

        assertKey(keys.get(0), "bbb", "comment2");
    }

    @Test
    public void testSkipsCommentLines() throws IOException {
        List<AuthorizedKey> keys = getKeys("# foo\ndummy bbb comment2");

        assertEquals(1, keys.size());

        assertKey(keys.get(0), "bbb", "comment2");
    }

    private void assertKey(AuthorizedKey key, String data, String comment) {
        assertEquals("dummy", key.getType());
        assertArrayEquals(BaseEncoding.base64().decode(data), key.getData());
        assertEquals(comment, key.getComment());
    }

    private List<AuthorizedKey> getKeys(String content) throws IOException {
        ByteArrayInputStream is =
            new ByteArrayInputStream(content.getBytes(UTF_8));

        return newArrayList(authorizedKeyParser.parse(is));
    }
}
