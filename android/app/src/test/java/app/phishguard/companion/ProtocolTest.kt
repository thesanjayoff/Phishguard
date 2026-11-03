package app.phishguard.companion

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtocolTest {
    @Test fun lanAndLoopbackHttpServersAreAllowed() {
        for (u in listOf("http://192.168.1.20:8765", "http://10.0.2.2:8765", "http://172.16.5.4", "http://172.31.255.1", "http://127.0.0.1:8765",
            "http://localhost:8765", "http://mypc.local:8765", "http://100.101.102.103:8765", "http://pc.tail1234.ts.net:8765", "http://[::1]:8765")) {
            assertTrue(u, Protocol.isAllowedServer(u))
        }
    }

    @Test fun publicHttpServersAndOddInputsAreRefused() {
        for (u in listOf("http://example.com", "http://8.8.8.8", "http://172.32.0.1", "http://172.15.0.1", "http://192.169.1.1", "http://100.128.0.1",
            "ftp://192.168.1.20", "192.168.1.20", "", "http://user:pw@192.168.1.20", "http://192.168.1.256", "http://fcexample.com", "javascript:alert(1)")) {
            assertFalse(u, Protocol.isAllowedServer(u))
        }
    }

    @Test fun httpsIsAllowedAnywhere() {
        assertTrue(Protocol.isAllowedServer("https://phishguard.example.com"))
    }

    @Test fun normalizeStripsTrailingSlashAndSpaces() {
        assertEquals("http://192.168.1.20:8765", Protocol.normalizeBase(" http://192.168.1.20:8765/ "))
    }

    @Test fun smsIdIsStableAndDependsOnEveryField() {
        val a = Sms("VM-HDFCBK", "hello", 1_700_000_000_000)
        assertEquals(Protocol.smsId(a), Protocol.smsId(a.copy()))
        assertTrue(Protocol.smsId(a).startsWith("a-") && Protocol.smsId(a).length == 34)
        assertTrue(Protocol.smsId(a) != Protocol.smsId(a.copy(body = "hello!")))
        assertTrue(Protocol.smsId(a) != Protocol.smsId(a.copy(sender = "VM-HDFCBX")))
        assertTrue(Protocol.smsId(a) != Protocol.smsId(a.copy(epochMs = a.epochMs + 1)))
    }

    @Test fun smsJsonMatchesTheServerSchemaAndCapsLength() {
        val j = Protocol.smsJson(Sms("S".repeat(500), "b".repeat(50_000), 1_700_000_000_000))
        assertEquals(100, j.getString("sender").length)
        assertEquals(20_000, j.getString("body").length)
        assertEquals("2023-11-14T22:13:20Z", j.getString("received_at"))
        assertEquals(setOf("sender", "body", "received_at", "id"), j.keys().asSequence().toSet())
    }

    @Test fun batchesAreCappedAtTheServerLimit() {
        val items = (1..150).map { Sms("A", "m$it", it.toLong()) }
        assertEquals(Protocol.MAX_BATCH, Protocol.batchJson(items).getJSONArray("messages").length())
    }

    @Test fun shareJsonOmitsEmptyTitle() {
        assertFalse(Protocol.shareJson("check this", "  ").has("title"))
        assertEquals("Subject", Protocol.shareJson("check this", "Subject").getString("title"))
    }

    @Test fun summariseHandlesVerdictsAndGarbage() {
        val ok = JSONObject().put("label", "phishing").put("score", 93).put("summary", "Likely phishing: lookalike domain.").toString()
        assertEquals("PHISHING (93/100)\nLikely phishing: lookalike domain.", Protocol.summarise(ok))
        assertTrue(Protocol.summarise("<html>").contains("not in the expected format"))
    }
}
