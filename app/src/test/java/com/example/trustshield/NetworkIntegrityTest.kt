package com.example.trustshield

import com.example.trustshield.network.NetFinding
import com.example.trustshield.network.NetLevel
import com.example.trustshield.network.NetworkIntegrity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkIntegrityTest {

    @Test
    fun privateAndLoopbackAddressesAreNotRoutable() {
        listOf("10.1.2.3", "192.168.0.10", "172.16.5.5", "172.31.255.1", "127.0.0.1", "169.254.1.1", "0.0.0.0").forEach {
            assertTrue(it, NetworkIntegrity.isNonRoutable(it))
        }
        listOf("8.8.8.8", "142.250.80.46", "172.15.0.1", "172.32.0.1", "100.64.1.1").forEach {
            assertFalse(it, NetworkIntegrity.isNonRoutable(it))
        }
    }

    @Test
    fun dnsAnswerPointingAtAPrivateAddressWhileTheTrustedServiceSaysPublicIsDanger() {
        val f = NetworkIntegrity.judgeDns("google.com", listOf("192.168.1.66"), listOf("142.250.80.46"))
        assertEquals(NetLevel.DANGER, f.level)
    }

    @Test
    fun differentPublicAddressesAreNormalForLargeSites() {
        val f = NetworkIntegrity.judgeDns("google.com", listOf("142.250.1.1"), listOf("142.250.80.46"))
        assertEquals(NetLevel.SAFE, f.level)
    }

    @Test
    fun noDnsAnswerIsUnknownNotDanger() {
        assertEquals(NetLevel.UNKNOWN, NetworkIntegrity.judgeDns("google.com", emptyList(), listOf("1.2.3.4")).level)
    }

    @Test
    fun aRejectedCertificateIsDangerAndAnUnknownIssuerIsAWarning() {
        assertEquals(NetLevel.DANGER, NetworkIntegrity.judgeCertificate("github.com", null, "SSLHandshakeException", false).level)
        assertEquals(NetLevel.WARNING, NetworkIntegrity.judgeCertificate("github.com", "Zscaler Inc.", null, true).level)
        assertEquals(NetLevel.SAFE, NetworkIntegrity.judgeCertificate("github.com", "DigiCert Inc", null, true).level)
        assertEquals(NetLevel.SAFE, NetworkIntegrity.judgeCertificate("www.google.com", "Google Trust Services", null, true).level)
        assertEquals(NetLevel.UNKNOWN, NetworkIntegrity.judgeCertificate("github.com", null, null, false).level)
    }

    @Test
    fun aChangedConnectivityPageIsAWarning() {
        assertEquals(NetLevel.SAFE, NetworkIntegrity.judgeWebPage(204, 0).level)
        assertEquals(NetLevel.WARNING, NetworkIntegrity.judgeWebPage(200, 1500).level)
        assertEquals(NetLevel.WARNING, NetworkIntegrity.judgeWebPage(302, 0).level)
        assertEquals(NetLevel.UNKNOWN, NetworkIntegrity.judgeWebPage(null, 0).level)
    }

    @Test
    fun theWorstFindingDecidesTheHeadline() {
        val safe = NetFinding("a", "ok", NetLevel.SAFE)
        val warn = NetFinding("b", "hmm", NetLevel.WARNING)
        val danger = NetFinding("c", "bad", NetLevel.DANGER)
        val unknown = NetFinding("d", "?", NetLevel.UNKNOWN)
        assertEquals(NetLevel.SAFE, NetworkIntegrity.combine(listOf(safe, unknown)).level)
        assertEquals(NetLevel.WARNING, NetworkIntegrity.combine(listOf(safe, warn)).level)
        assertEquals(NetLevel.DANGER, NetworkIntegrity.combine(listOf(warn, danger, safe)).level)
        assertEquals(NetLevel.UNKNOWN, NetworkIntegrity.combine(listOf(unknown, unknown)).level)
    }

    @Test
    fun issuerOrganisationAndDohAnswersAreParsed() {
        assertEquals("Google Trust Services LLC", NetworkIntegrity.organisationOf("CN=GTS CA 1C3,O=Google Trust Services LLC,C=US"))
        assertEquals("Let's Encrypt", NetworkIntegrity.organisationOf("CN=R3,O=Let's Encrypt,C=US"))
        assertEquals(null, NetworkIntegrity.organisationOf("CN=only-a-common-name"))
        val json = """{"Status":0,"Answer":[{"name":"google.com","type":1,"TTL":30,"data":"142.250.80.46"},{"name":"google.com","type":1,"TTL":30,"data":"142.250.80.47"}]}"""
        assertEquals(listOf("142.250.80.46", "142.250.80.47"), NetworkIntegrity.parseDohAddresses(json))
    }
}
