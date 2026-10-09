package com.example.trustshield.network

import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException

/**
 * "Is someone in the middle of this network?"
 *
 * A person-in-the-middle on a Wi-Fi network can answer DNS questions with a wrong address, show a sign-in page instead of the
 * real site, or present a forged certificate. We cannot see the attacker's packets (Android does not let apps read the ARP
 * table), but we can see the EFFECTS on three well-known sites and compare them with what a trusted, encrypted DNS service
 * (DNS-over-HTTPS) and the certificate authorities say:
 *
 *   1. DNS: does the network's answer for a public site point at a private or loopback address?
 *   2. Certificates: does the connection to a known site fail certificate checks, or present a certificate from an unknown issuer?
 *   3. Web pages: does a plain page that must answer "204 No Content" come back changed (a sign-in or redirect page)?
 *
 * The decision logic lives in [NetworkIntegrity] (pure functions, unit-tested); [NetworkChecker] only does the I/O.
 */
enum class NetLevel { SAFE, WARNING, DANGER, UNKNOWN }

data class NetFinding(val title: String, val detail: String, val level: NetLevel)

data class NetworkCheckResult(val level: NetLevel, val headline: String, val findings: List<NetFinding>)

object NetworkIntegrity {
    /** Certificate issuers (organisations) that issue for ordinary public sites. Anything else is worth a second look. */
    val KNOWN_PUBLIC_CA_ORGS = setOf(
        "google trust services", "google trust services llc", "digicert", "digicert inc", "let's encrypt", "internet security research group",
        "amazon", "sectigo", "sectigo limited", "comodo ca limited", "globalsign", "globalsign nv-sa", "godaddy.com, inc.", "the go daddy group",
        "microsoft corporation", "cloudflare, inc.", "entrust", "entrust, inc.", "ssl.com", "zerossl", "buypass as", "certum", "actalis s.p.a.",
        "identrust", "starfield technologies, inc.", "wikimedia foundation, inc.", "github, inc.", "apple inc.", "baltimore", "usertrust"
    )

    fun isNonRoutable(ip: String): Boolean {
        val parts = ip.trim().split(".")
        if (parts.size != 4) return ip.trim().startsWith("fe80") || ip.trim() == "::1" || ip.trim().startsWith("fc") || ip.trim().startsWith("fd")
        val n = parts.map { it.toIntOrNull() ?: return false }
        return n[0] == 0 || n[0] == 10 || n[0] == 127 || (n[0] == 169 && n[1] == 254) ||
            (n[0] == 172 && n[1] in 16..31) || (n[0] == 192 && n[1] == 168)
    }

    /** DNS: the network's answer for a public site must not be a private/loopback address. */
    fun judgeDns(domain: String, systemIps: List<String>, trustedIps: List<String>): NetFinding {
        if (systemIps.isEmpty()) return NetFinding("DNS for $domain", "The network did not answer.", NetLevel.UNKNOWN)
        val bad = systemIps.filter { isNonRoutable(it) }
        if (bad.isNotEmpty() && trustedIps.any { !isNonRoutable(it) }) {
            return NetFinding(
                "DNS for $domain",
                "This network says $domain is at ${bad.first()}, a private address. A trusted DNS service says it is on the public internet. " +
                    "Someone on this network is redirecting your traffic.",
                NetLevel.DANGER
            )
        }
        return NetFinding("DNS for $domain", "The answer looks normal.", NetLevel.SAFE)
    }

    /** Certificates: a connection that fails verification, or an issuer that is not a public authority. */
    fun judgeCertificate(host: String, issuerOrg: String?, handshakeError: String?, reached: Boolean): NetFinding {
        if (handshakeError != null) {
            return NetFinding(
                "Padlock for $host",
                "The secure connection to $host was refused because its certificate could not be verified ($handshakeError). " +
                    "A forged certificate means someone is intercepting the connection.",
                NetLevel.DANGER
            )
        }
        if (!reached) return NetFinding("Padlock for $host", "Could not connect.", NetLevel.UNKNOWN)
        val issuer = issuerOrg?.trim()?.lowercase().orEmpty()
        if (issuer.isEmpty() || KNOWN_PUBLIC_CA_ORGS.none { issuer.contains(it) }) {
            return NetFinding(
                "Padlock for $host",
                "The certificate was issued by \"${issuerOrg ?: "an unknown authority"}\", not a public one. " +
                    "This network may be inspecting encrypted traffic (common on workplace networks, also used by attackers).",
                NetLevel.WARNING
            )
        }
        return NetFinding("Padlock for $host", "Valid certificate from ${issuerOrg}.", NetLevel.SAFE)
    }

    /** The connectivity-check page must answer 204 with no body; anything else means the network rewrote the page. */
    fun judgeWebPage(responseCode: Int?, bodyLength: Int): NetFinding = when {
        responseCode == null -> NetFinding("Web page check", "Could not connect.", NetLevel.UNKNOWN)
        responseCode == 204 && bodyLength == 0 -> NetFinding("Web page check", "Plain web pages arrive unchanged.", NetLevel.SAFE)
        else -> NetFinding(
            "Web page check",
            "A page that should be empty came back changed (code $responseCode). This network shows its own sign-in or redirect page, " +
                "which is how fake Wi-Fi hotspots collect passwords.",
            NetLevel.WARNING
        )
    }

    fun combine(findings: List<NetFinding>): NetworkCheckResult {
        val danger = findings.firstOrNull { it.level == NetLevel.DANGER }
        val warning = findings.firstOrNull { it.level == NetLevel.WARNING }
        val usable = findings.count { it.level != NetLevel.UNKNOWN }
        return when {
            danger != null -> NetworkCheckResult(NetLevel.DANGER, "This network looks unsafe. Do not log in or enter passwords.", findings)
            warning != null -> NetworkCheckResult(NetLevel.WARNING, "This network changes some traffic. Be careful with sensitive sites.", findings)
            usable == 0 -> NetworkCheckResult(NetLevel.UNKNOWN, "The check could not run. Are you online?", findings)
            else -> NetworkCheckResult(NetLevel.SAFE, "No sign of tampering on this network.", findings)
        }
    }

    /** "CN=GTS CA 1C3,O=Google Trust Services LLC,C=US" -> "Google Trust Services LLC" */
    fun organisationOf(distinguishedName: String): String? =
        Regex("""(?:^|,)\s*O=((?:\\,|[^,])+)""").find(distinguishedName)?.groupValues?.get(1)?.replace("\\,", ",")?.trim()

    /** Extracts the "Answer" addresses from a DNS-over-HTTPS JSON reply without needing a JSON library. */
    fun parseDohAddresses(json: String): List<String> =
        Regex(""""data"\s*:\s*"((?:\d{1,3}\.){3}\d{1,3})"""").findAll(json).map { it.groupValues[1] }.toList()
}

/** The part that talks to the network. Runs on a background thread; every step has a short timeout. */
class NetworkChecker {
    private val dnsDomains = listOf("google.com", "wikipedia.org", "cloudflare.com")
    private val certHosts = listOf("www.google.com", "github.com", "www.wikipedia.org")

    fun run(): NetworkCheckResult {
        val findings = mutableListOf<NetFinding>()
        for (domain in dnsDomains) findings += checkDns(domain)
        for (host in certHosts) findings += checkCertificate(host)
        findings += checkWebPage()
        return NetworkIntegrity.combine(findings)
    }

    private fun checkDns(domain: String): NetFinding {
        val system = try {
            InetAddress.getAllByName(domain).mapNotNull { it.hostAddress }.filter { !it.contains(":") }
        } catch (e: Exception) {
            emptyList()
        }
        val trusted = try {
            val conn = URL("https://cloudflare-dns.com/dns-query?name=$domain&type=A").openConnection() as HttpsURLConnection
            conn.connectTimeout = 4000
            conn.readTimeout = 4000
            conn.setRequestProperty("accept", "application/dns-json")
            conn.inputStream.bufferedReader().use { NetworkIntegrity.parseDohAddresses(it.readText()) }
        } catch (e: Exception) {
            emptyList()
        }
        return NetworkIntegrity.judgeDns(domain, system, trusted)
    }

    private fun checkCertificate(host: String): NetFinding {
        return try {
            val conn = URL("https://$host/").openConnection() as HttpsURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "HEAD"
            conn.connect()
            val leaf = conn.serverCertificates.firstOrNull() as? X509Certificate
            val issuer = leaf?.issuerX500Principal?.name?.let { NetworkIntegrity.organisationOf(it) }
            conn.disconnect()
            NetworkIntegrity.judgeCertificate(host, issuer, null, reached = true)
        } catch (e: SSLException) {
            NetworkIntegrity.judgeCertificate(host, null, e.javaClass.simpleName, reached = false)
        } catch (e: Exception) {
            NetworkIntegrity.judgeCertificate(host, null, null, reached = false)
        }
    }

    private fun checkWebPage(): NetFinding {
        return try {
            val conn = URL("http://connectivitycheck.gstatic.com/generate_204").openConnection() as HttpURLConnection
            conn.connectTimeout = 4000
            conn.readTimeout = 4000
            conn.instanceFollowRedirects = false
            val code = conn.responseCode
            val stream = if (code == 204) null else (if (code >= 400) conn.errorStream else conn.inputStream)
            val body = stream?.use { it.readBytes().size } ?: 0
            conn.disconnect()
            NetworkIntegrity.judgeWebPage(code, body)
        } catch (e: Exception) {
            NetworkIntegrity.judgeWebPage(null, 0)
        }
    }
}
