package burp

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.utilities.URLEncoding
import java.io.File
import java.util.regex.Pattern
import kotlin.collections.listOf


class ReqMutator internal constructor() {

    companion object {
        internal var protocolBasedMutations: SettingsBox = SettingsBox()
        internal var pathBasedMutations: SettingsBox = SettingsBox()
        internal var headerBasedMutations: SettingsBox = SettingsBox()
        internal var smuggleBasedMutations: SettingsBox = SettingsBox()
        internal var paramMinerMutations: SettingsBox = SettingsBox()
    }

    init {
        // Protocol based mutations
        protocolBasedMutations.register("HvsX", true, "/%20X vs /%20H")
        protocolBasedMutations.register("HTTP/13.37", true, "/%20HTTP/1.1%0D%0AX:%20x vs /%20HTTP/13.37%0D%0AX:%20x")
        protocolBasedMutations.register("http/0.9", true, "")
        protocolBasedMutations.register("http/null", false, "")
        protocolBasedMutations.register("split", true, "End request without host header")
        //protocolBasedMutations.register("basic...", false, "Doesn't work")
        protocolBasedMutations.register("httx", true, "")
        protocolBasedMutations.register("tunnel", true, "")
        protocolBasedMutations.register("expect-tunnel", true, "") //Worked on target's we already knew about. still cool
        //protocolBasedMutations.register("expect-range-tunnel", true) //TODO Is this worth implementing?
        //protocolBasedMutations.register("http/1.0", true, "") //Failed terribly
        //protocolBasedMutations.register("HTTP/13.37 - akamai", true, "") //Fails
        //protocolBasedMutations.register("HTTP//13.37", true, "") //Failed
        protocolBasedMutations.register("split0.9", false, "")
        protocolBasedMutations.register("javaHTTP/13.37",true, "")
        protocolBasedMutations.register("bareLF", true, "Bare LF (no CR) injection with HTTP/13.37 -> 505")
        protocolBasedMutations.register("bareCR", true, "Bare CR (no LF) injection with HTTP/13.37 -> 505")
        protocolBasedMutations.register("overlongCRLF", true, "Overlong UTF-8 CRLF (%c0%8d%c0%8a) with HTTP/13.37 -> 505 on decoders that accept invalid UTF-8")
        protocolBasedMutations.register("unicodeLineSep", true, "U+2028 LINE SEPARATOR (%e2%80%a8) with HTTP/13.37 -> 505 on JS-runtime parsers (Node.js, Bun, Deno) that treat U+2028 as line terminator")

        // Header based mutations
        headerBasedMutations.register("dupeHost", true, "")
        headerBasedMutations.register("dupeHostSpace", true, "")
        headerBasedMutations.register("dupeHostTab", true, "")
        headerBasedMutations.register("notChunked", true, "")
        headerBasedMutations.register("missingHost", true, "From https://portswigger.net/research/making-http-header-injection-critical-via-response-queue-poisoning")
        headerBasedMutations.register("expect", true, "")
        headerBasedMutations.register("teTimeout", true, "")
        headerBasedMutations.register("clTimeout", true, "")
        headerBasedMutations.register("range-valid", true,"")
        headerBasedMutations.register("range-invalid", true,"")
        headerBasedMutations.register("max-forwardsTimeout", true,"")
        headerBasedMutations.register("ifMatch", true, "")
        headerBasedMutations.register("responseHeaderInjection", false, "") //very FP prone
        headerBasedMutations.register("clNoHost", true, "")
        headerBasedMutations.register("teUserAgentTimeout", true, "")
        headerBasedMutations.register("headerSpace", true, "")
        headerBasedMutations.register("authorization",  true, "")
        headerBasedMutations.register("setCookie",  true, "")
        headerBasedMutations.register("upgrade", true, "")
        headerBasedMutations.register("upgradeNoConnection", true, "")
        headerBasedMutations.register("expect-100", true, "")
        headerBasedMutations.register("expect-100space", true, "")
        headerBasedMutations.register("expect-100tab", true, "")
        headerBasedMutations.register("expect-100wrap", true, "")
        headerBasedMutations.register("expect-100body", true, "")
        headerBasedMutations.register("connection", true, "")
        for (i in 0 .. 4) {
            headerBasedMutations.register("max-forwardsTrace$i", true, "")
            headerBasedMutations.register("max-forwardsOptions$i", true, "")
        }
        headerBasedMutations.register("badHeaderName", false, "")
        headerBasedMutations.register("clinvalid", true, "")
        headerBasedMutations.register("accept", true, "")
        headerBasedMutations.register("headerTab", true, "")
        headerBasedMutations.register("headerWrap", true, "")
        headerBasedMutations.register("contentType-invalid", true, "")
        headerBasedMutations.register("expectHEAD", true, "")
        headerBasedMutations.register("range-multi", true, "")
        //mutations.register("headerSemiColon", false, "") Extremely FP prone... A lot of servers just reject ";" full stop
        headerBasedMutations.register("negotiate-valid", true, "")
        headerBasedMutations.register("ifNoneMatch", true, "")
        headerBasedMutations.register("ifModifiedSince", true, "")
        headerBasedMutations.register("onlyIfCached", true, "Cache-Control: only-if-cached -> 504 (RFC 9111 §5.2.1.7)")
        headerBasedMutations.register("ifUnmodifiedSince", true, "If-Unmodified-Since with past date -> 412 (RFC 9110 §13.1.4)")
        headerBasedMutations.register("dualContentLength", true, "Two conflicting Content-Length headers -> 400 (RFC 9110 §8.6)")
        headerBasedMutations.register("earlyData", true, "Early-Data: 1 -> 425 Too Early (RFC 8470 §5; TLS 1.3 0-RTT replay protection)")
        headerBasedMutations.register("clHuge", true, "Content-Length: 9999999999 -> 413 Content Too Large (exceeds server body-size limit immediately)")
        headerBasedMutations.register("bareLFExpect", true, "Bare LF (%0a, no CR) header injection: Expect: notright -> 417 (tests %0a-only parsing, distinct from request-line bareLF)")
        headerBasedMutations.register("hostInvalidPort", true, "Host: target:99999 (port > 65535) -> 400 Bad Request (RFC 9112 §3.2 invalid Host field value)")
        headerBasedMutations.register("optionsSmuggle", true, "Smuggle OPTIONS / -> 'Allow:' header concatenated into response (RFC 9110 §10.2.1). Universal: OPTIONS is enabled on virtually every server. Complements 'tunnel' which depends on TRACE being disabled")
        headerBasedMutations.register("connectionCloseAck", true, "Connection: close -> server acknowledges with 'Connection: close' in response (RFC 9112 §9.6). Universal: HTTP/1.1 connection-management is uniformly implemented. Tests close-acknowledgement code path via response-header reflection — distinct from existing 'connection' which injects Connection: Host to trigger 400")
        headerBasedMutations.register("viaLoop", true, "Via: 1.1 <self> -> 502 Bad Gateway when proxy detects own pseudonym in chain (RFC 9110 §7.6.3). 502 is currently uncovered; tests the intermediary layer rather than origin")

        // Path based mutations
        pathBasedMutations.register("robots", true, "Inspired by the CL.0 scan check")
        pathBasedMutations.register("sitemap", true, "Inspired by the CL.0 scan check")
        pathBasedMutations.register("favicon", true, "Inspired by the CL.0 scan check")
        pathBasedMutations.register("pathTraversal", true, "")

        //Smuggle based mutations?
        smuggleBasedMutations.register("CL.TE-body-timeout", true, "Inspired by CL.TE detection")
        smuggleBasedMutations.register("TE.CL-body-timeout", true, "Inspired by TE.CL detection")

        //TODO /%20HTTP/1.1%0d%0aX:%20x vs /%252e%252e%252f%20HTTP/1.1%0d%0aX:%20x



        //Could dynamically register a mutation for litterally every header in param-miner...
        // todo Create permutations additionally...
        this::class.java.getResourceAsStream("/headers")?.bufferedReader()?.lines()?.forEach {
                headerName -> paramMinerMutations.register("header|$headerName", true, "")
        }
    }

    fun getProbe(baseRequest: HttpRequest, technique: String): Payload {

        var basePath = ""

        //Get the base path...
        if (Utilities.globalSettings.getBoolean("maintain path")) {
            basePath = baseRequest.pathWithoutQuery().replaceFirst("/", "")
        }

        if  (Utilities.globalSettings.getBoolean("Enable path override")) {
            basePath = Utilities.globalSettings.getString("path override").replaceFirst("/", "") //remove / prefix if there
        }

        val payload: Payload = Payload()

        payload.name = technique

        if (technique.startsWith("header|") && Utilities.globalSettings.getBoolean("Enable fallback diff")) {
            var headerName = technique.split("|")[1]
            if (headerName[0].isLowerCase()) {headerName = headerName[0].toString().uppercase() + headerName.substring(1)} //uppercase the first letter of headers to be more... compliant...
            val endOfheaderName = headerName.substring(1)
            val encodedFirstChar = String.format("%%%02x", headerName[0].toByte()) //URL ENCODE the first byte
            payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a$encodedFirstChar${endOfheaderName.replaceFirst(headerName.get(0).toString(), "z")}:%20nottherightvalue%0d%0aX:%20x")
            payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a$encodedFirstChar$endOfheaderName:%20nottherightvalue%0d%0aX:%20x")
            payload.expectedResponseMatches = listOf() //Nothing expected... only works for Diffing...
        }

        //Why are some chars in header names URL encoded? Because Akamai... nginx will decode them so... I think it's okay!
        when (technique) {
            "HvsX" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20X")
                payload.probeRequest = baseRequest.withPath("/$basePath%20H")
                payload.expectedResponseMatches = listOf("400 Bad Request")
                //todo add payload.potentialBadChar to allow dynamic follow-up that tries just that char without CRLF...
            }
            "HTTP/13.37" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/13.37%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("505 HTTP Version Not Supported")
            }
            "HTTP/13.37 - akamai" -> { //Failed
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%e5%98%8d%e5%98%8aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/13.37%e5%98%8d%e5%98%8aX:%20x")
                payload.expectedResponseMatches = listOf("505 HTTP Version Not Supported")
            }
            "HTTP//13.37" -> { // the "noramlize" in nginx will compress adjacent slashes... SO this would be valid only after noramalization I think...
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/%2f1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/%2f13.37%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("505 HTTP Version Not Supported")
            }
            "notChunked" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%54zansfer-Encoding:%20notchunked%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%54ransfer-Encoding:%20notchunked%0d%0aFoo:%20bar")
                payload.expectedResponseMatches = listOf("501 Not Implemented")
            }
            "dupeHost" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0D%0A%48xst:%20x%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0D%0A%48ost:%20x%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "dupeHostSpace" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0D%0A%48xst%20:%20x%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0D%0A%48ost%20:%20x%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "dupeHostTab" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0D%0A%48xst%09:%20x%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0D%0A%48ost%09:%20x%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "expect" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45zpect:%20notright%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45xpect:%20notright%0d%0aFoo:%20bar")
                payload.expectedResponseMatches = listOf("417 Expectation Failed")
            }
            "range-valid" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%52znge:%20bytes=0-10%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%52ange:%20bytes=0-10%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("206 Partial Content")
            }
            "range-invalid" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%52znge:%20bytes=0-abcde%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%52ange:%20bytes=0-abcde%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("416 Range Not Satisfiable")
            }
            "range-multi" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%52znge:%20bytes=1-2,4-5%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%52ange:%20bytes=1-2,4-5%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("Content-Type: multipart/")
            }
            "ifMatch" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%49z-Match:%20%22this-etag-is-definitely-wrong%22%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%49f-Match:%20%22this-etag-is-definitely-wrong%22%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("412 Precondition Failed")
            }
            "robots" -> {
                payload.benignRequest = baseRequest.withPath("/${basePath}robots.txtz%20HTTP/1.1%0d%0aFoo:%20bar") //Check that we don't just allow anything after the static path...
                payload.probeRequest = baseRequest.withPath("/${basePath}robots.txt%20HTTP/1.1%0d%0aFoo:%20bar")
                payload.expectedResponseMatches = listOf("llow: ", "200 OK")
            }
            "favicon" -> {
                payload.benignRequest = baseRequest.withPath("/${basePath}favicon.icoz%20HTTP/1.1%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/${basePath}favicon.ico%20HTTP/1.1%0d%0aFoo:%20bar")
                payload.expectedResponseMatches = listOf("Content-Type: image/", "200 OK")
            }
            "sitemap" -> {
                payload.benignRequest = baseRequest.withPath("/${basePath}sitemap.xmlz%20HTTP/1.1%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/${basePath}sitemap.xml%20HTTP/1.1%0d%0aFoo:%20bar")
                payload.expectedResponseMatches = listOf("Content-Type: application/xml", "200 OK")
            }
            "teTimeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%54zansfer-Encoding:%20chunked%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%54ransfer-Encoding:%20chunked%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "clTimeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43zntent-Length:%205%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43ontent-Length:%205%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "max-forwardsTimeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%4dzx-Forwards:%200%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%4dax-Forwards:%200%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "missingHost" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%48ost:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aGET%20%2f%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%48xst:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aGET%20%2f%20HTTP/1.1%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "responseHeaderInjection" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%2520HTTP/1.1%25201337%20No%2520response%2520headers%2520received%250d%250aX:%2520x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%201337%20No%20response%20headers%20received%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("1337 No response headers received")
            }
            "clNoHost" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%48ost:%20" + baseRequest.httpService().host() + "%0d%0a%43ontent-Length:%2012%0d%0a%0d%0ax=y")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%48xst:%20" + baseRequest.httpService().host() + "%0d%0a%43ontent-Length:%2012%0d%0a%0d%0ax=y")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "teUserAgentTimeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%54z:%20nothing%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%54e:%20nothing%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "headerSpace" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aFoo%20:%20bar")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "authorization" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%41zthorization:%20notcorrect%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%41uthorization:%20notcorrect%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("401 Unauthorized")
            }
            "setCookie" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%53zt-Cookie:%20notcorrect%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%53et-Cookie:%20notcorrect%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("455")
            }
            "http/0.9" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/0.9%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("1337 No response headers received")
            }
            "http/null" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("1337 No response headers received")
            }
            "upgrade" -> { //Still need to actually run this one fully.... Trying now, might wanna try without the connection header also...
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43onnection:%20zpgrade%0d%0azpgrade:%20websocket%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43onnection:%20upgrade%0d%0aUpgrade:%20websocket%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("101 Switching Protocols")
            }
            "upgradeNoConnection" -> { //Still need to actually run this one fully.... Trying now, might wanna try without the connection header also...
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0azpgrade:%20websocket%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aUpgrade:%20websocket%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("101 Switching Protocols")
            }
            "basic..." -> { //Trying to come up with a method of universal detection... DID NOT work well at all
                payload.benignRequest = baseRequest.withPath("/$basePath%2520%250d%250a")
                payload.probeRequest = baseRequest.withPath("/$basePath%20%0d%0a")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "httx" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTX/1.1%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            //Tunnelling detection... Since a lot of the nginx configurations are probably BLIND / regular tunnelling... then in theory we could do a "trigger tunnel" vs "not trigger tunnel" kinda thing...
            "tunnel" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%48xst:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aTRACE%20%2f%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%48ost:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aTRACE%20%2f%20HTTP/1.1%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("HTTP/1", "405 Not Allowed")
            }
            "expect-tunnel" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%48ost:%20" + baseRequest.httpService().host() + "%0d%0a%45xpect:%20100-Continue%0d%0a%0d%0aTRACE%20/%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%48ost:%20" + baseRequest.httpService().host() + "%0d%0a%45zpect:%20100-Continue%0d%0a%0d%0aTRACE%20/%20HTTP/1.1%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("HTTP/1", "405 Not Allowed")
            }
            "expect-100" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45zpect:%20100-continue%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45xpect:%20100-continue%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("100 Continue")
            }
            "expect-100space" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45zpect%20:%20100-continue%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45xpect%20:%20100-continue%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("100 Continue")
            }
            "expect-100tab" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45zpect%09:%20100-continue%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45xpect%09:%20100-continue%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("100 Continue")
            }
            "expect-100wrap" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45zpect:%20%0d%0a%20100-continue%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45xpect:%20%0d%0a%20100-continue%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("100 Continue")
            }
            "expect-100body" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45zpect:%20100-continue%0d%0aX:%20x").withBody("x=y").withMethod("POST")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45xpect:%20100-continue%0d%0aX:%20x").withBody("x=y").withMethod("POST")
                payload.expectedResponseMatches = listOf("100 Continue")
            }
            "connection" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43znnection:%20Host%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43onnection:%20Host%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            //TODO Should we NOT smuggle the max forwards header... and stead just see if adding max fowards breaks things?
            "max-forwardsTrace"+technique[technique.length - 1] -> {
                val maxForwardsValue = technique[technique.length - 1]
                val canary = Utilities.montoyaApi.utilities().randomUtils().randomString(8)
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%4dzx-Forwards:%20$maxForwardsValue%0d%0aX:%20x").withMethod("TRACE").withAddedHeader("Foo", canary)
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%4dax-Forwards:%20$maxForwardsValue%0d%0aX:%20x").withMethod("TRACE").withAddedHeader("Foo", canary)
                payload.expectedResponseMatches = listOf(canary)
            }
            "max-forwardsOptions"+technique[technique.length - 1] -> {
                val maxForwardsValue = technique[technique.length - 1]
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%4dzx-Forwards:%20$maxForwardsValue%0d%0aX:%20x").withMethod("OPTIONS")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%4dax-Forwards:%20$maxForwardsValue%0d%0aX:%20x").withMethod("OPTIONS")
                payload.expectedResponseMatches = listOf("200 OK")
            }
            "clinvalid" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43zntent-Length:%20Z%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43ontent-Length:%20Z%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "split" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "split0.9" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("NO_HEADERS")
            }
            "badHeaderName" -> { // Produces a lot of FP
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX%58:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX%5c:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "accept" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%41zcept:%20foo%2fbar%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%41ccept:%20foo%2fbar%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("406 Not Acceptable")
            }
            "headerTab" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX%09:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "headerWrap" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20%0d%0a%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "headerSemiColon" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX;%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "contentType-invalid" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43zntent-Type:%20foobar%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43ontent-Type:%20foobar%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("406 Not Acceptable")
            }
            "CL.TE-body-timeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%54zansfer-Encoding:%20chunked%0d%0aX:%20x").withBody("d\r\nx=y\r\n0\r\n\r\n").withMethod("POST")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%54ransfer-Encoding:%20chunked%0d%0aX:%20x").withBody("d\r\nx=y\r\n0\r\n\r\n").withMethod("POST")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "TE.CL-body-timeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43zntent-length:%2014%0d%0aX:%20x").withBody("3\r\nx=y\r\n0\r\n\r\n").withMethod("POST").withRemovedHeader("Content-Length").withAddedHeader("Transfer-Encoding", "chunked")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43ontent-length:%2014%0d%0aX:%20x").withBody("3\r\nx=y\r\n0\r\n\r\n").withMethod("POST").withRemovedHeader("Content-Length").withAddedHeader("Transfer-Encoding", "chunked")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "http/1.0" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%54ransfer-Encoding:%20chunkedd%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.0%0d%0a%54ransfer-Encoding:%20chunkedd%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("200 OK") //We expect the probe to return the same as the base request really. benign should trigger a 501 and probe should not (since TE isn't supported by HP1.0
            }
            "javaHTTP/13.37" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%c4%8d%c4%8aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/13.37%c4%8d%c4%8aX:%20x")
                payload.expectedResponseMatches = listOf("505 HTTP Version Not Supported")
            }
            "bareLF" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/13.37%0aX:%20x")
                payload.expectedResponseMatches = listOf("505 HTTP Version Not Supported")
            }
            "bareCR" -> {
                // Mirror of bareLF but with %0d (CR alone, no LF). RFC 9112 §2.2 requires
                // CRLF as the line terminator, but some parsers tolerate bare CR. If the
                // parser splits on %0d alone it sees HTTP/13.37 as the version -> 505.
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0dX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/13.37%0dX:%20x")
                payload.expectedResponseMatches = listOf("505 HTTP Version Not Supported")
            }
            "unicodeLineSep" -> {
                // U+2028 LINE SEPARATOR, encoded as UTF-8 %e2%80%a8. ECMAScript §7.3 lists
                // U+2028 as a LineTerminatorSequence; HTTP parsers that share character-class
                // tables with JS runtimes (Node.js llhttp, Bun's uWebSockets, Deno's hyper
                // bindings) may accept it as a line terminator. If the parser splits on it,
                // it sees HTTP/13.37 as the version → 505. Distinct from bareLF (U+000A),
                // bareCR (U+000D), overlongCRLF (invalid UTF-8), and javaHTTP/13.37
                // (U+010D/010A remap) — each targets a different non-standard terminator
                // interpretation in a different class of HTTP implementation.
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%e2%80%a8X:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/13.37%e2%80%a8X:%20x")
                payload.expectedResponseMatches = listOf("505 HTTP Version Not Supported")
            }
            "overlongCRLF" -> {
                // %c0%8d = overlong UTF-8 encoding of U+000D (CR); %c0%8a = overlong of
                // U+000A (LF). Both are invalid UTF-8 but some lenient decoders (older
                // PHP, certain Java containers, some WASM runtimes) normalise them to
                // their ASCII counterparts before parsing the request line. If so, the
                // decoder sees HTTP/13.37 as the version and returns 505. Distinct from
                // javaHTTP/13.37 which uses valid Unicode chars (%c4%8d%c4%8a / U+010D,
                // U+010A) that only specific JVM HTTP implementations remap.
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%c0%8d%c0%8aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/13.37%c0%8d%c0%8aX:%20x")
                payload.expectedResponseMatches = listOf("505 HTTP Version Not Supported")
            }
            "expectHEAD" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45zpect:%20100-continue%0d%0a%43ontent-Length:%207%0d%0aX:%20x").withMethod("HEAD")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45xpect:%20100-continue%0d%0a%43ontent-Length:%207%0d%0aX:%20x").withMethod("HEAD")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "pathTraversal" -> {
                if (basePath.endsWith("/")) { //not great...
                    payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                    payload.probeRequest = baseRequest.withPath("/$basePath%252e%252e%252f%20HTTP/1.1%0d%0aX:%20x")
                    payload.expectedResponseMatches = listOf("400 Bad Request")
                } else {
                    payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                    payload.probeRequest = baseRequest.withPath("/$basePath%252f%252e%252e%252f%20HTTP/1.1%0d%0aX:%20x")
                    payload.expectedResponseMatches = listOf("400 Bad Request")
                }
            }
            "negotiate-valid" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%4exgotiate:%20trans%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%4eegotiate:%20trans%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("300 Multiple Choices")
            }
            "ifNoneMatch" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%49z-None-Match:%20*%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%49f-None-Match:%20*%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("304 Not Modified")
            }
            "ifModifiedSince" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%49z-Modified-Since:%20Sat,%2001%20Jan%202050%2000%3a00%3a00%20GMT%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%49f-Modified-Since:%20Sat,%2001%20Jan%202050%2000%3a00%3a00%20GMT%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("304 Not Modified")
            }
            "onlyIfCached" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43zche-Control:%20only-if-cached%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43ache-Control:%20only-if-cached%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("504 Gateway Timeout")
            }
            "ifUnmodifiedSince" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%49z-Unmodified-Since:%20Mon,%2001%20Jan%201990%2000%3a00%3a00%20GMT%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%49f-Unmodified-Since:%20Mon,%2001%20Jan%201990%2000%3a00%3a00%20GMT%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("412 Precondition Failed")
            }
            "dualContentLength" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43zntent-Length:%201%0d%0a%43zntent-Length:%202%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43ontent-Length:%201%0d%0a%43ontent-Length:%202%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "earlyData" -> {
                // %45 = E; second char a->z for benign. RFC 8470 §5: servers that reject
                // TLS 1.3 0-RTT early data to prevent replays MUST return 425 Too Early.
                // 425 is one of the rarest status codes in production, so FP rate is
                // near-zero. Fires on nginx 1.15+, many CDNs, and replay-sensitive APIs.
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45zrly-Data:%201%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%45arly-Data:%201%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("425 Too Early")
            }
            "clHuge" -> {
                // %43 = C; second char o->z for benign. Claiming a multi-GB body exceeds
                // server body-size limits (e.g. nginx client_max_body_size) and triggers
                // 413 immediately — no body is sent, so no timeout. Distinct from clTimeout
                // (small CL waits for body) and clinvalid (non-numeric value -> 400).
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43zntent-Length:%209999999999%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43ontent-Length:%209999999999%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("413")
            }
            "hostInvalidPort" -> {
                // %48 = H; second char o->x for benign (Hxst is unknown). RFC 9112 §3.2:
                // the Host field-value must be a valid uri-host; port 99999 exceeds the
                // 0-65535 range and is structurally invalid. A conformant server MUST
                // return 400 Bad Request. Distinct from dupeHost (valid value causing
                // collision) — this is a single Host field with an invalid value.
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%48xst:%20" + baseRequest.httpService().host() + "%3a99999%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%48ost:%20" + baseRequest.httpService().host() + "%3a99999%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "bareLFExpect" -> {
                // Tests whether the server's header parser accepts bare LF (%0a, no CR) as a
                // line terminator — distinct from the request-line bareLF technique. RFC 9112
                // §2.2 forbids bare LF in requests, but lenient parsers may accept it in headers.
                // Both benign and probe use %0a separators; only the header name differs.
                // If bare-LF injection works AND Expect is processed -> 417.
                // %45 = E; second char x->z for benign.
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0a%45zpect:%20notright%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0a%45xpect:%20notright%0aX:%20x")
                payload.expectedResponseMatches = listOf("417 Expectation Failed")
            }
            "optionsSmuggle" -> {
                // Smuggle OPTIONS / behind the original request. RFC 9110 §10.2.1 mandates
                // that conformant servers respond to OPTIONS with an Allow: header listing
                // supported methods. If header smuggling concatenates the smuggled response
                // into our response stream (same upstream mechanic as 'tunnel'), the probe's
                // body contains "Allow: " while the benign (typo'd Host -> first request 400s,
                // smuggled never executes) does not. Universal: OPTIONS is enabled on virtually
                // every HTTP server, distinct from 'tunnel' which depends on TRACE being
                // disabled (a common but not universal default). Also fires on exact-match
                // (single specific token) where 'tunnel' tends to fall through to fallback diff.
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%48xst:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aOPTIONS%20%2f%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%48ost:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aOPTIONS%20%2f%20HTTP/1.1%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("Allow: ")
            }
            "connectionCloseAck" -> {
                // Connection: close in the request causes RFC 9112 §9.6-compliant servers to
                // acknowledge with Connection: close in the response (and close the underlying
                // TCP connection afterwards). Tests connection-management state via response-
                // header reflection — a code path none of the existing techniques exercise.
                // The existing 'connection' technique injects Connection: Host to trigger 400;
                // this one is the *successful* close-acknowledgement path.
                //   - benign: typo'd ('Cznnection') -> server doesn't see it, default
                //     keep-alive, response omits Connection: close
                //   - probe: valid Connection: close -> server reflects with Connection: close
                // Caveat: where the outgoing request already carries Connection: close, both
                // sides will match and the test is fire-rate-lossy (never FP) on those targets.
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43znnection:%20close%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%43onnection:%20close%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("Connection: close")
            }
            "viaLoop" -> {
                // Inject Via with the target's own host:port as a pseudonym already in the
                // forwarding chain. RFC 9110 §7.6.3 mandates Via for proxy chain construction
                // and SHOULDs loop detection: a proxy that sees what looks like its own
                // identifier breaks the cycle by returning 502 Bad Gateway. Tests the
                // intermediary layer — distinct from every existing technique which targets
                // origin parsers — and 502 is a status code none of the existing techniques
                // covers. Fires on Apache mod_proxy, HAProxy, Squid, and many CDN edges; will
                // not fire on origin-only servers or default-config nginx (acceptable miss).
                // Some WebDAV stacks return 508 Loop Detected instead; match string stays
                // strict on 502 and accepts those as misses.
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%56za:%201.1%20" + baseRequest.httpService().host() + ":" + baseRequest.httpService().port() + "%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a%56ia:%201.1%20" + baseRequest.httpService().host() + ":" + baseRequest.httpService().port() + "%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("502 Bad Gateway")
            }

            //TO BYPASS AKAMAI we can just URL encode the first letter of the header... \__:D__/
        }

        //Add encodings
        val benignPath = payload.benignRequest!!.pathWithoutQuery()
        val probePath = payload.probeRequest!!.pathWithoutQuery()
        var benignEncodedPath = benignPath
        var probeEncodedPath = probePath

        if (Utilities.globalSettings.getBoolean("Encode-colons")) {
            benignEncodedPath = encodePathAfterBasePath(benignEncodedPath, basePath, ":", "%3a")
            probeEncodedPath = encodePathAfterBasePath(probeEncodedPath, basePath, ":", "%3a")
        }

        if (Utilities.globalSettings.getBoolean("Encode-forward-slash")) {

            // If the request is just towards / then we want to treat "/" as the basePath here
            if (basePath == "") {
                basePath = "/"
            }
            benignEncodedPath = encodePathAfterBasePath(benignEncodedPath, basePath, "/", "%2f")
            probeEncodedPath = encodePathAfterBasePath(probeEncodedPath, basePath, "/", "%2f")
        }

        if (Utilities.globalSettings.getBoolean("Encode-period")) {
            benignEncodedPath = encodePathAfterBasePath(benignEncodedPath, basePath, ".", "%2e")
            probeEncodedPath = encodePathAfterBasePath(probeEncodedPath, basePath, ".", "%2e")
        }

        //replace path with encoded path
        payload.benignRequest = payload.benignRequest!!.withPath(benignEncodedPath)
        payload.probeRequest = payload.probeRequest!!.withPath(probeEncodedPath)

        return payload
    }

    private fun encodePathAfterBasePath(path: String, basePath: String, charToEncode: String, encodedChar: String): String {
        var offset = path.indexOf(basePath) + basePath.length
        if (offset < basePath.length) { // if basePath not found or empty
            offset = 0
        }
        val prefix = path.substring(0, offset)
        val suffix = path.substring(offset)
        return prefix + suffix.replace(charToEncode, encodedChar)
    }

}
