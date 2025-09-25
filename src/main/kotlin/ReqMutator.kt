package burp

import burp.api.montoya.http.message.requests.HttpRequest
import java.io.File
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
        protocolBasedMutations.register("http/null", true, "")
        protocolBasedMutations.register("split", true, "End request without host header")
        //protocolBasedMutations.register("basic...", false, "Doesn't work")
        protocolBasedMutations.register("httx", true, "")
        protocolBasedMutations.register("tunnel", true, "")
        //protocolBasedMutations.register("http/1.0", true, "") //Failed terribly
        //protocolBasedMutations.register("HTTP/13.37 - akamai", true, "") //Fails
        //protocolBasedMutations.register("HTTP//13.37", true, "") //Failed
        protocolBasedMutations.register("split0.9", true, "")

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
        headerBasedMutations.register("responseHeaderInjection", true, "")
        headerBasedMutations.register("clNoHost", true, "")
        headerBasedMutations.register("teUserAgentTimeout", true, "")
        headerBasedMutations.register("headerSpace", true, "")
        headerBasedMutations.register("authorization",  true, "")
        headerBasedMutations.register("setCookie",  true, "")
        headerBasedMutations.register("upgrade", true, "")
        headerBasedMutations.register("expect-100", true, "")
        headerBasedMutations.register("connection", true, "")
        for (i in 0 .. 4) {
            headerBasedMutations.register("max-forwardsTrace$i", true, "")
            headerBasedMutations.register("max-forwardsOptions$i", true, "")
        }
        headerBasedMutations.register("badHeaderName", true, "")
        headerBasedMutations.register("clinvalid", true, "")
        headerBasedMutations.register("accept", true, "")
        headerBasedMutations.register("headerTab", true, "")
        headerBasedMutations.register("headerWrap", true, "")
        headerBasedMutations.register("contentType-invalid", true, "")
        //mutations.register("headerSemiColon", false, "") Extremely FP prone... A lot of servers just reject ";" full stop

        // Path based mutations
        pathBasedMutations.register("robots", true, "Inspired by the CL.0 scan check")
        pathBasedMutations.register("sitemap", true, "Inspired by the CL.0 scan check")
        pathBasedMutations.register("favicon", true, "Inspired by the CL.0 scan check")

        //Smuggle based mutations?
        smuggleBasedMutations.register("CL.TE-body-timeout", true, "Inspired by CL.TE detection")
        smuggleBasedMutations.register("TE.CL-body-timeout", true, "Inspired by TE.CL detection")




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

        val payload: Payload = Payload()

        payload.name = technique

        if (technique.startsWith("header|") && Utilities.globalSettings.getBoolean("Enable dodgy BPS diff")) {
            var headerName = technique.split("|")[1]
            if (headerName[0].isLowerCase()) {headerName = headerName[0].toString().uppercase() + headerName.substring(1)} //uppercase the first letter of headers to be more... compliant...
            val endOfheaderName = headerName.substring(1)
            val encodedFirstChar = String.format("%%%02x", headerName[0].toByte()) //URL ENCODE the first byte
            payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a$encodedFirstChar${endOfheaderName.replaceFirst(headerName.get(0).toString(), "z")}:%20nottherightvalue%0d%0aX:%20x")
            payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a$encodedFirstChar$endOfheaderName:%20nottherightvalue%0d%0aX:%20x")
            payload.expectedResponseMatches = listOf() //Nothing expected... only works for Diffing...
        }

        //Why are some chars in header names URL encoded? Because Akamai... nginx will decode them so... I think it's okay!
        when (technique) {
            "HvsX" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20X")
                payload.probeRequest = baseRequest.withPath("/$basePath%20H")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "HTTP/13.37" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f13.37%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("505 HTTP Version Not Supported")
            }
            "HTTP/13.37 - akamai" -> { //Failed
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%e5%98%8d%e5%98%8aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f13.37%e5%98%8d%e5%98%8aX:%20x")
                payload.expectedResponseMatches = listOf("505 HTTP Version Not Supported")
            }
            "HTTP//13.37" -> { // the "noramlize" in nginx will compress adjacent slashes... SO this would be valid only after noramalization I think...
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f%2f1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f%2f13.37%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("505 HTTP Version Not Supported")
            }
            "notChunked" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%54zansfer-Encoding:%20notchunked%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%54ransfer-Encoding:%20notchunked%0d%0aFoo:%20bar")
                payload.expectedResponseMatches = listOf("501 Not Implemented")
            }
            "dupeHost" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0D%0A%48xst:%20x%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0D%0A%48ost:%20x%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "dupeHostSpace" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0D%0A%48xst%20:%20x%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0D%0A%48ost%20:%20x%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "dupeHostTab" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0D%0A%48xst%09:%20x%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0D%0A%48ost%09:%20x%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "expect" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%45zpect:%20notright%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%45xpect:%20notright%0d%0aFoo:%20bar")
                payload.expectedResponseMatches = listOf("417 Expectation Failed")
            }
            "range-valid" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%52znge:%20bytes=0-10%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%52ange:%20bytes=0-10%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("206 Partial Content")
            }
            "range-invalid" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%52znge:%20bytes=0-abcde%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%52ange:%20bytes=0-abcde%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("416 Range Not Satisfiable")
            }
            "ifMatch" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%49z-Match:%20%22this-etag-is-definitely-wrong%22%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%49f-Match:%20%22this-etag-is-definitely-wrong%22%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("412 Precondition Failed")
            }
            "robots" -> {
                payload.benignRequest = baseRequest.withPath("/${basePath}robots.txtz%20HTTP%2f1.1%0d%0aFoo:%20bar") //Check that we don't just allow anything after the static path...
                payload.probeRequest = baseRequest.withPath("/${basePath}robots.txt%20HTTP%2f1.1%0d%0aFoo:%20bar")
                payload.expectedResponseMatches = listOf("llow: ", "200 OK")
            }
            "favicon" -> {
                payload.benignRequest = baseRequest.withPath("/${basePath}favicon.icoz%20HTTP%2f1.1%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/${basePath}favicon.ico%20HTTP%2f1.1%0d%0aFoo:%20bar")
                payload.expectedResponseMatches = listOf("Content-Type: image/", "200 OK")
            }
            "sitemap" -> {
                payload.benignRequest = baseRequest.withPath("/${basePath}sitemap.xmlz%20HTTP%2f1.1%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/${basePath}sitemap.xml%20HTTP%2f1.1%0d%0aFoo:%20bar")
                payload.expectedResponseMatches = listOf("Content-Type: application/xml", "200 OK")
            }
            "teTimeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%54zansfer-Encoding:%20chunked%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%54ransfer-Encoding:%20chunked%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "clTimeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%43zntent-Length:%2010000%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%43ontent-Length:%2010000%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "max-forwardsTimeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%4dzx-Forwards:%200%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%4dax-Forwards:%200%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "missingHost" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%48ost:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aGET%20%2f%20HTTP%2f1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%48xst:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aGET%20%2f%20HTTP%2f1.1%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "responseHeaderInjection" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%2520HTTP%2f1.1%25201337%20No%2520response%2520headers%2520received%250d%250aX:%2520x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%201337%20No%20response%20headers%20received%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("1337 No response headers received")
            }
            "clNoHost" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%48ost:%20" + baseRequest.httpService().host() + "%0d%0a%43ontent-Length:%2012%0d%0a%0d%0ax=y")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%48xst:%20" + baseRequest.httpService().host() + "%0d%0a%43ontent-Length:%2012%0d%0a%0d%0ax=y")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "teUserAgentTimeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%54z:%20nothing%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%54e:%20nothing%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "headerSpace" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aFoo%20:%20bar")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "authorization" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%41zthorization:%20notcorrect%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%41uthorization:%20notcorrect%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("401 Unauthorized")
            }
            "setCookie" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%53zt-Cookie:%20notcorrect%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%53et-Cookie:%20notcorrect%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("455")
            }
            "http/0.9" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f0.9%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("1337 No response headers received")
            }
            "http/null" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("1337 No response headers received")
            }
            "upgrade" -> { //Still need to actually run this one fully....
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%43onnection:%20zpgrade%0d%0azpgrade:%20websocket%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%43onnection:%20upgrade%0d%0aUpgrade:%20websocket%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("101 Switching Protocols")
            }
            "basic..." -> { //Trying to come up with a method of universal detection... DID NOT work well at all
                payload.benignRequest = baseRequest.withPath("/$basePath%250d%250a")
                payload.probeRequest = baseRequest.withPath("/$basePath%0d%0a")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "httx" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTX%2f1.1%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            //Tunnelling detection... Since a lot of the nginx configurations are probably BLIND / regular tunnelling... then in theory we could do a "trigger tunnel" vs "not trigger tunnel" kinda thing...
            "tunnel" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%48xst:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aTRACE%20%2f%20HTTP%2f1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%48ost:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aTRACE%20%2f%20HTTP%2f1.1%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("HTTP/1", "405 Not Allowed")
            }
            "expect-100" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%45zpect:%20100-continue%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%45xpect:%20100-continue%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("100 Continue")
            }
            "connection" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%43znnection:%20Host%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%43onnection:%20Host%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "max-forwardsTrace"+technique[technique.length - 1] -> {
                val maxForwardsValue = technique[technique.length - 1]
                val canary = Utilities.montoyaApi.utilities().randomUtils().randomString(8)
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%4dzx-Forwards:%20$maxForwardsValue%0d%0aX:%20x").withMethod("TRACE").withAddedHeader("Foo", canary)
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%4dax-Forwards:%20$maxForwardsValue%0d%0aX:%20x").withMethod("TRACE").withAddedHeader("Foo", canary)
                payload.expectedResponseMatches = listOf(canary)
            }
            "max-forwardsOptions"+technique[technique.length - 1] -> {
                val maxForwardsValue = technique[technique.length - 1]
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%4dzx-Forwards:%20$maxForwardsValue%0d%0aX:%20x").withMethod("OPTIONS")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%4dax-Forwards:%20$maxForwardsValue%0d%0aX:%20x").withMethod("OPTIONS")
                payload.expectedResponseMatches = listOf("200 OK")
            }
            "clinvalid" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%43zntent-Length:%20Z%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%43ontent-Length:%20Z%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "split" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "split0.9" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20%0d%0a%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "badHeaderName" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX%58:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX%5c:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "accept" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%41zcept:%20foo%2fbar%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%41ccept:%20foo%2fbar%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("406 Not Acceptable")
            }
            "headerTab" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX%09:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "headerWrap" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX:%20%0d%0a%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "headerSemiColon" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0aX;%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "contentType-invalid" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%43zntent-Type:%20foobar%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%43ontent-Type:%20foobar%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("406 Not Acceptable")
            }
            "CL.TE-body-timeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%54zansfer-Encoding:%20chunked%0d%0aX:%20x").withBody("d\r\nx=y\r\n0\r\n\r\n").withMethod("POST")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%54ransfer-Encoding:%20chunked%0d%0aX:%20x").withBody("d\r\nx=y\r\n0\r\n\r\n").withMethod("POST")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "TE.CL-body-timeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%43zntent-length:%2014%0d%0aX:%20x").withBody("3\r\nx=y\r\n0\r\n\r\n").withMethod("POST").withRemovedHeader("Content-Length").withAddedHeader("Transfer-Encoding", "chunked")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%43ontent-length:%2014%0d%0aX:%20x").withBody("3\r\nx=y\r\n0\r\n\r\n").withMethod("POST").withRemovedHeader("Content-Length").withAddedHeader("Transfer-Encoding", "chunked")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "http/1.0" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.1%0d%0a%54ransfer-Encoding:%20chunkedd%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP%2f1.0%0d%0a%54ransfer-Encoding:%20chunkedd%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("200 OK") //We expect the probe to return the same as the base request really. benign should trigger a 501 and probe should not (since TE isn't supported by HP1.0
            }
    	    //Something to do with connection header... If we remove a required header like "host" or similar... trying now
            //Something to do with the akamai talk on unicode... `%e5%98%8d%e5%98%8a == %0d%0a` somehow...

            //TO BYPASS AKAMAI we can just URL encode the first letter of the header... \__:D__/
        }
        return payload
    }

}
