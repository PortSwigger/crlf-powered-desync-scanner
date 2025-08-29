package burp

import burp.api.montoya.http.message.requests.HttpRequest
import java.io.File
import kotlin.collections.listOf


class ReqMutator internal constructor() {

    companion object {
        internal var mutations: SettingsBox = SettingsBox()
        internal var paramMinerMutations: SettingsBox = SettingsBox()
    }

    init {
        mutations.register("HvsX", true, "/%20X vs /%20H")
        mutations.register("HTTP/13.37", true, "/%20HTTP/1.1%0D%0AX:%20x vs /%20HTTP/13.37%0D%0AX:%20x")
        mutations.register("dupeHost", true, "/%20HTTP/1.1%0D%0AXXXX:%20x vs /%20HTTP/1.1%0D%0AHost:%20x")
        mutations.register("notChunked", true, "/%20HTTP/1.1%0d%0aTransfer-Encoding:%20notchunked%0d%0aFoo:%20bar vs 501 not implemented")
        mutations.register("robots", true, "/robots.txt%20HTTP/1.1%0d%0aFoo:%20bar vs /robots.txtnot")
        mutations.register("sitemap", false, "FP prone... /sitemap.xml%20HTTP/1.1%0d%0aFoo:%20bar vs /sitemap.xmlnot")
        mutations.register("favicon", true, "/favicon.ico%20HTTP/1.1%0d%0aFoo:%20bar vs /favicon.iconot")
        mutations.register("missingHost", true, "From https://portswigger.net/research/making-http-header-injection-critical-via-response-queue-poisoning")
        mutations.register("expect", true, "Expect: notreal vs Ezpect: notreal")
        mutations.register("teTimeout", true, "")
        mutations.register("clTimeout", true, "")
        mutations.register("range", true,"")
        mutations.register("max-forwardsTimeout", true,"")
        mutations.register("ifMatch", true, "")
        mutations.register("responseHeaderInjection", true, "")
        mutations.register("clNoHost", true, "")
        mutations.register("teUserAgentTimeout", true, "")
        mutations.register("headerSpace", true, "")
        mutations.register("authorization",  true, "")
        mutations.register("setCookie",  true, "")
        mutations.register("http/0.9", true, "")
        mutations.register("http/null", true, "")
	mutations.register("upgrade", true, "")
	mutations.register("basic...", false, "")
	mutations.register("httx", true, "")
	mutations.register("tunnel", true, "")

        //Could dynamically register a mutation for litterally every header in param-miner...
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
            val headerName = technique.split("|")[1]
            payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a${headerName.replaceFirst(headerName.get(0).toString(), "z")}:%20nottherightvalue%0d%0aX:%20x")
            payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0a$headerName:%20nottherightvalue%0d%0aX:%20x")
            payload.expectedResponseMatches = listOf() //Nothing expected... only works for Diffing...
        }

        when (technique) {
            "HvsX" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20X")
                payload.probeRequest = baseRequest.withPath("/$basePath%20H")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "HTTP/13.37" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/13.37%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("505 HTTP Version Not Supported")
            }
            "notChunked" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aTzansfer-Encoding:%20notchunked%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aTransfer-Encoding:%20notchunked%0d%0aFoo:%20bar")
                payload.expectedResponseMatches = listOf("501 Not Implemented")
            }
            "dupeHost" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0D%0AHxst:%20x%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0D%0AHost:%20x%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "expect" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aEzpect:%20notright%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aExpect:%20notright%0d%0aFoo:%20bar")
                payload.expectedResponseMatches = listOf("417 Expectation Failed")
            }
            "range" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aRznge:%20bytes=999999-1000000%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aRange:%20bytes=999999-1000000%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("416 Range Not Satisfiable")
            }
            "ifMatch" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aIz-Match:%20%22this-etag-is-definitely-wrong%22%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aIf-Match:%20%22this-etag-is-definitely-wrong%22%0d%0aX:%20x")
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
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aTzansfer-Encoding:%20chunked%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aTransfer-Encoding:%20chunked%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "clTimeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aCzntent-Length:%2010000%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aContent-Length:%2010000%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "max-forwardsTimeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aMzx-Forwards:%200%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aMax-Forwards:%200%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "missingHost" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aHost:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aGET%20/%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0ahxst:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aGET%20/%20HTTP/1.1%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "responseHeaderInjection" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%2520HTTP/1.1%25201337%20No%2520response%2520headers%2520received%250d%250aX:%2520x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%201337%20No%20response%20headers%20received%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("1337 No response headers received")
            }
            "clNoHost" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aHost:%20" + baseRequest.httpService().host() + "%0d%0aContent-Length:%2012%0d%0a%0d%0ax=y")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aHxst:%20" + baseRequest.httpService().host() + "%0d%0aContent-Length:%2012%0d%0a%0d%0ax=y")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "teUserAgentTimeout" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aTz:%20nothing%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aTe:%20nothing%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("TIMEOUT")
            }
            "headerSpace" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aFoo:%20bar")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aFoo%20:%20bar")
                payload.expectedResponseMatches = listOf("400 Bad Request")
            }
            "authorization" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aAzthorization:%20notcorrect%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aAuthorization:%20notcorrect%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("401 Unauthorized")
            }
            "setCookie" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aSzt-Cookie:%20notcorrect%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aSet-Cookie:%20notcorrect%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("455")
            }
            "http/0.9" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/0.9%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("1337 No response headers received")
            }
            "http/null" -> {
                payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
                payload.probeRequest = baseRequest.withPath("/$basePath%0d%0aX:%20x")
                payload.expectedResponseMatches = listOf("1337 No response headers received")
            }
	    "upgrade" -> { //Still need to actually run this one fully....
		payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aConnection:%20zpgrade%0d%0azpgrade:%20websocket%0d%0aX:%20x")
		payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aConnection:%20upgrade%0d%0aUpgrade:%20websocket%0d%0aX:%20x")
		payload.expectedResponseMatches = listOf("101 Switching Protocols")
	    }
	    "basic..." -> { //Trying to come up with a method of universal detection... DID NOT work well at all
		payload.benignRequest = baseRequest.withPath("/$basePath%250d%250a")
		payload.probeRequest = baseRequest.withPath("/$basePath%0d%0a")
		payload.expectedResponseMatches = listOf("400 Bad Request")
	    }
	    "httx" -> {
		payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aX:%20x")
		payload.probeRequest = baseRequest.withPath("/$basePath%20HTTX/1.1%0d%0aX:%20x")
		payload.expectedResponseMatches = listOf("400 Bad Request")
	    }
	    //Tunnelling detection... Since a lot of the nginx configurations are probably BLIND / regular tunnelling... then in theory we could do a "trigger tunnel" vs "not trigger tunnel" kinda thing... 
	    "tunnel" -> {
		payload.benignRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aHxst:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aTRACE%20/%20HTTP/1.1%0d%0aX:%20x")
		payload.probeRequest = baseRequest.withPath("/$basePath%20HTTP/1.1%0d%0aHost:%20" + baseRequest.httpService().host() + "%0d%0a%0d%0aTRACE%20/%20HTTP/1.1%0d%0aX:%20x")
		payload.expectedResponseMatches = listOf("HTTP/1", "405 Not Allowed")
	    }
        }
        return payload
    }

}
