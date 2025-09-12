package burp

import burp.ReqMutator.Companion.mutations
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.StatusCodeClass
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.message.responses.analysis.AttributeType
import burp.api.montoya.logging.Logging
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
        scanSettings.register("Enable dodgy BPS diff", false, "If predicted match fails, report findings based Backslash Powered Scanner-style diff")
        scanSettings.register("Enable param-miner headers", false, "")
	scanSettings.register("maintain path", false)

        scanSettings.importSettings(BurpExtender.configSettings)
        scanSettings.importSettings(mutations)

    }

    //this is where your scan logic goes
    override fun doScan(baseReq: ByteArray, service: IHttpService): MutableList<IScanIssue> {

	val wafChecker = WAFChecker()

        val enabledMutations = arrayListOf<String>()
        for (mutation in mutations.settings) {
            if (Utilities.globalSettings.getBoolean(mutation)) {
                enabledMutations.add(mutation)
            }
        }
        //Add param miner headers if enabled
        if (Utilities.globalSettings.getBoolean("Enable param-miner headers")) {
            for (mutation in ReqMutator.paramMinerMutations.settings) {
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

            val baseRequest = Utilities.buildMontoyaReq(Utilities.addCacheBuster(baseReq, Utilities.generateCanary()), service) //Easy way to build a montoya request so you can stop messing with the old version

            var currentVariantAttributes = mutableSetOf<AttributeType>()
            var previousVariantAttributes = mutableSetOf<AttributeType>()

            lateinit var previousBenignResponse: HttpResponse
            lateinit var previousProbeResponse: HttpResponse

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

                    if (responseHasErrors(benignRequestResponse)) {
                        currentVariantAttributes = mutableSetOf<AttributeType>() //Reset to not cause issues
                        false //indicate failure
                    } else {

                        //If we have no status code... fix that...
                        if (benignRequestResponse.response().statusCode() == "0".toShort()) {
                            benignRequestResponse = fixMissingStatuscode(benignRequestResponse)
                        }
                        true
                    }
                }

                val sendProbeRequest = {
                    probeRequestResponse = Utilities.montoyaApi.http().sendRequest(probe.probeRequest, hpMode)

                    if (responseHasErrors(probeRequestResponse) && !technique.contains("timeout", true)) { //If it's an expected timeout, don't check for errors
                        currentVariantAttributes = mutableSetOf<AttributeType>() //reset to not cause issues.
                        false //indicate failure
                    } else {
                        //If we have no status code... fix that...
                        if (!technique.contains("timeout", true)) {//If it's an expected timeout, don't check for status
                            if (probeRequestResponse.response().statusCode() == "0".toShort()) {
                                probeRequestResponse = fixMissingStatuscode(probeRequestResponse)
                            }
                        }
                        true
                    }
                }


                //Randomly choose which probe goes first...
                val runSuccess = if (Random.nextBoolean()) {
                    sendBenignRequest() && sendProbeRequest()
                } else {
                    sendProbeRequest() && sendBenignRequest()
                }

                //Exit if either probe failed
                if (!runSuccess) {
                    currentVariantAttributes = mutableSetOf<AttributeType>()
                    break
                }

                //Check if the responses are inconsistent on their own...
                if (i != 1) { //Skip on first run...
                    val baseResponseVariationsAnalyzer = Utilities.montoyaApi.http().createResponseVariationsAnalyzer()
                    baseResponseVariationsAnalyzer.updateWith(previousBenignResponse)
                    baseResponseVariationsAnalyzer.updateWith(benignRequestResponse.response())

                    val probeResponseVariationsAnalyzer = Utilities.montoyaApi.http().createResponseVariationsAnalyzer()
                    probeResponseVariationsAnalyzer.updateWith(previousProbeResponse)
                    probeResponseVariationsAnalyzer.updateWith(probeRequestResponse.response())

                    val baseVariantAttributes = baseResponseVariationsAnalyzer.variantAttributes().intersect(interestingAttributes)
                    val probeVariantAttributes = probeResponseVariationsAnalyzer.variantAttributes().intersect(interestingAttributes)

                    if (baseVariantAttributes.isNotEmpty() || probeVariantAttributes.isNotEmpty()) {
                        //Requests are inconsistent on their own... gotta skip
                        currentVariantAttributes = mutableSetOf<AttributeType>() //reset to not cause issues.
                        break
                    }
                }

                //Set previous responses to keep track...
                previousBenignResponse = benignRequestResponse.response()
                previousProbeResponse = probeRequestResponse.response()



                val responseVariationsAnalyzer = Utilities.montoyaApi.http().createResponseVariationsAnalyzer()
                responseVariationsAnalyzer.updateWith(benignRequestResponse.response())

                if (probeRequestResponse.hasResponse()) {
                    responseVariationsAnalyzer.updateWith(probeRequestResponse.response())
                } else { //assume timeout. create empty response if it doesn't already exist
                    val timeoutResponse = HttpResponse.httpResponse()
                    responseVariationsAnalyzer.updateWith(timeoutResponse)
                }

                currentVariantAttributes = responseVariationsAnalyzer.variantAttributes().intersect(interestingAttributes).toMutableSet()

                // If nothing changes at all, give up
                if (currentVariantAttributes.isEmpty()) {
                    break
                }

                //If after the current repeat our variant attributes don't match... somethings inconsistent regardless of probe
                if (i != 1 && previousVariantAttributes != currentVariantAttributes) {
                    //Make the attributes empty so we can prevent reporting
                    currentVariantAttributes = mutableSetOf()
                    break
                }
                previousVariantAttributes = currentVariantAttributes
            }

            if (currentVariantAttributes.isNotEmpty()) {

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
                            if (probeRequestResponse.response().contains(match, true)) {
                                numberOfMatches += 1
                            }

                            if (benignRequestResponse.response().contains(match, true)) {
                                numberOfMatches = 0 //set to 0 to cause the logic below to fail... if the match also appears in the base response it's probably nothing...
                            }
                    }
                    if (numberOfMatches != 0 && numberOfMatches == probe.expectedResponseMatches.size) { //If we got a match on every entry one of the expected response matches.
                        report("Request Splitting via $technique",
                            "The application behaves in a manner that is consistent with HTTP Request Splitting...",
                            benignRequestResponse,
                            probeRequestResponse
                        )
                        continue
                    }
                }

                //Skip any techniques that we don't care about checking response attributes for OR just skip altogether if not enabled
                if (technique in listOf("robots", "sitemap", "favicon") || !Utilities.globalSettings.getBoolean("Enable dodgy BPS diff")) {
                    continue
                }

                var attributeDiffString = """
                    <table>
                        <tr>
                            <td></td>
                            <td><b>Base<b></td>
                            <td><b>Probe<b></td>
                        </tr>
                """.trimIndent()

                for (attribute in currentVariantAttributes) {
                    var benignValue = ""
                    var probeValue = ""
                    if (attribute.name == "CONTENT_TYPE") {
                        benignValue = benignRequestResponse.response().headerValue("Content-Type")
                        probeValue = probeRequestResponse.response().headerValue("Content-Type")
                    } else {
                        benignValue = benignRequestResponse.response().attributes(attribute)[0].value().toString()
                        probeValue  = probeRequestResponse.response().attributes(attribute)[0].value().toString()
                    }

                    attributeDiffString += """
                        <tr>
                            <td>${attribute.name}</td>
                            <td>$benignValue</td>
                            <td>$probeValue</td>
                        </tr>
                    """
                }
                attributeDiffString += "</table>"

                report(
                    "Request Splitting via $technique - Dodgy", """
                    The application behaves in a manner that is consistent with HTTP Request Splitting...Sort of:<br>
                    $attributeDiffString
                     """, benignRequestResponse, probeRequestResponse
                )
                continue
            }
        }



        return mutableListOf<IScanIssue>()
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

//fun isFalsePositive(requestResponse: HttpRequestResponse, technique: String): Boolean {
//
//    if (!requestResponse.hasResponse()) {
//        return false
//    }
//
//    val response = requestResponse.response()
//
//    var serverHeader: String = ""
//    if (response.hasHeader("server")) {
//        serverHeader = response.headerValue("server")
//    } else {
//        serverHeader = ""
//    }
//
//    //Filter out akamai and it's host based sillyness
//    if (technique.contains("host", true) && (serverHeader.contains("akamai", true) || response.bodyToString().contains("edgesuite", true))) {
//        return true
//    }
//
//    //Filter out akamai and it's Content-Length in path sillyness
//    if (technique.contains("clTimeout", true) && (serverHeader.contains("akamai", true) || response.bodyToString().contains("edgesuite", true))) {
//        return true
//    }
//
//    //Filter out tengine and it's silly WAF.
//    if (technique.contains("1337", true) && (response.bodyToString().contains("punish/waf_block.html", true))) {
//        return true
//    }
//
//    if (response.statusCode() == "403".toShort() &&
//        response.contains("You don't have permission to access ", true) &&
//        response.contains("edgesuite", true)) {
//        return true
//    }
//
//    //See this a lot
//    if (technique == "header|javascript" && response.bodyToString().contains("The requested URL was rejected. Please consult with your administrator")) {
//        return true
//    }
//
//    if (technique in listOf("header|content-encoding", "header|connection") && response.bodyToString().contains("Your request was blocked by DPG Media's Web Application Firewall.")) {
//        return true
//    }
//
//    if (technique in listOf("header|javascript") && response.bodyToString().contains("This website is using a security service to protect itself from online attacks. The action you just performed triggered the security solution. There are several actions that could trigger this block including submitting a certain word or phrase, a SQL command or malformed data.")) {
//        return true
//    }
//
//    return false
//}
