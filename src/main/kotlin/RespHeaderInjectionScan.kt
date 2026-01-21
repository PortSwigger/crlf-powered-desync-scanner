package burp

import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.RequestOptions

//this is a basic scan check implementation
internal class RespHeaderInjectionScan(name: String?) : Scan(name) {

    //Init is a constructor in Kotlin. Import any settings you wanted outside of the global ones
    init {
        super.name
        scanSettings.importSettings(BurpExtender.configSettings)
    }

    //this is where your scan logic goes
    override fun doScan(baseReq: ByteArray, service: IHttpService): MutableList<IScanIssue> {
        // Finding Data
        var name = "Response Header Injection"
        var description = "Response Header Injection"

        val original: ByteArray
        if (Utilities.isHTTP2(baseReq)) {
            original = Utilities.replaceFirst(baseReq, "HTTP/2\r\n", "HTTP/1.1\r\n")
        } else {
            original = baseReq
        }

        val baseRequest = BulkUtilities.buildMontoyaReq(original, service)

        val options = RequestOptions.requestOptions().withHttpMode(HttpMode.HTTP_1)


        val canary = Utilities.randomString(8)
        val injectedRequest = baseRequest.withPath("/%0d%0aInjected%3a%20$canary")

        val checkRequestResponse = Scan.request(injectedRequest, options)

        //Skip over entry if header isn't reflected at all

        if (!checkRequestResponse.hasResponse()) {
            return mutableListOf<IScanIssue>()
        }
        if (!checkRequestResponse.response().hasHeader("Injected", canary)) {
            return mutableListOf<IScanIssue>()
        }

        // Follow up with length header.
        val splitRequest = baseRequest.withPath("/%0d%0a%43ontent-Length%3a%203%0d%0a%0d%0a")

        val splitRequestResponse = Scan.request(splitRequest, options)

        var addSplit = false

        if (splitRequestResponse.timedOut() || (checkRequestResponse.serverStatus() != splitRequestResponse.serverStatus())) {
            name  += ": Splitting?"
            description = "Response Header Injection with interesting response to length headers"
            addSplit = true
        }

        if (addSplit) {
            report(name, description, baseReq, checkRequestResponse, splitRequestResponse)
        } else {
            report(name, description, baseReq, checkRequestResponse)
        }

        return mutableListOf<IScanIssue>()
    }
}