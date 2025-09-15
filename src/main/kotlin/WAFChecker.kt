package burp

import burp.api.montoya.http.message.responses.HttpResponse

class WAFChecker {
    //private val wafSignatures = mutableListOf<WAFSignature>()
	private val wafSignaturesBody = listOf<String>(
		"You don't have permission to access ",
		"The requested URL was rejected. Please consult with your administrator",
		"Your request was blocked by DPG Media's Web Application Firewall.",
		"This website is using a security service to protect itself from online attacks. The action you just performed triggered the security solution. There are several actions that could trigger this block including submitting a certain word or phrase, a SQL command or malformed data.",
		"punsh/waf_block.html",
		"<BODY>\nAn error occurred while processing your request.<p>",
		"Request Rejected",
		"Blocked request",
		"Your request has been blocked"
	)
	private val wafSignaturesHeaders = listOf<String>(
		"AkamaiGHost"
	)

    init {

//        wafSignatures.add(WAFSignature(
//            name = "akamai",
//            techniques = listOf("dupeHost", "missingHost", "clNoHost", "clTimeout", "connection"),
//            bodyMatches = listOf("edgesuite"),
//			serverMatches = listOf("AkamaiGHost"),
//			isAndMatch = true //needs to be edgesuite and akamaiGhost
//        ))
//		wafSignatures.add(WAFSignature(
//            name = "tengine",
//            techniques = listOf("1337"),
//            bodyMatches = listOf("punsh/waf_block.html"),
//			serverMatches = listOf("tengine"),
//			isAndMatch = true
//        ))
//		wafSignatures.add(WAFSignature(
//            name = "akamaiNoServerHeader",
//            techniques = listOf("dupeHost", "missingHost", "clNoHost", "clTimeout", "connection"),
//            bodyMatches = listOf("edgesuite", "You don't have permission to access "),
//			serverMatches = listOf(),
//			isAndMatch = true
//        ))
//		wafSignatures.add(WAFSignature(
//            name = "javascriptInPath",
//            techniques = listOf("header|javascript"),
//            bodyMatches = listOf("The requested URL was rejected. Please consult with your administrator"),
//			serverMatches = listOf(),
//			isAndMatch = true
//        ))
//		wafSignatures.add(WAFSignature(
//            name = "DPG Media's WAF",
//            techniques = listOf("header|content-encoding", "header|connection"),
//            bodyMatches = listOf("Your request was blocked by DPG Media's Web Application Firewall."),
//			serverMatches = listOf(),
//			isAndMatch = true
//        ))
//		wafSignatures.add(WAFSignature(
//            name = "underAttack",
//            techniques = listOf("header|javascript"),
//            bodyMatches = listOf("This website is using a security service to protect itself from online attacks. The action you just performed triggered the security solution. There are several actions that could trigger this block including submitting a certain word or phrase, a SQL command or malformed data."),
//			serverMatches = listOf(),
//			isAndMatch = true
//        ))

    }

    fun isWafResponse(response: HttpResponse?): Boolean {
		if (response == null) {
			return false
		}
        for (match in wafSignaturesBody) {
			if (response.toString().contains(match, false)) {
				return true
			}


	    
//			var serverHeader = ""
//			if (response.hasHeader("server")) {
//				serverHeader = response.headerValue("server")
//			}
//
//			//Skip if the current technique isn't in the list of known techniques for this signature
//			if (technique !in signature.techniques) {
//				continue
//			}
//
//			if (signature.isAndMatch && serverHeader.isNotBlank()) { //check for blank server header also. If it's blank, there's no point running the && checks...
//			for (match in signature.bodyMatches) {
//				if (!response.toString().contains(match, true)) {
//				continue
//				}
//			}
//			if (serverHeader.isNotBlank()) {
//				for (match in signature.serverMatches) {
//				if (!response.headerValue("server").contains(match, true)) {
//					continue
//				}
//				}
//			}
//			return true //if we made it to here, none of the matches failed for body or server header... so report a FP
//			} else {
//			for (match in signature.bodyMatches) {
//				if (response.toString().contains(match, true)) {
//				return true
//				}
//			}
//			if (serverHeader.isNotBlank()) {
//				for (match in signature.serverMatches) {
//				if (response.headerValue("server").contains(match, true)) {
//					return true
//				}
//				}
//			}
//	    }
		}

		if (response.hasHeader("Server")) {
			for (match in wafSignaturesHeaders) {
				if (response.headerValue("Server").lowercase().equals(match.lowercase())) {
					return true
				}
			}
		}

        return false //if we made it to here, none of the matched worked for && or || so we can be be pretty sure it's not a FP...
    }
}
