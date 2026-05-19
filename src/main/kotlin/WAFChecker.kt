package burp

import burp.api.montoya.http.message.responses.HttpResponse

class WAFChecker {
	private val wafSignaturesBody = listOf<String>(
		"You don't have permission to access ",
		"The requested URL was rejected. Please consult with your administrator",
		"Your request was blocked by DPG Media's Web Application Firewall.",
		"This website is using a security service to protect itself from online attacks. The action you just performed triggered the security solution. There are several actions that could trigger this block including submitting a certain word or phrase, a SQL command or malformed data.",
		"punish/waf_block.html",
		"<BODY>\nAn error occurred while processing your request.<p>",
		"Request Rejected",
		"Blocked request",
		"Your request has been blocked",
		"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234",
		"Acceso Denegado",
		"WAF Blocked Request",
		"Wafrule",
		"Complete the CAPTCHA verification to prove you're human."

	)
	private val wafSignaturesHeaders = listOf<String>(
		"AkamaiGHost"
	)

    fun isWafResponse(response: HttpResponse?): Boolean {
		if (response == null) {
			return false
		}
        for (match in wafSignaturesBody) {
			if (response.toString().contains(match, false)) {
				return true
			}
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
