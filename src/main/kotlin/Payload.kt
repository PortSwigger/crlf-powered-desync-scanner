package burp

import burp.api.montoya.http.message.requests.HttpRequest

class Payload (
    var name: String? = null,
    var benignRequest: HttpRequest? = null,
    var probeRequest: HttpRequest? = null,
    var expectedResponseMatches: List<String?> = listOf()
)