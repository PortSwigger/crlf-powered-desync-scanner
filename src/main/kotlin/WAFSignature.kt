package burp

class WAFSignature (
    var name: String,
    var techniques: List<String>,
    var bodyMatches: List<String>,
    var serverMatches: List<String>,
    var isAndMatch: Boolean
)

