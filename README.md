# CRLF-Powered Desync Scanner
This is the Burp Extension I used to detect all cases in my research [CRLF-Powered Desync Attacks: Beheading HTTP Streams](https://blackhat.com/us-26/briefings/schedule/index.html#crlf-powered-desync-attacks-beheading-http-streams-51712).

It's research scanner built using [BulkScan](https://github.com/albinowax/bulkScan) similar to  [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler) and others.

# Implementation
### Request Header Injection probe
Uses all of the defined mutations in `src/main/kotlin/ReqMutator` to fire a benign and then probe request. If the response contains an expected match, or differs significantly, an issue is reported.

If the response contained **all** expected matches, then the issue is reported as normal. If the fallback diff is used (uses `serverStatus` from `BulkScan`) then the issue is reported as `Dodgy` because... it's dodgy. 

There is a `WAFChecker` which uses static strings to try and reduce FPs from WAF rules and follow-up logic that ensures the behaviour is **consistent** or at least most likely not a WAF rule that isn't in the `WAFChecker` list already.
Additionally, there is an "auto-exploit via Response Queue Poisoning" button that may or may not work...

### Response Header Injection probe
Injects a random header and looks for that header in the response headers. 