# CRLF-Powered Desync Scanner
This is the Burp Extension we used to detect all cases our my research [CRLF-Powered Desync Attacks: Beheading HTTP Streams](https://portswigger.net/research/crlf-powered-desync-attacks).

It's a research-first scanner built using [BulkScan](https://github.com/albinowax/bulkScan) similar to  [HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler) and others.

# Implementation
### Request Header Injection probe
Uses all the defined mutations in `src/main/kotlin/ReqMutator` to fire a benign and then probe request. If the response contains an expected match, or differs significantly, an issue is reported.

If the response contained **all** expected matches, then the issue is reported as normal. If the fallback diff is enabled (uses `serverStatus` from `BulkScan`) then the issue is reported as `Dodgy`. 

There is also a `WAFChecker` which uses static strings to try and reduce FPs from WAF rules and follow-up logic that ensures the behaviour is **consistent** or at least most likely not a WAF rule that isn't in the `WAFChecker` list already.
Additionally, there is an "auto-exploit via Response Queue Poisoning" button that may or may not give you a clue that RQP works out of the box. 

### Response Header Injection probe
Injects a header containing a random canary into the request path and checks whether that header is reflected back in the response headers. If it is, the injection is confirmed and an issue is reported.

As a follow-up, it then injects a `Content-Length` header to see if the response can be split. If this causes a timeout or a change in the `serverStatus`, the issue is upgraded and reported as `Splitting?`. 