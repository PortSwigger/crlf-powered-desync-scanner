package burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import java.util.concurrent.ConcurrentHashMap


class BurpExtender: BurpExtension, IExtensionStateListener, IBurpExtender {
    //Stuff we need to access outside of this class
    companion object {
        internal val configSettings = SettingsBox()
    }

    val name: String = "CRLF-Powered Desync Scanner"
    private val version = "1.0"
    var unloaded: Boolean = false
    val hostsToSkip: ConcurrentHashMap<String, Boolean> = BulkScan.hostsToSkip

    //Grab our MontoyaApi instance. You can reach this using Utilities.montoyaApi from now on.
    override fun initialize(api: MontoyaApi) {
        Utilities.montoyaApi = api
        BulkUtilities.registerContextMenu()
        api.http().registerHttpHandler(LiveScan())
    }


    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {

        Utilities(callbacks, HashMap(), name)

        callbacks.setExtensionName(name)
        BulkScanLauncher(BulkScan.scans)
        callbacks.registerExtensionStateListener(this);

        //Scans
        ReqHeaderInjectionScan("Request Header Injection probe")
        RespHeaderInjectionScan("Response Header Injection probe")


        BulkUtilities.out("Loaded " + name + " v" + version)
        BulkUtilities.out("""
        ┌────────┐      ____ ____  _     _____     ____                                _   ____                               ____                                  
        │↵ ENTER │     / ___|  _ \| |   |  ___|   |  _ \ _____      _____ _ __ ___  __| | |  _ \  ___  ___ _   _ _ __   ___  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
        └──┐     │    | |   | |_) | |   | |_ _____| |_) / _ \ \ /\ / / _ \ '__/ _ \/ _` | | | | |/ _ \/ __| | | | '_ \ / __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
           │     │    | |___|  _ <| |___|  _|_____|  __/ (_) \ V  V /  __/ | |  __/ (_| | | |_| |  __/\__ \ |_| | | | | (__   ___) | (_| (_| | | | | | | |  __/ |   
           │     │     \____|_| \_\_____|_|       |_|   \___/ \_/\_/ \___|_|  \___|\__,_| |____/ \___||___/\__, |_| |_|\___| |____/ \___\__,_|_| |_|_| |_|\___|_|
           └─────┘                                                                                         |___/
        """.trimIndent())
    }

    //ON unload, kill everything in the queue!
    override fun extensionUnloaded() {
        BulkUtilities.log("Aborting all attacks");
        BulkUtilities.unloaded.set(true);
    }

}