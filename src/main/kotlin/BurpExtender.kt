package burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import java.util.concurrent.ConcurrentHashMap


class BurpExtender: BurpExtension, IExtensionStateListener, IBurpExtender {
    //Stuff we need to access outside of this class
    companion object {
        internal val configSettings = SettingsBox()
    }

    val name: String = "HTTP Header Injector"
    private val version = "1.0"
    var unloaded: Boolean = false
    val hostsToSkip: ConcurrentHashMap<String, Boolean> = BulkScan.hostsToSkip

    //Grab our MontoyaApi instance. You can reach this using Utilities.montoyaApi from now on.
    override fun initialize(api: MontoyaApi) {
        Utilities.montoyaApi = api
        BulkUtilities.registerContextMenu()
    }


    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {

        Utilities(callbacks, HashMap(), name)

        callbacks.setExtensionName(name)
        BulkScanLauncher(BulkScan.scans)
        callbacks.registerExtensionStateListener(this);

        //Scans
        ReqHeaderInjectionScan("Request Header Injection probe")
        RespHeaderInjectionScan("Response Header Injection probe")



        BulkUtilities.out("Loaded " + name + " v" + version);
    }

    //ON unload, kill everything in the queue!
    override fun extensionUnloaded() {
        BulkUtilities.log("Aborting all attacks");
        BulkUtilities.unloaded.set(true);
    }

}