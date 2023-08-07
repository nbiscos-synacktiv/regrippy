# Plugin written by Nicolas Biscos, nicolas.biscos@synacktiv.com
from regrippy import BasePlugin, PluginResult, mactime
from Registry.Registry import RegistryValue


class Plugin(BasePlugin):
    """Compliance check of log configuration regarding the ANSSI recommendations"""

    __REGHIVE__ = "SOFTWARE"
    enabled = list()

    def powershell(self):
        #path = r"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        path = r"Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        key = self.open_key(path)
        if key is None:
            res = PluginResult(key=key, value=None)
            #res.custom["PowerShell Block Logging"] = "**DEACTIVATED**"
            res.custom["Compliance"] = "PowerShell Block Logging **FAILED**"
            yield res
        else:
            enableScriptBlockLogging = key.value("EnableScriptBlockLogging")
            res = PluginResult(key=key, value=enableScriptBlockLogging)
            if enableScriptBlockLogging is None or enableScriptBlockLogging.value != 1:
                res.custom["Compliance"] = "PowerShell Block Logging **FAILED**"
            else:
                res.custom["Compliance"] = "PowerShell Block Logging Activated"
            yield res

    def logenabled(self):
        path = r"Microsoft\Windows\CurrentVersion\WINEVT\Channels"
        key = self.open_key(path)
        if key is None:
            return None

        musthave = ["Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController",
            "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController",
            "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController",
            "Microsoft-Windows-Authentication/ProtectedUser-Client",
            "Microsoft-Windows-NTLM/Operational"]
        for sk in key.subkeys():
            value = sk.value("Enabled")
            res = PluginResult(key=sk, value=value)
            if sk.name() in musthave and (value is None or value.value() != 1):
                res.custom["Compliance"] = "**FAILED**"
            else:
                self.enabled.append(sk.name())
            yield res

    def logsize(self):
        defaultMaxSize = 1048576
        for logname in self.enabled:
            key = self.open_key(rf"Microsoft\Windows\CurrentVersion\WINEVT\Channels\{logname}")
            if key is None:
                return None
            if "MaxSize" in key.values():
                value = key.value("MaxSize")
                val = value.value()
                res = PluginResult(key=key, value=value)
            else:
                val = defaultMaxSize
                res = PluginResult(key=key, value=None)
            if logname in ["Microsoft-Windows-TaskScheduler/Operational",
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                "Microsoft-Windows-TerminalServices-SessionBroker-Client/Operational"] and val < 20971520:
                res.custom["Compliance"] = "**MAXSIZE FAILED**"
            yield res



    def run(self):
        yield from self.powershell()
        yield from self.logenabled()
        yield from self.logsize()

    def display_human(self, result):
        if "Compliance" not in result.custom.keys():
            print(result.path, "=>", result.value_name, f"[{result.value_data}]")
        else:
            print(result.path, "=>", result.value_name, f"[{result.value_data}]", result.custom["Compliance"])
