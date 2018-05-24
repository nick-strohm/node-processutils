declare namespace processUtils {
    interface ProcessUtils {
        killProcess(pid: Number): Boolean;
        createProcess(launchString: String): Boolean;
        createProcessScheme(uriScheme: String): Boolean;
        getProcessId(processName: String): Number;
        injectProcess(pid: Number, dllPath: String): Boolean;
        executeInject(launchString: String, dllPath: String): Boolean;
    }
}

declare const processUtils: processUtils.ProcessUtils;
export = processUtils;