

/*************************************************************
 * system_services.cpp
 *************************************************************/
#include "include/sections/section5/system_services.h"
#include <windows.h>
#include <sstream>

// -----------------------------------------------------
// SystemServicesSection Implementation
// -----------------------------------------------------
void SystemServicesSection::initialize()
{
    // Add all checks for Section 5 (services 5.1 - 5.44)
    checks.push_back(std::make_unique<BluetoothAudioGatewayCheck>());          // 5.1
    checks.push_back(std::make_unique<BluetoothSupportServiceCheck>());        // 5.2
    checks.push_back(std::make_unique<ComputerBrowserCheck>());                // 5.3
    checks.push_back(std::make_unique<DownloadedMapsManagerCheck>());          // 5.4
    checks.push_back(std::make_unique<GeolocationServiceCheck>());             // 5.5
    checks.push_back(std::make_unique<IISAdminServiceCheck>());                // 5.6
    checks.push_back(std::make_unique<InfraredMonitorServiceCheck>());         // 5.7
    checks.push_back(std::make_unique<LinkLayerTopologyDiscoveryMapperCheck>()); // 5.8
    checks.push_back(std::make_unique<LxssManagerCheck>());                    // 5.9
    checks.push_back(std::make_unique<MicrosoftFTPServiceCheck>());            // 5.10
    checks.push_back(std::make_unique<MicrosoftiSCSIInitiatorServiceCheck>());  // 5.11
    checks.push_back(std::make_unique<OpenSSHServerCheck>());                  // 5.12
    checks.push_back(std::make_unique<PeerNameResolutionProtocolCheck>());      // 5.13
    checks.push_back(std::make_unique<PeerNetworkingGroupingCheck>());         // 5.14
    checks.push_back(std::make_unique<PeerNetworkingIdentityManagerCheck>());   // 5.15
    checks.push_back(std::make_unique<PNRPMachineNamePublicationServiceCheck>()); // 5.16
    checks.push_back(std::make_unique<PrintSpoolerCheck>());                   // 5.17
    checks.push_back(std::make_unique<ProblemReportsServiceCheck>());          // 5.18
    checks.push_back(std::make_unique<RemoteAccessAutoConnectionManagerCheck>()); // 5.19
    checks.push_back(std::make_unique<RemoteDesktopConfigurationCheck>());     // 5.20
    checks.push_back(std::make_unique<RemoteDesktopServicesCheck>());          // 5.21
    checks.push_back(std::make_unique<RemoteDesktopServicesUserModePortRedirectorCheck>()); // 5.22
    checks.push_back(std::make_unique<RPCLocatorCheck>());                     // 5.23
    checks.push_back(std::make_unique<RemoteRegistryCheck>());                 // 5.24
    checks.push_back(std::make_unique<RoutingAndRemoteAccessCheck>());         // 5.25
    checks.push_back(std::make_unique<ServerServiceCheck>());                  // 5.26
    checks.push_back(std::make_unique<SimpleTCPIPServicesCheck>());            // 5.27
    checks.push_back(std::make_unique<SNMPServiceCheck>());                    // 5.28
    checks.push_back(std::make_unique<SpecialAdministrationConsoleHelperCheck>()); // 5.29
    checks.push_back(std::make_unique<SSDPDiscoveryCheck>());                  // 5.30
    checks.push_back(std::make_unique<UPnPDeviceHostCheck>());                 // 5.31
    checks.push_back(std::make_unique<WebManagementServiceCheck>());           // 5.32
    checks.push_back(std::make_unique<WindowsErrorReportingServiceCheck>());    // 5.33
    checks.push_back(std::make_unique<WindowsEventCollectorCheck>());          // 5.34
    checks.push_back(std::make_unique<WindowsMediaPlayerNetworkSharingServiceCheck>()); // 5.35
    checks.push_back(std::make_unique<WindowsMobileHotspotServiceCheck>());    // 5.36
    checks.push_back(std::make_unique<WindowsPushNotificationsSystemServiceCheck>()); // 5.37
    checks.push_back(std::make_unique<WindowsPushToInstallServiceCheck>());    // 5.38
    checks.push_back(std::make_unique<WindowsRemoteManagementCheck>());        // 5.39
    checks.push_back(std::make_unique<WorldWideWebPublishingServiceCheck>());  // 5.40
    checks.push_back(std::make_unique<XboxAccessoryManagementServiceCheck>()); // 5.41
    checks.push_back(std::make_unique<XboxLiveAuthManagerCheck>());            // 5.42
    checks.push_back(std::make_unique<XboxLiveGameSaveCheck>());              // 5.43
    checks.push_back(std::make_unique<XboxLiveNetworkingServiceCheck>());      // 5.44
}

std::vector<BenchmarkResult> SystemServicesSection::runChecks()
{
    std::vector<BenchmarkResult> results;
    for (auto& check : checks) {
        results.push_back(check->check());
    }
    return results;
}

// Helper function
bool SystemServicesSection::IsServiceDisabledOrNotInstalled(const std::wstring& serviceName)
{
    SC_HANDLE hSCM = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        return false; // Could not open SCM; treat as error
    }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_QUERY_CONFIG);
    if (!hService) {
        // Possibly not installed
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            // "Not installed" => pass for the "Disabled or Not Installed" requirement
            return true;
        }
        return false;
    }

    // Query the config
    QUERY_SERVICE_CONFIGW svcConfig = {};
    BYTE buffer[8192];
    DWORD bytesNeeded = 0;
    LPQUERY_SERVICE_CONFIGW pConfig = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer);

    BOOL success = QueryServiceConfigW(hService, pConfig, sizeof(buffer), &bytesNeeded);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (!success) {
        return false; 
    }

    // If the StartType is SERVICE_DISABLED, we pass
    return (pConfig->dwStartType == SERVICE_DISABLED);
}

// -----------------------------------------------------
// Check Implementations
// -----------------------------------------------------
#define CHECK_SERVICE(SHORTNAME, CHECKNAME, SERVICENAME)                     \
BenchmarkResult CHECKNAME::check()                                           \
{                                                                            \
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,                \
                      "Failed to check service configuration");              \
    bool disabledOrMissing = SystemServicesSection::IsServiceDisabledOrNotInstalled(L##SERVICENAME); \
    if (disabledOrMissing) {                                                \
        r.status  = CheckStatus::Pass;                                       \
        r.details = #SERVICENAME " is disabled or not installed";            \
    } else {                                                                 \
        r.status  = CheckStatus::Fail;                                       \
        r.details = #SERVICENAME " is not disabled";                         \
    }                                                                        \
    return r;                                                                \
}

// 5.1
CHECK_SERVICE("BTAGService", BluetoothAudioGatewayCheck, "BTAGService")
// 5.2
CHECK_SERVICE("bthserv", BluetoothSupportServiceCheck, "bthserv")
// 5.3
CHECK_SERVICE("Browser", ComputerBrowserCheck, "Browser")
// 5.4
CHECK_SERVICE("MapsBroker", DownloadedMapsManagerCheck, "MapsBroker")
// 5.5
CHECK_SERVICE("lfsvc", GeolocationServiceCheck, "lfsvc")
// 5.6
CHECK_SERVICE("IISADMIN", IISAdminServiceCheck, "IISADMIN")
// 5.7
CHECK_SERVICE("irmon", InfraredMonitorServiceCheck, "irmon")
// 5.8
CHECK_SERVICE("lltdsvc", LinkLayerTopologyDiscoveryMapperCheck, "lltdsvc")
// 5.9
CHECK_SERVICE("LxssManager", LxssManagerCheck, "LxssManager")
// 5.10
CHECK_SERVICE("FTPSVC", MicrosoftFTPServiceCheck, "FTPSVC")
// 5.11
CHECK_SERVICE("MSiSCSI", MicrosoftiSCSIInitiatorServiceCheck, "MSiSCSI")
// 5.12
CHECK_SERVICE("sshd", OpenSSHServerCheck, "sshd")
// 5.13
CHECK_SERVICE("PNRPsvc", PeerNameResolutionProtocolCheck, "PNRPsvc")
// 5.14
CHECK_SERVICE("p2psvc", PeerNetworkingGroupingCheck, "p2psvc")
// 5.15
CHECK_SERVICE("p2pimsvc", PeerNetworkingIdentityManagerCheck, "p2pimsvc")
// 5.16
CHECK_SERVICE("PNRPAutoReg", PNRPMachineNamePublicationServiceCheck, "PNRPAutoReg")
// 5.17
CHECK_SERVICE("Spooler", PrintSpoolerCheck, "Spooler")
// 5.18
CHECK_SERVICE("wercplsupport", ProblemReportsServiceCheck, "wercplsupport")
// 5.19
CHECK_SERVICE("RasAuto", RemoteAccessAutoConnectionManagerCheck, "RasAuto")
// 5.20
CHECK_SERVICE("SessionEnv", RemoteDesktopConfigurationCheck, "SessionEnv")
// 5.21
CHECK_SERVICE("TermService", RemoteDesktopServicesCheck, "TermService")
// 5.22
CHECK_SERVICE("UmRdpService", RemoteDesktopServicesUserModePortRedirectorCheck, "UmRdpService")
// 5.23
CHECK_SERVICE("RpcLocator", RPCLocatorCheck, "RpcLocator")
// 5.24
CHECK_SERVICE("RemoteRegistry", RemoteRegistryCheck, "RemoteRegistry")
// 5.25
CHECK_SERVICE("RemoteAccess", RoutingAndRemoteAccessCheck, "RemoteAccess")
// 5.26
CHECK_SERVICE("LanmanServer", ServerServiceCheck, "LanmanServer")
// 5.27
CHECK_SERVICE("simptcp", SimpleTCPIPServicesCheck, "simptcp")
// 5.28
CHECK_SERVICE("SNMP", SNMPServiceCheck, "SNMP")
// 5.29
CHECK_SERVICE("sacsvr", SpecialAdministrationConsoleHelperCheck, "sacsvr")
// 5.30
CHECK_SERVICE("SSDPSRV", SSDPDiscoveryCheck, "SSDPSRV")
// 5.31
CHECK_SERVICE("upnphost", UPnPDeviceHostCheck, "upnphost")
// 5.32
CHECK_SERVICE("WMSvc", WebManagementServiceCheck, "WMSvc")
// 5.33
CHECK_SERVICE("WerSvc", WindowsErrorReportingServiceCheck, "WerSvc")
// 5.34
CHECK_SERVICE("Wecsvc", WindowsEventCollectorCheck, "Wecsvc")
// 5.35
CHECK_SERVICE("WMPNetworkSvc", WindowsMediaPlayerNetworkSharingServiceCheck, "WMPNetworkSvc")
// 5.36
CHECK_SERVICE("icssvc", WindowsMobileHotspotServiceCheck, "icssvc")
// 5.37
CHECK_SERVICE("WpnService", WindowsPushNotificationsSystemServiceCheck, "WpnService")
// 5.38
CHECK_SERVICE("PushToInstall", WindowsPushToInstallServiceCheck, "PushToInstall")
// 5.39
CHECK_SERVICE("WinRM", WindowsRemoteManagementCheck, "WinRM")
// 5.40
CHECK_SERVICE("W3SVC", WorldWideWebPublishingServiceCheck, "W3SVC")
// 5.41
CHECK_SERVICE("XboxGipSvc", XboxAccessoryManagementServiceCheck, "XboxGipSvc")
// 5.42
CHECK_SERVICE("XblAuthManager", XboxLiveAuthManagerCheck, "XblAuthManager")
// 5.43
CHECK_SERVICE("XblGameSave", XboxLiveGameSaveCheck, "XblGameSave")
// 5.44
CHECK_SERVICE("XboxNetApiSvc", XboxLiveNetworkingServiceCheck, "XboxNetApiSvc")

// End of system_services.cpp