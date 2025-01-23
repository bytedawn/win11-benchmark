/*************************************************************
 * system_services.h
 *************************************************************/
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "../../../include/benchmark_section.h"

// The new section class for Section 5 of your CIS Benchmark
class SystemServicesSection : public BenchmarkSection {
public:
    void initialize() override;
    std::vector<BenchmarkResult> runChecks() override;
    std::string getSectionName() const override { return "System Services"; }
    int getSectionNumber() const override { return 5; }

    // Helper to check if a service is either "Not Installed" or has "SERVICE_DISABLED"
    static bool IsServiceDisabledOrNotInstalled(const std::wstring& serviceName);
};

// 5.1
class BluetoothAudioGatewayCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.1"; }
    std::string getName() const override {
        return "Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled'";
    }
};

// 5.2
class BluetoothSupportServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.2"; }
    std::string getName() const override {
        return "Ensure 'Bluetooth Support Service (bthserv)' is set to 'Disabled'";
    }
};

// 5.3
class ComputerBrowserCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.3"; }
    std::string getName() const override {
        return "Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'";
    }
};

// 5.4
class DownloadedMapsManagerCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.4"; }
    std::string getName() const override {
        return "Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled'";
    }
};

// 5.5
class GeolocationServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.5"; }
    std::string getName() const override {
        return "Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled'";
    }
};

// 5.6
class IISAdminServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.6"; }
    std::string getName() const override {
        return "Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed'";
    }
};

// 5.7
class InfraredMonitorServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.7"; }
    std::string getName() const override {
        return "Ensure 'Infrared monitor service (irmon)' is set to 'Disabled' or 'Not Installed'";
    }
};

// 5.8
class LinkLayerTopologyDiscoveryMapperCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.8"; }
    std::string getName() const override {
        return "Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled'";
    }
};

// 5.9
class LxssManagerCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.9"; }
    std::string getName() const override {
        return "Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed'";
    }
};

// 5.10
class MicrosoftFTPServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.10"; }
    std::string getName() const override {
        return "Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed'";
    }
};

// 5.11
class MicrosoftiSCSIInitiatorServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.11"; }
    std::string getName() const override {
        return "Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled'";
    }
};

// 5.12
class OpenSSHServerCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.12"; }
    std::string getName() const override {
        return "Ensure 'OpenSSH SSH Server (sshd)' is set to 'Disabled' or 'Not Installed'";
    }
};

// 5.13
class PeerNameResolutionProtocolCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.13"; }
    std::string getName() const override {
        return "Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled'";
    }
};

// 5.14
class PeerNetworkingGroupingCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.14"; }
    std::string getName() const override {
        return "Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled'";
    }
};

// 5.15
class PeerNetworkingIdentityManagerCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.15"; }
    std::string getName() const override {
        return "Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled'";
    }
};

// 5.16
class PNRPMachineNamePublicationServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.16"; }
    std::string getName() const override {
        return "Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled'";
    }
};

// 5.17
class PrintSpoolerCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.17"; }
    std::string getName() const override {
        return "Ensure 'Print Spooler (Spooler)' is set to 'Disabled'";
    }
};

// 5.18
class ProblemReportsServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.18"; }
    std::string getName() const override {
        return "Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled'";
    }
};

// 5.19
class RemoteAccessAutoConnectionManagerCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.19"; }
    std::string getName() const override {
        return "Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled'";
    }
};

// 5.20
class RemoteDesktopConfigurationCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.20"; }
    std::string getName() const override {
        return "Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled'";
    }
};

// 5.21
class RemoteDesktopServicesCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.21"; }
    std::string getName() const override {
        return "Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled'";
    }
};

// 5.22
class RemoteDesktopServicesUserModePortRedirectorCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.22"; }
    std::string getName() const override {
        return "Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' is set to 'Disabled'";
    }
};

// 5.23
class RPCLocatorCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.23"; }
    std::string getName() const override {
        return "Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled'";
    }
};

// 5.24
class RemoteRegistryCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.24"; }
    std::string getName() const override {
        return "Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled'";
    }
};

// 5.25
class RoutingAndRemoteAccessCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.25"; }
    std::string getName() const override {
        return "Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled'";
    }
};

// 5.26
class ServerServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.26"; }
    std::string getName() const override {
        return "Ensure 'Server (LanmanServer)' is set to 'Disabled'";
    }
};

// 5.27
class SimpleTCPIPServicesCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.27"; }
    std::string getName() const override {
        return "Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed'";
    }
};

// 5.28
class SNMPServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.28"; }
    std::string getName() const override {
        return "Ensure 'SNMP Service (SNMP)' is set to 'Disabled' or 'Not Installed'";
    }
};

// 5.29
class SpecialAdministrationConsoleHelperCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.29"; }
    std::string getName() const override {
        return "Ensure 'Special Administration Console Helper (sacsvr)' is set to 'Disabled' or 'Not Installed'";
    }
};

// 5.30
class SSDPDiscoveryCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.30"; }
    std::string getName() const override {
        return "Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'";
    }
};

// 5.31
class UPnPDeviceHostCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.31"; }
    std::string getName() const override {
        return "Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled'";
    }
};

// 5.32
class WebManagementServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.32"; }
    std::string getName() const override {
        return "Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed'";
    }
};

// 5.33
class WindowsErrorReportingServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.33"; }
    std::string getName() const override {
        return "Ensure 'Windows Error Reporting Service (WerSvc)' is set to 'Disabled'";
    }
};

// 5.34
class WindowsEventCollectorCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.34"; }
    std::string getName() const override {
        return "Ensure 'Windows Event Collector (Wecsvc)' is set to 'Disabled'";
    }
};

// 5.35
class WindowsMediaPlayerNetworkSharingServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.35"; }
    std::string getName() const override {
        return "Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is set to 'Disabled' or 'Not Installed'";
    }
};

// 5.36
class WindowsMobileHotspotServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.36"; }
    std::string getName() const override {
        return "Ensure 'Windows Mobile Hotspot Service (icssvc)' is set to 'Disabled'";
    }
};

// 5.37
class WindowsPushNotificationsSystemServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.37"; }
    std::string getName() const override {
        return "Ensure 'Windows Push Notifications System Service (WpnService)' is set to 'Disabled'";
    }
};

// 5.38
class WindowsPushToInstallServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.38"; }
    std::string getName() const override {
        return "Ensure 'Windows PushToInstall Service (PushToInstall)' is set to 'Disabled'";
    }
};

// 5.39
class WindowsRemoteManagementCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.39"; }
    std::string getName() const override {
        return "Ensure 'Windows Remote Management (WinRM)' is set to 'Disabled'";
    }
};

// 5.40
class WorldWideWebPublishingServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.40"; }
    std::string getName() const override {
        return "Ensure 'World Wide Web Publishing Service (W3SVC)' is set to 'Disabled' or 'Not Installed'";
    }
};

// 5.41
class XboxAccessoryManagementServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.41"; }
    std::string getName() const override {
        return "Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled'";
    }
};

// 5.42
class XboxLiveAuthManagerCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.42"; }
    std::string getName() const override {
        return "Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled'";
    }
};

// 5.43
class XboxLiveGameSaveCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.43"; }
    std::string getName() const override {
        return "Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled'";
    }
};

// 5.44
class XboxLiveNetworkingServiceCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "5.44"; }
    std::string getName() const override {
        return "Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' is set to 'Disabled'";
    }
};
