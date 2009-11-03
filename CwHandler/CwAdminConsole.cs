/*
 +---------------------------------------------------------------------+
 Copyright 2009, Aaron LeMasters and Michael Davis                                    
 
 This file is part of Codeword.
  
 Codeword is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Codeword is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Codeword.  If not, see <http://www.gnu.org/licenses/>.
 +---------------------------------------------------------------------+
*/
using System;
using System.Collections.Generic;
using System.Collections;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Security;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace CwHandler
{
    internal partial class CwAdminConsole : Form
    {
        //constructor:
        public CwAdminConsole()
        {
            InitializeComponent();
        }

        //private data members that are set in cwAdminCredentialsWindow
        //which is used to configure the admin console credentials when connecting to an agent
        internal string AC_CRED_PFX_FILENAME = "";
        internal string AC_CRED_PFX_PASSWORD = "";
        internal bool AC_CRED_IGNORE_REMOTE_CERT_NAME_MISMATCH = false;
        internal bool AC_CRED_IGNORE_REMOTE_CERT_CHAIN_ERRORS = false;
        internal int numCredButtonClicks = 0;

        //last response received from agent
        internal CwXML.CodewordAgentAnomalyReport LastAnomalyReport;
        internal CwXML.CodewordSystemInformation LatestSystemInformation;
        internal CwXML.CodewordAgentAnomalyReport LastCollectionTask;

        //delegate used for child form CwAdminCredentialsWindow
        public delegate void SetParameterValueDelegate(string name, string value);

        ///////////////////////////////////////////////////////////////////////////////////
        //
        //
        //                      GUI FORM INITIALIZATION
        //
        //
        ///////////////////////////////////////////////////////////////////////////////////

        #region windows forms initialization code

        protected Button Button_GenerateMSI;
        protected TabPage FileSignaturesTabPage;
        private CheckBox RegistryHeuristics_NoOnDiskModule;
        private CheckBox RegistryHeuristics_UnsignedSystemModules;
        private CheckBox BHO_CollectBasicInformation;
        private CheckBox BHO_ScanForUnregisteredBHOs;
        private CheckBox ProcessThread_Crossview;
        private ImageList MainMenuIcons;
        private IContainer components;
        private TabPage RegistryHeuristicsTabPage;
        private TabControl HeuristicsTabContainer;
        private TabPage ProcessThreadTabPage;
        private TabPage BHOToolbarTabPage;
        private TabPage MemorySignaturesTabPage;
        protected Label label33;
        protected Label label32;
        protected TextBox MemorySignatures_NewKeywords;
        protected TextBox MemorySignatures_NewProcessName;
        protected Button AddMemorySignatureButton;
        protected ComboBox MemorySignatures_NewAction;
        protected Label label28;
        protected Label label29;
        protected ListView MemorySignatures_Listview;
        protected ColumnHeader processname;
        protected ColumnHeader processkeywords;
        protected ColumnHeader processaction;
        protected Button DeleteSelectedMemorySignatureButton;
        protected Label label48;
        protected Label label49;
        protected TextBox FileSignatures_NewFileSize;
        protected TextBox FileSignatures_NewFileHash;
        protected TextBox FileSignatures_NewFilename;
        protected CheckBox FileSignatures_NewFileHashTypeSHA1;
        protected CheckBox FileSignatures_NewFileHashTypeMD5;
        protected Label label47;
        protected Button AddFileSignatureButton;
        protected ComboBox FileSignatures_NewAction;
        protected Label label27;
        protected Label label26;
        protected ListView FileSignatures_Listview;
        protected ColumnHeader columnHeader3;
        protected ColumnHeader columnHeader4;
        protected Button DeleteSelectedFileSignature;
        protected TabPage RegistrySignaturesTabPage;
        protected TextBox FileSignatures_NewFilePESignature;
        protected Label label38;
        private ColumnHeader columnHeader7;
        private ColumnHeader columnHeader10;
        private ColumnHeader columnHeader11;
        private ColumnHeader columnHeader12;
        private ColumnHeader columnHeader13;
        protected Button Button_ScanLocalHost;
        private TreeView MainMenuTreeview;
        protected TextBox RegistrySignatures_NewValueName;
        protected TextBox RegistrySignatures_ValueData;
        protected TextBox RegistrySignatures_NewKeyName;
        protected Label label40;
        protected Label label25;
        protected Label label21;
        protected ComboBox RegistrySignatures_NewAction;
        protected Button AddRegistrySignatureButton;
        protected Button DeleteRegistrySignatureButton;
        private PictureBox pictureBox1;
        private TextBox MainLogoTextbox;
        private CheckBox RegistryHeuristics_GUIDScan;
        private CheckBox KernelHeuristics_SSDT_DetectHooks;
        private CheckBox KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors;
        private CheckBox KernelHeuristics_SSDT_DetectDetours;
        private CheckBox DriversHeuristics_DetectIRPHooks;
        private CheckBox checkBox1;
        private CheckBox DriversHeuristics_CheckDispatchRoutinesForDetours;
        private MenuStrip menuStrip;
        private ToolStripMenuItem fileToolStripMenuItem;
        private ToolStripMenuItem helpToolStripMenuItem1;
        private ToolStripMenuItem administratorConsoleManualToolStripMenuItem;
        private ToolStripMenuItem agentManualToolStripMenuItem;
        private ToolStripMenuItem installerManualToolStripMenuItem;
        private ToolStripMenuItem aboutCodewordToolStripMenuItem;
        private TabControl TopLevelTabControl;
        private TabPage CreateNewAgentTabPage;
        private TabPage ConnectExistingAgentTabPage;
        private TabPage RegistryGuidSignaturesTabPage;
        private ListView RegistrySignatures_Listview;
        private ColumnHeader KeyName;
        private ColumnHeader ValueName;
        private ColumnHeader ValueData;
        private ColumnHeader Action;
        protected TextBox DynRegGuidValueName;
        protected Label label36;
        private TextBox DynRegGuidKeyName;
        protected Label label35;
        protected Label label23;
        private TextBox StaticRegGuidValue;
        private ListView RegistryGuidSignatures_Listview;
        private Button AddRegGuidButton;
        private Button DeleteSelectedGuidButton;
        private ColumnHeader GuidValue;
        private ColumnHeader GuidType;
        private TabControl SignaturesTabContainer;
        private CheckBox checkBox3;
        private Label label37;
        private CheckBox checkBox4;
        private TextBox textBox5;
        private Label label39;
        private Button button1;
        private TextBox textBox6;
        private Label label65;
        private ToolStrip ConnectAgentToolstrip;
        private ToolStripTextBox ConnectToAgentPort;
        private TreeView RecentAgentsTreeview;
        private TextBox LogWindow;
        private TabControl FindingsTabContainer;
        private TabPage RegistryFindingsTabPage;
        private TabPage FileFindingsTabPage;
        private TabPage MemoryFindingsTabPage;
        private TabPage UserModeAnomaliesTabPage;
        private TabPage KernelModeAnomaliesTabPage;
        private TabPage LowLevelAnomaliesTabPage;
        private ToolStripButton ConnectAgentButton;
        private ToolStripSeparator toolStripSeparator1;
        private ToolStripButton StartScanButton;
        private ToolStripButton UpdateAgentButton;
        private ToolStripButton DownloadEvidenceButton;
        private ToolStripButton PerformMitigationTasksButton;
        private ListView AgentResults_RegistryListview;
        private ColumnHeader RegistryFindingsKeyName;
        private ColumnHeader RegistryFindingsValueName;
        private ColumnHeader RegistryFindingsValueData;
        private ColumnHeader RegistryFindingsIsFileOnDisk;
        private ToolStripMenuItem signaturesToolStripMenuItem;
        private ToolStripMenuItem loadSignatureTemplateToolStripMenuItem;
        private ToolStripMenuItem settingsToolStripMenuItem;
        private ToolStripMenuItem loadSettingsToolStripMenuItem;
        private ToolStripMenuItem saveSettingsToolStripMenuItem;
        private ToolStripMenuItem saveSignatureTemplateToolStripMenuItem;
        private ToolStripMenuItem allToolStripMenuItem;
        private ToolStripMenuItem registryToolStripMenuItem;
        private ToolStripMenuItem fileToolStripMenuItem1;
        private ToolStripMenuItem memoryToolStripMenuItem;
        private ToolStripTextBox ConnectToAgentIP;
        private ToolStripButton SetAdminConsoleCredentialsButton;
        private ToolStripButton HaltAgentButton;
        private ToolStripButton DisconnectAgentButton;
        private TextBox LastCommandPane;
        private ColumnHeader RegistryFindingsAction;
        private ColumnHeader RegistryFindingsActionSuccessful;
        private ListView AgentResults_FileListview;
        private ColumnHeader FileFindingsFileName;
        private ColumnHeader FileFindingsPath;
        private ColumnHeader FileFindingsSize;
        private ColumnHeader FileFindingsHash;
        private ColumnHeader FileFindingsPEHeaderSig;
        private ColumnHeader FileFindingsCreated;
        private ColumnHeader FileFindingsAccessed;
        private ColumnHeader FileFindingsModified;
        private ColumnHeader FileFindingsAction;
        private ColumnHeader FileFindingsActionSuccessful;
        private ListView AgentResults_MemoryListview;
        private ColumnHeader MemoryFindingsPid;
        private ColumnHeader MemoryFindingsPpid;
        private ColumnHeader MemoryFindingsProcessName;
        private ColumnHeader MemoryFindingsMatchingBlock;
        private ColumnHeader MemoryFindingsSuspiciousHeapRange;
        private ColumnHeader MemoryFindingsKeywords;
        private ColumnHeader MemoryFindingsChildThreads;
        private ColumnHeader MemoryFindingsAction;
        private ColumnHeader MemoryFindingsActionSuccessful;
        private Label label79;
        private Label label78;
        private TabPage SystemInfoTabPage;
        private TextBox systemInfoTextarea;
        private Label AgentTaskProgressBarLabel;
        private ProgressBar AgentTaskProgressBar;
        private GroupBox groupBox7;
        private GroupBox groupBox8;
        private CheckBox KernelHeuristics_GDT_GetInstalledCallGates;
        private GroupBox groupBox9;
        private CheckBox KernelHeuristics_IDT_DetectHooks;
        private CheckBox KernelHeuristics_IDT_DetectDetours;
        private ImageList MitigationTasksImageList;
        protected Label label81;
        protected TextBox RegistrySignatures_ChangeValueData;
        protected Label label80;
        private ColumnHeader RegistryFindingsChangeValueData;
        private ColumnHeader ChangeValueData;
        private TabPage EnterprisePullTabPage;
        protected TabControl GeneralSettingsTabContainer;
        private TabPage AgentStartupTabPage;
        private GroupBox groupBox5;
        private Label label24;
        private CheckBox AgentSelfProtectionRunKernelHeuristicsFirst;
        private GroupBox groupBox1;
        private Label label63;
        private RadioButton StartupEnterpriseMode;
        private Label label62;
        private Label label61;
        private RadioButton StartupRemoteControlMode;
        private RadioButton StartupFireAndForgetMode;
        private Label label66;
        private TabPage AgentConnectionTabPage;
        private GroupBox groupBox6;
        private Label label77;
        private TextBox AgentEnforceCertificateIssuer;
        private Label label76;
        private Label label75;
        protected Label label55;
        private CheckBox AgentAuthenticateClientToServer;
        protected TextBox AgentPFXPassword;
        private CheckBox AgentAuthenticateServerToClient;
        protected TextBox AgentPFXFile;
        private CheckBox AgentEnforceStrongAuthentication;
        protected Button BrowseButton2;
        protected Label label54;
        private GroupBox groupBox4;
        private CheckBox AgentRandomizeListeningPort;
        private TextBox AgentListeningPort;
        private Label label72;
        private TabPage AgentPersistenceAndStealthTabPage;
        private GroupBox groupBox3;
        private CheckBox Stealth_UseZwLoadDriver;
        protected CheckBox Stealth_RandomizeAgentProcessName;
        private Label label73;
        protected CheckBox Stealth_HideAgentProcess;
        private CheckBox Stealth_LoadAndCallImage;
        protected CheckBox Stealth_No_Dotnet;
        private GroupBox groupBox2;
        private Label label74;
        private TextBox AgentServiceName;
        private Label label71;
        private Label label68;
        private Label label69;
        private RadioButton PersistenceRunOnce;
        private RadioButton PersistenceInstallAsService;
        private Label label70;
        private TabPage MitigationTabPage;
        protected CheckBox Option_AutoMitigate;
        protected CheckBox Option_Delete_MalwareFoundInRegistry;
        protected CheckBox Option_Disable_Autorun;
        protected CheckBox Option_Disable_USB;
        private TabPage CollectionModeTabPage;
        private TextBox textBox4;
        private TextBox textBox3;
        private TextBox textBox2;
        private TextBox textBox1;
        private CheckBox ModeSelection_MaxParanoia;
        private RadioButton ModeSelection_Offline;
        private RadioButton ModeSelection_Live;
        protected TabPage ReportingTabPage;
        private Panel ReportingAuthPanel;
        protected Label label56;
        protected TextBox Reporting_Archive_Password;
        protected Label label52;
        protected ComboBox Reporting_Auth_Type;
        protected Label label51;
        protected Label label50;
        protected Label label46;
        protected TextBox Reporting_Auth_Server_PubKey;
        protected TextBox Reporting_Auth_Password;
        protected TextBox Reporting_Auth_UserName;
        protected Button BrowseButton1;
        protected Label label20;
        protected Label label17;
        protected Label label18;
        private Panel ReportingTlsPanel;
        protected Label label53;
        protected TextBox Reporting_TLS_Port;
        protected CheckBox Reporting_Use_TLS;
        protected Label label13;
        private Panel ReportingWebPanel;
        protected Label label45;
        protected TextBox Reporting_WebServer_Port;
        protected Label label44;
        protected TextBox Reporting_Method_WebServer_URI;
        protected Label label19;
        private Panel ReportingEmailPanel;
        protected Label label43;
        protected TextBox Reporting_SMTP_Port;
        protected TextBox Reporting_SMTP_Server;
        protected TextBox Reporting_Method_EmailAddress;
        protected Label label16;
        protected Label label15;
        protected Label label12;
        private Panel ReportingFtpPanel;
        protected Label label57;
        protected TextBox Reporting_Method_FTPServer;
        protected Label label11;
        private Panel ReportingNetworkSharePanel;
        protected Label label42;
        protected TextBox Reporting_Method_NetworkShare;
        protected Label label31;
        protected Label label9;
        protected CheckBox Reporting_EnableAutoReporting;
        protected TabPage InformationTabPage;
        private TextBox Information_Notes;
        protected TextBox Information_AdminEmail;
        protected TextBox Information_AdminPhone;
        protected TextBox Information_OrgName;
        protected TextBox Information_AdminName;
        protected TextBox Information_OrgLocation;
        protected TextBox Information_NetworkName;
        protected TextBox Information_NetworkAddrRange;
        protected Label label59;
        protected Label label58;
        protected Label label8;
        protected Label label4;
        protected Label label14;
        protected Label label1;
        protected Label label2;
        protected Label label3;
        protected Label label5;
        protected Label label6;
        protected Label label7;
        protected TabPage AdvancedTabPage;
        private Label label67;
        private CheckBox Advanced_3rdPartyApp_Distribute;
        private TextBox Advanced_3rdPartyApp_Arguments;
        private TextBox Advanced_3rdPartyApp_Filename;
        private Label label41;
        private Button Advanced_File_Browse_Button;
        private Label label10;
        protected CheckBox MemorySignatures_UseRegistryFindings;
        protected CheckBox MemorySignatures_SearchCmdLine;
        protected CheckBox MemorySignatures_SearchLoadedModules;
        protected CheckBox MemorySignatures_SearchHeapSpace;
        protected Label label34;
        private ToolTip ToolTipShowAnExample;
        private ListView SSDTAnomaliesListview;
        private GroupBox groupBox10;
        private ColumnHeader SSDTIndex;
        private ColumnHeader SSDTFuncExpected;
        private ColumnHeader SSDTFuncAddr;
        private ColumnHeader SSDTFuncFound;
        private ColumnHeader SSDTSuspectMod;
        private ColumnHeader SSDTAnomaly;
        private ColumnHeader SSDTFuncDisassembly;
        private ColumnHeader SSDTDetourTarget;
        private ImageList AnomaliesIcons;
        private CheckBox KernelHeuristics_Win32Api_CheckExportsForDetours;
        private GroupBox groupBox11;
        private GroupBox groupBox12;
        private ListView Win32ApiDetoursListview;
        private ColumnHeader columnHeader1;
        private ColumnHeader columnHeader2;
        private ColumnHeader columnHeader5;
        private ColumnHeader columnHeader14;
        private ColumnHeader columnHeader15;
        private ColumnHeader columnHeader6;
        private ColumnHeader columnHeader8;
        private GroupBox groupBox13;
        private CheckBox GUISubsystem_CheckSSDTShadowDetours;
        private CheckBox GUISubsystem_CollectSSDTShadow;
        private GroupBox groupBox14;
        private Label label82;
        private TextBox AddDriverDevice;
        private Label label64;
        private TextBox AddDriverModule;
        private Label label60;
        private Button AddDriverButton;
        private Label label83;
        private GroupBox groupBox17;
        private ListView DriverAnomaliesListview;
        private ColumnHeader columnHeader17;
        private ColumnHeader columnHeader18;
        private ColumnHeader columnHeader19;
        private ColumnHeader columnHeader20;
        private ColumnHeader columnHeader21;
        private ColumnHeader columnHeader22;
        private ColumnHeader columnHeader23;
        private TabPage ModuleTab;
        private Label label84;
        private TextBox ModuleTargets;
        private GroupBox groupBox19;
        private CheckBox Module_EATHooks;
        private GroupBox groupBox18;
        private CheckBox Module_IATHooks;
        private ColumnHeader columnHeader24;
        private GroupBox groupBox20;
        private ListView ProcessAnomaliesListview;
        private ColumnHeader columnHeader25;
        private ColumnHeader columnHeader26;
        private ColumnHeader columnHeader27;
        private ColumnHeader columnHeader28;
        private ColumnHeader columnHeader29;
        private ColumnHeader columnHeader35;
        private ColumnHeader columnHeader37;
        private ColumnHeader columnHeader38;
        private GroupBox groupBox21;
        private ListView ProcessResourcesAnomaliesListview;
        private ColumnHeader columnHeader30;
        private ColumnHeader columnHeader31;
        private ColumnHeader columnHeader32;
        private TabPage KernelTabPage;
        private TabPage GDI32SubsystemTabPage;
        private TabPage DriversTabPage;
        private ListView AddDriverListview;
        private ColumnHeader columnHeader9;
        private ColumnHeader columnHeader16;
        private Label label30;
        private TabPage NdisTdiTabPage;
        private CheckBox NDIS_TDI_FindProtocolStacks;
        private TabPage BIOSTabPage;
        private TabPage BootSectorTabPage;
        private Label label22;
        private CheckBox ProcessThread_BruteForcePIDs;
        private ToolStripMenuItem exitToolStripMenuItem;
    
        protected void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.Windows.Forms.TreeNode treeNode1 = new System.Windows.Forms.TreeNode("Startup", 0, 0);
            System.Windows.Forms.TreeNode treeNode2 = new System.Windows.Forms.TreeNode("Connection");
            System.Windows.Forms.TreeNode treeNode3 = new System.Windows.Forms.TreeNode("Persistence/Stealth");
            System.Windows.Forms.TreeNode treeNode4 = new System.Windows.Forms.TreeNode("Mitigation");
            System.Windows.Forms.TreeNode treeNode5 = new System.Windows.Forms.TreeNode("Collection Mode");
            System.Windows.Forms.TreeNode treeNode6 = new System.Windows.Forms.TreeNode("Reporting");
            System.Windows.Forms.TreeNode treeNode7 = new System.Windows.Forms.TreeNode("Information");
            System.Windows.Forms.TreeNode treeNode8 = new System.Windows.Forms.TreeNode("Misc. Options");
            System.Windows.Forms.TreeNode treeNode9 = new System.Windows.Forms.TreeNode("Advanced");
            System.Windows.Forms.TreeNode treeNode10 = new System.Windows.Forms.TreeNode("Agent Settings", 2, 2, new System.Windows.Forms.TreeNode[] {
            treeNode1,
            treeNode2,
            treeNode3,
            treeNode4,
            treeNode5,
            treeNode6,
            treeNode7,
            treeNode8,
            treeNode9});
            System.Windows.Forms.TreeNode treeNode11 = new System.Windows.Forms.TreeNode("Registry Guid");
            System.Windows.Forms.TreeNode treeNode12 = new System.Windows.Forms.TreeNode("Registry");
            System.Windows.Forms.TreeNode treeNode13 = new System.Windows.Forms.TreeNode("File");
            System.Windows.Forms.TreeNode treeNode14 = new System.Windows.Forms.TreeNode("Memory");
            System.Windows.Forms.TreeNode treeNode15 = new System.Windows.Forms.TreeNode("Signatures", 1, 1, new System.Windows.Forms.TreeNode[] {
            treeNode11,
            treeNode12,
            treeNode13,
            treeNode14});
            System.Windows.Forms.TreeNode treeNode16 = new System.Windows.Forms.TreeNode("Process/Thread");
            System.Windows.Forms.TreeNode treeNode17 = new System.Windows.Forms.TreeNode("Module");
            System.Windows.Forms.TreeNode treeNode18 = new System.Windows.Forms.TreeNode("BHO/Toolbar");
            System.Windows.Forms.TreeNode treeNode19 = new System.Windows.Forms.TreeNode("Registry");
            System.Windows.Forms.TreeNode treeNode20 = new System.Windows.Forms.TreeNode("Kernel/Ntdll");
            System.Windows.Forms.TreeNode treeNode21 = new System.Windows.Forms.TreeNode("GDI32 Subsystem");
            System.Windows.Forms.TreeNode treeNode22 = new System.Windows.Forms.TreeNode("Drivers");
            System.Windows.Forms.TreeNode treeNode23 = new System.Windows.Forms.TreeNode("Call Gates");
            System.Windows.Forms.TreeNode treeNode24 = new System.Windows.Forms.TreeNode("NDIS/TDI");
            System.Windows.Forms.TreeNode treeNode25 = new System.Windows.Forms.TreeNode("BIOS");
            System.Windows.Forms.TreeNode treeNode26 = new System.Windows.Forms.TreeNode("Boot sector");
            System.Windows.Forms.TreeNode treeNode27 = new System.Windows.Forms.TreeNode("Heuristics", 3, 3, new System.Windows.Forms.TreeNode[] {
            treeNode16,
            treeNode17,
            treeNode18,
            treeNode19,
            treeNode20,
            treeNode21,
            treeNode22,
            treeNode23,
            treeNode24,
            treeNode25,
            treeNode26});
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(CwAdminConsole));
            System.Windows.Forms.ListViewItem listViewItem1 = new System.Windows.Forms.ListViewItem(new string[] {
            "tcpip.sys",
            "\\Device\\Tcp"}, -1);
            this.Button_GenerateMSI = new System.Windows.Forms.Button();
            this.fileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.exitToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.FileSignaturesTabPage = new System.Windows.Forms.TabPage();
            this.FileSignatures_NewFilePESignature = new System.Windows.Forms.TextBox();
            this.label38 = new System.Windows.Forms.Label();
            this.label48 = new System.Windows.Forms.Label();
            this.label49 = new System.Windows.Forms.Label();
            this.FileSignatures_NewFileSize = new System.Windows.Forms.TextBox();
            this.FileSignatures_NewFileHash = new System.Windows.Forms.TextBox();
            this.FileSignatures_NewFilename = new System.Windows.Forms.TextBox();
            this.FileSignatures_NewFileHashTypeSHA1 = new System.Windows.Forms.CheckBox();
            this.FileSignatures_NewFileHashTypeMD5 = new System.Windows.Forms.CheckBox();
            this.label47 = new System.Windows.Forms.Label();
            this.AddFileSignatureButton = new System.Windows.Forms.Button();
            this.FileSignatures_NewAction = new System.Windows.Forms.ComboBox();
            this.label27 = new System.Windows.Forms.Label();
            this.label26 = new System.Windows.Forms.Label();
            this.FileSignatures_Listview = new System.Windows.Forms.ListView();
            this.columnHeader3 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader7 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader10 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader11 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader12 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader13 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader4 = new System.Windows.Forms.ColumnHeader();
            this.DeleteSelectedFileSignature = new System.Windows.Forms.Button();
            this.RegistrySignaturesTabPage = new System.Windows.Forms.TabPage();
            this.label81 = new System.Windows.Forms.Label();
            this.RegistrySignatures_ChangeValueData = new System.Windows.Forms.TextBox();
            this.label80 = new System.Windows.Forms.Label();
            this.RegistrySignatures_Listview = new System.Windows.Forms.ListView();
            this.KeyName = new System.Windows.Forms.ColumnHeader();
            this.ValueName = new System.Windows.Forms.ColumnHeader();
            this.ValueData = new System.Windows.Forms.ColumnHeader();
            this.ChangeValueData = new System.Windows.Forms.ColumnHeader();
            this.Action = new System.Windows.Forms.ColumnHeader();
            this.RegistrySignatures_NewValueName = new System.Windows.Forms.TextBox();
            this.RegistrySignatures_ValueData = new System.Windows.Forms.TextBox();
            this.RegistrySignatures_NewKeyName = new System.Windows.Forms.TextBox();
            this.label40 = new System.Windows.Forms.Label();
            this.label25 = new System.Windows.Forms.Label();
            this.label21 = new System.Windows.Forms.Label();
            this.RegistrySignatures_NewAction = new System.Windows.Forms.ComboBox();
            this.AddRegistrySignatureButton = new System.Windows.Forms.Button();
            this.DeleteRegistrySignatureButton = new System.Windows.Forms.Button();
            this.Button_ScanLocalHost = new System.Windows.Forms.Button();
            this.MainMenuTreeview = new System.Windows.Forms.TreeView();
            this.MainMenuIcons = new System.Windows.Forms.ImageList(this.components);
            this.SignaturesTabContainer = new System.Windows.Forms.TabControl();
            this.RegistryGuidSignaturesTabPage = new System.Windows.Forms.TabPage();
            this.DeleteSelectedGuidButton = new System.Windows.Forms.Button();
            this.RegistryGuidSignatures_Listview = new System.Windows.Forms.ListView();
            this.GuidValue = new System.Windows.Forms.ColumnHeader();
            this.GuidType = new System.Windows.Forms.ColumnHeader();
            this.AddRegGuidButton = new System.Windows.Forms.Button();
            this.StaticRegGuidValue = new System.Windows.Forms.TextBox();
            this.DynRegGuidValueName = new System.Windows.Forms.TextBox();
            this.label36 = new System.Windows.Forms.Label();
            this.DynRegGuidKeyName = new System.Windows.Forms.TextBox();
            this.label35 = new System.Windows.Forms.Label();
            this.label23 = new System.Windows.Forms.Label();
            this.MemorySignaturesTabPage = new System.Windows.Forms.TabPage();
            this.label33 = new System.Windows.Forms.Label();
            this.label32 = new System.Windows.Forms.Label();
            this.MemorySignatures_NewKeywords = new System.Windows.Forms.TextBox();
            this.MemorySignatures_NewProcessName = new System.Windows.Forms.TextBox();
            this.AddMemorySignatureButton = new System.Windows.Forms.Button();
            this.MemorySignatures_NewAction = new System.Windows.Forms.ComboBox();
            this.label28 = new System.Windows.Forms.Label();
            this.label29 = new System.Windows.Forms.Label();
            this.MemorySignatures_Listview = new System.Windows.Forms.ListView();
            this.processname = new System.Windows.Forms.ColumnHeader();
            this.processkeywords = new System.Windows.Forms.ColumnHeader();
            this.processaction = new System.Windows.Forms.ColumnHeader();
            this.DeleteSelectedMemorySignatureButton = new System.Windows.Forms.Button();
            this.HeuristicsTabContainer = new System.Windows.Forms.TabControl();
            this.ProcessThreadTabPage = new System.Windows.Forms.TabPage();
            this.groupBox14 = new System.Windows.Forms.GroupBox();
            this.label22 = new System.Windows.Forms.Label();
            this.ProcessThread_BruteForcePIDs = new System.Windows.Forms.CheckBox();
            this.ProcessThread_Crossview = new System.Windows.Forms.CheckBox();
            this.ModuleTab = new System.Windows.Forms.TabPage();
            this.label84 = new System.Windows.Forms.Label();
            this.ModuleTargets = new System.Windows.Forms.TextBox();
            this.groupBox19 = new System.Windows.Forms.GroupBox();
            this.Module_EATHooks = new System.Windows.Forms.CheckBox();
            this.groupBox18 = new System.Windows.Forms.GroupBox();
            this.Module_IATHooks = new System.Windows.Forms.CheckBox();
            this.BHOToolbarTabPage = new System.Windows.Forms.TabPage();
            this.BHO_CollectBasicInformation = new System.Windows.Forms.CheckBox();
            this.BHO_ScanForUnregisteredBHOs = new System.Windows.Forms.CheckBox();
            this.RegistryHeuristicsTabPage = new System.Windows.Forms.TabPage();
            this.RegistryHeuristics_GUIDScan = new System.Windows.Forms.CheckBox();
            this.RegistryHeuristics_UnsignedSystemModules = new System.Windows.Forms.CheckBox();
            this.RegistryHeuristics_NoOnDiskModule = new System.Windows.Forms.CheckBox();
            this.KernelTabPage = new System.Windows.Forms.TabPage();
            this.groupBox11 = new System.Windows.Forms.GroupBox();
            this.KernelHeuristics_Win32Api_CheckExportsForDetours = new System.Windows.Forms.CheckBox();
            this.groupBox7 = new System.Windows.Forms.GroupBox();
            this.KernelHeuristics_SSDT_DetectHooks = new System.Windows.Forms.CheckBox();
            this.KernelHeuristics_SSDT_DetectDetours = new System.Windows.Forms.CheckBox();
            this.groupBox9 = new System.Windows.Forms.GroupBox();
            this.KernelHeuristics_IDT_DetectHooks = new System.Windows.Forms.CheckBox();
            this.KernelHeuristics_IDT_DetectDetours = new System.Windows.Forms.CheckBox();
            this.groupBox8 = new System.Windows.Forms.GroupBox();
            this.KernelHeuristics_GDT_GetInstalledCallGates = new System.Windows.Forms.CheckBox();
            this.KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors = new System.Windows.Forms.CheckBox();
            this.GDI32SubsystemTabPage = new System.Windows.Forms.TabPage();
            this.groupBox13 = new System.Windows.Forms.GroupBox();
            this.GUISubsystem_CheckSSDTShadowDetours = new System.Windows.Forms.CheckBox();
            this.GUISubsystem_CollectSSDTShadow = new System.Windows.Forms.CheckBox();
            this.DriversTabPage = new System.Windows.Forms.TabPage();
            this.AddDriverListview = new System.Windows.Forms.ListView();
            this.columnHeader9 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader16 = new System.Windows.Forms.ColumnHeader();
            this.label30 = new System.Windows.Forms.Label();
            this.label83 = new System.Windows.Forms.Label();
            this.label60 = new System.Windows.Forms.Label();
            this.AddDriverButton = new System.Windows.Forms.Button();
            this.DriversHeuristics_DetectIRPHooks = new System.Windows.Forms.CheckBox();
            this.label82 = new System.Windows.Forms.Label();
            this.DriversHeuristics_CheckDispatchRoutinesForDetours = new System.Windows.Forms.CheckBox();
            this.AddDriverDevice = new System.Windows.Forms.TextBox();
            this.checkBox1 = new System.Windows.Forms.CheckBox();
            this.label64 = new System.Windows.Forms.Label();
            this.AddDriverModule = new System.Windows.Forms.TextBox();
            this.NdisTdiTabPage = new System.Windows.Forms.TabPage();
            this.NDIS_TDI_FindProtocolStacks = new System.Windows.Forms.CheckBox();
            this.BIOSTabPage = new System.Windows.Forms.TabPage();
            this.BootSectorTabPage = new System.Windows.Forms.TabPage();
            this.MainLogoTextbox = new System.Windows.Forms.TextBox();
            this.menuStrip = new System.Windows.Forms.MenuStrip();
            this.settingsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.loadSettingsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.saveSettingsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.signaturesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.loadSignatureTemplateToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.saveSignatureTemplateToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.allToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.registryToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.fileToolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.memoryToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.helpToolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.administratorConsoleManualToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.agentManualToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.installerManualToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutCodewordToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.TopLevelTabControl = new System.Windows.Forms.TabControl();
            this.CreateNewAgentTabPage = new System.Windows.Forms.TabPage();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.GeneralSettingsTabContainer = new System.Windows.Forms.TabControl();
            this.AgentStartupTabPage = new System.Windows.Forms.TabPage();
            this.groupBox5 = new System.Windows.Forms.GroupBox();
            this.label24 = new System.Windows.Forms.Label();
            this.AgentSelfProtectionRunKernelHeuristicsFirst = new System.Windows.Forms.CheckBox();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.label63 = new System.Windows.Forms.Label();
            this.StartupEnterpriseMode = new System.Windows.Forms.RadioButton();
            this.label62 = new System.Windows.Forms.Label();
            this.label61 = new System.Windows.Forms.Label();
            this.StartupRemoteControlMode = new System.Windows.Forms.RadioButton();
            this.StartupFireAndForgetMode = new System.Windows.Forms.RadioButton();
            this.label66 = new System.Windows.Forms.Label();
            this.AgentConnectionTabPage = new System.Windows.Forms.TabPage();
            this.groupBox6 = new System.Windows.Forms.GroupBox();
            this.label77 = new System.Windows.Forms.Label();
            this.AgentEnforceCertificateIssuer = new System.Windows.Forms.TextBox();
            this.label76 = new System.Windows.Forms.Label();
            this.label75 = new System.Windows.Forms.Label();
            this.label55 = new System.Windows.Forms.Label();
            this.AgentAuthenticateClientToServer = new System.Windows.Forms.CheckBox();
            this.AgentPFXPassword = new System.Windows.Forms.TextBox();
            this.AgentAuthenticateServerToClient = new System.Windows.Forms.CheckBox();
            this.AgentPFXFile = new System.Windows.Forms.TextBox();
            this.AgentEnforceStrongAuthentication = new System.Windows.Forms.CheckBox();
            this.BrowseButton2 = new System.Windows.Forms.Button();
            this.label54 = new System.Windows.Forms.Label();
            this.groupBox4 = new System.Windows.Forms.GroupBox();
            this.AgentRandomizeListeningPort = new System.Windows.Forms.CheckBox();
            this.AgentListeningPort = new System.Windows.Forms.TextBox();
            this.label72 = new System.Windows.Forms.Label();
            this.AgentPersistenceAndStealthTabPage = new System.Windows.Forms.TabPage();
            this.groupBox3 = new System.Windows.Forms.GroupBox();
            this.Stealth_UseZwLoadDriver = new System.Windows.Forms.CheckBox();
            this.Stealth_RandomizeAgentProcessName = new System.Windows.Forms.CheckBox();
            this.label73 = new System.Windows.Forms.Label();
            this.Stealth_HideAgentProcess = new System.Windows.Forms.CheckBox();
            this.Stealth_LoadAndCallImage = new System.Windows.Forms.CheckBox();
            this.Stealth_No_Dotnet = new System.Windows.Forms.CheckBox();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.label74 = new System.Windows.Forms.Label();
            this.AgentServiceName = new System.Windows.Forms.TextBox();
            this.label71 = new System.Windows.Forms.Label();
            this.label68 = new System.Windows.Forms.Label();
            this.label69 = new System.Windows.Forms.Label();
            this.PersistenceRunOnce = new System.Windows.Forms.RadioButton();
            this.PersistenceInstallAsService = new System.Windows.Forms.RadioButton();
            this.label70 = new System.Windows.Forms.Label();
            this.MitigationTabPage = new System.Windows.Forms.TabPage();
            this.Option_AutoMitigate = new System.Windows.Forms.CheckBox();
            this.Option_Delete_MalwareFoundInRegistry = new System.Windows.Forms.CheckBox();
            this.Option_Disable_Autorun = new System.Windows.Forms.CheckBox();
            this.Option_Disable_USB = new System.Windows.Forms.CheckBox();
            this.CollectionModeTabPage = new System.Windows.Forms.TabPage();
            this.textBox4 = new System.Windows.Forms.TextBox();
            this.textBox3 = new System.Windows.Forms.TextBox();
            this.textBox2 = new System.Windows.Forms.TextBox();
            this.textBox1 = new System.Windows.Forms.TextBox();
            this.ModeSelection_MaxParanoia = new System.Windows.Forms.CheckBox();
            this.ModeSelection_Offline = new System.Windows.Forms.RadioButton();
            this.ModeSelection_Live = new System.Windows.Forms.RadioButton();
            this.ReportingTabPage = new System.Windows.Forms.TabPage();
            this.ReportingAuthPanel = new System.Windows.Forms.Panel();
            this.label56 = new System.Windows.Forms.Label();
            this.Reporting_Archive_Password = new System.Windows.Forms.TextBox();
            this.label52 = new System.Windows.Forms.Label();
            this.Reporting_Auth_Type = new System.Windows.Forms.ComboBox();
            this.label51 = new System.Windows.Forms.Label();
            this.label50 = new System.Windows.Forms.Label();
            this.label46 = new System.Windows.Forms.Label();
            this.Reporting_Auth_Server_PubKey = new System.Windows.Forms.TextBox();
            this.Reporting_Auth_Password = new System.Windows.Forms.TextBox();
            this.Reporting_Auth_UserName = new System.Windows.Forms.TextBox();
            this.BrowseButton1 = new System.Windows.Forms.Button();
            this.label20 = new System.Windows.Forms.Label();
            this.label17 = new System.Windows.Forms.Label();
            this.label18 = new System.Windows.Forms.Label();
            this.ReportingTlsPanel = new System.Windows.Forms.Panel();
            this.label53 = new System.Windows.Forms.Label();
            this.Reporting_TLS_Port = new System.Windows.Forms.TextBox();
            this.Reporting_Use_TLS = new System.Windows.Forms.CheckBox();
            this.label13 = new System.Windows.Forms.Label();
            this.ReportingWebPanel = new System.Windows.Forms.Panel();
            this.label45 = new System.Windows.Forms.Label();
            this.Reporting_WebServer_Port = new System.Windows.Forms.TextBox();
            this.label44 = new System.Windows.Forms.Label();
            this.Reporting_Method_WebServer_URI = new System.Windows.Forms.TextBox();
            this.label19 = new System.Windows.Forms.Label();
            this.ReportingEmailPanel = new System.Windows.Forms.Panel();
            this.label43 = new System.Windows.Forms.Label();
            this.Reporting_SMTP_Port = new System.Windows.Forms.TextBox();
            this.Reporting_SMTP_Server = new System.Windows.Forms.TextBox();
            this.Reporting_Method_EmailAddress = new System.Windows.Forms.TextBox();
            this.label16 = new System.Windows.Forms.Label();
            this.label15 = new System.Windows.Forms.Label();
            this.label12 = new System.Windows.Forms.Label();
            this.ReportingFtpPanel = new System.Windows.Forms.Panel();
            this.label57 = new System.Windows.Forms.Label();
            this.Reporting_Method_FTPServer = new System.Windows.Forms.TextBox();
            this.label11 = new System.Windows.Forms.Label();
            this.ReportingNetworkSharePanel = new System.Windows.Forms.Panel();
            this.label42 = new System.Windows.Forms.Label();
            this.Reporting_Method_NetworkShare = new System.Windows.Forms.TextBox();
            this.label31 = new System.Windows.Forms.Label();
            this.label9 = new System.Windows.Forms.Label();
            this.Reporting_EnableAutoReporting = new System.Windows.Forms.CheckBox();
            this.InformationTabPage = new System.Windows.Forms.TabPage();
            this.Information_Notes = new System.Windows.Forms.TextBox();
            this.Information_AdminEmail = new System.Windows.Forms.TextBox();
            this.Information_AdminPhone = new System.Windows.Forms.TextBox();
            this.Information_OrgName = new System.Windows.Forms.TextBox();
            this.Information_AdminName = new System.Windows.Forms.TextBox();
            this.Information_OrgLocation = new System.Windows.Forms.TextBox();
            this.Information_NetworkName = new System.Windows.Forms.TextBox();
            this.Information_NetworkAddrRange = new System.Windows.Forms.TextBox();
            this.label59 = new System.Windows.Forms.Label();
            this.label58 = new System.Windows.Forms.Label();
            this.label8 = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.label14 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.label7 = new System.Windows.Forms.Label();
            this.AdvancedTabPage = new System.Windows.Forms.TabPage();
            this.label67 = new System.Windows.Forms.Label();
            this.Advanced_3rdPartyApp_Distribute = new System.Windows.Forms.CheckBox();
            this.Advanced_3rdPartyApp_Arguments = new System.Windows.Forms.TextBox();
            this.Advanced_3rdPartyApp_Filename = new System.Windows.Forms.TextBox();
            this.label41 = new System.Windows.Forms.Label();
            this.Advanced_File_Browse_Button = new System.Windows.Forms.Button();
            this.label10 = new System.Windows.Forms.Label();
            this.MemorySignatures_UseRegistryFindings = new System.Windows.Forms.CheckBox();
            this.MemorySignatures_SearchCmdLine = new System.Windows.Forms.CheckBox();
            this.MemorySignatures_SearchLoadedModules = new System.Windows.Forms.CheckBox();
            this.MemorySignatures_SearchHeapSpace = new System.Windows.Forms.CheckBox();
            this.label34 = new System.Windows.Forms.Label();
            this.ConnectExistingAgentTabPage = new System.Windows.Forms.TabPage();
            this.AgentTaskProgressBarLabel = new System.Windows.Forms.Label();
            this.AgentTaskProgressBar = new System.Windows.Forms.ProgressBar();
            this.label79 = new System.Windows.Forms.Label();
            this.label78 = new System.Windows.Forms.Label();
            this.LastCommandPane = new System.Windows.Forms.TextBox();
            this.FindingsTabContainer = new System.Windows.Forms.TabControl();
            this.SystemInfoTabPage = new System.Windows.Forms.TabPage();
            this.systemInfoTextarea = new System.Windows.Forms.TextBox();
            this.RegistryFindingsTabPage = new System.Windows.Forms.TabPage();
            this.AgentResults_RegistryListview = new System.Windows.Forms.ListView();
            this.RegistryFindingsKeyName = new System.Windows.Forms.ColumnHeader();
            this.RegistryFindingsValueName = new System.Windows.Forms.ColumnHeader();
            this.RegistryFindingsValueData = new System.Windows.Forms.ColumnHeader();
            this.RegistryFindingsChangeValueData = new System.Windows.Forms.ColumnHeader();
            this.RegistryFindingsIsFileOnDisk = new System.Windows.Forms.ColumnHeader();
            this.RegistryFindingsAction = new System.Windows.Forms.ColumnHeader();
            this.RegistryFindingsActionSuccessful = new System.Windows.Forms.ColumnHeader();
            this.MitigationTasksImageList = new System.Windows.Forms.ImageList(this.components);
            this.FileFindingsTabPage = new System.Windows.Forms.TabPage();
            this.AgentResults_FileListview = new System.Windows.Forms.ListView();
            this.FileFindingsFileName = new System.Windows.Forms.ColumnHeader();
            this.FileFindingsPath = new System.Windows.Forms.ColumnHeader();
            this.FileFindingsSize = new System.Windows.Forms.ColumnHeader();
            this.FileFindingsHash = new System.Windows.Forms.ColumnHeader();
            this.FileFindingsPEHeaderSig = new System.Windows.Forms.ColumnHeader();
            this.FileFindingsCreated = new System.Windows.Forms.ColumnHeader();
            this.FileFindingsAccessed = new System.Windows.Forms.ColumnHeader();
            this.FileFindingsModified = new System.Windows.Forms.ColumnHeader();
            this.FileFindingsAction = new System.Windows.Forms.ColumnHeader();
            this.FileFindingsActionSuccessful = new System.Windows.Forms.ColumnHeader();
            this.MemoryFindingsTabPage = new System.Windows.Forms.TabPage();
            this.AgentResults_MemoryListview = new System.Windows.Forms.ListView();
            this.MemoryFindingsPid = new System.Windows.Forms.ColumnHeader();
            this.MemoryFindingsPpid = new System.Windows.Forms.ColumnHeader();
            this.MemoryFindingsProcessName = new System.Windows.Forms.ColumnHeader();
            this.MemoryFindingsMatchingBlock = new System.Windows.Forms.ColumnHeader();
            this.MemoryFindingsSuspiciousHeapRange = new System.Windows.Forms.ColumnHeader();
            this.MemoryFindingsKeywords = new System.Windows.Forms.ColumnHeader();
            this.MemoryFindingsChildThreads = new System.Windows.Forms.ColumnHeader();
            this.MemoryFindingsAction = new System.Windows.Forms.ColumnHeader();
            this.MemoryFindingsActionSuccessful = new System.Windows.Forms.ColumnHeader();
            this.UserModeAnomaliesTabPage = new System.Windows.Forms.TabPage();
            this.groupBox21 = new System.Windows.Forms.GroupBox();
            this.ProcessResourcesAnomaliesListview = new System.Windows.Forms.ListView();
            this.columnHeader30 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader31 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader32 = new System.Windows.Forms.ColumnHeader();
            this.AnomaliesIcons = new System.Windows.Forms.ImageList(this.components);
            this.groupBox20 = new System.Windows.Forms.GroupBox();
            this.ProcessAnomaliesListview = new System.Windows.Forms.ListView();
            this.columnHeader25 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader26 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader27 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader28 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader29 = new System.Windows.Forms.ColumnHeader();
            this.KernelModeAnomaliesTabPage = new System.Windows.Forms.TabPage();
            this.groupBox17 = new System.Windows.Forms.GroupBox();
            this.DriverAnomaliesListview = new System.Windows.Forms.ListView();
            this.columnHeader17 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader18 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader24 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader19 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader20 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader21 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader22 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader23 = new System.Windows.Forms.ColumnHeader();
            this.groupBox12 = new System.Windows.Forms.GroupBox();
            this.Win32ApiDetoursListview = new System.Windows.Forms.ListView();
            this.columnHeader8 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader1 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader2 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader5 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader14 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader6 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader15 = new System.Windows.Forms.ColumnHeader();
            this.groupBox10 = new System.Windows.Forms.GroupBox();
            this.SSDTAnomaliesListview = new System.Windows.Forms.ListView();
            this.SSDTIndex = new System.Windows.Forms.ColumnHeader();
            this.SSDTFuncAddr = new System.Windows.Forms.ColumnHeader();
            this.SSDTAnomaly = new System.Windows.Forms.ColumnHeader();
            this.SSDTFuncExpected = new System.Windows.Forms.ColumnHeader();
            this.SSDTFuncFound = new System.Windows.Forms.ColumnHeader();
            this.SSDTSuspectMod = new System.Windows.Forms.ColumnHeader();
            this.SSDTDetourTarget = new System.Windows.Forms.ColumnHeader();
            this.SSDTFuncDisassembly = new System.Windows.Forms.ColumnHeader();
            this.LowLevelAnomaliesTabPage = new System.Windows.Forms.TabPage();
            this.RecentAgentsTreeview = new System.Windows.Forms.TreeView();
            this.LogWindow = new System.Windows.Forms.TextBox();
            this.ConnectAgentToolstrip = new System.Windows.Forms.ToolStrip();
            this.ConnectToAgentIP = new System.Windows.Forms.ToolStripTextBox();
            this.ConnectToAgentPort = new System.Windows.Forms.ToolStripTextBox();
            this.ConnectAgentButton = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            this.StartScanButton = new System.Windows.Forms.ToolStripButton();
            this.UpdateAgentButton = new System.Windows.Forms.ToolStripButton();
            this.DownloadEvidenceButton = new System.Windows.Forms.ToolStripButton();
            this.PerformMitigationTasksButton = new System.Windows.Forms.ToolStripButton();
            this.SetAdminConsoleCredentialsButton = new System.Windows.Forms.ToolStripButton();
            this.DisconnectAgentButton = new System.Windows.Forms.ToolStripButton();
            this.HaltAgentButton = new System.Windows.Forms.ToolStripButton();
            this.EnterprisePullTabPage = new System.Windows.Forms.TabPage();
            this.columnHeader35 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader37 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader38 = new System.Windows.Forms.ColumnHeader();
            this.checkBox3 = new System.Windows.Forms.CheckBox();
            this.label37 = new System.Windows.Forms.Label();
            this.checkBox4 = new System.Windows.Forms.CheckBox();
            this.textBox5 = new System.Windows.Forms.TextBox();
            this.label39 = new System.Windows.Forms.Label();
            this.button1 = new System.Windows.Forms.Button();
            this.textBox6 = new System.Windows.Forms.TextBox();
            this.label65 = new System.Windows.Forms.Label();
            this.ToolTipShowAnExample = new System.Windows.Forms.ToolTip(this.components);
            this.FileSignaturesTabPage.SuspendLayout();
            this.RegistrySignaturesTabPage.SuspendLayout();
            this.SignaturesTabContainer.SuspendLayout();
            this.RegistryGuidSignaturesTabPage.SuspendLayout();
            this.MemorySignaturesTabPage.SuspendLayout();
            this.HeuristicsTabContainer.SuspendLayout();
            this.ProcessThreadTabPage.SuspendLayout();
            this.groupBox14.SuspendLayout();
            this.ModuleTab.SuspendLayout();
            this.groupBox19.SuspendLayout();
            this.groupBox18.SuspendLayout();
            this.BHOToolbarTabPage.SuspendLayout();
            this.RegistryHeuristicsTabPage.SuspendLayout();
            this.KernelTabPage.SuspendLayout();
            this.groupBox11.SuspendLayout();
            this.groupBox7.SuspendLayout();
            this.groupBox9.SuspendLayout();
            this.groupBox8.SuspendLayout();
            this.GDI32SubsystemTabPage.SuspendLayout();
            this.groupBox13.SuspendLayout();
            this.DriversTabPage.SuspendLayout();
            this.NdisTdiTabPage.SuspendLayout();
            this.menuStrip.SuspendLayout();
            this.TopLevelTabControl.SuspendLayout();
            this.CreateNewAgentTabPage.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            this.GeneralSettingsTabContainer.SuspendLayout();
            this.AgentStartupTabPage.SuspendLayout();
            this.groupBox5.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.AgentConnectionTabPage.SuspendLayout();
            this.groupBox6.SuspendLayout();
            this.groupBox4.SuspendLayout();
            this.AgentPersistenceAndStealthTabPage.SuspendLayout();
            this.groupBox3.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.MitigationTabPage.SuspendLayout();
            this.CollectionModeTabPage.SuspendLayout();
            this.ReportingTabPage.SuspendLayout();
            this.ReportingAuthPanel.SuspendLayout();
            this.ReportingTlsPanel.SuspendLayout();
            this.ReportingWebPanel.SuspendLayout();
            this.ReportingEmailPanel.SuspendLayout();
            this.ReportingFtpPanel.SuspendLayout();
            this.ReportingNetworkSharePanel.SuspendLayout();
            this.InformationTabPage.SuspendLayout();
            this.AdvancedTabPage.SuspendLayout();
            this.ConnectExistingAgentTabPage.SuspendLayout();
            this.FindingsTabContainer.SuspendLayout();
            this.SystemInfoTabPage.SuspendLayout();
            this.RegistryFindingsTabPage.SuspendLayout();
            this.FileFindingsTabPage.SuspendLayout();
            this.MemoryFindingsTabPage.SuspendLayout();
            this.UserModeAnomaliesTabPage.SuspendLayout();
            this.groupBox21.SuspendLayout();
            this.groupBox20.SuspendLayout();
            this.KernelModeAnomaliesTabPage.SuspendLayout();
            this.groupBox17.SuspendLayout();
            this.groupBox12.SuspendLayout();
            this.groupBox10.SuspendLayout();
            this.ConnectAgentToolstrip.SuspendLayout();
            this.SuspendLayout();
            // 
            // Button_GenerateMSI
            // 
            this.Button_GenerateMSI.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.Button_GenerateMSI.Location = new System.Drawing.Point(11, 411);
            this.Button_GenerateMSI.Name = "Button_GenerateMSI";
            this.Button_GenerateMSI.Size = new System.Drawing.Size(122, 34);
            this.Button_GenerateMSI.TabIndex = 20;
            this.Button_GenerateMSI.Text = "Generate MSI";
            this.Button_GenerateMSI.UseVisualStyleBackColor = false;
            this.Button_GenerateMSI.Click += new System.EventHandler(this.Button_GenerateMSI_Click);
            // 
            // fileToolStripMenuItem
            // 
            this.fileToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.exitToolStripMenuItem});
            this.fileToolStripMenuItem.Name = "fileToolStripMenuItem";
            this.fileToolStripMenuItem.Size = new System.Drawing.Size(37, 20);
            this.fileToolStripMenuItem.Text = "File";
            // 
            // exitToolStripMenuItem
            // 
            this.exitToolStripMenuItem.Name = "exitToolStripMenuItem";
            this.exitToolStripMenuItem.Size = new System.Drawing.Size(92, 22);
            this.exitToolStripMenuItem.Text = "Exit";
            this.exitToolStripMenuItem.Click += new System.EventHandler(this.exitToolStripMenuItem_Click);
            // 
            // FileSignaturesTabPage
            // 
            this.FileSignaturesTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.FileSignaturesTabPage.Controls.Add(this.FileSignatures_NewFilePESignature);
            this.FileSignaturesTabPage.Controls.Add(this.label38);
            this.FileSignaturesTabPage.Controls.Add(this.label48);
            this.FileSignaturesTabPage.Controls.Add(this.label49);
            this.FileSignaturesTabPage.Controls.Add(this.FileSignatures_NewFileSize);
            this.FileSignaturesTabPage.Controls.Add(this.FileSignatures_NewFileHash);
            this.FileSignaturesTabPage.Controls.Add(this.FileSignatures_NewFilename);
            this.FileSignaturesTabPage.Controls.Add(this.FileSignatures_NewFileHashTypeSHA1);
            this.FileSignaturesTabPage.Controls.Add(this.FileSignatures_NewFileHashTypeMD5);
            this.FileSignaturesTabPage.Controls.Add(this.label47);
            this.FileSignaturesTabPage.Controls.Add(this.AddFileSignatureButton);
            this.FileSignaturesTabPage.Controls.Add(this.FileSignatures_NewAction);
            this.FileSignaturesTabPage.Controls.Add(this.label27);
            this.FileSignaturesTabPage.Controls.Add(this.label26);
            this.FileSignaturesTabPage.Controls.Add(this.FileSignatures_Listview);
            this.FileSignaturesTabPage.Controls.Add(this.DeleteSelectedFileSignature);
            this.FileSignaturesTabPage.ForeColor = System.Drawing.Color.White;
            this.FileSignaturesTabPage.Location = new System.Drawing.Point(4, 22);
            this.FileSignaturesTabPage.Name = "FileSignaturesTabPage";
            this.FileSignaturesTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.FileSignaturesTabPage.Size = new System.Drawing.Size(892, 493);
            this.FileSignaturesTabPage.TabIndex = 1;
            this.FileSignaturesTabPage.Text = "File";
            // 
            // FileSignatures_NewFilePESignature
            // 
            this.FileSignatures_NewFilePESignature.Location = new System.Drawing.Point(97, 96);
            this.FileSignatures_NewFilePESignature.Name = "FileSignatures_NewFilePESignature";
            this.FileSignatures_NewFilePESignature.Size = new System.Drawing.Size(217, 20);
            this.FileSignatures_NewFilePESignature.TabIndex = 58;
            this.ToolTipShowAnExample.SetToolTip(this.FileSignatures_NewFilePESignature, "[OPTIONAL]  See the documentation for details on defining a PE header signature.");
            // 
            // label38
            // 
            this.label38.AutoSize = true;
            this.label38.Location = new System.Drawing.Point(18, 94);
            this.label38.Name = "label38";
            this.label38.Size = new System.Drawing.Size(70, 13);
            this.label38.TabIndex = 59;
            this.label38.Text = "PE signature:";
            // 
            // label48
            // 
            this.label48.AutoSize = true;
            this.label48.Location = new System.Drawing.Point(494, 53);
            this.label48.Name = "label48";
            this.label48.Size = new System.Drawing.Size(32, 13);
            this.label48.TabIndex = 57;
            this.label48.Text = "bytes";
            // 
            // label49
            // 
            this.label49.AutoSize = true;
            this.label49.Location = new System.Drawing.Point(345, 52);
            this.label49.Name = "label49";
            this.label49.Size = new System.Drawing.Size(47, 13);
            this.label49.TabIndex = 56;
            this.label49.Text = "File size:";
            // 
            // FileSignatures_NewFileSize
            // 
            this.FileSignatures_NewFileSize.Location = new System.Drawing.Point(400, 49);
            this.FileSignatures_NewFileSize.Name = "FileSignatures_NewFileSize";
            this.FileSignatures_NewFileSize.Size = new System.Drawing.Size(88, 20);
            this.FileSignatures_NewFileSize.TabIndex = 55;
            this.ToolTipShowAnExample.SetToolTip(this.FileSignatures_NewFileSize, "[OPTIONAL] If you know the file size, specify it here.");
            // 
            // FileSignatures_NewFileHash
            // 
            this.FileSignatures_NewFileHash.Location = new System.Drawing.Point(97, 46);
            this.FileSignatures_NewFileHash.Name = "FileSignatures_NewFileHash";
            this.FileSignatures_NewFileHash.Size = new System.Drawing.Size(217, 20);
            this.FileSignatures_NewFileHash.TabIndex = 16;
            this.ToolTipShowAnExample.SetToolTip(this.FileSignatures_NewFileHash, "[OPTIONAL] If you know the MD-5 or SHA-1 hash, specify it here.");
            // 
            // FileSignatures_NewFilename
            // 
            this.FileSignatures_NewFilename.Location = new System.Drawing.Point(97, 14);
            this.FileSignatures_NewFilename.Name = "FileSignatures_NewFilename";
            this.FileSignatures_NewFilename.Size = new System.Drawing.Size(217, 20);
            this.FileSignatures_NewFilename.TabIndex = 12;
            this.ToolTipShowAnExample.SetToolTip(this.FileSignatures_NewFilename, "[OPTIONAL] Specify the file name ONLY - not the full path.  E.g, HookingMalware.d" +
                    "ll");
            // 
            // FileSignatures_NewFileHashTypeSHA1
            // 
            this.FileSignatures_NewFileHashTypeSHA1.AutoSize = true;
            this.FileSignatures_NewFileHashTypeSHA1.ForeColor = System.Drawing.Color.White;
            this.FileSignatures_NewFileHashTypeSHA1.Location = new System.Drawing.Point(155, 71);
            this.FileSignatures_NewFileHashTypeSHA1.Name = "FileSignatures_NewFileHashTypeSHA1";
            this.FileSignatures_NewFileHashTypeSHA1.Size = new System.Drawing.Size(57, 17);
            this.FileSignatures_NewFileHashTypeSHA1.TabIndex = 51;
            this.FileSignatures_NewFileHashTypeSHA1.Text = "SHA-1";
            this.FileSignatures_NewFileHashTypeSHA1.UseVisualStyleBackColor = true;
            this.FileSignatures_NewFileHashTypeSHA1.CheckedChanged += new System.EventHandler(this.FileSignatures_NewFileHashTypeSHA1_CheckedChanged);
            // 
            // FileSignatures_NewFileHashTypeMD5
            // 
            this.FileSignatures_NewFileHashTypeMD5.AutoSize = true;
            this.FileSignatures_NewFileHashTypeMD5.ForeColor = System.Drawing.Color.White;
            this.FileSignatures_NewFileHashTypeMD5.Location = new System.Drawing.Point(97, 71);
            this.FileSignatures_NewFileHashTypeMD5.Name = "FileSignatures_NewFileHashTypeMD5";
            this.FileSignatures_NewFileHashTypeMD5.Size = new System.Drawing.Size(52, 17);
            this.FileSignatures_NewFileHashTypeMD5.TabIndex = 50;
            this.FileSignatures_NewFileHashTypeMD5.Text = "MD-5";
            this.FileSignatures_NewFileHashTypeMD5.UseVisualStyleBackColor = true;
            this.FileSignatures_NewFileHashTypeMD5.CheckedChanged += new System.EventHandler(this.FileSignatures_NewFileHashTypeMD5_CheckedChanged);
            // 
            // label47
            // 
            this.label47.AutoSize = true;
            this.label47.ForeColor = System.Drawing.Color.White;
            this.label47.Location = new System.Drawing.Point(18, 49);
            this.label47.Name = "label47";
            this.label47.Size = new System.Drawing.Size(52, 13);
            this.label47.TabIndex = 17;
            this.label47.Text = "File hash:";
            // 
            // AddFileSignatureButton
            // 
            this.AddFileSignatureButton.ForeColor = System.Drawing.Color.Black;
            this.AddFileSignatureButton.Location = new System.Drawing.Point(781, 78);
            this.AddFileSignatureButton.Name = "AddFileSignatureButton";
            this.AddFileSignatureButton.Size = new System.Drawing.Size(108, 25);
            this.AddFileSignatureButton.TabIndex = 15;
            this.AddFileSignatureButton.Text = "Add";
            this.AddFileSignatureButton.UseVisualStyleBackColor = true;
            this.AddFileSignatureButton.Click += new System.EventHandler(this.AddFileSignatureButton_Click);
            // 
            // FileSignatures_NewAction
            // 
            this.FileSignatures_NewAction.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.FileSignatures_NewAction.FormattingEnabled = true;
            this.FileSignatures_NewAction.Items.AddRange(new object[] {
            "Delete if found"});
            this.FileSignatures_NewAction.Location = new System.Drawing.Point(400, 14);
            this.FileSignatures_NewAction.Name = "FileSignatures_NewAction";
            this.FileSignatures_NewAction.Size = new System.Drawing.Size(140, 21);
            this.FileSignatures_NewAction.TabIndex = 14;
            this.ToolTipShowAnExample.SetToolTip(this.FileSignatures_NewAction, "[REQUIRED] What do you want to do with this item if it is found?");
            // 
            // label27
            // 
            this.label27.AutoSize = true;
            this.label27.ForeColor = System.Drawing.Color.White;
            this.label27.Location = new System.Drawing.Point(345, 17);
            this.label27.Name = "label27";
            this.label27.Size = new System.Drawing.Size(40, 13);
            this.label27.TabIndex = 13;
            this.label27.Text = "Action:";
            // 
            // label26
            // 
            this.label26.AutoSize = true;
            this.label26.ForeColor = System.Drawing.Color.White;
            this.label26.Location = new System.Drawing.Point(18, 17);
            this.label26.Name = "label26";
            this.label26.Size = new System.Drawing.Size(55, 13);
            this.label26.TabIndex = 11;
            this.label26.Text = "File name:";
            // 
            // FileSignatures_Listview
            // 
            this.FileSignatures_Listview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader3,
            this.columnHeader7,
            this.columnHeader10,
            this.columnHeader11,
            this.columnHeader12,
            this.columnHeader13,
            this.columnHeader4});
            this.FileSignatures_Listview.FullRowSelect = true;
            this.FileSignatures_Listview.GridLines = true;
            this.FileSignatures_Listview.Location = new System.Drawing.Point(6, 136);
            this.FileSignatures_Listview.MultiSelect = false;
            this.FileSignatures_Listview.Name = "FileSignatures_Listview";
            this.FileSignatures_Listview.ShowItemToolTips = true;
            this.FileSignatures_Listview.Size = new System.Drawing.Size(883, 308);
            this.FileSignatures_Listview.TabIndex = 9;
            this.FileSignatures_Listview.UseCompatibleStateImageBehavior = false;
            this.FileSignatures_Listview.View = System.Windows.Forms.View.Details;
            this.FileSignatures_Listview.SelectedIndexChanged += new System.EventHandler(this.FileSignatures_Listview_SelectedIndexChanged);
            // 
            // columnHeader3
            // 
            this.columnHeader3.Text = "Name";
            this.columnHeader3.Width = 103;
            // 
            // columnHeader7
            // 
            this.columnHeader7.Text = "Hash";
            this.columnHeader7.Width = 84;
            // 
            // columnHeader10
            // 
            this.columnHeader10.Text = "Hash Type";
            this.columnHeader10.Width = 68;
            // 
            // columnHeader11
            // 
            this.columnHeader11.Text = "Size";
            this.columnHeader11.Width = 64;
            // 
            // columnHeader12
            // 
            this.columnHeader12.Text = "PE Hash";
            this.columnHeader12.Width = 107;
            // 
            // columnHeader13
            // 
            this.columnHeader13.Text = "PE Hash Type";
            this.columnHeader13.Width = 86;
            // 
            // columnHeader4
            // 
            this.columnHeader4.Text = "Action";
            this.columnHeader4.Width = 113;
            // 
            // DeleteSelectedFileSignature
            // 
            this.DeleteSelectedFileSignature.ForeColor = System.Drawing.Color.Black;
            this.DeleteSelectedFileSignature.Location = new System.Drawing.Point(781, 108);
            this.DeleteSelectedFileSignature.Name = "DeleteSelectedFileSignature";
            this.DeleteSelectedFileSignature.Size = new System.Drawing.Size(108, 23);
            this.DeleteSelectedFileSignature.TabIndex = 8;
            this.DeleteSelectedFileSignature.Text = "Delete Selected";
            this.DeleteSelectedFileSignature.UseVisualStyleBackColor = true;
            this.DeleteSelectedFileSignature.Click += new System.EventHandler(this.DeleteSelectedFileSignatureButton_Click);
            // 
            // RegistrySignaturesTabPage
            // 
            this.RegistrySignaturesTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.RegistrySignaturesTabPage.Controls.Add(this.label81);
            this.RegistrySignaturesTabPage.Controls.Add(this.RegistrySignatures_ChangeValueData);
            this.RegistrySignaturesTabPage.Controls.Add(this.label80);
            this.RegistrySignaturesTabPage.Controls.Add(this.RegistrySignatures_Listview);
            this.RegistrySignaturesTabPage.Controls.Add(this.RegistrySignatures_NewValueName);
            this.RegistrySignaturesTabPage.Controls.Add(this.RegistrySignatures_ValueData);
            this.RegistrySignaturesTabPage.Controls.Add(this.RegistrySignatures_NewKeyName);
            this.RegistrySignaturesTabPage.Controls.Add(this.label40);
            this.RegistrySignaturesTabPage.Controls.Add(this.label25);
            this.RegistrySignaturesTabPage.Controls.Add(this.label21);
            this.RegistrySignaturesTabPage.Controls.Add(this.RegistrySignatures_NewAction);
            this.RegistrySignaturesTabPage.Controls.Add(this.AddRegistrySignatureButton);
            this.RegistrySignaturesTabPage.Controls.Add(this.DeleteRegistrySignatureButton);
            this.RegistrySignaturesTabPage.ForeColor = System.Drawing.Color.White;
            this.RegistrySignaturesTabPage.Location = new System.Drawing.Point(4, 22);
            this.RegistrySignaturesTabPage.Name = "RegistrySignaturesTabPage";
            this.RegistrySignaturesTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.RegistrySignaturesTabPage.Size = new System.Drawing.Size(892, 493);
            this.RegistrySignaturesTabPage.TabIndex = 0;
            this.RegistrySignaturesTabPage.Text = "Registry";
            // 
            // label81
            // 
            this.label81.AutoSize = true;
            this.label81.Location = new System.Drawing.Point(14, 88);
            this.label81.Name = "label81";
            this.label81.Size = new System.Drawing.Size(58, 13);
            this.label81.TabIndex = 58;
            this.label81.Text = "New Data:";
            // 
            // RegistrySignatures_ChangeValueData
            // 
            this.RegistrySignatures_ChangeValueData.Enabled = false;
            this.RegistrySignatures_ChangeValueData.Location = new System.Drawing.Point(81, 85);
            this.RegistrySignatures_ChangeValueData.Multiline = true;
            this.RegistrySignatures_ChangeValueData.Name = "RegistrySignatures_ChangeValueData";
            this.RegistrySignatures_ChangeValueData.Size = new System.Drawing.Size(372, 32);
            this.RegistrySignatures_ChangeValueData.TabIndex = 57;
            this.ToolTipShowAnExample.SetToolTip(this.RegistrySignatures_ChangeValueData, "[OPTIONAL] This field is only used when you have selected the \"Change...\" action " +
                    "from the drop-down below.");
            // 
            // label80
            // 
            this.label80.AutoSize = true;
            this.label80.Location = new System.Drawing.Point(623, 17);
            this.label80.Name = "label80";
            this.label80.Size = new System.Drawing.Size(71, 13);
            this.label80.TabIndex = 56;
            this.label80.Text = "(Value Name)";
            // 
            // RegistrySignatures_Listview
            // 
            this.RegistrySignatures_Listview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.KeyName,
            this.ValueName,
            this.ValueData,
            this.ChangeValueData,
            this.Action});
            this.RegistrySignatures_Listview.FullRowSelect = true;
            this.RegistrySignatures_Listview.GridLines = true;
            this.RegistrySignatures_Listview.Location = new System.Drawing.Point(6, 136);
            this.RegistrySignatures_Listview.Name = "RegistrySignatures_Listview";
            this.RegistrySignatures_Listview.Size = new System.Drawing.Size(883, 308);
            this.RegistrySignatures_Listview.TabIndex = 55;
            this.RegistrySignatures_Listview.UseCompatibleStateImageBehavior = false;
            this.RegistrySignatures_Listview.View = System.Windows.Forms.View.Details;
            this.RegistrySignatures_Listview.SelectedIndexChanged += new System.EventHandler(this.RegistrySignatures_Listview_SelectedIndexChanged);
            // 
            // KeyName
            // 
            this.KeyName.Text = "Key Name";
            this.KeyName.Width = 182;
            // 
            // ValueName
            // 
            this.ValueName.Text = "Value Name";
            this.ValueName.Width = 119;
            // 
            // ValueData
            // 
            this.ValueData.Text = "Value Data";
            this.ValueData.Width = 120;
            // 
            // ChangeValueData
            // 
            this.ChangeValueData.Text = "New Value Data";
            this.ChangeValueData.Width = 97;
            // 
            // Action
            // 
            this.Action.Text = "Action";
            this.Action.Width = 104;
            // 
            // RegistrySignatures_NewValueName
            // 
            this.RegistrySignatures_NewValueName.Location = new System.Drawing.Point(472, 14);
            this.RegistrySignatures_NewValueName.Name = "RegistrySignatures_NewValueName";
            this.RegistrySignatures_NewValueName.Size = new System.Drawing.Size(139, 20);
            this.RegistrySignatures_NewValueName.TabIndex = 51;
            this.ToolTipShowAnExample.SetToolTip(this.RegistrySignatures_NewValueName, "[OPTIONAL] Put the registry key\'s value name here, e.g., InprocServer32");
            // 
            // RegistrySignatures_ValueData
            // 
            this.RegistrySignatures_ValueData.Location = new System.Drawing.Point(81, 44);
            this.RegistrySignatures_ValueData.Multiline = true;
            this.RegistrySignatures_ValueData.Name = "RegistrySignatures_ValueData";
            this.RegistrySignatures_ValueData.Size = new System.Drawing.Size(372, 32);
            this.RegistrySignatures_ValueData.TabIndex = 44;
            this.ToolTipShowAnExample.SetToolTip(this.RegistrySignatures_ValueData, "[OPTIONAL] If you already know what the value data should be for this key, specif" +
                    "y it here.");
            // 
            // RegistrySignatures_NewKeyName
            // 
            this.RegistrySignatures_NewKeyName.Location = new System.Drawing.Point(81, 14);
            this.RegistrySignatures_NewKeyName.Name = "RegistrySignatures_NewKeyName";
            this.RegistrySignatures_NewKeyName.Size = new System.Drawing.Size(372, 20);
            this.RegistrySignatures_NewKeyName.TabIndex = 39;
            this.ToolTipShowAnExample.SetToolTip(this.RegistrySignatures_NewKeyName, "[REQUIRED] Be sure to reference any GUIDs you have defined, e.g., HKCR\\CLSID\\{GUI" +
                    "D}\\InprocServer32");
            this.RegistrySignatures_NewKeyName.TextChanged += new System.EventHandler(this.RegistrySignatures_NewKeyName_TextChanged);
            // 
            // label40
            // 
            this.label40.AutoSize = true;
            this.label40.Location = new System.Drawing.Point(458, 17);
            this.label40.Name = "label40";
            this.label40.Size = new System.Drawing.Size(12, 13);
            this.label40.TabIndex = 52;
            this.label40.Text = "\\";
            // 
            // label25
            // 
            this.label25.AutoSize = true;
            this.label25.Location = new System.Drawing.Point(13, 49);
            this.label25.Name = "label25";
            this.label25.Size = new System.Drawing.Size(63, 13);
            this.label25.TabIndex = 43;
            this.label25.Text = "Value Data:";
            // 
            // label21
            // 
            this.label21.AutoSize = true;
            this.label21.Location = new System.Drawing.Point(13, 17);
            this.label21.Name = "label21";
            this.label21.Size = new System.Drawing.Size(28, 13);
            this.label21.TabIndex = 41;
            this.label21.Text = "Key:";
            // 
            // RegistrySignatures_NewAction
            // 
            this.RegistrySignatures_NewAction.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.RegistrySignatures_NewAction.ForeColor = System.Drawing.Color.Black;
            this.RegistrySignatures_NewAction.FormattingEnabled = true;
            this.RegistrySignatures_NewAction.Items.AddRange(new object[] {
            "Delete",
            "Delete All",
            "Clear",
            "Change...",
            "Leave Alone"});
            this.RegistrySignatures_NewAction.Location = new System.Drawing.Point(472, 48);
            this.RegistrySignatures_NewAction.Name = "RegistrySignatures_NewAction";
            this.RegistrySignatures_NewAction.Size = new System.Drawing.Size(136, 21);
            this.RegistrySignatures_NewAction.TabIndex = 40;
            this.ToolTipShowAnExample.SetToolTip(this.RegistrySignatures_NewAction, "[REQUIRED] What do you want to do with this item if it is found?");
            this.RegistrySignatures_NewAction.SelectedIndexChanged += new System.EventHandler(this.RegistrySignatures_NewAction_SelectedIndexChanged);
            // 
            // AddRegistrySignatureButton
            // 
            this.AddRegistrySignatureButton.ForeColor = System.Drawing.Color.Black;
            this.AddRegistrySignatureButton.Location = new System.Drawing.Point(781, 77);
            this.AddRegistrySignatureButton.Name = "AddRegistrySignatureButton";
            this.AddRegistrySignatureButton.Size = new System.Drawing.Size(108, 27);
            this.AddRegistrySignatureButton.TabIndex = 38;
            this.AddRegistrySignatureButton.Text = "Add";
            this.AddRegistrySignatureButton.UseVisualStyleBackColor = true;
            this.AddRegistrySignatureButton.Click += new System.EventHandler(this.AddRegistrySignatureButton_Click);
            // 
            // DeleteRegistrySignatureButton
            // 
            this.DeleteRegistrySignatureButton.ForeColor = System.Drawing.Color.Black;
            this.DeleteRegistrySignatureButton.Location = new System.Drawing.Point(781, 108);
            this.DeleteRegistrySignatureButton.Name = "DeleteRegistrySignatureButton";
            this.DeleteRegistrySignatureButton.Size = new System.Drawing.Size(108, 23);
            this.DeleteRegistrySignatureButton.TabIndex = 36;
            this.DeleteRegistrySignatureButton.Text = "Delete Selected";
            this.DeleteRegistrySignatureButton.UseVisualStyleBackColor = true;
            this.DeleteRegistrySignatureButton.Click += new System.EventHandler(this.DeleteRegistrySignatureButton_Click);
            // 
            // Button_ScanLocalHost
            // 
            this.Button_ScanLocalHost.BackColor = System.Drawing.SystemColors.ControlDark;
            this.Button_ScanLocalHost.Location = new System.Drawing.Point(139, 411);
            this.Button_ScanLocalHost.Name = "Button_ScanLocalHost";
            this.Button_ScanLocalHost.Size = new System.Drawing.Size(120, 34);
            this.Button_ScanLocalHost.TabIndex = 27;
            this.Button_ScanLocalHost.Text = "Scan Local Host";
            this.Button_ScanLocalHost.UseVisualStyleBackColor = false;
            this.Button_ScanLocalHost.Click += new System.EventHandler(this.Button_ScanLocalHost_Click);
            // 
            // MainMenuTreeview
            // 
            this.MainMenuTreeview.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.MainMenuTreeview.Cursor = System.Windows.Forms.Cursors.Hand;
            this.MainMenuTreeview.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.MainMenuTreeview.ForeColor = System.Drawing.SystemColors.Window;
            this.MainMenuTreeview.HideSelection = false;
            this.MainMenuTreeview.ImageIndex = 0;
            this.MainMenuTreeview.ImageList = this.MainMenuIcons;
            this.MainMenuTreeview.ItemHeight = 25;
            this.MainMenuTreeview.LineColor = System.Drawing.Color.White;
            this.MainMenuTreeview.Location = new System.Drawing.Point(11, 6);
            this.MainMenuTreeview.Name = "MainMenuTreeview";
            treeNode1.ImageIndex = 0;
            treeNode1.Name = "ChildNode_GeneralSettings1";
            treeNode1.SelectedImageIndex = 0;
            treeNode1.Text = "Startup";
            treeNode2.ImageIndex = 0;
            treeNode2.Name = "ChildNode_GeneralSettings2";
            treeNode2.Text = "Connection";
            treeNode3.ImageIndex = 0;
            treeNode3.Name = "ChildNode_GeneralSettings3";
            treeNode3.Text = "Persistence/Stealth";
            treeNode4.Name = "ChildNode_GeneralSettings4";
            treeNode4.Text = "Mitigation";
            treeNode5.ImageIndex = 0;
            treeNode5.Name = "ChildNode_GeneralSettings5";
            treeNode5.Text = "Collection Mode";
            treeNode6.Name = "ChildNode_GeneralSettings6";
            treeNode6.Text = "Reporting";
            treeNode7.Name = "ChildNode_GeneralSettings7";
            treeNode7.Text = "Information";
            treeNode8.Name = "ChildNode_GeneralSettings8";
            treeNode8.Text = "Misc. Options";
            treeNode9.Name = "ChildNode_GeneralSettings9";
            treeNode9.Text = "Advanced";
            treeNode10.ImageIndex = 2;
            treeNode10.Name = "RootNode_GeneralSettings";
            treeNode10.SelectedImageIndex = 2;
            treeNode10.Text = "Agent Settings";
            treeNode11.Name = "ChildNode_Signatures_RegistryGuid";
            treeNode11.Text = "Registry Guid";
            treeNode12.Name = "ChildNode_Signatures_Registry";
            treeNode12.Text = "Registry";
            treeNode13.Name = "ChildNode_Signatures_File";
            treeNode13.Text = "File";
            treeNode14.Name = "ChildNode_Signatures_Memory";
            treeNode14.Text = "Memory";
            treeNode15.ImageIndex = 1;
            treeNode15.Name = "RootNode_Signatures";
            treeNode15.SelectedImageIndex = 1;
            treeNode15.Text = "Signatures";
            treeNode16.Name = "ChildNode_Heuristics_UserModeIntegrity_ProcessThread";
            treeNode16.Text = "Process/Thread";
            treeNode17.Name = "Node0";
            treeNode17.Text = "Module";
            treeNode18.Name = "ChildNode_Heuristics_UserModeIntegrity_BHOToolbar";
            treeNode18.Text = "BHO/Toolbar";
            treeNode19.Name = "ChildNode_Heuristics_UserModeIntegrity_Registry";
            treeNode19.Text = "Registry";
            treeNode20.Name = "ChildNode_Heuristics_KernelModeIntegrity_Kernel";
            treeNode20.Text = "Kernel/Ntdll";
            treeNode21.Name = "ChildNode_Heuristics_KernelModeIntegrity_GUISubsystem";
            treeNode21.Text = "GDI32 Subsystem";
            treeNode22.Name = "ChildNode_Heuristics_KernelModeIntegrity_Drivers";
            treeNode22.Text = "Drivers";
            treeNode23.Name = "ChildNode_Heuristics_KernelModeIntegrity_CallGates";
            treeNode23.Text = "Call Gates";
            treeNode24.Name = "ChildNode_Heuristics_KernelModeIntegrity_NDIS_TDI";
            treeNode24.Text = "NDIS/TDI";
            treeNode25.Name = "ChildNode_Heuristics_LowLevelIntegrity_BIOS";
            treeNode25.Text = "BIOS";
            treeNode26.Name = "ChildNode_Heuristics_LowLevelIntegrity_BootSector";
            treeNode26.Text = "Boot sector";
            treeNode27.ImageIndex = 3;
            treeNode27.Name = "RootNode_Heuristics";
            treeNode27.SelectedImageIndex = 3;
            treeNode27.Text = "Heuristics";
            this.MainMenuTreeview.Nodes.AddRange(new System.Windows.Forms.TreeNode[] {
            treeNode10,
            treeNode15,
            treeNode27});
            this.MainMenuTreeview.SelectedImageIndex = 0;
            this.MainMenuTreeview.Size = new System.Drawing.Size(248, 401);
            this.MainMenuTreeview.TabIndex = 17;
            this.MainMenuTreeview.NodeMouseClick += new System.Windows.Forms.TreeNodeMouseClickEventHandler(this.MainMenuTreeview_NodeMouseClick);
            // 
            // MainMenuIcons
            // 
            this.MainMenuIcons.ImageStream = ((System.Windows.Forms.ImageListStreamer)(resources.GetObject("MainMenuIcons.ImageStream")));
            this.MainMenuIcons.TransparentColor = System.Drawing.Color.Transparent;
            this.MainMenuIcons.Images.SetKeyName(0, "rightarrow_white.png");
            this.MainMenuIcons.Images.SetKeyName(1, "nuclear.png");
            this.MainMenuIcons.Images.SetKeyName(2, "info.png");
            this.MainMenuIcons.Images.SetKeyName(3, "fire.png");
            this.MainMenuIcons.Images.SetKeyName(4, "rightarrow.png");
            this.MainMenuIcons.Images.SetKeyName(5, "pc_icon.jpg");
            // 
            // SignaturesTabContainer
            // 
            this.SignaturesTabContainer.Controls.Add(this.RegistrySignaturesTabPage);
            this.SignaturesTabContainer.Controls.Add(this.FileSignaturesTabPage);
            this.SignaturesTabContainer.Controls.Add(this.MemorySignaturesTabPage);
            this.SignaturesTabContainer.Controls.Add(this.RegistryGuidSignaturesTabPage);
            this.SignaturesTabContainer.Location = new System.Drawing.Point(265, 6);
            this.SignaturesTabContainer.Name = "SignaturesTabContainer";
            this.SignaturesTabContainer.SelectedIndex = 0;
            this.SignaturesTabContainer.Size = new System.Drawing.Size(900, 519);
            this.SignaturesTabContainer.TabIndex = 28;
            this.SignaturesTabContainer.Visible = false;
            // 
            // RegistryGuidSignaturesTabPage
            // 
            this.RegistryGuidSignaturesTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.RegistryGuidSignaturesTabPage.Controls.Add(this.DeleteSelectedGuidButton);
            this.RegistryGuidSignaturesTabPage.Controls.Add(this.RegistryGuidSignatures_Listview);
            this.RegistryGuidSignaturesTabPage.Controls.Add(this.AddRegGuidButton);
            this.RegistryGuidSignaturesTabPage.Controls.Add(this.StaticRegGuidValue);
            this.RegistryGuidSignaturesTabPage.Controls.Add(this.DynRegGuidValueName);
            this.RegistryGuidSignaturesTabPage.Controls.Add(this.label36);
            this.RegistryGuidSignaturesTabPage.Controls.Add(this.DynRegGuidKeyName);
            this.RegistryGuidSignaturesTabPage.Controls.Add(this.label35);
            this.RegistryGuidSignaturesTabPage.Controls.Add(this.label23);
            this.RegistryGuidSignaturesTabPage.ForeColor = System.Drawing.Color.White;
            this.RegistryGuidSignaturesTabPage.Location = new System.Drawing.Point(4, 22);
            this.RegistryGuidSignaturesTabPage.Name = "RegistryGuidSignaturesTabPage";
            this.RegistryGuidSignaturesTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.RegistryGuidSignaturesTabPage.Size = new System.Drawing.Size(892, 493);
            this.RegistryGuidSignaturesTabPage.TabIndex = 3;
            this.RegistryGuidSignaturesTabPage.Text = "Registry GUIDs";
            // 
            // DeleteSelectedGuidButton
            // 
            this.DeleteSelectedGuidButton.ForeColor = System.Drawing.Color.Black;
            this.DeleteSelectedGuidButton.Location = new System.Drawing.Point(787, 53);
            this.DeleteSelectedGuidButton.Name = "DeleteSelectedGuidButton";
            this.DeleteSelectedGuidButton.Size = new System.Drawing.Size(99, 23);
            this.DeleteSelectedGuidButton.TabIndex = 58;
            this.DeleteSelectedGuidButton.Text = "Delete Selected";
            this.DeleteSelectedGuidButton.UseVisualStyleBackColor = true;
            this.DeleteSelectedGuidButton.Click += new System.EventHandler(this.DeleteSelectedGuidButton_Click);
            // 
            // RegistryGuidSignatures_Listview
            // 
            this.RegistryGuidSignatures_Listview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.GuidValue,
            this.GuidType});
            this.RegistryGuidSignatures_Listview.FullRowSelect = true;
            this.RegistryGuidSignatures_Listview.GridLines = true;
            this.RegistryGuidSignatures_Listview.Location = new System.Drawing.Point(6, 82);
            this.RegistryGuidSignatures_Listview.Name = "RegistryGuidSignatures_Listview";
            this.RegistryGuidSignatures_Listview.Size = new System.Drawing.Size(880, 362);
            this.RegistryGuidSignatures_Listview.TabIndex = 57;
            this.RegistryGuidSignatures_Listview.UseCompatibleStateImageBehavior = false;
            this.RegistryGuidSignatures_Listview.View = System.Windows.Forms.View.Details;
            this.RegistryGuidSignatures_Listview.SelectedIndexChanged += new System.EventHandler(this.RegistryGuidSignatures_Listview_SelectedIndexChanged);
            // 
            // GuidValue
            // 
            this.GuidValue.Text = "Guid";
            this.GuidValue.Width = 690;
            // 
            // GuidType
            // 
            this.GuidType.Text = "Type";
            this.GuidType.Width = 174;
            // 
            // AddRegGuidButton
            // 
            this.AddRegGuidButton.ForeColor = System.Drawing.Color.Black;
            this.AddRegGuidButton.Location = new System.Drawing.Point(787, 24);
            this.AddRegGuidButton.Name = "AddRegGuidButton";
            this.AddRegGuidButton.Size = new System.Drawing.Size(99, 23);
            this.AddRegGuidButton.TabIndex = 56;
            this.AddRegGuidButton.Text = "Add";
            this.AddRegGuidButton.UseVisualStyleBackColor = true;
            this.AddRegGuidButton.Click += new System.EventHandler(this.AddRegGuidButton_Click);
            // 
            // StaticRegGuidValue
            // 
            this.StaticRegGuidValue.Location = new System.Drawing.Point(84, 50);
            this.StaticRegGuidValue.Name = "StaticRegGuidValue";
            this.StaticRegGuidValue.Size = new System.Drawing.Size(318, 20);
            this.StaticRegGuidValue.TabIndex = 55;
            this.ToolTipShowAnExample.SetToolTip(this.StaticRegGuidValue, "Exclude the braces, e.g.  01E04581-4EEE-11D0-BFE9-00AA005B4383");
            this.StaticRegGuidValue.TextChanged += new System.EventHandler(this.StaticRegGuidValue_TextChanged);
            // 
            // DynRegGuidValueName
            // 
            this.DynRegGuidValueName.Location = new System.Drawing.Point(426, 17);
            this.DynRegGuidValueName.Name = "DynRegGuidValueName";
            this.DynRegGuidValueName.Size = new System.Drawing.Size(164, 20);
            this.DynRegGuidValueName.TabIndex = 53;
            this.ToolTipShowAnExample.SetToolTip(this.DynRegGuidValueName, "[REQUIRED] Put the registry key\'s VALUE NAME here, e.g., MyGuidValueStoredHere");
            // 
            // label36
            // 
            this.label36.AutoSize = true;
            this.label36.Location = new System.Drawing.Point(408, 21);
            this.label36.Name = "label36";
            this.label36.Size = new System.Drawing.Size(12, 13);
            this.label36.TabIndex = 54;
            this.label36.Text = "\\";
            // 
            // DynRegGuidKeyName
            // 
            this.DynRegGuidKeyName.Location = new System.Drawing.Point(85, 18);
            this.DynRegGuidKeyName.Name = "DynRegGuidKeyName";
            this.DynRegGuidKeyName.Size = new System.Drawing.Size(317, 20);
            this.DynRegGuidKeyName.TabIndex = 44;
            this.ToolTipShowAnExample.SetToolTip(this.DynRegGuidKeyName, "Dynamic GUIDs are discovered at runtime based on the key name you supply here and" +
                    " plugged into Registry signatures you define on the next tab using the expansion" +
                    " variable {GUID}.");
            this.DynRegGuidKeyName.TextChanged += new System.EventHandler(this.DynRegGuidKeyName_TextChanged);
            // 
            // label35
            // 
            this.label35.AutoSize = true;
            this.label35.Location = new System.Drawing.Point(16, 53);
            this.label35.Name = "label35";
            this.label35.Size = new System.Drawing.Size(37, 13);
            this.label35.TabIndex = 43;
            this.label35.Text = "Static:";
            // 
            // label23
            // 
            this.label23.AutoSize = true;
            this.label23.Location = new System.Drawing.Point(16, 20);
            this.label23.Name = "label23";
            this.label23.Size = new System.Drawing.Size(51, 13);
            this.label23.TabIndex = 42;
            this.label23.Text = "Dynamic:";
            // 
            // MemorySignaturesTabPage
            // 
            this.MemorySignaturesTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.MemorySignaturesTabPage.Controls.Add(this.label33);
            this.MemorySignaturesTabPage.Controls.Add(this.label32);
            this.MemorySignaturesTabPage.Controls.Add(this.MemorySignatures_NewKeywords);
            this.MemorySignaturesTabPage.Controls.Add(this.MemorySignatures_NewProcessName);
            this.MemorySignaturesTabPage.Controls.Add(this.AddMemorySignatureButton);
            this.MemorySignaturesTabPage.Controls.Add(this.MemorySignatures_NewAction);
            this.MemorySignaturesTabPage.Controls.Add(this.label28);
            this.MemorySignaturesTabPage.Controls.Add(this.label29);
            this.MemorySignaturesTabPage.Controls.Add(this.MemorySignatures_Listview);
            this.MemorySignaturesTabPage.Controls.Add(this.DeleteSelectedMemorySignatureButton);
            this.MemorySignaturesTabPage.ForeColor = System.Drawing.Color.White;
            this.MemorySignaturesTabPage.Location = new System.Drawing.Point(4, 22);
            this.MemorySignaturesTabPage.Name = "MemorySignaturesTabPage";
            this.MemorySignaturesTabPage.Size = new System.Drawing.Size(892, 493);
            this.MemorySignaturesTabPage.TabIndex = 2;
            this.MemorySignaturesTabPage.Text = "Memory";
            // 
            // label33
            // 
            this.label33.AutoSize = true;
            this.label33.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Italic, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label33.Location = new System.Drawing.Point(75, 117);
            this.label33.Name = "label33";
            this.label33.Size = new System.Drawing.Size(91, 13);
            this.label33.TabIndex = 42;
            this.label33.Text = "comma-separated";
            // 
            // label32
            // 
            this.label32.AutoSize = true;
            this.label32.Location = new System.Drawing.Point(16, 46);
            this.label32.Name = "label32";
            this.label32.Size = new System.Drawing.Size(56, 13);
            this.label32.TabIndex = 41;
            this.label32.Text = "Keywords:";
            // 
            // MemorySignatures_NewKeywords
            // 
            this.MemorySignatures_NewKeywords.Location = new System.Drawing.Point(78, 43);
            this.MemorySignatures_NewKeywords.Multiline = true;
            this.MemorySignatures_NewKeywords.Name = "MemorySignatures_NewKeywords";
            this.MemorySignatures_NewKeywords.Size = new System.Drawing.Size(546, 71);
            this.MemorySignatures_NewKeywords.TabIndex = 40;
            this.ToolTipShowAnExample.SetToolTip(this.MemorySignatures_NewKeywords, "[OPTIONAL] Codeword will search the target process\'s heap space, command line str" +
                    "ing, and loaded module list for any keywords you specify here.");
            // 
            // MemorySignatures_NewProcessName
            // 
            this.MemorySignatures_NewProcessName.Location = new System.Drawing.Point(449, 11);
            this.MemorySignatures_NewProcessName.Name = "MemorySignatures_NewProcessName";
            this.MemorySignatures_NewProcessName.Size = new System.Drawing.Size(175, 20);
            this.MemorySignatures_NewProcessName.TabIndex = 36;
            this.ToolTipShowAnExample.SetToolTip(this.MemorySignatures_NewProcessName, "[REQUIRED] The name of the process to search for, e.g., calc.exe");
            this.MemorySignatures_NewProcessName.TextChanged += new System.EventHandler(this.MemorySignatures_NewProcessName_TextChanged);
            // 
            // AddMemorySignatureButton
            // 
            this.AddMemorySignatureButton.ForeColor = System.Drawing.Color.Black;
            this.AddMemorySignatureButton.Location = new System.Drawing.Point(781, 84);
            this.AddMemorySignatureButton.Name = "AddMemorySignatureButton";
            this.AddMemorySignatureButton.Size = new System.Drawing.Size(108, 21);
            this.AddMemorySignatureButton.TabIndex = 39;
            this.AddMemorySignatureButton.Text = "Add";
            this.AddMemorySignatureButton.UseVisualStyleBackColor = true;
            this.AddMemorySignatureButton.Click += new System.EventHandler(this.AddMemorySignatureButton_Click);
            // 
            // MemorySignatures_NewAction
            // 
            this.MemorySignatures_NewAction.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.MemorySignatures_NewAction.FormattingEnabled = true;
            this.MemorySignatures_NewAction.Items.AddRange(new object[] {
            "Terminate process if exists",
            "Terminate process if keyword found",
            "Suspend containing thread if keyword found"});
            this.MemorySignatures_NewAction.Location = new System.Drawing.Point(78, 10);
            this.MemorySignatures_NewAction.Name = "MemorySignatures_NewAction";
            this.MemorySignatures_NewAction.Size = new System.Drawing.Size(281, 21);
            this.MemorySignatures_NewAction.TabIndex = 38;
            this.ToolTipShowAnExample.SetToolTip(this.MemorySignatures_NewAction, "[REQUIRED] What do you want to do with this item if it is found?");
            // 
            // label28
            // 
            this.label28.AutoSize = true;
            this.label28.ForeColor = System.Drawing.Color.White;
            this.label28.Location = new System.Drawing.Point(16, 14);
            this.label28.Name = "label28";
            this.label28.Size = new System.Drawing.Size(40, 13);
            this.label28.TabIndex = 37;
            this.label28.Text = "Action:";
            // 
            // label29
            // 
            this.label29.AutoSize = true;
            this.label29.ForeColor = System.Drawing.Color.White;
            this.label29.Location = new System.Drawing.Point(366, 14);
            this.label29.Name = "label29";
            this.label29.Size = new System.Drawing.Size(77, 13);
            this.label29.TabIndex = 35;
            this.label29.Text = "Process name:";
            // 
            // MemorySignatures_Listview
            // 
            this.MemorySignatures_Listview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.processname,
            this.processkeywords,
            this.processaction});
            this.MemorySignatures_Listview.FullRowSelect = true;
            this.MemorySignatures_Listview.GridLines = true;
            this.MemorySignatures_Listview.Location = new System.Drawing.Point(9, 139);
            this.MemorySignatures_Listview.MultiSelect = false;
            this.MemorySignatures_Listview.Name = "MemorySignatures_Listview";
            this.MemorySignatures_Listview.ShowItemToolTips = true;
            this.MemorySignatures_Listview.Size = new System.Drawing.Size(880, 305);
            this.MemorySignatures_Listview.TabIndex = 34;
            this.MemorySignatures_Listview.UseCompatibleStateImageBehavior = false;
            this.MemorySignatures_Listview.View = System.Windows.Forms.View.Details;
            this.MemorySignatures_Listview.SelectedIndexChanged += new System.EventHandler(this.MemorySignatures_Listview_SelectedIndexChanged);
            // 
            // processname
            // 
            this.processname.Text = "Process Name";
            this.processname.Width = 125;
            // 
            // processkeywords
            // 
            this.processkeywords.Text = "Keywords";
            this.processkeywords.Width = 312;
            // 
            // processaction
            // 
            this.processaction.Text = "Action";
            this.processaction.Width = 122;
            // 
            // DeleteSelectedMemorySignatureButton
            // 
            this.DeleteSelectedMemorySignatureButton.ForeColor = System.Drawing.Color.Black;
            this.DeleteSelectedMemorySignatureButton.Location = new System.Drawing.Point(781, 112);
            this.DeleteSelectedMemorySignatureButton.Name = "DeleteSelectedMemorySignatureButton";
            this.DeleteSelectedMemorySignatureButton.Size = new System.Drawing.Size(108, 22);
            this.DeleteSelectedMemorySignatureButton.TabIndex = 33;
            this.DeleteSelectedMemorySignatureButton.Text = "Delete Selected";
            this.DeleteSelectedMemorySignatureButton.UseVisualStyleBackColor = true;
            this.DeleteSelectedMemorySignatureButton.Click += new System.EventHandler(this.DeleteSelectedMemorySignatureButton_Click);
            // 
            // HeuristicsTabContainer
            // 
            this.HeuristicsTabContainer.Controls.Add(this.ProcessThreadTabPage);
            this.HeuristicsTabContainer.Controls.Add(this.ModuleTab);
            this.HeuristicsTabContainer.Controls.Add(this.BHOToolbarTabPage);
            this.HeuristicsTabContainer.Controls.Add(this.RegistryHeuristicsTabPage);
            this.HeuristicsTabContainer.Controls.Add(this.KernelTabPage);
            this.HeuristicsTabContainer.Controls.Add(this.GDI32SubsystemTabPage);
            this.HeuristicsTabContainer.Controls.Add(this.DriversTabPage);
            this.HeuristicsTabContainer.Controls.Add(this.NdisTdiTabPage);
            this.HeuristicsTabContainer.Controls.Add(this.BIOSTabPage);
            this.HeuristicsTabContainer.Controls.Add(this.BootSectorTabPage);
            this.HeuristicsTabContainer.Location = new System.Drawing.Point(265, 6);
            this.HeuristicsTabContainer.Name = "HeuristicsTabContainer";
            this.HeuristicsTabContainer.SelectedIndex = 0;
            this.HeuristicsTabContainer.Size = new System.Drawing.Size(900, 519);
            this.HeuristicsTabContainer.TabIndex = 0;
            this.HeuristicsTabContainer.Visible = false;
            // 
            // ProcessThreadTabPage
            // 
            this.ProcessThreadTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.ProcessThreadTabPage.Controls.Add(this.groupBox14);
            this.ProcessThreadTabPage.ForeColor = System.Drawing.Color.White;
            this.ProcessThreadTabPage.Location = new System.Drawing.Point(4, 22);
            this.ProcessThreadTabPage.Name = "ProcessThreadTabPage";
            this.ProcessThreadTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.ProcessThreadTabPage.Size = new System.Drawing.Size(892, 493);
            this.ProcessThreadTabPage.TabIndex = 0;
            this.ProcessThreadTabPage.Text = "Process/Thread";
            // 
            // groupBox14
            // 
            this.groupBox14.Controls.Add(this.label22);
            this.groupBox14.Controls.Add(this.ProcessThread_BruteForcePIDs);
            this.groupBox14.Controls.Add(this.ProcessThread_Crossview);
            this.groupBox14.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox14.Location = new System.Drawing.Point(11, 17);
            this.groupBox14.Name = "groupBox14";
            this.groupBox14.Size = new System.Drawing.Size(875, 116);
            this.groupBox14.TabIndex = 8;
            this.groupBox14.TabStop = false;
            this.groupBox14.Text = "Processes";
            // 
            // label22
            // 
            this.label22.AutoSize = true;
            this.label22.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label22.ForeColor = System.Drawing.Color.White;
            this.label22.Location = new System.Drawing.Point(12, 26);
            this.label22.Name = "label22";
            this.label22.Size = new System.Drawing.Size(131, 13);
            this.label22.TabIndex = 3;
            this.label22.Text = "Hidden process detection:";
            // 
            // ProcessThread_BruteForcePIDs
            // 
            this.ProcessThread_BruteForcePIDs.AutoSize = true;
            this.ProcessThread_BruteForcePIDs.Checked = true;
            this.ProcessThread_BruteForcePIDs.CheckState = System.Windows.Forms.CheckState.Checked;
            this.ProcessThread_BruteForcePIDs.ForeColor = System.Drawing.Color.White;
            this.ProcessThread_BruteForcePIDs.Location = new System.Drawing.Point(27, 70);
            this.ProcessThread_BruteForcePIDs.Name = "ProcessThread_BruteForcePIDs";
            this.ProcessThread_BruteForcePIDs.Size = new System.Drawing.Size(104, 17);
            this.ProcessThread_BruteForcePIDs.TabIndex = 2;
            this.ProcessThread_BruteForcePIDs.Text = "Brute force PIDs";
            this.ProcessThread_BruteForcePIDs.UseVisualStyleBackColor = true;
            // 
            // ProcessThread_Crossview
            // 
            this.ProcessThread_Crossview.AutoSize = true;
            this.ProcessThread_Crossview.Checked = true;
            this.ProcessThread_Crossview.CheckState = System.Windows.Forms.CheckState.Checked;
            this.ProcessThread_Crossview.ForeColor = System.Drawing.Color.White;
            this.ProcessThread_Crossview.Location = new System.Drawing.Point(27, 47);
            this.ProcessThread_Crossview.Name = "ProcessThread_Crossview";
            this.ProcessThread_Crossview.Size = new System.Drawing.Size(117, 17);
            this.ProcessThread_Crossview.TabIndex = 1;
            this.ProcessThread_Crossview.Text = "Cross-view analysis";
            this.ProcessThread_Crossview.UseVisualStyleBackColor = true;
            // 
            // ModuleTab
            // 
            this.ModuleTab.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.ModuleTab.Controls.Add(this.label84);
            this.ModuleTab.Controls.Add(this.ModuleTargets);
            this.ModuleTab.Controls.Add(this.groupBox19);
            this.ModuleTab.Controls.Add(this.groupBox18);
            this.ModuleTab.Location = new System.Drawing.Point(4, 22);
            this.ModuleTab.Name = "ModuleTab";
            this.ModuleTab.Padding = new System.Windows.Forms.Padding(3);
            this.ModuleTab.Size = new System.Drawing.Size(892, 493);
            this.ModuleTab.TabIndex = 4;
            this.ModuleTab.Text = "Module";
            // 
            // label84
            // 
            this.label84.AutoSize = true;
            this.label84.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label84.ForeColor = System.Drawing.Color.Chartreuse;
            this.label84.Location = new System.Drawing.Point(8, 213);
            this.label84.Name = "label84";
            this.label84.Size = new System.Drawing.Size(166, 13);
            this.label84.TabIndex = 12;
            this.label84.Text = "Process modules to inspect:";
            // 
            // ModuleTargets
            // 
            this.ModuleTargets.Location = new System.Drawing.Point(11, 235);
            this.ModuleTargets.Multiline = true;
            this.ModuleTargets.Name = "ModuleTargets";
            this.ModuleTargets.Size = new System.Drawing.Size(273, 87);
            this.ModuleTargets.TabIndex = 11;
            this.ToolTipShowAnExample.SetToolTip(this.ModuleTargets, "Supply a comma-separated list of processes you wish to inspect for these hook typ" +
                    "es.  Example:  iexplore.exe, explorer.exe");
            // 
            // groupBox19
            // 
            this.groupBox19.Controls.Add(this.Module_EATHooks);
            this.groupBox19.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox19.Location = new System.Drawing.Point(11, 122);
            this.groupBox19.Name = "groupBox19";
            this.groupBox19.Size = new System.Drawing.Size(875, 69);
            this.groupBox19.TabIndex = 10;
            this.groupBox19.TabStop = false;
            this.groupBox19.Text = "Exports";
            // 
            // Module_EATHooks
            // 
            this.Module_EATHooks.AutoSize = true;
            this.Module_EATHooks.Checked = true;
            this.Module_EATHooks.CheckState = System.Windows.Forms.CheckState.Checked;
            this.Module_EATHooks.ForeColor = System.Drawing.Color.White;
            this.Module_EATHooks.Location = new System.Drawing.Point(12, 30);
            this.Module_EATHooks.Name = "Module_EATHooks";
            this.Module_EATHooks.Size = new System.Drawing.Size(121, 17);
            this.Module_EATHooks.TabIndex = 1;
            this.Module_EATHooks.Text = "Look for EAT hooks";
            this.Module_EATHooks.UseVisualStyleBackColor = true;
            // 
            // groupBox18
            // 
            this.groupBox18.Controls.Add(this.Module_IATHooks);
            this.groupBox18.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox18.Location = new System.Drawing.Point(11, 18);
            this.groupBox18.Name = "groupBox18";
            this.groupBox18.Size = new System.Drawing.Size(875, 79);
            this.groupBox18.TabIndex = 9;
            this.groupBox18.TabStop = false;
            this.groupBox18.Text = "Imports";
            // 
            // Module_IATHooks
            // 
            this.Module_IATHooks.AutoSize = true;
            this.Module_IATHooks.Checked = true;
            this.Module_IATHooks.CheckState = System.Windows.Forms.CheckState.Checked;
            this.Module_IATHooks.ForeColor = System.Drawing.Color.White;
            this.Module_IATHooks.Location = new System.Drawing.Point(12, 30);
            this.Module_IATHooks.Name = "Module_IATHooks";
            this.Module_IATHooks.Size = new System.Drawing.Size(117, 17);
            this.Module_IATHooks.TabIndex = 1;
            this.Module_IATHooks.Text = "Look for IAT hooks";
            this.Module_IATHooks.UseVisualStyleBackColor = true;
            // 
            // BHOToolbarTabPage
            // 
            this.BHOToolbarTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.BHOToolbarTabPage.Controls.Add(this.BHO_CollectBasicInformation);
            this.BHOToolbarTabPage.Controls.Add(this.BHO_ScanForUnregisteredBHOs);
            this.BHOToolbarTabPage.ForeColor = System.Drawing.Color.White;
            this.BHOToolbarTabPage.Location = new System.Drawing.Point(4, 22);
            this.BHOToolbarTabPage.Name = "BHOToolbarTabPage";
            this.BHOToolbarTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.BHOToolbarTabPage.Size = new System.Drawing.Size(892, 493);
            this.BHOToolbarTabPage.TabIndex = 1;
            this.BHOToolbarTabPage.Text = "BHO/Toolbar";
            // 
            // BHO_CollectBasicInformation
            // 
            this.BHO_CollectBasicInformation.AutoSize = true;
            this.BHO_CollectBasicInformation.Checked = true;
            this.BHO_CollectBasicInformation.CheckState = System.Windows.Forms.CheckState.Checked;
            this.BHO_CollectBasicInformation.Location = new System.Drawing.Point(17, 20);
            this.BHO_CollectBasicInformation.Name = "BHO_CollectBasicInformation";
            this.BHO_CollectBasicInformation.Size = new System.Drawing.Size(179, 17);
            this.BHO_CollectBasicInformation.TabIndex = 2;
            this.BHO_CollectBasicInformation.Text = "Collect list of BHO\'s and toolbars";
            this.BHO_CollectBasicInformation.UseVisualStyleBackColor = true;
            // 
            // BHO_ScanForUnregisteredBHOs
            // 
            this.BHO_ScanForUnregisteredBHOs.AutoSize = true;
            this.BHO_ScanForUnregisteredBHOs.Checked = true;
            this.BHO_ScanForUnregisteredBHOs.CheckState = System.Windows.Forms.CheckState.Checked;
            this.BHO_ScanForUnregisteredBHOs.Location = new System.Drawing.Point(17, 46);
            this.BHO_ScanForUnregisteredBHOs.Name = "BHO_ScanForUnregisteredBHOs";
            this.BHO_ScanForUnregisteredBHOs.Size = new System.Drawing.Size(338, 17);
            this.BHO_ScanForUnregisteredBHOs.TabIndex = 0;
            this.BHO_ScanForUnregisteredBHOs.Text = "Scan loaded module list in Internet Explorer for unregistered BHO\'s";
            this.BHO_ScanForUnregisteredBHOs.UseVisualStyleBackColor = true;
            // 
            // RegistryHeuristicsTabPage
            // 
            this.RegistryHeuristicsTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.RegistryHeuristicsTabPage.Controls.Add(this.RegistryHeuristics_GUIDScan);
            this.RegistryHeuristicsTabPage.Controls.Add(this.RegistryHeuristics_UnsignedSystemModules);
            this.RegistryHeuristicsTabPage.Controls.Add(this.RegistryHeuristics_NoOnDiskModule);
            this.RegistryHeuristicsTabPage.ForeColor = System.Drawing.Color.White;
            this.RegistryHeuristicsTabPage.Location = new System.Drawing.Point(4, 22);
            this.RegistryHeuristicsTabPage.Name = "RegistryHeuristicsTabPage";
            this.RegistryHeuristicsTabPage.Size = new System.Drawing.Size(892, 493);
            this.RegistryHeuristicsTabPage.TabIndex = 3;
            this.RegistryHeuristicsTabPage.Text = "Registry";
            // 
            // RegistryHeuristics_GUIDScan
            // 
            this.RegistryHeuristics_GUIDScan.AutoSize = true;
            this.RegistryHeuristics_GUIDScan.Checked = true;
            this.RegistryHeuristics_GUIDScan.CheckState = System.Windows.Forms.CheckState.Checked;
            this.RegistryHeuristics_GUIDScan.Location = new System.Drawing.Point(17, 64);
            this.RegistryHeuristics_GUIDScan.Name = "RegistryHeuristics_GUIDScan";
            this.RegistryHeuristics_GUIDScan.Size = new System.Drawing.Size(153, 17);
            this.RegistryHeuristics_GUIDScan.TabIndex = 2;
            this.RegistryHeuristics_GUIDScan.Text = "Scan for suspicious GUIDs";
            this.RegistryHeuristics_GUIDScan.UseVisualStyleBackColor = true;
            // 
            // RegistryHeuristics_UnsignedSystemModules
            // 
            this.RegistryHeuristics_UnsignedSystemModules.AutoSize = true;
            this.RegistryHeuristics_UnsignedSystemModules.Checked = true;
            this.RegistryHeuristics_UnsignedSystemModules.CheckState = System.Windows.Forms.CheckState.Checked;
            this.RegistryHeuristics_UnsignedSystemModules.Location = new System.Drawing.Point(17, 41);
            this.RegistryHeuristics_UnsignedSystemModules.Name = "RegistryHeuristics_UnsignedSystemModules";
            this.RegistryHeuristics_UnsignedSystemModules.Size = new System.Drawing.Size(274, 17);
            this.RegistryHeuristics_UnsignedSystemModules.TabIndex = 1;
            this.RegistryHeuristics_UnsignedSystemModules.Text = "Scan for unsigned modules in privileged registry keys";
            this.RegistryHeuristics_UnsignedSystemModules.UseVisualStyleBackColor = true;
            // 
            // RegistryHeuristics_NoOnDiskModule
            // 
            this.RegistryHeuristics_NoOnDiskModule.AutoSize = true;
            this.RegistryHeuristics_NoOnDiskModule.Checked = true;
            this.RegistryHeuristics_NoOnDiskModule.CheckState = System.Windows.Forms.CheckState.Checked;
            this.RegistryHeuristics_NoOnDiskModule.Location = new System.Drawing.Point(17, 20);
            this.RegistryHeuristics_NoOnDiskModule.Name = "RegistryHeuristics_NoOnDiskModule";
            this.RegistryHeuristics_NoOnDiskModule.Size = new System.Drawing.Size(304, 17);
            this.RegistryHeuristics_NoOnDiskModule.TabIndex = 0;
            this.RegistryHeuristics_NoOnDiskModule.Text = "Scan for registry entries that reference files that do not exist";
            this.RegistryHeuristics_NoOnDiskModule.UseVisualStyleBackColor = true;
            // 
            // KernelTabPage
            // 
            this.KernelTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.KernelTabPage.Controls.Add(this.groupBox11);
            this.KernelTabPage.Controls.Add(this.groupBox7);
            this.KernelTabPage.Controls.Add(this.groupBox9);
            this.KernelTabPage.Controls.Add(this.groupBox8);
            this.KernelTabPage.Location = new System.Drawing.Point(4, 22);
            this.KernelTabPage.Name = "KernelTabPage";
            this.KernelTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.KernelTabPage.Size = new System.Drawing.Size(892, 493);
            this.KernelTabPage.TabIndex = 5;
            this.KernelTabPage.Text = "Kernel/Ntdll";
            // 
            // groupBox11
            // 
            this.groupBox11.Controls.Add(this.KernelHeuristics_Win32Api_CheckExportsForDetours);
            this.groupBox11.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox11.Location = new System.Drawing.Point(17, 343);
            this.groupBox11.Name = "groupBox11";
            this.groupBox11.Size = new System.Drawing.Size(869, 74);
            this.groupBox11.TabIndex = 9;
            this.groupBox11.TabStop = false;
            this.groupBox11.Text = "Win32 API";
            // 
            // KernelHeuristics_Win32Api_CheckExportsForDetours
            // 
            this.KernelHeuristics_Win32Api_CheckExportsForDetours.AutoSize = true;
            this.KernelHeuristics_Win32Api_CheckExportsForDetours.Checked = true;
            this.KernelHeuristics_Win32Api_CheckExportsForDetours.CheckState = System.Windows.Forms.CheckState.Checked;
            this.KernelHeuristics_Win32Api_CheckExportsForDetours.ForeColor = System.Drawing.Color.White;
            this.KernelHeuristics_Win32Api_CheckExportsForDetours.Location = new System.Drawing.Point(21, 27);
            this.KernelHeuristics_Win32Api_CheckExportsForDetours.Name = "KernelHeuristics_Win32Api_CheckExportsForDetours";
            this.KernelHeuristics_Win32Api_CheckExportsForDetours.Size = new System.Drawing.Size(288, 17);
            this.KernelHeuristics_Win32Api_CheckExportsForDetours.TabIndex = 8;
            this.KernelHeuristics_Win32Api_CheckExportsForDetours.Text = "Check all exported functions of system DLLs for detours";
            this.KernelHeuristics_Win32Api_CheckExportsForDetours.UseVisualStyleBackColor = true;
            // 
            // groupBox7
            // 
            this.groupBox7.Controls.Add(this.KernelHeuristics_SSDT_DetectHooks);
            this.groupBox7.Controls.Add(this.KernelHeuristics_SSDT_DetectDetours);
            this.groupBox7.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox7.Location = new System.Drawing.Point(17, 18);
            this.groupBox7.Name = "groupBox7";
            this.groupBox7.Size = new System.Drawing.Size(869, 91);
            this.groupBox7.TabIndex = 5;
            this.groupBox7.TabStop = false;
            this.groupBox7.Text = "SSDT";
            // 
            // KernelHeuristics_SSDT_DetectHooks
            // 
            this.KernelHeuristics_SSDT_DetectHooks.AutoSize = true;
            this.KernelHeuristics_SSDT_DetectHooks.Checked = true;
            this.KernelHeuristics_SSDT_DetectHooks.CheckState = System.Windows.Forms.CheckState.Checked;
            this.KernelHeuristics_SSDT_DetectHooks.ForeColor = System.Drawing.Color.White;
            this.KernelHeuristics_SSDT_DetectHooks.Location = new System.Drawing.Point(21, 26);
            this.KernelHeuristics_SSDT_DetectHooks.Name = "KernelHeuristics_SSDT_DetectHooks";
            this.KernelHeuristics_SSDT_DetectHooks.Size = new System.Drawing.Size(90, 17);
            this.KernelHeuristics_SSDT_DetectHooks.TabIndex = 1;
            this.KernelHeuristics_SSDT_DetectHooks.Text = "Detect hooks";
            this.KernelHeuristics_SSDT_DetectHooks.UseVisualStyleBackColor = true;
            // 
            // KernelHeuristics_SSDT_DetectDetours
            // 
            this.KernelHeuristics_SSDT_DetectDetours.AutoSize = true;
            this.KernelHeuristics_SSDT_DetectDetours.Checked = true;
            this.KernelHeuristics_SSDT_DetectDetours.CheckState = System.Windows.Forms.CheckState.Checked;
            this.KernelHeuristics_SSDT_DetectDetours.ForeColor = System.Drawing.Color.White;
            this.KernelHeuristics_SSDT_DetectDetours.Location = new System.Drawing.Point(21, 51);
            this.KernelHeuristics_SSDT_DetectDetours.Name = "KernelHeuristics_SSDT_DetectDetours";
            this.KernelHeuristics_SSDT_DetectDetours.Size = new System.Drawing.Size(237, 17);
            this.KernelHeuristics_SSDT_DetectDetours.TabIndex = 2;
            this.KernelHeuristics_SSDT_DetectDetours.Text = "Check service function prologues for detours";
            this.KernelHeuristics_SSDT_DetectDetours.UseVisualStyleBackColor = true;
            // 
            // groupBox9
            // 
            this.groupBox9.Controls.Add(this.KernelHeuristics_IDT_DetectHooks);
            this.groupBox9.Controls.Add(this.KernelHeuristics_IDT_DetectDetours);
            this.groupBox9.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox9.Location = new System.Drawing.Point(17, 235);
            this.groupBox9.Name = "groupBox9";
            this.groupBox9.Size = new System.Drawing.Size(869, 91);
            this.groupBox9.TabIndex = 7;
            this.groupBox9.TabStop = false;
            this.groupBox9.Text = "IDT";
            // 
            // KernelHeuristics_IDT_DetectHooks
            // 
            this.KernelHeuristics_IDT_DetectHooks.AutoSize = true;
            this.KernelHeuristics_IDT_DetectHooks.Checked = true;
            this.KernelHeuristics_IDT_DetectHooks.CheckState = System.Windows.Forms.CheckState.Checked;
            this.KernelHeuristics_IDT_DetectHooks.ForeColor = System.Drawing.Color.White;
            this.KernelHeuristics_IDT_DetectHooks.Location = new System.Drawing.Point(21, 26);
            this.KernelHeuristics_IDT_DetectHooks.Name = "KernelHeuristics_IDT_DetectHooks";
            this.KernelHeuristics_IDT_DetectHooks.Size = new System.Drawing.Size(90, 17);
            this.KernelHeuristics_IDT_DetectHooks.TabIndex = 1;
            this.KernelHeuristics_IDT_DetectHooks.Text = "Detect hooks";
            this.KernelHeuristics_IDT_DetectHooks.UseVisualStyleBackColor = true;
            // 
            // KernelHeuristics_IDT_DetectDetours
            // 
            this.KernelHeuristics_IDT_DetectDetours.AutoSize = true;
            this.KernelHeuristics_IDT_DetectDetours.Checked = true;
            this.KernelHeuristics_IDT_DetectDetours.CheckState = System.Windows.Forms.CheckState.Checked;
            this.KernelHeuristics_IDT_DetectDetours.ForeColor = System.Drawing.Color.White;
            this.KernelHeuristics_IDT_DetectDetours.Location = new System.Drawing.Point(21, 51);
            this.KernelHeuristics_IDT_DetectDetours.Name = "KernelHeuristics_IDT_DetectDetours";
            this.KernelHeuristics_IDT_DetectDetours.Size = new System.Drawing.Size(221, 17);
            this.KernelHeuristics_IDT_DetectDetours.TabIndex = 2;
            this.KernelHeuristics_IDT_DetectDetours.Text = "Check ISR function prologues for detours";
            this.KernelHeuristics_IDT_DetectDetours.UseVisualStyleBackColor = true;
            // 
            // groupBox8
            // 
            this.groupBox8.Controls.Add(this.KernelHeuristics_GDT_GetInstalledCallGates);
            this.groupBox8.Controls.Add(this.KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors);
            this.groupBox8.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox8.Location = new System.Drawing.Point(17, 122);
            this.groupBox8.Name = "groupBox8";
            this.groupBox8.Size = new System.Drawing.Size(869, 95);
            this.groupBox8.TabIndex = 6;
            this.groupBox8.TabStop = false;
            this.groupBox8.Text = "GDT";
            // 
            // KernelHeuristics_GDT_GetInstalledCallGates
            // 
            this.KernelHeuristics_GDT_GetInstalledCallGates.AutoSize = true;
            this.KernelHeuristics_GDT_GetInstalledCallGates.Checked = true;
            this.KernelHeuristics_GDT_GetInstalledCallGates.CheckState = System.Windows.Forms.CheckState.Checked;
            this.KernelHeuristics_GDT_GetInstalledCallGates.ForeColor = System.Drawing.Color.White;
            this.KernelHeuristics_GDT_GetInstalledCallGates.Location = new System.Drawing.Point(21, 50);
            this.KernelHeuristics_GDT_GetInstalledCallGates.Name = "KernelHeuristics_GDT_GetInstalledCallGates";
            this.KernelHeuristics_GDT_GetInstalledCallGates.Size = new System.Drawing.Size(183, 17);
            this.KernelHeuristics_GDT_GetInstalledCallGates.TabIndex = 4;
            this.KernelHeuristics_GDT_GetInstalledCallGates.Text = "Collect a list of installed call gates";
            this.KernelHeuristics_GDT_GetInstalledCallGates.UseVisualStyleBackColor = true;
            // 
            // KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors
            // 
            this.KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors.AutoSize = true;
            this.KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors.Checked = true;
            this.KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors.CheckState = System.Windows.Forms.CheckState.Checked;
            this.KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors.ForeColor = System.Drawing.Color.White;
            this.KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors.Location = new System.Drawing.Point(21, 27);
            this.KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors.Name = "KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors";
            this.KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors.Size = new System.Drawing.Size(214, 17);
            this.KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors.TabIndex = 3;
            this.KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors.Text = "Look for suspicious segment descriptors";
            this.KernelHeuristics_GDT_LookForSuspiciousSegmentDescriptors.UseVisualStyleBackColor = true;
            // 
            // GDI32SubsystemTabPage
            // 
            this.GDI32SubsystemTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.GDI32SubsystemTabPage.Controls.Add(this.groupBox13);
            this.GDI32SubsystemTabPage.Location = new System.Drawing.Point(4, 22);
            this.GDI32SubsystemTabPage.Name = "GDI32SubsystemTabPage";
            this.GDI32SubsystemTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.GDI32SubsystemTabPage.Size = new System.Drawing.Size(892, 493);
            this.GDI32SubsystemTabPage.TabIndex = 6;
            this.GDI32SubsystemTabPage.Text = "GDI32 Subsystem";
            // 
            // groupBox13
            // 
            this.groupBox13.Controls.Add(this.GUISubsystem_CheckSSDTShadowDetours);
            this.groupBox13.Controls.Add(this.GUISubsystem_CollectSSDTShadow);
            this.groupBox13.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox13.Location = new System.Drawing.Point(17, 18);
            this.groupBox13.Name = "groupBox13";
            this.groupBox13.Size = new System.Drawing.Size(860, 91);
            this.groupBox13.TabIndex = 6;
            this.groupBox13.TabStop = false;
            this.groupBox13.Text = "SSDT Shadow Table";
            // 
            // GUISubsystem_CheckSSDTShadowDetours
            // 
            this.GUISubsystem_CheckSSDTShadowDetours.AutoSize = true;
            this.GUISubsystem_CheckSSDTShadowDetours.ForeColor = System.Drawing.Color.White;
            this.GUISubsystem_CheckSSDTShadowDetours.Location = new System.Drawing.Point(21, 55);
            this.GUISubsystem_CheckSSDTShadowDetours.Name = "GUISubsystem_CheckSSDTShadowDetours";
            this.GUISubsystem_CheckSSDTShadowDetours.Size = new System.Drawing.Size(341, 17);
            this.GUISubsystem_CheckSSDTShadowDetours.TabIndex = 3;
            this.GUISubsystem_CheckSSDTShadowDetours.Text = "Check SSDT Shadow Table service function prologues for detours";
            this.GUISubsystem_CheckSSDTShadowDetours.UseVisualStyleBackColor = true;
            // 
            // GUISubsystem_CollectSSDTShadow
            // 
            this.GUISubsystem_CollectSSDTShadow.AutoSize = true;
            this.GUISubsystem_CollectSSDTShadow.ForeColor = System.Drawing.Color.White;
            this.GUISubsystem_CollectSSDTShadow.Location = new System.Drawing.Point(21, 26);
            this.GUISubsystem_CollectSSDTShadow.Name = "GUISubsystem_CollectSSDTShadow";
            this.GUISubsystem_CollectSSDTShadow.Size = new System.Drawing.Size(205, 17);
            this.GUISubsystem_CollectSSDTShadow.TabIndex = 1;
            this.GUISubsystem_CollectSSDTShadow.Text = "Detect hooks in SSDT Shadow Table";
            this.GUISubsystem_CollectSSDTShadow.UseVisualStyleBackColor = true;
            // 
            // DriversTabPage
            // 
            this.DriversTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.DriversTabPage.Controls.Add(this.AddDriverListview);
            this.DriversTabPage.Controls.Add(this.label30);
            this.DriversTabPage.Controls.Add(this.label83);
            this.DriversTabPage.Controls.Add(this.label60);
            this.DriversTabPage.Controls.Add(this.AddDriverButton);
            this.DriversTabPage.Controls.Add(this.DriversHeuristics_DetectIRPHooks);
            this.DriversTabPage.Controls.Add(this.label82);
            this.DriversTabPage.Controls.Add(this.DriversHeuristics_CheckDispatchRoutinesForDetours);
            this.DriversTabPage.Controls.Add(this.AddDriverDevice);
            this.DriversTabPage.Controls.Add(this.checkBox1);
            this.DriversTabPage.Controls.Add(this.label64);
            this.DriversTabPage.Controls.Add(this.AddDriverModule);
            this.DriversTabPage.Location = new System.Drawing.Point(4, 22);
            this.DriversTabPage.Name = "DriversTabPage";
            this.DriversTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.DriversTabPage.Size = new System.Drawing.Size(892, 493);
            this.DriversTabPage.TabIndex = 7;
            this.DriversTabPage.Text = "Drivers";
            // 
            // AddDriverListview
            // 
            this.AddDriverListview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader9,
            this.columnHeader16});
            this.AddDriverListview.GridLines = true;
            this.AddDriverListview.Items.AddRange(new System.Windows.Forms.ListViewItem[] {
            listViewItem1});
            this.AddDriverListview.Location = new System.Drawing.Point(300, 45);
            this.AddDriverListview.Name = "AddDriverListview";
            this.AddDriverListview.Size = new System.Drawing.Size(342, 186);
            this.AddDriverListview.TabIndex = 16;
            this.AddDriverListview.UseCompatibleStateImageBehavior = false;
            this.AddDriverListview.View = System.Windows.Forms.View.Details;
            // 
            // columnHeader9
            // 
            this.columnHeader9.Text = "Driver module";
            this.columnHeader9.Width = 129;
            // 
            // columnHeader16
            // 
            this.columnHeader16.Text = "Driver device";
            this.columnHeader16.Width = 206;
            // 
            // label30
            // 
            this.label30.AutoSize = true;
            this.label30.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label30.ForeColor = System.Drawing.Color.Chartreuse;
            this.label30.Location = new System.Drawing.Point(297, 20);
            this.label30.Name = "label30";
            this.label30.Size = new System.Drawing.Size(105, 13);
            this.label30.TabIndex = 15;
            this.label30.Text = "Drivers to check:";
            // 
            // label83
            // 
            this.label83.AutoSize = true;
            this.label83.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label83.ForeColor = System.Drawing.Color.Chartreuse;
            this.label83.Location = new System.Drawing.Point(16, 137);
            this.label83.Name = "label83";
            this.label83.Size = new System.Drawing.Size(54, 13);
            this.label83.TabIndex = 14;
            this.label83.Text = "Options:";
            // 
            // label60
            // 
            this.label60.AutoSize = true;
            this.label60.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label60.ForeColor = System.Drawing.Color.Chartreuse;
            this.label60.Location = new System.Drawing.Point(16, 20);
            this.label60.Name = "label60";
            this.label60.Size = new System.Drawing.Size(80, 13);
            this.label60.TabIndex = 8;
            this.label60.Text = "Add a driver:";
            // 
            // AddDriverButton
            // 
            this.AddDriverButton.ForeColor = System.Drawing.Color.Black;
            this.AddDriverButton.Location = new System.Drawing.Point(121, 108);
            this.AddDriverButton.Name = "AddDriverButton";
            this.AddDriverButton.Size = new System.Drawing.Size(75, 23);
            this.AddDriverButton.TabIndex = 13;
            this.AddDriverButton.Text = "Add";
            this.AddDriverButton.UseVisualStyleBackColor = true;
            this.AddDriverButton.Click += new System.EventHandler(this.AddDriverButton_Click);
            // 
            // DriversHeuristics_DetectIRPHooks
            // 
            this.DriversHeuristics_DetectIRPHooks.AutoSize = true;
            this.DriversHeuristics_DetectIRPHooks.Checked = true;
            this.DriversHeuristics_DetectIRPHooks.CheckState = System.Windows.Forms.CheckState.Checked;
            this.DriversHeuristics_DetectIRPHooks.ForeColor = System.Drawing.Color.White;
            this.DriversHeuristics_DetectIRPHooks.Location = new System.Drawing.Point(23, 168);
            this.DriversHeuristics_DetectIRPHooks.Name = "DriversHeuristics_DetectIRPHooks";
            this.DriversHeuristics_DetectIRPHooks.Size = new System.Drawing.Size(125, 17);
            this.DriversHeuristics_DetectIRPHooks.TabIndex = 4;
            this.DriversHeuristics_DetectIRPHooks.Text = "Check for IRP hooks";
            this.DriversHeuristics_DetectIRPHooks.UseVisualStyleBackColor = true;
            // 
            // label82
            // 
            this.label82.AutoSize = true;
            this.label82.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label82.ForeColor = System.Drawing.Color.White;
            this.label82.Location = new System.Drawing.Point(19, 79);
            this.label82.Name = "label82";
            this.label82.Size = new System.Drawing.Size(44, 13);
            this.label82.TabIndex = 12;
            this.label82.Text = "Device:";
            // 
            // DriversHeuristics_CheckDispatchRoutinesForDetours
            // 
            this.DriversHeuristics_CheckDispatchRoutinesForDetours.AutoSize = true;
            this.DriversHeuristics_CheckDispatchRoutinesForDetours.Checked = true;
            this.DriversHeuristics_CheckDispatchRoutinesForDetours.CheckState = System.Windows.Forms.CheckState.Checked;
            this.DriversHeuristics_CheckDispatchRoutinesForDetours.ForeColor = System.Drawing.Color.White;
            this.DriversHeuristics_CheckDispatchRoutinesForDetours.Location = new System.Drawing.Point(23, 191);
            this.DriversHeuristics_CheckDispatchRoutinesForDetours.Name = "DriversHeuristics_CheckDispatchRoutinesForDetours";
            this.DriversHeuristics_CheckDispatchRoutinesForDetours.Size = new System.Drawing.Size(222, 17);
            this.DriversHeuristics_CheckDispatchRoutinesForDetours.TabIndex = 5;
            this.DriversHeuristics_CheckDispatchRoutinesForDetours.Text = "Check driver dispatch routines for detours";
            this.DriversHeuristics_CheckDispatchRoutinesForDetours.UseVisualStyleBackColor = true;
            // 
            // AddDriverDevice
            // 
            this.AddDriverDevice.Location = new System.Drawing.Point(70, 76);
            this.AddDriverDevice.Name = "AddDriverDevice";
            this.AddDriverDevice.Size = new System.Drawing.Size(126, 20);
            this.AddDriverDevice.TabIndex = 11;
            this.ToolTipShowAnExample.SetToolTip(this.AddDriverDevice, "The driver\'s device object");
            // 
            // checkBox1
            // 
            this.checkBox1.AutoSize = true;
            this.checkBox1.Checked = true;
            this.checkBox1.CheckState = System.Windows.Forms.CheckState.Checked;
            this.checkBox1.ForeColor = System.Drawing.Color.White;
            this.checkBox1.Location = new System.Drawing.Point(23, 215);
            this.checkBox1.Name = "checkBox1";
            this.checkBox1.Size = new System.Drawing.Size(226, 17);
            this.checkBox1.TabIndex = 6;
            this.checkBox1.Text = "Report all drivers attached to device stack";
            this.checkBox1.UseVisualStyleBackColor = true;
            // 
            // label64
            // 
            this.label64.AutoSize = true;
            this.label64.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label64.ForeColor = System.Drawing.Color.White;
            this.label64.Location = new System.Drawing.Point(20, 49);
            this.label64.Name = "label64";
            this.label64.Size = new System.Drawing.Size(45, 13);
            this.label64.TabIndex = 10;
            this.label64.Text = "Module:";
            // 
            // AddDriverModule
            // 
            this.AddDriverModule.Location = new System.Drawing.Point(71, 46);
            this.AddDriverModule.Name = "AddDriverModule";
            this.AddDriverModule.Size = new System.Drawing.Size(126, 20);
            this.AddDriverModule.TabIndex = 9;
            this.ToolTipShowAnExample.SetToolTip(this.AddDriverModule, "Enter the name of the driver binary module you wish to check");
            // 
            // NdisTdiTabPage
            // 
            this.NdisTdiTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.NdisTdiTabPage.Controls.Add(this.NDIS_TDI_FindProtocolStacks);
            this.NdisTdiTabPage.Location = new System.Drawing.Point(4, 22);
            this.NdisTdiTabPage.Name = "NdisTdiTabPage";
            this.NdisTdiTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.NdisTdiTabPage.Size = new System.Drawing.Size(892, 493);
            this.NdisTdiTabPage.TabIndex = 8;
            this.NdisTdiTabPage.Text = "NDIS/TDI";
            // 
            // NDIS_TDI_FindProtocolStacks
            // 
            this.NDIS_TDI_FindProtocolStacks.AutoSize = true;
            this.NDIS_TDI_FindProtocolStacks.ForeColor = System.Drawing.Color.White;
            this.NDIS_TDI_FindProtocolStacks.Location = new System.Drawing.Point(23, 19);
            this.NDIS_TDI_FindProtocolStacks.Name = "NDIS_TDI_FindProtocolStacks";
            this.NDIS_TDI_FindProtocolStacks.Size = new System.Drawing.Size(215, 17);
            this.NDIS_TDI_FindProtocolStacks.TabIndex = 1;
            this.NDIS_TDI_FindProtocolStacks.Text = "Collect information on all protocol stacks";
            this.NDIS_TDI_FindProtocolStacks.UseVisualStyleBackColor = true;
            // 
            // BIOSTabPage
            // 
            this.BIOSTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.BIOSTabPage.Location = new System.Drawing.Point(4, 22);
            this.BIOSTabPage.Name = "BIOSTabPage";
            this.BIOSTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.BIOSTabPage.Size = new System.Drawing.Size(892, 493);
            this.BIOSTabPage.TabIndex = 9;
            this.BIOSTabPage.Text = "BIOS";
            // 
            // BootSectorTabPage
            // 
            this.BootSectorTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.BootSectorTabPage.Location = new System.Drawing.Point(4, 22);
            this.BootSectorTabPage.Name = "BootSectorTabPage";
            this.BootSectorTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.BootSectorTabPage.Size = new System.Drawing.Size(892, 493);
            this.BootSectorTabPage.TabIndex = 10;
            this.BootSectorTabPage.Text = "Boot Sector";
            // 
            // MainLogoTextbox
            // 
            this.MainLogoTextbox.BackColor = System.Drawing.Color.Black;
            this.MainLogoTextbox.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.MainLogoTextbox.Font = new System.Drawing.Font("Microsoft Sans Serif", 10F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.MainLogoTextbox.ForeColor = System.Drawing.Color.Chartreuse;
            this.MainLogoTextbox.Location = new System.Drawing.Point(265, 6);
            this.MainLogoTextbox.Multiline = true;
            this.MainLogoTextbox.Name = "MainLogoTextbox";
            this.MainLogoTextbox.ReadOnly = true;
            this.MainLogoTextbox.Size = new System.Drawing.Size(902, 519);
            this.MainLogoTextbox.TabIndex = 35;
            this.MainLogoTextbox.Text = resources.GetString("MainLogoTextbox.Text");
            // 
            // menuStrip
            // 
            this.menuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.fileToolStripMenuItem,
            this.settingsToolStripMenuItem,
            this.signaturesToolStripMenuItem,
            this.helpToolStripMenuItem1});
            this.menuStrip.Location = new System.Drawing.Point(0, 0);
            this.menuStrip.Name = "menuStrip";
            this.menuStrip.Size = new System.Drawing.Size(1181, 24);
            this.menuStrip.TabIndex = 36;
            this.menuStrip.Text = "menuStrip";
            // 
            // settingsToolStripMenuItem
            // 
            this.settingsToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.loadSettingsToolStripMenuItem,
            this.saveSettingsToolStripMenuItem});
            this.settingsToolStripMenuItem.Name = "settingsToolStripMenuItem";
            this.settingsToolStripMenuItem.Size = new System.Drawing.Size(61, 20);
            this.settingsToolStripMenuItem.Text = "Settings";
            // 
            // loadSettingsToolStripMenuItem
            // 
            this.loadSettingsToolStripMenuItem.Name = "loadSettingsToolStripMenuItem";
            this.loadSettingsToolStripMenuItem.Size = new System.Drawing.Size(153, 22);
            this.loadSettingsToolStripMenuItem.Text = "Load settings...";
            this.loadSettingsToolStripMenuItem.Click += new System.EventHandler(this.loadSettingsToolStripMenuItem_Click);
            // 
            // saveSettingsToolStripMenuItem
            // 
            this.saveSettingsToolStripMenuItem.Name = "saveSettingsToolStripMenuItem";
            this.saveSettingsToolStripMenuItem.Size = new System.Drawing.Size(153, 22);
            this.saveSettingsToolStripMenuItem.Text = "Save settings...";
            this.saveSettingsToolStripMenuItem.Click += new System.EventHandler(this.saveSettingsToolStripMenuItem_Click);
            // 
            // signaturesToolStripMenuItem
            // 
            this.signaturesToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.loadSignatureTemplateToolStripMenuItem,
            this.saveSignatureTemplateToolStripMenuItem});
            this.signaturesToolStripMenuItem.Name = "signaturesToolStripMenuItem";
            this.signaturesToolStripMenuItem.Size = new System.Drawing.Size(74, 20);
            this.signaturesToolStripMenuItem.Text = "Signatures";
            // 
            // loadSignatureTemplateToolStripMenuItem
            // 
            this.loadSignatureTemplateToolStripMenuItem.Name = "loadSignatureTemplateToolStripMenuItem";
            this.loadSignatureTemplateToolStripMenuItem.Size = new System.Drawing.Size(221, 22);
            this.loadSignatureTemplateToolStripMenuItem.Text = "Import signature template...";
            this.loadSignatureTemplateToolStripMenuItem.Click += new System.EventHandler(this.loadSignatureTemplateToolStripMenuItem_Click);
            // 
            // saveSignatureTemplateToolStripMenuItem
            // 
            this.saveSignatureTemplateToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.allToolStripMenuItem,
            this.registryToolStripMenuItem,
            this.fileToolStripMenuItem1,
            this.memoryToolStripMenuItem});
            this.saveSignatureTemplateToolStripMenuItem.Name = "saveSignatureTemplateToolStripMenuItem";
            this.saveSignatureTemplateToolStripMenuItem.Size = new System.Drawing.Size(221, 22);
            this.saveSignatureTemplateToolStripMenuItem.Text = "Export signature template";
            // 
            // allToolStripMenuItem
            // 
            this.allToolStripMenuItem.Name = "allToolStripMenuItem";
            this.allToolStripMenuItem.Size = new System.Drawing.Size(119, 22);
            this.allToolStripMenuItem.Text = "All...";
            this.allToolStripMenuItem.Click += new System.EventHandler(this.allToolStripMenuItem_Click);
            // 
            // registryToolStripMenuItem
            // 
            this.registryToolStripMenuItem.Name = "registryToolStripMenuItem";
            this.registryToolStripMenuItem.Size = new System.Drawing.Size(119, 22);
            this.registryToolStripMenuItem.Text = "Registry";
            this.registryToolStripMenuItem.Click += new System.EventHandler(this.registryToolStripMenuItem_Click);
            // 
            // fileToolStripMenuItem1
            // 
            this.fileToolStripMenuItem1.Name = "fileToolStripMenuItem1";
            this.fileToolStripMenuItem1.Size = new System.Drawing.Size(119, 22);
            this.fileToolStripMenuItem1.Text = "File";
            this.fileToolStripMenuItem1.Click += new System.EventHandler(this.fileToolStripMenuItem1_Click);
            // 
            // memoryToolStripMenuItem
            // 
            this.memoryToolStripMenuItem.Name = "memoryToolStripMenuItem";
            this.memoryToolStripMenuItem.Size = new System.Drawing.Size(119, 22);
            this.memoryToolStripMenuItem.Text = "Memory";
            this.memoryToolStripMenuItem.Click += new System.EventHandler(this.memoryToolStripMenuItem_Click);
            // 
            // helpToolStripMenuItem1
            // 
            this.helpToolStripMenuItem1.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.administratorConsoleManualToolStripMenuItem,
            this.agentManualToolStripMenuItem,
            this.installerManualToolStripMenuItem,
            this.aboutCodewordToolStripMenuItem});
            this.helpToolStripMenuItem1.Name = "helpToolStripMenuItem1";
            this.helpToolStripMenuItem1.Size = new System.Drawing.Size(44, 20);
            this.helpToolStripMenuItem1.Text = "Help";
            // 
            // administratorConsoleManualToolStripMenuItem
            // 
            this.administratorConsoleManualToolStripMenuItem.Name = "administratorConsoleManualToolStripMenuItem";
            this.administratorConsoleManualToolStripMenuItem.Size = new System.Drawing.Size(236, 22);
            this.administratorConsoleManualToolStripMenuItem.Text = "Administrator Console Manual";
            // 
            // agentManualToolStripMenuItem
            // 
            this.agentManualToolStripMenuItem.Name = "agentManualToolStripMenuItem";
            this.agentManualToolStripMenuItem.Size = new System.Drawing.Size(236, 22);
            this.agentManualToolStripMenuItem.Text = "Agent Manual";
            // 
            // installerManualToolStripMenuItem
            // 
            this.installerManualToolStripMenuItem.Name = "installerManualToolStripMenuItem";
            this.installerManualToolStripMenuItem.Size = new System.Drawing.Size(236, 22);
            this.installerManualToolStripMenuItem.Text = "Installer Manual";
            // 
            // aboutCodewordToolStripMenuItem
            // 
            this.aboutCodewordToolStripMenuItem.Name = "aboutCodewordToolStripMenuItem";
            this.aboutCodewordToolStripMenuItem.Size = new System.Drawing.Size(236, 22);
            this.aboutCodewordToolStripMenuItem.Text = "About Codeword...";
            // 
            // TopLevelTabControl
            // 
            this.TopLevelTabControl.Controls.Add(this.CreateNewAgentTabPage);
            this.TopLevelTabControl.Controls.Add(this.ConnectExistingAgentTabPage);
            this.TopLevelTabControl.Controls.Add(this.EnterprisePullTabPage);
            this.TopLevelTabControl.Dock = System.Windows.Forms.DockStyle.Fill;
            this.TopLevelTabControl.Location = new System.Drawing.Point(0, 24);
            this.TopLevelTabControl.Name = "TopLevelTabControl";
            this.TopLevelTabControl.SelectedIndex = 0;
            this.TopLevelTabControl.Size = new System.Drawing.Size(1181, 685);
            this.TopLevelTabControl.TabIndex = 59;
            // 
            // CreateNewAgentTabPage
            // 
            this.CreateNewAgentTabPage.BackColor = System.Drawing.Color.Black;
            this.CreateNewAgentTabPage.Controls.Add(this.MainMenuTreeview);
            this.CreateNewAgentTabPage.Controls.Add(this.pictureBox1);
            this.CreateNewAgentTabPage.Controls.Add(this.Button_ScanLocalHost);
            this.CreateNewAgentTabPage.Controls.Add(this.Button_GenerateMSI);
            this.CreateNewAgentTabPage.Controls.Add(this.HeuristicsTabContainer);
            this.CreateNewAgentTabPage.Controls.Add(this.GeneralSettingsTabContainer);
            this.CreateNewAgentTabPage.Controls.Add(this.MainLogoTextbox);
            this.CreateNewAgentTabPage.Controls.Add(this.SignaturesTabContainer);
            this.CreateNewAgentTabPage.Location = new System.Drawing.Point(4, 22);
            this.CreateNewAgentTabPage.Name = "CreateNewAgentTabPage";
            this.CreateNewAgentTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.CreateNewAgentTabPage.Size = new System.Drawing.Size(1173, 659);
            this.CreateNewAgentTabPage.TabIndex = 0;
            this.CreateNewAgentTabPage.Text = "Create New Agent";
            // 
            // pictureBox1
            // 
            this.pictureBox1.Image = global::CwHandler.Properties.Resources.cw_logo_mid;
            this.pictureBox1.Location = new System.Drawing.Point(3, 451);
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.Size = new System.Drawing.Size(251, 74);
            this.pictureBox1.TabIndex = 33;
            this.pictureBox1.TabStop = false;
            // 
            // GeneralSettingsTabContainer
            // 
            this.GeneralSettingsTabContainer.Controls.Add(this.AgentStartupTabPage);
            this.GeneralSettingsTabContainer.Controls.Add(this.AgentConnectionTabPage);
            this.GeneralSettingsTabContainer.Controls.Add(this.AgentPersistenceAndStealthTabPage);
            this.GeneralSettingsTabContainer.Controls.Add(this.MitigationTabPage);
            this.GeneralSettingsTabContainer.Controls.Add(this.CollectionModeTabPage);
            this.GeneralSettingsTabContainer.Controls.Add(this.ReportingTabPage);
            this.GeneralSettingsTabContainer.Controls.Add(this.InformationTabPage);
            this.GeneralSettingsTabContainer.Controls.Add(this.AdvancedTabPage);
            this.GeneralSettingsTabContainer.Location = new System.Drawing.Point(265, 6);
            this.GeneralSettingsTabContainer.Name = "GeneralSettingsTabContainer";
            this.GeneralSettingsTabContainer.SelectedIndex = 0;
            this.GeneralSettingsTabContainer.Size = new System.Drawing.Size(900, 519);
            this.GeneralSettingsTabContainer.TabIndex = 1;
            this.GeneralSettingsTabContainer.Visible = false;
            this.GeneralSettingsTabContainer.Click += new System.EventHandler(this.MemoryTabPage_Click);
            // 
            // AgentStartupTabPage
            // 
            this.AgentStartupTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.AgentStartupTabPage.Controls.Add(this.groupBox5);
            this.AgentStartupTabPage.Controls.Add(this.groupBox1);
            this.AgentStartupTabPage.ForeColor = System.Drawing.Color.White;
            this.AgentStartupTabPage.Location = new System.Drawing.Point(4, 22);
            this.AgentStartupTabPage.Name = "AgentStartupTabPage";
            this.AgentStartupTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.AgentStartupTabPage.Size = new System.Drawing.Size(892, 493);
            this.AgentStartupTabPage.TabIndex = 9;
            this.AgentStartupTabPage.Text = "Startup";
            // 
            // groupBox5
            // 
            this.groupBox5.Controls.Add(this.label24);
            this.groupBox5.Controls.Add(this.AgentSelfProtectionRunKernelHeuristicsFirst);
            this.groupBox5.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox5.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox5.Location = new System.Drawing.Point(17, 247);
            this.groupBox5.Name = "groupBox5";
            this.groupBox5.Size = new System.Drawing.Size(600, 146);
            this.groupBox5.TabIndex = 19;
            this.groupBox5.TabStop = false;
            this.groupBox5.Text = "Self-protection";
            // 
            // label24
            // 
            this.label24.AutoSize = true;
            this.label24.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label24.ForeColor = System.Drawing.Color.Red;
            this.label24.Location = new System.Drawing.Point(55, 49);
            this.label24.Name = "label24";
            this.label24.Size = new System.Drawing.Size(414, 26);
            this.label24.TabIndex = 17;
            this.label24.Text = "Note:  this will force Fire-and-forget mode; if no kernel anomalies are reported," +
                " you can \r\ndeploy a second agent with a different startup mode.";
            // 
            // AgentSelfProtectionRunKernelHeuristicsFirst
            // 
            this.AgentSelfProtectionRunKernelHeuristicsFirst.AutoSize = true;
            this.AgentSelfProtectionRunKernelHeuristicsFirst.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.AgentSelfProtectionRunKernelHeuristicsFirst.ForeColor = System.Drawing.Color.White;
            this.AgentSelfProtectionRunKernelHeuristicsFirst.Location = new System.Drawing.Point(21, 28);
            this.AgentSelfProtectionRunKernelHeuristicsFirst.Name = "AgentSelfProtectionRunKernelHeuristicsFirst";
            this.AgentSelfProtectionRunKernelHeuristicsFirst.Size = new System.Drawing.Size(263, 17);
            this.AgentSelfProtectionRunKernelHeuristicsFirst.TabIndex = 16;
            this.AgentSelfProtectionRunKernelHeuristicsFirst.Text = "Identify kernel anomalies and abort startup if found";
            this.AgentSelfProtectionRunKernelHeuristicsFirst.UseVisualStyleBackColor = true;
            this.AgentSelfProtectionRunKernelHeuristicsFirst.CheckedChanged += new System.EventHandler(this.AgentSelfProtectionRunKernelHeuristicsFirst_CheckedChanged);
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.label63);
            this.groupBox1.Controls.Add(this.StartupEnterpriseMode);
            this.groupBox1.Controls.Add(this.label62);
            this.groupBox1.Controls.Add(this.label61);
            this.groupBox1.Controls.Add(this.StartupRemoteControlMode);
            this.groupBox1.Controls.Add(this.StartupFireAndForgetMode);
            this.groupBox1.Controls.Add(this.label66);
            this.groupBox1.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox1.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox1.Location = new System.Drawing.Point(17, 18);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(600, 211);
            this.groupBox1.TabIndex = 17;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Startup Mode";
            // 
            // label63
            // 
            this.label63.AutoSize = true;
            this.label63.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label63.ForeColor = System.Drawing.Color.White;
            this.label63.Location = new System.Drawing.Point(77, 176);
            this.label63.Name = "label63";
            this.label63.Size = new System.Drawing.Size(262, 13);
            this.label63.TabIndex = 16;
            this.label63.Text = "Run the scan and open a listening port for commands.";
            // 
            // StartupEnterpriseMode
            // 
            this.StartupEnterpriseMode.AutoSize = true;
            this.StartupEnterpriseMode.Checked = true;
            this.StartupEnterpriseMode.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.StartupEnterpriseMode.Location = new System.Drawing.Point(58, 155);
            this.StartupEnterpriseMode.Name = "StartupEnterpriseMode";
            this.StartupEnterpriseMode.Size = new System.Drawing.Size(101, 17);
            this.StartupEnterpriseMode.TabIndex = 15;
            this.StartupEnterpriseMode.TabStop = true;
            this.StartupEnterpriseMode.Text = "Enterprise mode";
            this.StartupEnterpriseMode.UseVisualStyleBackColor = true;
            this.StartupEnterpriseMode.CheckedChanged += new System.EventHandler(this.StartupEnterpriseMode_CheckedChanged);
            // 
            // label62
            // 
            this.label62.AutoSize = true;
            this.label62.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label62.ForeColor = System.Drawing.Color.White;
            this.label62.Location = new System.Drawing.Point(77, 118);
            this.label62.Name = "label62";
            this.label62.Size = new System.Drawing.Size(176, 13);
            this.label62.TabIndex = 14;
            this.label62.Text = "Open a listening port for commands.";
            // 
            // label61
            // 
            this.label61.AutoSize = true;
            this.label61.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label61.ForeColor = System.Drawing.Color.White;
            this.label61.Location = new System.Drawing.Point(77, 66);
            this.label61.Name = "label61";
            this.label61.Size = new System.Drawing.Size(220, 13);
            this.label61.TabIndex = 13;
            this.label61.Text = "Run the scan, report back, and remove itself.";
            // 
            // StartupRemoteControlMode
            // 
            this.StartupRemoteControlMode.AutoSize = true;
            this.StartupRemoteControlMode.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.StartupRemoteControlMode.Location = new System.Drawing.Point(58, 97);
            this.StartupRemoteControlMode.Name = "StartupRemoteControlMode";
            this.StartupRemoteControlMode.Size = new System.Drawing.Size(126, 17);
            this.StartupRemoteControlMode.TabIndex = 12;
            this.StartupRemoteControlMode.Text = "Remote control mode";
            this.StartupRemoteControlMode.UseVisualStyleBackColor = true;
            this.StartupRemoteControlMode.CheckedChanged += new System.EventHandler(this.StartupRemoteControlMode_CheckedChanged);
            // 
            // StartupFireAndForgetMode
            // 
            this.StartupFireAndForgetMode.AutoSize = true;
            this.StartupFireAndForgetMode.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.StartupFireAndForgetMode.Location = new System.Drawing.Point(58, 46);
            this.StartupFireAndForgetMode.Name = "StartupFireAndForgetMode";
            this.StartupFireAndForgetMode.Size = new System.Drawing.Size(125, 17);
            this.StartupFireAndForgetMode.TabIndex = 11;
            this.StartupFireAndForgetMode.Text = "Fire-and-Forget mode";
            this.StartupFireAndForgetMode.UseVisualStyleBackColor = true;
            this.StartupFireAndForgetMode.CheckedChanged += new System.EventHandler(this.StartupFireAndForgetMode_CheckedChanged);
            // 
            // label66
            // 
            this.label66.AutoSize = true;
            this.label66.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label66.ForeColor = System.Drawing.Color.White;
            this.label66.Location = new System.Drawing.Point(18, 23);
            this.label66.Name = "label66";
            this.label66.Size = new System.Drawing.Size(288, 13);
            this.label66.TabIndex = 10;
            this.label66.Text = "Once the agent has executed, what would you like it to do?";
            // 
            // AgentConnectionTabPage
            // 
            this.AgentConnectionTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.AgentConnectionTabPage.Controls.Add(this.groupBox6);
            this.AgentConnectionTabPage.Controls.Add(this.groupBox4);
            this.AgentConnectionTabPage.Location = new System.Drawing.Point(4, 22);
            this.AgentConnectionTabPage.Name = "AgentConnectionTabPage";
            this.AgentConnectionTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.AgentConnectionTabPage.Size = new System.Drawing.Size(892, 493);
            this.AgentConnectionTabPage.TabIndex = 10;
            this.AgentConnectionTabPage.Text = "Connection";
            // 
            // groupBox6
            // 
            this.groupBox6.Controls.Add(this.label77);
            this.groupBox6.Controls.Add(this.AgentEnforceCertificateIssuer);
            this.groupBox6.Controls.Add(this.label76);
            this.groupBox6.Controls.Add(this.label75);
            this.groupBox6.Controls.Add(this.label55);
            this.groupBox6.Controls.Add(this.AgentAuthenticateClientToServer);
            this.groupBox6.Controls.Add(this.AgentPFXPassword);
            this.groupBox6.Controls.Add(this.AgentAuthenticateServerToClient);
            this.groupBox6.Controls.Add(this.AgentPFXFile);
            this.groupBox6.Controls.Add(this.AgentEnforceStrongAuthentication);
            this.groupBox6.Controls.Add(this.BrowseButton2);
            this.groupBox6.Controls.Add(this.label54);
            this.groupBox6.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox6.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox6.Location = new System.Drawing.Point(16, 101);
            this.groupBox6.Name = "groupBox6";
            this.groupBox6.Size = new System.Drawing.Size(600, 316);
            this.groupBox6.TabIndex = 20;
            this.groupBox6.TabStop = false;
            this.groupBox6.Text = "Authentication";
            // 
            // label77
            // 
            this.label77.AutoSize = true;
            this.label77.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label77.ForeColor = System.Drawing.Color.Yellow;
            this.label77.Location = new System.Drawing.Point(18, 282);
            this.label77.Name = "label77";
            this.label77.Size = new System.Drawing.Size(250, 13);
            this.label77.TabIndex = 144;
            this.label77.Text = "*Note:  AES-256 is only supported after WinXP SP3";
            // 
            // AgentEnforceCertificateIssuer
            // 
            this.AgentEnforceCertificateIssuer.Location = new System.Drawing.Point(149, 184);
            this.AgentEnforceCertificateIssuer.Name = "AgentEnforceCertificateIssuer";
            this.AgentEnforceCertificateIssuer.Size = new System.Drawing.Size(278, 20);
            this.AgentEnforceCertificateIssuer.TabIndex = 4;
            // 
            // label76
            // 
            this.label76.AutoSize = true;
            this.label76.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label76.ForeColor = System.Drawing.Color.White;
            this.label76.Location = new System.Drawing.Point(18, 25);
            this.label76.Name = "label76";
            this.label76.Size = new System.Drawing.Size(274, 13);
            this.label76.TabIndex = 143;
            this.label76.Text = "Agent\'s private/public key pair in PFX/PKCS #12 format:";
            // 
            // label75
            // 
            this.label75.AutoSize = true;
            this.label75.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label75.ForeColor = System.Drawing.Color.White;
            this.label75.Location = new System.Drawing.Point(18, 187);
            this.label75.Name = "label75";
            this.label75.Size = new System.Drawing.Size(126, 13);
            this.label75.TabIndex = 3;
            this.label75.Text = "Enforce certificate issuer:";
            // 
            // label55
            // 
            this.label55.AutoSize = true;
            this.label55.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label55.ForeColor = System.Drawing.Color.White;
            this.label55.Location = new System.Drawing.Point(38, 74);
            this.label55.Name = "label55";
            this.label55.Size = new System.Drawing.Size(56, 13);
            this.label55.TabIndex = 142;
            this.label55.Text = "Password:";
            // 
            // AgentAuthenticateClientToServer
            // 
            this.AgentAuthenticateClientToServer.AutoSize = true;
            this.AgentAuthenticateClientToServer.Checked = true;
            this.AgentAuthenticateClientToServer.CheckState = System.Windows.Forms.CheckState.Checked;
            this.AgentAuthenticateClientToServer.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.AgentAuthenticateClientToServer.ForeColor = System.Drawing.Color.White;
            this.AgentAuthenticateClientToServer.Location = new System.Drawing.Point(21, 157);
            this.AgentAuthenticateClientToServer.Name = "AgentAuthenticateClientToServer";
            this.AgentAuthenticateClientToServer.Size = new System.Drawing.Size(158, 17);
            this.AgentAuthenticateClientToServer.TabIndex = 2;
            this.AgentAuthenticateClientToServer.Text = "Authenticate client to server";
            this.AgentAuthenticateClientToServer.UseVisualStyleBackColor = true;
            // 
            // AgentPFXPassword
            // 
            this.AgentPFXPassword.Location = new System.Drawing.Point(163, 71);
            this.AgentPFXPassword.Name = "AgentPFXPassword";
            this.AgentPFXPassword.PasswordChar = '*';
            this.AgentPFXPassword.Size = new System.Drawing.Size(210, 20);
            this.AgentPFXPassword.TabIndex = 141;
            this.AgentPFXPassword.UseSystemPasswordChar = true;
            // 
            // AgentAuthenticateServerToClient
            // 
            this.AgentAuthenticateServerToClient.AutoSize = true;
            this.AgentAuthenticateServerToClient.Checked = true;
            this.AgentAuthenticateServerToClient.CheckState = System.Windows.Forms.CheckState.Checked;
            this.AgentAuthenticateServerToClient.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.AgentAuthenticateServerToClient.ForeColor = System.Drawing.Color.White;
            this.AgentAuthenticateServerToClient.Location = new System.Drawing.Point(21, 134);
            this.AgentAuthenticateServerToClient.Name = "AgentAuthenticateServerToClient";
            this.AgentAuthenticateServerToClient.Size = new System.Drawing.Size(158, 17);
            this.AgentAuthenticateServerToClient.TabIndex = 1;
            this.AgentAuthenticateServerToClient.Text = "Authenticate server to client";
            this.AgentAuthenticateServerToClient.UseVisualStyleBackColor = true;
            // 
            // AgentPFXFile
            // 
            this.AgentPFXFile.Location = new System.Drawing.Point(163, 45);
            this.AgentPFXFile.Name = "AgentPFXFile";
            this.AgentPFXFile.Size = new System.Drawing.Size(210, 20);
            this.AgentPFXFile.TabIndex = 139;
            // 
            // AgentEnforceStrongAuthentication
            // 
            this.AgentEnforceStrongAuthentication.AutoSize = true;
            this.AgentEnforceStrongAuthentication.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.AgentEnforceStrongAuthentication.ForeColor = System.Drawing.Color.White;
            this.AgentEnforceStrongAuthentication.Location = new System.Drawing.Point(21, 111);
            this.AgentEnforceStrongAuthentication.Name = "AgentEnforceStrongAuthentication";
            this.AgentEnforceStrongAuthentication.Size = new System.Drawing.Size(232, 17);
            this.AgentEnforceStrongAuthentication.TabIndex = 0;
            this.AgentEnforceStrongAuthentication.Text = "Force strong authentication (AES-256 only)*";
            this.AgentEnforceStrongAuthentication.UseVisualStyleBackColor = true;
            // 
            // BrowseButton2
            // 
            this.BrowseButton2.ForeColor = System.Drawing.Color.Black;
            this.BrowseButton2.Location = new System.Drawing.Point(379, 43);
            this.BrowseButton2.Name = "BrowseButton2";
            this.BrowseButton2.Size = new System.Drawing.Size(75, 23);
            this.BrowseButton2.TabIndex = 140;
            this.BrowseButton2.Text = "Browse";
            this.BrowseButton2.UseVisualStyleBackColor = true;
            this.BrowseButton2.Click += new System.EventHandler(this.BrowseButton2_Click);
            // 
            // label54
            // 
            this.label54.AutoSize = true;
            this.label54.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label54.ForeColor = System.Drawing.Color.White;
            this.label54.Location = new System.Drawing.Point(38, 50);
            this.label54.Name = "label54";
            this.label54.Size = new System.Drawing.Size(67, 13);
            this.label54.TabIndex = 138;
            this.label54.Text = "Keystore file:";
            // 
            // groupBox4
            // 
            this.groupBox4.Controls.Add(this.AgentRandomizeListeningPort);
            this.groupBox4.Controls.Add(this.AgentListeningPort);
            this.groupBox4.Controls.Add(this.label72);
            this.groupBox4.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox4.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox4.Location = new System.Drawing.Point(16, 18);
            this.groupBox4.Name = "groupBox4";
            this.groupBox4.Size = new System.Drawing.Size(600, 69);
            this.groupBox4.TabIndex = 19;
            this.groupBox4.TabStop = false;
            this.groupBox4.Text = "Agent service";
            // 
            // AgentRandomizeListeningPort
            // 
            this.AgentRandomizeListeningPort.AutoSize = true;
            this.AgentRandomizeListeningPort.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.AgentRandomizeListeningPort.ForeColor = System.Drawing.Color.White;
            this.AgentRandomizeListeningPort.Location = new System.Drawing.Point(186, 32);
            this.AgentRandomizeListeningPort.Name = "AgentRandomizeListeningPort";
            this.AgentRandomizeListeningPort.Size = new System.Drawing.Size(142, 17);
            this.AgentRandomizeListeningPort.TabIndex = 16;
            this.AgentRandomizeListeningPort.Text = "Use random port number";
            this.AgentRandomizeListeningPort.UseVisualStyleBackColor = true;
            // 
            // AgentListeningPort
            // 
            this.AgentListeningPort.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.AgentListeningPort.Location = new System.Drawing.Point(103, 29);
            this.AgentListeningPort.Name = "AgentListeningPort";
            this.AgentListeningPort.Size = new System.Drawing.Size(61, 20);
            this.AgentListeningPort.TabIndex = 15;
            this.AgentListeningPort.Text = "41014";
            // 
            // label72
            // 
            this.label72.AutoSize = true;
            this.label72.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label72.ForeColor = System.Drawing.Color.White;
            this.label72.Location = new System.Drawing.Point(18, 32);
            this.label72.Name = "label72";
            this.label72.Size = new System.Drawing.Size(73, 13);
            this.label72.TabIndex = 14;
            this.label72.Text = "Listening port:";
            // 
            // AgentPersistenceAndStealthTabPage
            // 
            this.AgentPersistenceAndStealthTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.AgentPersistenceAndStealthTabPage.Controls.Add(this.groupBox3);
            this.AgentPersistenceAndStealthTabPage.Controls.Add(this.groupBox2);
            this.AgentPersistenceAndStealthTabPage.ForeColor = System.Drawing.Color.White;
            this.AgentPersistenceAndStealthTabPage.Location = new System.Drawing.Point(4, 22);
            this.AgentPersistenceAndStealthTabPage.Name = "AgentPersistenceAndStealthTabPage";
            this.AgentPersistenceAndStealthTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.AgentPersistenceAndStealthTabPage.Size = new System.Drawing.Size(892, 493);
            this.AgentPersistenceAndStealthTabPage.TabIndex = 8;
            this.AgentPersistenceAndStealthTabPage.Text = "Persistence/Stealth";
            // 
            // groupBox3
            // 
            this.groupBox3.Controls.Add(this.Stealth_UseZwLoadDriver);
            this.groupBox3.Controls.Add(this.Stealth_RandomizeAgentProcessName);
            this.groupBox3.Controls.Add(this.label73);
            this.groupBox3.Controls.Add(this.Stealth_HideAgentProcess);
            this.groupBox3.Controls.Add(this.Stealth_LoadAndCallImage);
            this.groupBox3.Controls.Add(this.Stealth_No_Dotnet);
            this.groupBox3.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox3.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox3.Location = new System.Drawing.Point(17, 247);
            this.groupBox3.Name = "groupBox3";
            this.groupBox3.Size = new System.Drawing.Size(600, 184);
            this.groupBox3.TabIndex = 77;
            this.groupBox3.TabStop = false;
            this.groupBox3.Text = "Stealth";
            // 
            // Stealth_UseZwLoadDriver
            // 
            this.Stealth_UseZwLoadDriver.AutoSize = true;
            this.Stealth_UseZwLoadDriver.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Stealth_UseZwLoadDriver.ForeColor = System.Drawing.Color.White;
            this.Stealth_UseZwLoadDriver.Location = new System.Drawing.Point(58, 138);
            this.Stealth_UseZwLoadDriver.Name = "Stealth_UseZwLoadDriver";
            this.Stealth_UseZwLoadDriver.Size = new System.Drawing.Size(183, 17);
            this.Stealth_UseZwLoadDriver.TabIndex = 77;
            this.Stealth_UseZwLoadDriver.Text = "Load driver using ZwLoadDriver()";
            this.Stealth_UseZwLoadDriver.UseVisualStyleBackColor = true;
            // 
            // Stealth_RandomizeAgentProcessName
            // 
            this.Stealth_RandomizeAgentProcessName.AutoSize = true;
            this.Stealth_RandomizeAgentProcessName.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Stealth_RandomizeAgentProcessName.ForeColor = System.Drawing.Color.White;
            this.Stealth_RandomizeAgentProcessName.Location = new System.Drawing.Point(58, 46);
            this.Stealth_RandomizeAgentProcessName.Name = "Stealth_RandomizeAgentProcessName";
            this.Stealth_RandomizeAgentProcessName.Size = new System.Drawing.Size(233, 17);
            this.Stealth_RandomizeAgentProcessName.TabIndex = 76;
            this.Stealth_RandomizeAgentProcessName.Text = "Randomize the name of the agent\'s process";
            this.Stealth_RandomizeAgentProcessName.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.Stealth_RandomizeAgentProcessName.UseVisualStyleBackColor = true;
            // 
            // label73
            // 
            this.label73.AutoSize = true;
            this.label73.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label73.ForeColor = System.Drawing.Color.White;
            this.label73.Location = new System.Drawing.Point(18, 23);
            this.label73.Name = "label73";
            this.label73.Size = new System.Drawing.Size(236, 13);
            this.label73.TabIndex = 10;
            this.label73.Text = "How should the agent keep its presence secret?";
            // 
            // Stealth_HideAgentProcess
            // 
            this.Stealth_HideAgentProcess.AutoSize = true;
            this.Stealth_HideAgentProcess.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Stealth_HideAgentProcess.ForeColor = System.Drawing.Color.White;
            this.Stealth_HideAgentProcess.Location = new System.Drawing.Point(58, 69);
            this.Stealth_HideAgentProcess.Name = "Stealth_HideAgentProcess";
            this.Stealth_HideAgentProcess.Size = new System.Drawing.Size(143, 17);
            this.Stealth_HideAgentProcess.TabIndex = 75;
            this.Stealth_HideAgentProcess.Text = "Hide the agent\'s process";
            this.Stealth_HideAgentProcess.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.Stealth_HideAgentProcess.UseVisualStyleBackColor = true;
            // 
            // Stealth_LoadAndCallImage
            // 
            this.Stealth_LoadAndCallImage.AutoSize = true;
            this.Stealth_LoadAndCallImage.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Stealth_LoadAndCallImage.ForeColor = System.Drawing.Color.White;
            this.Stealth_LoadAndCallImage.Location = new System.Drawing.Point(58, 115);
            this.Stealth_LoadAndCallImage.Name = "Stealth_LoadAndCallImage";
            this.Stealth_LoadAndCallImage.Size = new System.Drawing.Size(236, 17);
            this.Stealth_LoadAndCallImage.TabIndex = 73;
            this.Stealth_LoadAndCallImage.Text = "Load driver using system load and call image";
            this.Stealth_LoadAndCallImage.UseVisualStyleBackColor = true;
            // 
            // Stealth_No_Dotnet
            // 
            this.Stealth_No_Dotnet.AutoSize = true;
            this.Stealth_No_Dotnet.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Stealth_No_Dotnet.ForeColor = System.Drawing.Color.White;
            this.Stealth_No_Dotnet.Location = new System.Drawing.Point(58, 92);
            this.Stealth_No_Dotnet.Name = "Stealth_No_Dotnet";
            this.Stealth_No_Dotnet.Size = new System.Drawing.Size(165, 17);
            this.Stealth_No_Dotnet.TabIndex = 74;
            this.Stealth_No_Dotnet.Text = "Do not attempt to install .NET";
            this.Stealth_No_Dotnet.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.Stealth_No_Dotnet.UseVisualStyleBackColor = true;
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.label74);
            this.groupBox2.Controls.Add(this.AgentServiceName);
            this.groupBox2.Controls.Add(this.label71);
            this.groupBox2.Controls.Add(this.label68);
            this.groupBox2.Controls.Add(this.label69);
            this.groupBox2.Controls.Add(this.PersistenceRunOnce);
            this.groupBox2.Controls.Add(this.PersistenceInstallAsService);
            this.groupBox2.Controls.Add(this.label70);
            this.groupBox2.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox2.ForeColor = System.Drawing.Color.Chartreuse;
            this.groupBox2.Location = new System.Drawing.Point(17, 18);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(600, 223);
            this.groupBox2.TabIndex = 19;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Persistence";
            // 
            // label74
            // 
            this.label74.AutoSize = true;
            this.label74.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label74.ForeColor = System.Drawing.Color.White;
            this.label74.Location = new System.Drawing.Point(164, 116);
            this.label74.Name = "label74";
            this.label74.Size = new System.Drawing.Size(119, 13);
            this.label74.TabIndex = 17;
            this.label74.Text = "*Installs to system folder";
            // 
            // AgentServiceName
            // 
            this.AgentServiceName.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.AgentServiceName.Location = new System.Drawing.Point(160, 89);
            this.AgentServiceName.Name = "AgentServiceName";
            this.AgentServiceName.Size = new System.Drawing.Size(243, 20);
            this.AgentServiceName.TabIndex = 16;
            this.AgentServiceName.Text = "CwAgent";
            // 
            // label71
            // 
            this.label71.AutoSize = true;
            this.label71.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label71.ForeColor = System.Drawing.Color.White;
            this.label71.Location = new System.Drawing.Point(77, 92);
            this.label71.Name = "label71";
            this.label71.Size = new System.Drawing.Size(75, 13);
            this.label71.TabIndex = 15;
            this.label71.Text = "Service name:";
            // 
            // label68
            // 
            this.label68.AutoSize = true;
            this.label68.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label68.ForeColor = System.Drawing.Color.White;
            this.label68.Location = new System.Drawing.Point(77, 152);
            this.label68.Name = "label68";
            this.label68.Size = new System.Drawing.Size(290, 13);
            this.label68.TabIndex = 14;
            this.label68.Text = "The agent will destroy itself after completing the given tasks.";
            // 
            // label69
            // 
            this.label69.AutoSize = true;
            this.label69.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label69.ForeColor = System.Drawing.Color.White;
            this.label69.Location = new System.Drawing.Point(77, 66);
            this.label69.Name = "label69";
            this.label69.Size = new System.Drawing.Size(328, 13);
            this.label69.TabIndex = 13;
            this.label69.Text = "The agent will remain on the system until an administrator removes it.";
            // 
            // PersistenceRunOnce
            // 
            this.PersistenceRunOnce.AutoSize = true;
            this.PersistenceRunOnce.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.PersistenceRunOnce.Location = new System.Drawing.Point(58, 131);
            this.PersistenceRunOnce.Name = "PersistenceRunOnce";
            this.PersistenceRunOnce.Size = new System.Drawing.Size(72, 17);
            this.PersistenceRunOnce.TabIndex = 12;
            this.PersistenceRunOnce.Text = "Run once";
            this.PersistenceRunOnce.UseVisualStyleBackColor = true;
            // 
            // PersistenceInstallAsService
            // 
            this.PersistenceInstallAsService.AutoSize = true;
            this.PersistenceInstallAsService.Checked = true;
            this.PersistenceInstallAsService.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.PersistenceInstallAsService.Location = new System.Drawing.Point(58, 46);
            this.PersistenceInstallAsService.Name = "PersistenceInstallAsService";
            this.PersistenceInstallAsService.Size = new System.Drawing.Size(112, 17);
            this.PersistenceInstallAsService.TabIndex = 11;
            this.PersistenceInstallAsService.TabStop = true;
            this.PersistenceInstallAsService.Text = "Install as a service";
            this.PersistenceInstallAsService.UseVisualStyleBackColor = true;
            // 
            // label70
            // 
            this.label70.AutoSize = true;
            this.label70.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label70.ForeColor = System.Drawing.Color.White;
            this.label70.Location = new System.Drawing.Point(18, 23);
            this.label70.Name = "label70";
            this.label70.Size = new System.Drawing.Size(242, 13);
            this.label70.TabIndex = 10;
            this.label70.Text = "How long should the agent remain on the system?";
            // 
            // MitigationTabPage
            // 
            this.MitigationTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.MitigationTabPage.Controls.Add(this.Option_AutoMitigate);
            this.MitigationTabPage.Controls.Add(this.Option_Delete_MalwareFoundInRegistry);
            this.MitigationTabPage.Controls.Add(this.Option_Disable_Autorun);
            this.MitigationTabPage.Controls.Add(this.Option_Disable_USB);
            this.MitigationTabPage.Location = new System.Drawing.Point(4, 22);
            this.MitigationTabPage.Name = "MitigationTabPage";
            this.MitigationTabPage.Size = new System.Drawing.Size(892, 493);
            this.MitigationTabPage.TabIndex = 11;
            this.MitigationTabPage.Text = "Mitigation";
            // 
            // Option_AutoMitigate
            // 
            this.Option_AutoMitigate.AutoSize = true;
            this.Option_AutoMitigate.ForeColor = System.Drawing.Color.White;
            this.Option_AutoMitigate.Location = new System.Drawing.Point(19, 18);
            this.Option_AutoMitigate.Name = "Option_AutoMitigate";
            this.Option_AutoMitigate.Size = new System.Drawing.Size(186, 17);
            this.Option_AutoMitigate.TabIndex = 80;
            this.Option_AutoMitigate.Text = "Automatically mitigate any findings";
            this.Option_AutoMitigate.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.Option_AutoMitigate.UseVisualStyleBackColor = true;
            // 
            // Option_Delete_MalwareFoundInRegistry
            // 
            this.Option_Delete_MalwareFoundInRegistry.AutoSize = true;
            this.Option_Delete_MalwareFoundInRegistry.Checked = true;
            this.Option_Delete_MalwareFoundInRegistry.CheckState = System.Windows.Forms.CheckState.Checked;
            this.Option_Delete_MalwareFoundInRegistry.ForeColor = System.Drawing.Color.White;
            this.Option_Delete_MalwareFoundInRegistry.Location = new System.Drawing.Point(19, 87);
            this.Option_Delete_MalwareFoundInRegistry.Name = "Option_Delete_MalwareFoundInRegistry";
            this.Option_Delete_MalwareFoundInRegistry.Size = new System.Drawing.Size(246, 17);
            this.Option_Delete_MalwareFoundInRegistry.TabIndex = 79;
            this.Option_Delete_MalwareFoundInRegistry.Text = "Delete malicious files found in registry from disk";
            this.Option_Delete_MalwareFoundInRegistry.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.Option_Delete_MalwareFoundInRegistry.UseVisualStyleBackColor = true;
            // 
            // Option_Disable_Autorun
            // 
            this.Option_Disable_Autorun.AutoSize = true;
            this.Option_Disable_Autorun.ForeColor = System.Drawing.Color.White;
            this.Option_Disable_Autorun.Location = new System.Drawing.Point(19, 64);
            this.Option_Disable_Autorun.Name = "Option_Disable_Autorun";
            this.Option_Disable_Autorun.Size = new System.Drawing.Size(277, 17);
            this.Option_Disable_Autorun.TabIndex = 78;
            this.Option_Disable_Autorun.Text = "Disable/Disassociate Autorun (may require OS patch)";
            this.Option_Disable_Autorun.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.Option_Disable_Autorun.UseVisualStyleBackColor = true;
            // 
            // Option_Disable_USB
            // 
            this.Option_Disable_USB.AutoSize = true;
            this.Option_Disable_USB.ForeColor = System.Drawing.Color.White;
            this.Option_Disable_USB.Location = new System.Drawing.Point(19, 41);
            this.Option_Disable_USB.Name = "Option_Disable_USB";
            this.Option_Disable_USB.Size = new System.Drawing.Size(232, 17);
            this.Option_Disable_USB.TabIndex = 77;
            this.Option_Disable_USB.Text = "Disable the use of USB devices on all hosts";
            this.Option_Disable_USB.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.Option_Disable_USB.UseVisualStyleBackColor = true;
            // 
            // CollectionModeTabPage
            // 
            this.CollectionModeTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.CollectionModeTabPage.Controls.Add(this.textBox4);
            this.CollectionModeTabPage.Controls.Add(this.textBox3);
            this.CollectionModeTabPage.Controls.Add(this.textBox2);
            this.CollectionModeTabPage.Controls.Add(this.textBox1);
            this.CollectionModeTabPage.Controls.Add(this.ModeSelection_MaxParanoia);
            this.CollectionModeTabPage.Controls.Add(this.ModeSelection_Offline);
            this.CollectionModeTabPage.Controls.Add(this.ModeSelection_Live);
            this.CollectionModeTabPage.ForeColor = System.Drawing.Color.White;
            this.CollectionModeTabPage.Location = new System.Drawing.Point(4, 22);
            this.CollectionModeTabPage.Name = "CollectionModeTabPage";
            this.CollectionModeTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.CollectionModeTabPage.Size = new System.Drawing.Size(892, 493);
            this.CollectionModeTabPage.TabIndex = 1;
            this.CollectionModeTabPage.Text = "Collection";
            // 
            // textBox4
            // 
            this.textBox4.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.textBox4.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBox4.ForeColor = System.Drawing.Color.White;
            this.textBox4.Location = new System.Drawing.Point(44, 280);
            this.textBox4.Multiline = true;
            this.textBox4.Name = "textBox4";
            this.textBox4.Size = new System.Drawing.Size(522, 57);
            this.textBox4.TabIndex = 9;
            this.textBox4.Text = resources.GetString("textBox4.Text");
            // 
            // textBox3
            // 
            this.textBox3.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.textBox3.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBox3.ForeColor = System.Drawing.Color.White;
            this.textBox3.Location = new System.Drawing.Point(17, 20);
            this.textBox3.Multiline = true;
            this.textBox3.Name = "textBox3";
            this.textBox3.Size = new System.Drawing.Size(593, 40);
            this.textBox3.TabIndex = 7;
            this.textBox3.Text = "Please choose the analysis mode you would like the agent to use.  This mode will " +
                "greatly impact how evidence is collected and analyzed.";
            // 
            // textBox2
            // 
            this.textBox2.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.textBox2.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBox2.ForeColor = System.Drawing.Color.White;
            this.textBox2.Location = new System.Drawing.Point(44, 186);
            this.textBox2.Multiline = true;
            this.textBox2.Name = "textBox2";
            this.textBox2.Size = new System.Drawing.Size(522, 40);
            this.textBox2.TabIndex = 5;
            this.textBox2.Text = resources.GetString("textBox2.Text");
            // 
            // textBox1
            // 
            this.textBox1.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.textBox1.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBox1.ForeColor = System.Drawing.Color.White;
            this.textBox1.Location = new System.Drawing.Point(46, 95);
            this.textBox1.Multiline = true;
            this.textBox1.Name = "textBox1";
            this.textBox1.Size = new System.Drawing.Size(522, 40);
            this.textBox1.TabIndex = 3;
            this.textBox1.Text = resources.GetString("textBox1.Text");
            // 
            // ModeSelection_MaxParanoia
            // 
            this.ModeSelection_MaxParanoia.AutoSize = true;
            this.ModeSelection_MaxParanoia.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.ModeSelection_MaxParanoia.Location = new System.Drawing.Point(17, 257);
            this.ModeSelection_MaxParanoia.Name = "ModeSelection_MaxParanoia";
            this.ModeSelection_MaxParanoia.Size = new System.Drawing.Size(181, 17);
            this.ModeSelection_MaxParanoia.TabIndex = 8;
            this.ModeSelection_MaxParanoia.Text = "Exercise maximum paranoia";
            this.ModeSelection_MaxParanoia.UseVisualStyleBackColor = true;
            // 
            // ModeSelection_Offline
            // 
            this.ModeSelection_Offline.AutoSize = true;
            this.ModeSelection_Offline.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.ModeSelection_Offline.ForeColor = System.Drawing.Color.DodgerBlue;
            this.ModeSelection_Offline.Location = new System.Drawing.Point(33, 163);
            this.ModeSelection_Offline.Name = "ModeSelection_Offline";
            this.ModeSelection_Offline.Size = new System.Drawing.Size(307, 17);
            this.ModeSelection_Offline.TabIndex = 4;
            this.ModeSelection_Offline.Text = "OFFLINE ANALYSIS (Use Memory Snapshot Only)";
            this.ModeSelection_Offline.UseVisualStyleBackColor = true;
            // 
            // ModeSelection_Live
            // 
            this.ModeSelection_Live.AutoSize = true;
            this.ModeSelection_Live.Checked = true;
            this.ModeSelection_Live.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.ModeSelection_Live.ForeColor = System.Drawing.Color.DarkOrange;
            this.ModeSelection_Live.Location = new System.Drawing.Point(34, 69);
            this.ModeSelection_Live.Name = "ModeSelection_Live";
            this.ModeSelection_Live.Size = new System.Drawing.Size(235, 17);
            this.ModeSelection_Live.TabIndex = 1;
            this.ModeSelection_Live.TabStop = true;
            this.ModeSelection_Live.Text = "LIVE ANALYSIS (Use Windows APIs)";
            this.ModeSelection_Live.UseVisualStyleBackColor = true;
            // 
            // ReportingTabPage
            // 
            this.ReportingTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.ReportingTabPage.Controls.Add(this.ReportingAuthPanel);
            this.ReportingTabPage.Controls.Add(this.ReportingTlsPanel);
            this.ReportingTabPage.Controls.Add(this.ReportingWebPanel);
            this.ReportingTabPage.Controls.Add(this.ReportingEmailPanel);
            this.ReportingTabPage.Controls.Add(this.ReportingFtpPanel);
            this.ReportingTabPage.Controls.Add(this.ReportingNetworkSharePanel);
            this.ReportingTabPage.Controls.Add(this.label9);
            this.ReportingTabPage.Controls.Add(this.Reporting_EnableAutoReporting);
            this.ReportingTabPage.ForeColor = System.Drawing.Color.White;
            this.ReportingTabPage.Location = new System.Drawing.Point(4, 22);
            this.ReportingTabPage.Name = "ReportingTabPage";
            this.ReportingTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.ReportingTabPage.Size = new System.Drawing.Size(892, 493);
            this.ReportingTabPage.TabIndex = 3;
            this.ReportingTabPage.Text = "Reporting";
            // 
            // ReportingAuthPanel
            // 
            this.ReportingAuthPanel.Controls.Add(this.label56);
            this.ReportingAuthPanel.Controls.Add(this.Reporting_Archive_Password);
            this.ReportingAuthPanel.Controls.Add(this.label52);
            this.ReportingAuthPanel.Controls.Add(this.Reporting_Auth_Type);
            this.ReportingAuthPanel.Controls.Add(this.label51);
            this.ReportingAuthPanel.Controls.Add(this.label50);
            this.ReportingAuthPanel.Controls.Add(this.label46);
            this.ReportingAuthPanel.Controls.Add(this.Reporting_Auth_Server_PubKey);
            this.ReportingAuthPanel.Controls.Add(this.Reporting_Auth_Password);
            this.ReportingAuthPanel.Controls.Add(this.Reporting_Auth_UserName);
            this.ReportingAuthPanel.Controls.Add(this.BrowseButton1);
            this.ReportingAuthPanel.Controls.Add(this.label20);
            this.ReportingAuthPanel.Controls.Add(this.label17);
            this.ReportingAuthPanel.Controls.Add(this.label18);
            this.ReportingAuthPanel.Enabled = false;
            this.ReportingAuthPanel.ForeColor = System.Drawing.Color.Transparent;
            this.ReportingAuthPanel.Location = new System.Drawing.Point(8, 237);
            this.ReportingAuthPanel.Name = "ReportingAuthPanel";
            this.ReportingAuthPanel.Size = new System.Drawing.Size(625, 207);
            this.ReportingAuthPanel.TabIndex = 81;
            // 
            // label56
            // 
            this.label56.AutoSize = true;
            this.label56.Location = new System.Drawing.Point(17, 142);
            this.label56.Name = "label56";
            this.label56.Size = new System.Drawing.Size(94, 13);
            this.label56.TabIndex = 139;
            this.label56.Text = "Archive password:";
            // 
            // Reporting_Archive_Password
            // 
            this.Reporting_Archive_Password.Location = new System.Drawing.Point(113, 139);
            this.Reporting_Archive_Password.Name = "Reporting_Archive_Password";
            this.Reporting_Archive_Password.Size = new System.Drawing.Size(210, 20);
            this.Reporting_Archive_Password.TabIndex = 138;
            this.Reporting_Archive_Password.UseSystemPasswordChar = true;
            // 
            // label52
            // 
            this.label52.AutoSize = true;
            this.label52.ForeColor = System.Drawing.Color.White;
            this.label52.Location = new System.Drawing.Point(348, 37);
            this.label52.Name = "label52";
            this.label52.Size = new System.Drawing.Size(34, 13);
            this.label52.TabIndex = 132;
            this.label52.Text = "Type:";
            // 
            // Reporting_Auth_Type
            // 
            this.Reporting_Auth_Type.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.Reporting_Auth_Type.FormattingEnabled = true;
            this.Reporting_Auth_Type.Items.AddRange(new object[] {
            "Basic",
            "Digest",
            "NTLM",
            "Kerberos"});
            this.Reporting_Auth_Type.Location = new System.Drawing.Point(388, 33);
            this.Reporting_Auth_Type.Name = "Reporting_Auth_Type";
            this.Reporting_Auth_Type.Size = new System.Drawing.Size(138, 21);
            this.Reporting_Auth_Type.TabIndex = 131;
            // 
            // label51
            // 
            this.label51.AutoSize = true;
            this.label51.ForeColor = System.Drawing.Color.White;
            this.label51.Location = new System.Drawing.Point(17, 101);
            this.label51.Name = "label51";
            this.label51.Size = new System.Drawing.Size(55, 13);
            this.label51.TabIndex = 130;
            this.label51.Text = "Transport:";
            // 
            // label50
            // 
            this.label50.AutoSize = true;
            this.label50.ForeColor = System.Drawing.Color.White;
            this.label50.Location = new System.Drawing.Point(17, 33);
            this.label50.Name = "label50";
            this.label50.Size = new System.Drawing.Size(62, 13);
            this.label50.TabIndex = 129;
            this.label50.Text = "Application:";
            // 
            // label46
            // 
            this.label46.AutoSize = true;
            this.label46.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label46.ForeColor = System.Drawing.Color.Chartreuse;
            this.label46.Location = new System.Drawing.Point(8, 7);
            this.label46.Name = "label46";
            this.label46.Size = new System.Drawing.Size(93, 13);
            this.label46.TabIndex = 128;
            this.label46.Text = "Authentication:";
            // 
            // Reporting_Auth_Server_PubKey
            // 
            this.Reporting_Auth_Server_PubKey.Enabled = false;
            this.Reporting_Auth_Server_PubKey.Location = new System.Drawing.Point(235, 98);
            this.Reporting_Auth_Server_PubKey.Name = "Reporting_Auth_Server_PubKey";
            this.Reporting_Auth_Server_PubKey.Size = new System.Drawing.Size(210, 20);
            this.Reporting_Auth_Server_PubKey.TabIndex = 126;
            // 
            // Reporting_Auth_Password
            // 
            this.Reporting_Auth_Password.Location = new System.Drawing.Point(177, 65);
            this.Reporting_Auth_Password.Name = "Reporting_Auth_Password";
            this.Reporting_Auth_Password.Size = new System.Drawing.Size(147, 20);
            this.Reporting_Auth_Password.TabIndex = 124;
            this.Reporting_Auth_Password.UseSystemPasswordChar = true;
            // 
            // Reporting_Auth_UserName
            // 
            this.Reporting_Auth_UserName.Location = new System.Drawing.Point(177, 34);
            this.Reporting_Auth_UserName.Name = "Reporting_Auth_UserName";
            this.Reporting_Auth_UserName.Size = new System.Drawing.Size(147, 20);
            this.Reporting_Auth_UserName.TabIndex = 122;
            // 
            // BrowseButton1
            // 
            this.BrowseButton1.Enabled = false;
            this.BrowseButton1.ForeColor = System.Drawing.Color.Black;
            this.BrowseButton1.Location = new System.Drawing.Point(451, 96);
            this.BrowseButton1.Name = "BrowseButton1";
            this.BrowseButton1.Size = new System.Drawing.Size(75, 23);
            this.BrowseButton1.TabIndex = 127;
            this.BrowseButton1.Text = "Browse";
            this.BrowseButton1.UseVisualStyleBackColor = true;
            // 
            // label20
            // 
            this.label20.AutoSize = true;
            this.label20.Location = new System.Drawing.Point(110, 103);
            this.label20.Name = "label20";
            this.label20.Size = new System.Drawing.Size(98, 13);
            this.label20.TabIndex = 125;
            this.label20.Text = "Public Key (server):";
            // 
            // label17
            // 
            this.label17.AutoSize = true;
            this.label17.Location = new System.Drawing.Point(110, 68);
            this.label17.Name = "label17";
            this.label17.Size = new System.Drawing.Size(56, 13);
            this.label17.TabIndex = 123;
            this.label17.Text = "Password:";
            // 
            // label18
            // 
            this.label18.AutoSize = true;
            this.label18.Location = new System.Drawing.Point(110, 37);
            this.label18.Name = "label18";
            this.label18.Size = new System.Drawing.Size(61, 13);
            this.label18.TabIndex = 121;
            this.label18.Text = "User name:";
            // 
            // ReportingTlsPanel
            // 
            this.ReportingTlsPanel.Controls.Add(this.label53);
            this.ReportingTlsPanel.Controls.Add(this.Reporting_TLS_Port);
            this.ReportingTlsPanel.Controls.Add(this.Reporting_Use_TLS);
            this.ReportingTlsPanel.Controls.Add(this.label13);
            this.ReportingTlsPanel.Enabled = false;
            this.ReportingTlsPanel.Location = new System.Drawing.Point(8, 199);
            this.ReportingTlsPanel.Name = "ReportingTlsPanel";
            this.ReportingTlsPanel.Size = new System.Drawing.Size(625, 32);
            this.ReportingTlsPanel.TabIndex = 86;
            // 
            // label53
            // 
            this.label53.AutoSize = true;
            this.label53.ForeColor = System.Drawing.Color.White;
            this.label53.Location = new System.Drawing.Point(301, 10);
            this.label53.Name = "label53";
            this.label53.Size = new System.Drawing.Size(28, 13);
            this.label53.TabIndex = 117;
            this.label53.Text = "port:";
            // 
            // Reporting_TLS_Port
            // 
            this.Reporting_TLS_Port.Location = new System.Drawing.Point(335, 7);
            this.Reporting_TLS_Port.Name = "Reporting_TLS_Port";
            this.Reporting_TLS_Port.Size = new System.Drawing.Size(46, 20);
            this.Reporting_TLS_Port.TabIndex = 116;
            // 
            // Reporting_Use_TLS
            // 
            this.Reporting_Use_TLS.AutoSize = true;
            this.Reporting_Use_TLS.Location = new System.Drawing.Point(189, 9);
            this.Reporting_Use_TLS.Name = "Reporting_Use_TLS";
            this.Reporting_Use_TLS.Size = new System.Drawing.Size(93, 17);
            this.Reporting_Use_TLS.TabIndex = 115;
            this.Reporting_Use_TLS.Text = "Use TLS/SSL";
            this.Reporting_Use_TLS.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.Reporting_Use_TLS.UseVisualStyleBackColor = true;
            // 
            // label13
            // 
            this.label13.AutoSize = true;
            this.label13.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label13.ForeColor = System.Drawing.Color.Chartreuse;
            this.label13.Location = new System.Drawing.Point(8, 9);
            this.label13.Name = "label13";
            this.label13.Size = new System.Drawing.Size(166, 13);
            this.label13.TabIndex = 114;
            this.label13.Text = "Confidentiality and Integrity:";
            // 
            // ReportingWebPanel
            // 
            this.ReportingWebPanel.Controls.Add(this.label45);
            this.ReportingWebPanel.Controls.Add(this.Reporting_WebServer_Port);
            this.ReportingWebPanel.Controls.Add(this.label44);
            this.ReportingWebPanel.Controls.Add(this.Reporting_Method_WebServer_URI);
            this.ReportingWebPanel.Controls.Add(this.label19);
            this.ReportingWebPanel.Enabled = false;
            this.ReportingWebPanel.Location = new System.Drawing.Point(8, 162);
            this.ReportingWebPanel.Name = "ReportingWebPanel";
            this.ReportingWebPanel.Size = new System.Drawing.Size(625, 31);
            this.ReportingWebPanel.TabIndex = 85;
            // 
            // label45
            // 
            this.label45.AutoSize = true;
            this.label45.ForeColor = System.Drawing.Color.White;
            this.label45.Location = new System.Drawing.Point(403, 7);
            this.label45.Name = "label45";
            this.label45.Size = new System.Drawing.Size(28, 13);
            this.label45.TabIndex = 109;
            this.label45.Text = "port:";
            // 
            // Reporting_WebServer_Port
            // 
            this.Reporting_WebServer_Port.Location = new System.Drawing.Point(437, 4);
            this.Reporting_WebServer_Port.Name = "Reporting_WebServer_Port";
            this.Reporting_WebServer_Port.Size = new System.Drawing.Size(46, 20);
            this.Reporting_WebServer_Port.TabIndex = 108;
            // 
            // label44
            // 
            this.label44.AutoSize = true;
            this.label44.Location = new System.Drawing.Point(108, 7);
            this.label44.Name = "label44";
            this.label44.Size = new System.Drawing.Size(49, 13);
            this.label44.TabIndex = 107;
            this.label44.Text = "http(s)://";
            // 
            // Reporting_Method_WebServer_URI
            // 
            this.Reporting_Method_WebServer_URI.Location = new System.Drawing.Point(163, 4);
            this.Reporting_Method_WebServer_URI.Name = "Reporting_Method_WebServer_URI";
            this.Reporting_Method_WebServer_URI.Size = new System.Drawing.Size(234, 20);
            this.Reporting_Method_WebServer_URI.TabIndex = 106;
            // 
            // label19
            // 
            this.label19.AutoSize = true;
            this.label19.ForeColor = System.Drawing.Color.White;
            this.label19.Location = new System.Drawing.Point(15, 7);
            this.label19.Name = "label19";
            this.label19.Size = new System.Drawing.Size(87, 13);
            this.label19.TabIndex = 105;
            this.label19.Text = "Web server URI:";
            // 
            // ReportingEmailPanel
            // 
            this.ReportingEmailPanel.Controls.Add(this.label43);
            this.ReportingEmailPanel.Controls.Add(this.Reporting_SMTP_Port);
            this.ReportingEmailPanel.Controls.Add(this.Reporting_SMTP_Server);
            this.ReportingEmailPanel.Controls.Add(this.Reporting_Method_EmailAddress);
            this.ReportingEmailPanel.Controls.Add(this.label16);
            this.ReportingEmailPanel.Controls.Add(this.label15);
            this.ReportingEmailPanel.Controls.Add(this.label12);
            this.ReportingEmailPanel.Enabled = false;
            this.ReportingEmailPanel.Location = new System.Drawing.Point(8, 99);
            this.ReportingEmailPanel.Name = "ReportingEmailPanel";
            this.ReportingEmailPanel.Size = new System.Drawing.Size(625, 57);
            this.ReportingEmailPanel.TabIndex = 84;
            // 
            // label43
            // 
            this.label43.AutoSize = true;
            this.label43.ForeColor = System.Drawing.Color.White;
            this.label43.Location = new System.Drawing.Point(405, 33);
            this.label43.Name = "label43";
            this.label43.Size = new System.Drawing.Size(28, 13);
            this.label43.TabIndex = 108;
            this.label43.Text = "port:";
            // 
            // Reporting_SMTP_Port
            // 
            this.Reporting_SMTP_Port.Location = new System.Drawing.Point(439, 30);
            this.Reporting_SMTP_Port.Name = "Reporting_SMTP_Port";
            this.Reporting_SMTP_Port.Size = new System.Drawing.Size(46, 20);
            this.Reporting_SMTP_Port.TabIndex = 107;
            // 
            // Reporting_SMTP_Server
            // 
            this.Reporting_SMTP_Server.Location = new System.Drawing.Point(188, 30);
            this.Reporting_SMTP_Server.Name = "Reporting_SMTP_Server";
            this.Reporting_SMTP_Server.Size = new System.Drawing.Size(211, 20);
            this.Reporting_SMTP_Server.TabIndex = 105;
            // 
            // Reporting_Method_EmailAddress
            // 
            this.Reporting_Method_EmailAddress.Location = new System.Drawing.Point(188, 4);
            this.Reporting_Method_EmailAddress.Name = "Reporting_Method_EmailAddress";
            this.Reporting_Method_EmailAddress.Size = new System.Drawing.Size(211, 20);
            this.Reporting_Method_EmailAddress.TabIndex = 103;
            // 
            // label16
            // 
            this.label16.AutoSize = true;
            this.label16.Location = new System.Drawing.Point(108, 33);
            this.label16.Name = "label16";
            this.label16.Size = new System.Drawing.Size(74, 13);
            this.label16.TabIndex = 106;
            this.label16.Text = "SMTP Server:";
            // 
            // label15
            // 
            this.label15.AutoSize = true;
            this.label15.Location = new System.Drawing.Point(108, 7);
            this.label15.Name = "label15";
            this.label15.Size = new System.Drawing.Size(48, 13);
            this.label15.TabIndex = 104;
            this.label15.Text = "Address:";
            // 
            // label12
            // 
            this.label12.AutoSize = true;
            this.label12.ForeColor = System.Drawing.Color.White;
            this.label12.Location = new System.Drawing.Point(17, 4);
            this.label12.Name = "label12";
            this.label12.Size = new System.Drawing.Size(38, 13);
            this.label12.TabIndex = 102;
            this.label12.Text = "E-mail:";
            // 
            // ReportingFtpPanel
            // 
            this.ReportingFtpPanel.Controls.Add(this.label57);
            this.ReportingFtpPanel.Controls.Add(this.Reporting_Method_FTPServer);
            this.ReportingFtpPanel.Controls.Add(this.label11);
            this.ReportingFtpPanel.Enabled = false;
            this.ReportingFtpPanel.Location = new System.Drawing.Point(8, 63);
            this.ReportingFtpPanel.Name = "ReportingFtpPanel";
            this.ReportingFtpPanel.Size = new System.Drawing.Size(625, 30);
            this.ReportingFtpPanel.TabIndex = 83;
            // 
            // label57
            // 
            this.label57.AutoSize = true;
            this.label57.Location = new System.Drawing.Point(108, 7);
            this.label57.Name = "label57";
            this.label57.Size = new System.Drawing.Size(32, 13);
            this.label57.TabIndex = 124;
            this.label57.Text = "ftp://";
            // 
            // Reporting_Method_FTPServer
            // 
            this.Reporting_Method_FTPServer.Location = new System.Drawing.Point(146, 4);
            this.Reporting_Method_FTPServer.Name = "Reporting_Method_FTPServer";
            this.Reporting_Method_FTPServer.Size = new System.Drawing.Size(211, 20);
            this.Reporting_Method_FTPServer.TabIndex = 123;
            // 
            // label11
            // 
            this.label11.AutoSize = true;
            this.label11.ForeColor = System.Drawing.Color.White;
            this.label11.Location = new System.Drawing.Point(17, 7);
            this.label11.Name = "label11";
            this.label11.Size = new System.Drawing.Size(64, 13);
            this.label11.TabIndex = 122;
            this.label11.Text = "FTP Server:";
            // 
            // ReportingNetworkSharePanel
            // 
            this.ReportingNetworkSharePanel.Controls.Add(this.label42);
            this.ReportingNetworkSharePanel.Controls.Add(this.Reporting_Method_NetworkShare);
            this.ReportingNetworkSharePanel.Controls.Add(this.label31);
            this.ReportingNetworkSharePanel.Enabled = false;
            this.ReportingNetworkSharePanel.Location = new System.Drawing.Point(8, 29);
            this.ReportingNetworkSharePanel.Name = "ReportingNetworkSharePanel";
            this.ReportingNetworkSharePanel.Size = new System.Drawing.Size(625, 33);
            this.ReportingNetworkSharePanel.TabIndex = 82;
            // 
            // label42
            // 
            this.label42.AutoSize = true;
            this.label42.ForeColor = System.Drawing.Color.White;
            this.label42.Location = new System.Drawing.Point(328, 15);
            this.label42.Name = "label42";
            this.label42.Size = new System.Drawing.Size(186, 13);
            this.label42.TabIndex = 102;
            this.label42.Text = "example:  \\\\CorpShare\\ScanResults$";
            // 
            // Reporting_Method_NetworkShare
            // 
            this.Reporting_Method_NetworkShare.Location = new System.Drawing.Point(111, 8);
            this.Reporting_Method_NetworkShare.Name = "Reporting_Method_NetworkShare";
            this.Reporting_Method_NetworkShare.Size = new System.Drawing.Size(211, 20);
            this.Reporting_Method_NetworkShare.TabIndex = 101;
            // 
            // label31
            // 
            this.label31.AutoSize = true;
            this.label31.ForeColor = System.Drawing.Color.White;
            this.label31.Location = new System.Drawing.Point(17, 11);
            this.label31.Name = "label31";
            this.label31.Size = new System.Drawing.Size(79, 13);
            this.label31.TabIndex = 100;
            this.label31.Text = "Network share:";
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label9.ForeColor = System.Drawing.Color.Chartreuse;
            this.label9.Location = new System.Drawing.Point(14, 13);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(96, 13);
            this.label9.TabIndex = 31;
            this.label9.Text = "Send results to:";
            // 
            // Reporting_EnableAutoReporting
            // 
            this.Reporting_EnableAutoReporting.AutoCheck = false;
            this.Reporting_EnableAutoReporting.AutoSize = true;
            this.Reporting_EnableAutoReporting.Location = new System.Drawing.Point(136, 13);
            this.Reporting_EnableAutoReporting.Name = "Reporting_EnableAutoReporting";
            this.Reporting_EnableAutoReporting.Size = new System.Drawing.Size(156, 17);
            this.Reporting_EnableAutoReporting.TabIndex = 26;
            this.Reporting_EnableAutoReporting.Text = "Enable automated reporting";
            this.Reporting_EnableAutoReporting.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.Reporting_EnableAutoReporting.UseVisualStyleBackColor = true;
            this.Reporting_EnableAutoReporting.MouseDown += new System.Windows.Forms.MouseEventHandler(this.Reporting_EnableAutoReporting_MouseDown);
            // 
            // InformationTabPage
            // 
            this.InformationTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.InformationTabPage.Controls.Add(this.Information_Notes);
            this.InformationTabPage.Controls.Add(this.Information_AdminEmail);
            this.InformationTabPage.Controls.Add(this.Information_AdminPhone);
            this.InformationTabPage.Controls.Add(this.Information_OrgName);
            this.InformationTabPage.Controls.Add(this.Information_AdminName);
            this.InformationTabPage.Controls.Add(this.Information_OrgLocation);
            this.InformationTabPage.Controls.Add(this.Information_NetworkName);
            this.InformationTabPage.Controls.Add(this.Information_NetworkAddrRange);
            this.InformationTabPage.Controls.Add(this.label59);
            this.InformationTabPage.Controls.Add(this.label58);
            this.InformationTabPage.Controls.Add(this.label8);
            this.InformationTabPage.Controls.Add(this.label4);
            this.InformationTabPage.Controls.Add(this.label14);
            this.InformationTabPage.Controls.Add(this.label1);
            this.InformationTabPage.Controls.Add(this.label2);
            this.InformationTabPage.Controls.Add(this.label3);
            this.InformationTabPage.Controls.Add(this.label5);
            this.InformationTabPage.Controls.Add(this.label6);
            this.InformationTabPage.Controls.Add(this.label7);
            this.InformationTabPage.ForeColor = System.Drawing.Color.White;
            this.InformationTabPage.Location = new System.Drawing.Point(4, 22);
            this.InformationTabPage.Name = "InformationTabPage";
            this.InformationTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.InformationTabPage.Size = new System.Drawing.Size(892, 493);
            this.InformationTabPage.TabIndex = 0;
            this.InformationTabPage.Text = "Information";
            // 
            // Information_Notes
            // 
            this.Information_Notes.Location = new System.Drawing.Point(101, 309);
            this.Information_Notes.Multiline = true;
            this.Information_Notes.Name = "Information_Notes";
            this.Information_Notes.Size = new System.Drawing.Size(407, 108);
            this.Information_Notes.TabIndex = 23;
            // 
            // Information_AdminEmail
            // 
            this.Information_AdminEmail.Location = new System.Drawing.Point(101, 257);
            this.Information_AdminEmail.Name = "Information_AdminEmail";
            this.Information_AdminEmail.Size = new System.Drawing.Size(255, 20);
            this.Information_AdminEmail.TabIndex = 21;
            // 
            // Information_AdminPhone
            // 
            this.Information_AdminPhone.Location = new System.Drawing.Point(101, 231);
            this.Information_AdminPhone.Name = "Information_AdminPhone";
            this.Information_AdminPhone.Size = new System.Drawing.Size(255, 20);
            this.Information_AdminPhone.TabIndex = 19;
            // 
            // Information_OrgName
            // 
            this.Information_OrgName.Location = new System.Drawing.Point(101, 37);
            this.Information_OrgName.Name = "Information_OrgName";
            this.Information_OrgName.Size = new System.Drawing.Size(407, 20);
            this.Information_OrgName.TabIndex = 9;
            // 
            // Information_AdminName
            // 
            this.Information_AdminName.Location = new System.Drawing.Point(101, 205);
            this.Information_AdminName.Name = "Information_AdminName";
            this.Information_AdminName.Size = new System.Drawing.Size(255, 20);
            this.Information_AdminName.TabIndex = 14;
            // 
            // Information_OrgLocation
            // 
            this.Information_OrgLocation.Location = new System.Drawing.Point(101, 63);
            this.Information_OrgLocation.Name = "Information_OrgLocation";
            this.Information_OrgLocation.Size = new System.Drawing.Size(407, 20);
            this.Information_OrgLocation.TabIndex = 10;
            // 
            // Information_NetworkName
            // 
            this.Information_NetworkName.Location = new System.Drawing.Point(101, 116);
            this.Information_NetworkName.Name = "Information_NetworkName";
            this.Information_NetworkName.Size = new System.Drawing.Size(407, 20);
            this.Information_NetworkName.TabIndex = 11;
            // 
            // Information_NetworkAddrRange
            // 
            this.Information_NetworkAddrRange.Location = new System.Drawing.Point(101, 143);
            this.Information_NetworkAddrRange.Name = "Information_NetworkAddrRange";
            this.Information_NetworkAddrRange.Size = new System.Drawing.Size(140, 20);
            this.Information_NetworkAddrRange.TabIndex = 12;
            // 
            // label59
            // 
            this.label59.AutoSize = true;
            this.label59.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label59.ForeColor = System.Drawing.Color.Chartreuse;
            this.label59.Location = new System.Drawing.Point(6, 293);
            this.label59.Name = "label59";
            this.label59.Size = new System.Drawing.Size(44, 13);
            this.label59.TabIndex = 22;
            this.label59.Text = "Notes:";
            // 
            // label58
            // 
            this.label58.AutoSize = true;
            this.label58.ForeColor = System.Drawing.Color.White;
            this.label58.Location = new System.Drawing.Point(14, 260);
            this.label58.Name = "label58";
            this.label58.Size = new System.Drawing.Size(35, 13);
            this.label58.TabIndex = 20;
            this.label58.Text = "Email:";
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.ForeColor = System.Drawing.Color.White;
            this.label8.Location = new System.Drawing.Point(14, 234);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(41, 13);
            this.label8.TabIndex = 18;
            this.label8.Text = "Phone:";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label4.ForeColor = System.Drawing.Color.Chartreuse;
            this.label4.Location = new System.Drawing.Point(6, 181);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(84, 13);
            this.label4.TabIndex = 17;
            this.label4.Text = "Administrator:";
            // 
            // label14
            // 
            this.label14.AutoSize = true;
            this.label14.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label14.ForeColor = System.Drawing.Color.Chartreuse;
            this.label14.Location = new System.Drawing.Point(6, 14);
            this.label14.Name = "label14";
            this.label14.Size = new System.Drawing.Size(82, 13);
            this.label14.TabIndex = 16;
            this.label14.Text = "Organization:";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.ForeColor = System.Drawing.Color.White;
            this.label1.Location = new System.Drawing.Point(14, 40);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(38, 13);
            this.label1.TabIndex = 0;
            this.label1.Text = "Name:";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label2.ForeColor = System.Drawing.Color.Chartreuse;
            this.label2.Location = new System.Drawing.Point(6, 96);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(58, 13);
            this.label2.TabIndex = 1;
            this.label2.Text = "Network:";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.ForeColor = System.Drawing.Color.White;
            this.label3.Location = new System.Drawing.Point(14, 146);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(83, 13);
            this.label3.TabIndex = 2;
            this.label3.Text = "Address Range:";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.ForeColor = System.Drawing.Color.White;
            this.label5.Location = new System.Drawing.Point(14, 123);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(38, 13);
            this.label5.TabIndex = 4;
            this.label5.Text = "Name:";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.ForeColor = System.Drawing.Color.White;
            this.label6.Location = new System.Drawing.Point(14, 66);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(51, 13);
            this.label6.TabIndex = 5;
            this.label6.Text = "Location:";
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.ForeColor = System.Drawing.Color.White;
            this.label7.Location = new System.Drawing.Point(14, 208);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(38, 13);
            this.label7.TabIndex = 6;
            this.label7.Text = "Name:";
            // 
            // AdvancedTabPage
            // 
            this.AdvancedTabPage.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.AdvancedTabPage.Controls.Add(this.label67);
            this.AdvancedTabPage.Controls.Add(this.Advanced_3rdPartyApp_Distribute);
            this.AdvancedTabPage.Controls.Add(this.Advanced_3rdPartyApp_Arguments);
            this.AdvancedTabPage.Controls.Add(this.Advanced_3rdPartyApp_Filename);
            this.AdvancedTabPage.Controls.Add(this.label41);
            this.AdvancedTabPage.Controls.Add(this.Advanced_File_Browse_Button);
            this.AdvancedTabPage.Controls.Add(this.label10);
            this.AdvancedTabPage.Controls.Add(this.MemorySignatures_UseRegistryFindings);
            this.AdvancedTabPage.Controls.Add(this.MemorySignatures_SearchCmdLine);
            this.AdvancedTabPage.Controls.Add(this.MemorySignatures_SearchLoadedModules);
            this.AdvancedTabPage.Controls.Add(this.MemorySignatures_SearchHeapSpace);
            this.AdvancedTabPage.Controls.Add(this.label34);
            this.AdvancedTabPage.ForeColor = System.Drawing.Color.White;
            this.AdvancedTabPage.Location = new System.Drawing.Point(4, 22);
            this.AdvancedTabPage.Name = "AdvancedTabPage";
            this.AdvancedTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.AdvancedTabPage.Size = new System.Drawing.Size(892, 493);
            this.AdvancedTabPage.TabIndex = 4;
            this.AdvancedTabPage.Text = "Advanced";
            // 
            // label67
            // 
            this.label67.AutoSize = true;
            this.label67.Location = new System.Drawing.Point(28, 182);
            this.label67.Name = "label67";
            this.label67.Size = new System.Drawing.Size(49, 13);
            this.label67.TabIndex = 81;
            this.label67.Text = "Program:";
            // 
            // Advanced_3rdPartyApp_Distribute
            // 
            this.Advanced_3rdPartyApp_Distribute.AutoSize = true;
            this.Advanced_3rdPartyApp_Distribute.Location = new System.Drawing.Point(94, 208);
            this.Advanced_3rdPartyApp_Distribute.Name = "Advanced_3rdPartyApp_Distribute";
            this.Advanced_3rdPartyApp_Distribute.Size = new System.Drawing.Size(149, 17);
            this.Advanced_3rdPartyApp_Distribute.TabIndex = 80;
            this.Advanced_3rdPartyApp_Distribute.Text = "Distribute this file with MSI";
            this.Advanced_3rdPartyApp_Distribute.UseVisualStyleBackColor = true;
            // 
            // Advanced_3rdPartyApp_Arguments
            // 
            this.Advanced_3rdPartyApp_Arguments.Location = new System.Drawing.Point(94, 240);
            this.Advanced_3rdPartyApp_Arguments.Name = "Advanced_3rdPartyApp_Arguments";
            this.Advanced_3rdPartyApp_Arguments.Size = new System.Drawing.Size(293, 20);
            this.Advanced_3rdPartyApp_Arguments.TabIndex = 79;
            // 
            // Advanced_3rdPartyApp_Filename
            // 
            this.Advanced_3rdPartyApp_Filename.Location = new System.Drawing.Point(94, 179);
            this.Advanced_3rdPartyApp_Filename.Name = "Advanced_3rdPartyApp_Filename";
            this.Advanced_3rdPartyApp_Filename.Size = new System.Drawing.Size(293, 20);
            this.Advanced_3rdPartyApp_Filename.TabIndex = 76;
            // 
            // label41
            // 
            this.label41.AutoSize = true;
            this.label41.Location = new System.Drawing.Point(28, 243);
            this.label41.Name = "label41";
            this.label41.Size = new System.Drawing.Size(60, 13);
            this.label41.TabIndex = 78;
            this.label41.Text = "Arguments:";
            // 
            // Advanced_File_Browse_Button
            // 
            this.Advanced_File_Browse_Button.ForeColor = System.Drawing.Color.Black;
            this.Advanced_File_Browse_Button.Location = new System.Drawing.Point(393, 177);
            this.Advanced_File_Browse_Button.Name = "Advanced_File_Browse_Button";
            this.Advanced_File_Browse_Button.Size = new System.Drawing.Size(95, 23);
            this.Advanced_File_Browse_Button.TabIndex = 77;
            this.Advanced_File_Browse_Button.Text = "Browse...";
            this.Advanced_File_Browse_Button.UseVisualStyleBackColor = true;
            // 
            // label10
            // 
            this.label10.AutoSize = true;
            this.label10.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label10.ForeColor = System.Drawing.Color.Chartreuse;
            this.label10.Location = new System.Drawing.Point(14, 150);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(95, 13);
            this.label10.TabIndex = 75;
            this.label10.Text = "Post-scan task:";
            // 
            // MemorySignatures_UseRegistryFindings
            // 
            this.MemorySignatures_UseRegistryFindings.AutoSize = true;
            this.MemorySignatures_UseRegistryFindings.Checked = true;
            this.MemorySignatures_UseRegistryFindings.CheckState = System.Windows.Forms.CheckState.Checked;
            this.MemorySignatures_UseRegistryFindings.Location = new System.Drawing.Point(17, 111);
            this.MemorySignatures_UseRegistryFindings.Name = "MemorySignatures_UseRegistryFindings";
            this.MemorySignatures_UseRegistryFindings.Size = new System.Drawing.Size(229, 17);
            this.MemorySignatures_UseRegistryFindings.TabIndex = 74;
            this.MemorySignatures_UseRegistryFindings.Text = "also search memory for any registry findings";
            this.MemorySignatures_UseRegistryFindings.UseVisualStyleBackColor = true;
            // 
            // MemorySignatures_SearchCmdLine
            // 
            this.MemorySignatures_SearchCmdLine.AutoSize = true;
            this.MemorySignatures_SearchCmdLine.Checked = true;
            this.MemorySignatures_SearchCmdLine.CheckState = System.Windows.Forms.CheckState.Checked;
            this.MemorySignatures_SearchCmdLine.Location = new System.Drawing.Point(17, 63);
            this.MemorySignatures_SearchCmdLine.Name = "MemorySignatures_SearchCmdLine";
            this.MemorySignatures_SearchCmdLine.Size = new System.Drawing.Size(159, 17);
            this.MemorySignatures_SearchCmdLine.TabIndex = 73;
            this.MemorySignatures_SearchCmdLine.Text = "process command line string";
            this.MemorySignatures_SearchCmdLine.UseVisualStyleBackColor = true;
            // 
            // MemorySignatures_SearchLoadedModules
            // 
            this.MemorySignatures_SearchLoadedModules.AutoSize = true;
            this.MemorySignatures_SearchLoadedModules.Checked = true;
            this.MemorySignatures_SearchLoadedModules.CheckState = System.Windows.Forms.CheckState.Checked;
            this.MemorySignatures_SearchLoadedModules.Location = new System.Drawing.Point(17, 86);
            this.MemorySignatures_SearchLoadedModules.Name = "MemorySignatures_SearchLoadedModules";
            this.MemorySignatures_SearchLoadedModules.Size = new System.Drawing.Size(144, 17);
            this.MemorySignatures_SearchLoadedModules.TabIndex = 72;
            this.MemorySignatures_SearchLoadedModules.Text = "module list (loaded DLLs)";
            this.MemorySignatures_SearchLoadedModules.UseVisualStyleBackColor = true;
            // 
            // MemorySignatures_SearchHeapSpace
            // 
            this.MemorySignatures_SearchHeapSpace.AutoSize = true;
            this.MemorySignatures_SearchHeapSpace.Checked = true;
            this.MemorySignatures_SearchHeapSpace.CheckState = System.Windows.Forms.CheckState.Checked;
            this.MemorySignatures_SearchHeapSpace.Location = new System.Drawing.Point(17, 40);
            this.MemorySignatures_SearchHeapSpace.Name = "MemorySignatures_SearchHeapSpace";
            this.MemorySignatures_SearchHeapSpace.Size = new System.Drawing.Size(82, 17);
            this.MemorySignatures_SearchHeapSpace.TabIndex = 71;
            this.MemorySignatures_SearchHeapSpace.Text = "heap space";
            this.MemorySignatures_SearchHeapSpace.UseVisualStyleBackColor = true;
            // 
            // label34
            // 
            this.label34.AutoSize = true;
            this.label34.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label34.ForeColor = System.Drawing.Color.Chartreuse;
            this.label34.Location = new System.Drawing.Point(14, 18);
            this.label34.Name = "label34";
            this.label34.Size = new System.Drawing.Size(203, 13);
            this.label34.TabIndex = 70;
            this.label34.Text = "Memory signatures search options:";
            // 
            // ConnectExistingAgentTabPage
            // 
            this.ConnectExistingAgentTabPage.BackColor = System.Drawing.Color.Black;
            this.ConnectExistingAgentTabPage.Controls.Add(this.AgentTaskProgressBarLabel);
            this.ConnectExistingAgentTabPage.Controls.Add(this.AgentTaskProgressBar);
            this.ConnectExistingAgentTabPage.Controls.Add(this.label79);
            this.ConnectExistingAgentTabPage.Controls.Add(this.label78);
            this.ConnectExistingAgentTabPage.Controls.Add(this.LastCommandPane);
            this.ConnectExistingAgentTabPage.Controls.Add(this.FindingsTabContainer);
            this.ConnectExistingAgentTabPage.Controls.Add(this.RecentAgentsTreeview);
            this.ConnectExistingAgentTabPage.Controls.Add(this.LogWindow);
            this.ConnectExistingAgentTabPage.Controls.Add(this.ConnectAgentToolstrip);
            this.ConnectExistingAgentTabPage.Location = new System.Drawing.Point(4, 22);
            this.ConnectExistingAgentTabPage.Name = "ConnectExistingAgentTabPage";
            this.ConnectExistingAgentTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.ConnectExistingAgentTabPage.Size = new System.Drawing.Size(1173, 659);
            this.ConnectExistingAgentTabPage.TabIndex = 1;
            this.ConnectExistingAgentTabPage.Text = "Connect to Existing Agent";
            // 
            // AgentTaskProgressBarLabel
            // 
            this.AgentTaskProgressBarLabel.AutoSize = true;
            this.AgentTaskProgressBarLabel.BackColor = System.Drawing.SystemColors.ButtonFace;
            this.AgentTaskProgressBarLabel.ForeColor = System.Drawing.Color.Black;
            this.AgentTaskProgressBarLabel.Location = new System.Drawing.Point(895, 27);
            this.AgentTaskProgressBarLabel.Name = "AgentTaskProgressBarLabel";
            this.AgentTaskProgressBarLabel.Size = new System.Drawing.Size(24, 13);
            this.AgentTaskProgressBarLabel.TabIndex = 8;
            this.AgentTaskProgressBarLabel.Text = "Idle";
            // 
            // AgentTaskProgressBar
            // 
            this.AgentTaskProgressBar.Location = new System.Drawing.Point(898, 6);
            this.AgentTaskProgressBar.Name = "AgentTaskProgressBar";
            this.AgentTaskProgressBar.Size = new System.Drawing.Size(199, 18);
            this.AgentTaskProgressBar.TabIndex = 7;
            // 
            // label79
            // 
            this.label79.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.label79.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label79.Location = new System.Drawing.Point(3, 466);
            this.label79.Name = "label79";
            this.label79.Size = new System.Drawing.Size(158, 23);
            this.label79.TabIndex = 6;
            this.label79.Text = "Command History";
            this.label79.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // label78
            // 
            this.label78.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.label78.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label78.Location = new System.Drawing.Point(4, 59);
            this.label78.Name = "label78";
            this.label78.Size = new System.Drawing.Size(157, 23);
            this.label78.TabIndex = 5;
            this.label78.Text = "Recent Agents";
            this.label78.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // LastCommandPane
            // 
            this.LastCommandPane.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.LastCommandPane.ForeColor = System.Drawing.Color.White;
            this.LastCommandPane.Location = new System.Drawing.Point(3, 489);
            this.LastCommandPane.Margin = new System.Windows.Forms.Padding(3, 25, 3, 3);
            this.LastCommandPane.Multiline = true;
            this.LastCommandPane.Name = "LastCommandPane";
            this.LastCommandPane.Size = new System.Drawing.Size(158, 170);
            this.LastCommandPane.TabIndex = 4;
            this.LastCommandPane.Text = "COMMAND:\r\nSENT ON:\r\nRESPONSE:";
            // 
            // FindingsTabContainer
            // 
            this.FindingsTabContainer.Controls.Add(this.SystemInfoTabPage);
            this.FindingsTabContainer.Controls.Add(this.RegistryFindingsTabPage);
            this.FindingsTabContainer.Controls.Add(this.FileFindingsTabPage);
            this.FindingsTabContainer.Controls.Add(this.MemoryFindingsTabPage);
            this.FindingsTabContainer.Controls.Add(this.UserModeAnomaliesTabPage);
            this.FindingsTabContainer.Controls.Add(this.KernelModeAnomaliesTabPage);
            this.FindingsTabContainer.Controls.Add(this.LowLevelAnomaliesTabPage);
            this.FindingsTabContainer.Location = new System.Drawing.Point(164, 60);
            this.FindingsTabContainer.Name = "FindingsTabContainer";
            this.FindingsTabContainer.SelectedIndex = 0;
            this.FindingsTabContainer.Size = new System.Drawing.Size(1006, 429);
            this.FindingsTabContainer.TabIndex = 3;
            // 
            // SystemInfoTabPage
            // 
            this.SystemInfoTabPage.Controls.Add(this.systemInfoTextarea);
            this.SystemInfoTabPage.Location = new System.Drawing.Point(4, 22);
            this.SystemInfoTabPage.Name = "SystemInfoTabPage";
            this.SystemInfoTabPage.Size = new System.Drawing.Size(998, 403);
            this.SystemInfoTabPage.TabIndex = 7;
            this.SystemInfoTabPage.Text = "System Info";
            this.SystemInfoTabPage.UseVisualStyleBackColor = true;
            // 
            // systemInfoTextarea
            // 
            this.systemInfoTextarea.BackColor = System.Drawing.Color.White;
            this.systemInfoTextarea.Dock = System.Windows.Forms.DockStyle.Fill;
            this.systemInfoTextarea.ForeColor = System.Drawing.Color.Black;
            this.systemInfoTextarea.Location = new System.Drawing.Point(0, 0);
            this.systemInfoTextarea.Margin = new System.Windows.Forms.Padding(3, 25, 3, 3);
            this.systemInfoTextarea.MaxLength = 24000000;
            this.systemInfoTextarea.Multiline = true;
            this.systemInfoTextarea.Name = "systemInfoTextarea";
            this.systemInfoTextarea.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.systemInfoTextarea.Size = new System.Drawing.Size(998, 403);
            this.systemInfoTextarea.TabIndex = 5;
            // 
            // RegistryFindingsTabPage
            // 
            this.RegistryFindingsTabPage.Controls.Add(this.AgentResults_RegistryListview);
            this.RegistryFindingsTabPage.Location = new System.Drawing.Point(4, 22);
            this.RegistryFindingsTabPage.Name = "RegistryFindingsTabPage";
            this.RegistryFindingsTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.RegistryFindingsTabPage.Size = new System.Drawing.Size(998, 403);
            this.RegistryFindingsTabPage.TabIndex = 0;
            this.RegistryFindingsTabPage.Text = "Registry";
            this.RegistryFindingsTabPage.UseVisualStyleBackColor = true;
            // 
            // AgentResults_RegistryListview
            // 
            this.AgentResults_RegistryListview.CheckBoxes = true;
            this.AgentResults_RegistryListview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.RegistryFindingsKeyName,
            this.RegistryFindingsValueName,
            this.RegistryFindingsValueData,
            this.RegistryFindingsChangeValueData,
            this.RegistryFindingsIsFileOnDisk,
            this.RegistryFindingsAction,
            this.RegistryFindingsActionSuccessful});
            this.AgentResults_RegistryListview.Dock = System.Windows.Forms.DockStyle.Fill;
            this.AgentResults_RegistryListview.FullRowSelect = true;
            this.AgentResults_RegistryListview.GridLines = true;
            this.AgentResults_RegistryListview.HideSelection = false;
            this.AgentResults_RegistryListview.Location = new System.Drawing.Point(3, 3);
            this.AgentResults_RegistryListview.Name = "AgentResults_RegistryListview";
            this.AgentResults_RegistryListview.Size = new System.Drawing.Size(992, 397);
            this.AgentResults_RegistryListview.SmallImageList = this.MitigationTasksImageList;
            this.AgentResults_RegistryListview.TabIndex = 0;
            this.AgentResults_RegistryListview.UseCompatibleStateImageBehavior = false;
            this.AgentResults_RegistryListview.View = System.Windows.Forms.View.Details;
            this.AgentResults_RegistryListview.ItemCheck += new System.Windows.Forms.ItemCheckEventHandler(this.AgentResults_RegistryListview_ItemCheck);
            // 
            // RegistryFindingsKeyName
            // 
            this.RegistryFindingsKeyName.Text = "Key Name";
            this.RegistryFindingsKeyName.Width = 233;
            // 
            // RegistryFindingsValueName
            // 
            this.RegistryFindingsValueName.Text = "Value Name";
            this.RegistryFindingsValueName.Width = 158;
            // 
            // RegistryFindingsValueData
            // 
            this.RegistryFindingsValueData.Text = "Value Data";
            this.RegistryFindingsValueData.Width = 203;
            // 
            // RegistryFindingsChangeValueData
            // 
            this.RegistryFindingsChangeValueData.Text = "New Value Data";
            this.RegistryFindingsChangeValueData.Width = 134;
            // 
            // RegistryFindingsIsFileOnDisk
            // 
            this.RegistryFindingsIsFileOnDisk.Text = "On Disk?";
            this.RegistryFindingsIsFileOnDisk.Width = 63;
            // 
            // RegistryFindingsAction
            // 
            this.RegistryFindingsAction.Text = "Action";
            this.RegistryFindingsAction.Width = 123;
            // 
            // RegistryFindingsActionSuccessful
            // 
            this.RegistryFindingsActionSuccessful.Text = "Successful?";
            this.RegistryFindingsActionSuccessful.Width = 73;
            // 
            // MitigationTasksImageList
            // 
            this.MitigationTasksImageList.ImageStream = ((System.Windows.Forms.ImageListStreamer)(resources.GetObject("MitigationTasksImageList.ImageStream")));
            this.MitigationTasksImageList.TransparentColor = System.Drawing.Color.Transparent;
            this.MitigationTasksImageList.Images.SetKeyName(0, "red_x.gif");
            this.MitigationTasksImageList.Images.SetKeyName(1, "green_check.png");
            this.MitigationTasksImageList.Images.SetKeyName(2, "blue_question.png");
            // 
            // FileFindingsTabPage
            // 
            this.FileFindingsTabPage.Controls.Add(this.AgentResults_FileListview);
            this.FileFindingsTabPage.Location = new System.Drawing.Point(4, 22);
            this.FileFindingsTabPage.Name = "FileFindingsTabPage";
            this.FileFindingsTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.FileFindingsTabPage.Size = new System.Drawing.Size(998, 403);
            this.FileFindingsTabPage.TabIndex = 1;
            this.FileFindingsTabPage.Text = "File";
            this.FileFindingsTabPage.UseVisualStyleBackColor = true;
            // 
            // AgentResults_FileListview
            // 
            this.AgentResults_FileListview.CheckBoxes = true;
            this.AgentResults_FileListview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.FileFindingsFileName,
            this.FileFindingsPath,
            this.FileFindingsSize,
            this.FileFindingsHash,
            this.FileFindingsPEHeaderSig,
            this.FileFindingsCreated,
            this.FileFindingsAccessed,
            this.FileFindingsModified,
            this.FileFindingsAction,
            this.FileFindingsActionSuccessful});
            this.AgentResults_FileListview.Dock = System.Windows.Forms.DockStyle.Fill;
            this.AgentResults_FileListview.FullRowSelect = true;
            this.AgentResults_FileListview.GridLines = true;
            this.AgentResults_FileListview.HideSelection = false;
            this.AgentResults_FileListview.Location = new System.Drawing.Point(3, 3);
            this.AgentResults_FileListview.Name = "AgentResults_FileListview";
            this.AgentResults_FileListview.Size = new System.Drawing.Size(992, 397);
            this.AgentResults_FileListview.SmallImageList = this.MitigationTasksImageList;
            this.AgentResults_FileListview.TabIndex = 1;
            this.AgentResults_FileListview.UseCompatibleStateImageBehavior = false;
            this.AgentResults_FileListview.View = System.Windows.Forms.View.Details;
            this.AgentResults_FileListview.ItemCheck += new System.Windows.Forms.ItemCheckEventHandler(this.AgentResults_FileListview_ItemCheck);
            // 
            // FileFindingsFileName
            // 
            this.FileFindingsFileName.Text = "Name";
            this.FileFindingsFileName.Width = 141;
            // 
            // FileFindingsPath
            // 
            this.FileFindingsPath.Text = "Path";
            this.FileFindingsPath.Width = 161;
            // 
            // FileFindingsSize
            // 
            this.FileFindingsSize.Text = "Size";
            this.FileFindingsSize.Width = 54;
            // 
            // FileFindingsHash
            // 
            this.FileFindingsHash.Text = "Hash";
            this.FileFindingsHash.Width = 160;
            // 
            // FileFindingsPEHeaderSig
            // 
            this.FileFindingsPEHeaderSig.Text = "PE Signature";
            this.FileFindingsPEHeaderSig.Width = 93;
            // 
            // FileFindingsCreated
            // 
            this.FileFindingsCreated.Text = "Created";
            this.FileFindingsCreated.Width = 73;
            // 
            // FileFindingsAccessed
            // 
            this.FileFindingsAccessed.Text = "Accessed";
            this.FileFindingsAccessed.Width = 79;
            // 
            // FileFindingsModified
            // 
            this.FileFindingsModified.Text = "Modified";
            this.FileFindingsModified.Width = 84;
            // 
            // FileFindingsAction
            // 
            this.FileFindingsAction.Text = "Action";
            // 
            // FileFindingsActionSuccessful
            // 
            this.FileFindingsActionSuccessful.Text = "Successful?";
            this.FileFindingsActionSuccessful.Width = 82;
            // 
            // MemoryFindingsTabPage
            // 
            this.MemoryFindingsTabPage.Controls.Add(this.AgentResults_MemoryListview);
            this.MemoryFindingsTabPage.Location = new System.Drawing.Point(4, 22);
            this.MemoryFindingsTabPage.Name = "MemoryFindingsTabPage";
            this.MemoryFindingsTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.MemoryFindingsTabPage.Size = new System.Drawing.Size(998, 403);
            this.MemoryFindingsTabPage.TabIndex = 2;
            this.MemoryFindingsTabPage.Text = "Memory";
            this.MemoryFindingsTabPage.UseVisualStyleBackColor = true;
            // 
            // AgentResults_MemoryListview
            // 
            this.AgentResults_MemoryListview.CheckBoxes = true;
            this.AgentResults_MemoryListview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.MemoryFindingsPid,
            this.MemoryFindingsPpid,
            this.MemoryFindingsProcessName,
            this.MemoryFindingsMatchingBlock,
            this.MemoryFindingsSuspiciousHeapRange,
            this.MemoryFindingsKeywords,
            this.MemoryFindingsChildThreads,
            this.MemoryFindingsAction,
            this.MemoryFindingsActionSuccessful});
            this.AgentResults_MemoryListview.Dock = System.Windows.Forms.DockStyle.Fill;
            this.AgentResults_MemoryListview.FullRowSelect = true;
            this.AgentResults_MemoryListview.GridLines = true;
            this.AgentResults_MemoryListview.HideSelection = false;
            this.AgentResults_MemoryListview.Location = new System.Drawing.Point(3, 3);
            this.AgentResults_MemoryListview.Name = "AgentResults_MemoryListview";
            this.AgentResults_MemoryListview.Size = new System.Drawing.Size(992, 397);
            this.AgentResults_MemoryListview.SmallImageList = this.MitigationTasksImageList;
            this.AgentResults_MemoryListview.TabIndex = 2;
            this.AgentResults_MemoryListview.UseCompatibleStateImageBehavior = false;
            this.AgentResults_MemoryListview.View = System.Windows.Forms.View.Details;
            this.AgentResults_MemoryListview.ItemCheck += new System.Windows.Forms.ItemCheckEventHandler(this.AgentResults_MemoryListview_ItemCheck);
            // 
            // MemoryFindingsPid
            // 
            this.MemoryFindingsPid.Text = "Pid";
            this.MemoryFindingsPid.Width = 55;
            // 
            // MemoryFindingsPpid
            // 
            this.MemoryFindingsPpid.Text = "Ppid";
            this.MemoryFindingsPpid.Width = 56;
            // 
            // MemoryFindingsProcessName
            // 
            this.MemoryFindingsProcessName.Text = "Name";
            this.MemoryFindingsProcessName.Width = 124;
            // 
            // MemoryFindingsMatchingBlock
            // 
            this.MemoryFindingsMatchingBlock.Text = "Matching Block";
            this.MemoryFindingsMatchingBlock.Width = 210;
            // 
            // MemoryFindingsSuspiciousHeapRange
            // 
            this.MemoryFindingsSuspiciousHeapRange.Text = "Suspicious Heap Range";
            this.MemoryFindingsSuspiciousHeapRange.Width = 128;
            // 
            // MemoryFindingsKeywords
            // 
            this.MemoryFindingsKeywords.Text = "Keywords";
            this.MemoryFindingsKeywords.Width = 131;
            // 
            // MemoryFindingsChildThreads
            // 
            this.MemoryFindingsChildThreads.Text = "Child Threads";
            this.MemoryFindingsChildThreads.Width = 87;
            // 
            // MemoryFindingsAction
            // 
            this.MemoryFindingsAction.Text = "Action";
            this.MemoryFindingsAction.Width = 98;
            // 
            // MemoryFindingsActionSuccessful
            // 
            this.MemoryFindingsActionSuccessful.Text = "Action Successful";
            this.MemoryFindingsActionSuccessful.Width = 101;
            // 
            // UserModeAnomaliesTabPage
            // 
            this.UserModeAnomaliesTabPage.AutoScroll = true;
            this.UserModeAnomaliesTabPage.Controls.Add(this.groupBox21);
            this.UserModeAnomaliesTabPage.Controls.Add(this.groupBox20);
            this.UserModeAnomaliesTabPage.Location = new System.Drawing.Point(4, 22);
            this.UserModeAnomaliesTabPage.Name = "UserModeAnomaliesTabPage";
            this.UserModeAnomaliesTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.UserModeAnomaliesTabPage.Size = new System.Drawing.Size(998, 403);
            this.UserModeAnomaliesTabPage.TabIndex = 3;
            this.UserModeAnomaliesTabPage.Text = "User Mode Anomalies";
            this.UserModeAnomaliesTabPage.UseVisualStyleBackColor = true;
            // 
            // groupBox21
            // 
            this.groupBox21.BackColor = System.Drawing.Color.Transparent;
            this.groupBox21.Controls.Add(this.ProcessResourcesAnomaliesListview);
            this.groupBox21.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox21.ForeColor = System.Drawing.Color.Red;
            this.groupBox21.Location = new System.Drawing.Point(6, 280);
            this.groupBox21.Name = "groupBox21";
            this.groupBox21.Size = new System.Drawing.Size(965, 268);
            this.groupBox21.TabIndex = 3;
            this.groupBox21.TabStop = false;
            this.groupBox21.Text = "Process Resources";
            // 
            // ProcessResourcesAnomaliesListview
            // 
            this.ProcessResourcesAnomaliesListview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader30,
            this.columnHeader31,
            this.columnHeader32});
            this.ProcessResourcesAnomaliesListview.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.ProcessResourcesAnomaliesListview.FullRowSelect = true;
            this.ProcessResourcesAnomaliesListview.GridLines = true;
            this.ProcessResourcesAnomaliesListview.Location = new System.Drawing.Point(6, 19);
            this.ProcessResourcesAnomaliesListview.Name = "ProcessResourcesAnomaliesListview";
            this.ProcessResourcesAnomaliesListview.Size = new System.Drawing.Size(953, 243);
            this.ProcessResourcesAnomaliesListview.SmallImageList = this.AnomaliesIcons;
            this.ProcessResourcesAnomaliesListview.TabIndex = 0;
            this.ProcessResourcesAnomaliesListview.UseCompatibleStateImageBehavior = false;
            this.ProcessResourcesAnomaliesListview.View = System.Windows.Forms.View.Details;
            // 
            // columnHeader30
            // 
            this.columnHeader30.Text = "Type";
            this.columnHeader30.Width = 211;
            // 
            // columnHeader31
            // 
            this.columnHeader31.Text = "Name";
            this.columnHeader31.Width = 528;
            // 
            // columnHeader32
            // 
            this.columnHeader32.Text = "Anomaly";
            this.columnHeader32.Width = 204;
            // 
            // AnomaliesIcons
            // 
            this.AnomaliesIcons.ImageStream = ((System.Windows.Forms.ImageListStreamer)(resources.GetObject("AnomaliesIcons.ImageStream")));
            this.AnomaliesIcons.TransparentColor = System.Drawing.Color.Transparent;
            this.AnomaliesIcons.Images.SetKeyName(0, "hook.png");
            this.AnomaliesIcons.Images.SetKeyName(1, "detour.png");
            this.AnomaliesIcons.Images.SetKeyName(2, "process_icon.png");
            this.AnomaliesIcons.Images.SetKeyName(3, "hidden_process_icon.png");
            // 
            // groupBox20
            // 
            this.groupBox20.BackColor = System.Drawing.Color.Transparent;
            this.groupBox20.Controls.Add(this.ProcessAnomaliesListview);
            this.groupBox20.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox20.ForeColor = System.Drawing.Color.Red;
            this.groupBox20.Location = new System.Drawing.Point(6, 6);
            this.groupBox20.Name = "groupBox20";
            this.groupBox20.Size = new System.Drawing.Size(965, 268);
            this.groupBox20.TabIndex = 2;
            this.groupBox20.TabStop = false;
            this.groupBox20.Text = "Process";
            // 
            // ProcessAnomaliesListview
            // 
            this.ProcessAnomaliesListview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader25,
            this.columnHeader26,
            this.columnHeader27,
            this.columnHeader28,
            this.columnHeader29});
            this.ProcessAnomaliesListview.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.ProcessAnomaliesListview.FullRowSelect = true;
            this.ProcessAnomaliesListview.GridLines = true;
            this.ProcessAnomaliesListview.Location = new System.Drawing.Point(6, 19);
            this.ProcessAnomaliesListview.Name = "ProcessAnomaliesListview";
            this.ProcessAnomaliesListview.Size = new System.Drawing.Size(953, 243);
            this.ProcessAnomaliesListview.SmallImageList = this.AnomaliesIcons;
            this.ProcessAnomaliesListview.TabIndex = 0;
            this.ProcessAnomaliesListview.UseCompatibleStateImageBehavior = false;
            this.ProcessAnomaliesListview.View = System.Windows.Forms.View.Details;
            // 
            // columnHeader25
            // 
            this.columnHeader25.Text = "PID";
            this.columnHeader25.Width = 59;
            // 
            // columnHeader26
            // 
            this.columnHeader26.Text = "PPID";
            // 
            // columnHeader27
            // 
            this.columnHeader27.Text = "Name";
            this.columnHeader27.Width = 204;
            // 
            // columnHeader28
            // 
            this.columnHeader28.Text = "Anomaly";
            this.columnHeader28.Width = 123;
            // 
            // columnHeader29
            // 
            this.columnHeader29.Text = "Module Path";
            this.columnHeader29.Width = 496;
            // 
            // KernelModeAnomaliesTabPage
            // 
            this.KernelModeAnomaliesTabPage.AutoScroll = true;
            this.KernelModeAnomaliesTabPage.Controls.Add(this.groupBox17);
            this.KernelModeAnomaliesTabPage.Controls.Add(this.groupBox12);
            this.KernelModeAnomaliesTabPage.Controls.Add(this.groupBox10);
            this.KernelModeAnomaliesTabPage.Location = new System.Drawing.Point(4, 22);
            this.KernelModeAnomaliesTabPage.Name = "KernelModeAnomaliesTabPage";
            this.KernelModeAnomaliesTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.KernelModeAnomaliesTabPage.Size = new System.Drawing.Size(998, 403);
            this.KernelModeAnomaliesTabPage.TabIndex = 4;
            this.KernelModeAnomaliesTabPage.Text = "Kernel Mode Anomalies";
            this.KernelModeAnomaliesTabPage.UseVisualStyleBackColor = true;
            // 
            // groupBox17
            // 
            this.groupBox17.BackColor = System.Drawing.Color.Transparent;
            this.groupBox17.Controls.Add(this.DriverAnomaliesListview);
            this.groupBox17.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox17.ForeColor = System.Drawing.Color.Red;
            this.groupBox17.Location = new System.Drawing.Point(6, 560);
            this.groupBox17.Name = "groupBox17";
            this.groupBox17.Size = new System.Drawing.Size(965, 268);
            this.groupBox17.TabIndex = 3;
            this.groupBox17.TabStop = false;
            this.groupBox17.Text = "Drivers";
            // 
            // DriverAnomaliesListview
            // 
            this.DriverAnomaliesListview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader17,
            this.columnHeader18,
            this.columnHeader24,
            this.columnHeader19,
            this.columnHeader20,
            this.columnHeader21,
            this.columnHeader22,
            this.columnHeader23});
            this.DriverAnomaliesListview.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.DriverAnomaliesListview.FullRowSelect = true;
            this.DriverAnomaliesListview.GridLines = true;
            this.DriverAnomaliesListview.Location = new System.Drawing.Point(6, 19);
            this.DriverAnomaliesListview.Name = "DriverAnomaliesListview";
            this.DriverAnomaliesListview.Size = new System.Drawing.Size(953, 243);
            this.DriverAnomaliesListview.SmallImageList = this.AnomaliesIcons;
            this.DriverAnomaliesListview.TabIndex = 0;
            this.DriverAnomaliesListview.UseCompatibleStateImageBehavior = false;
            this.DriverAnomaliesListview.View = System.Windows.Forms.View.Details;
            // 
            // columnHeader17
            // 
            this.columnHeader17.Text = "Driver/Device Name";
            this.columnHeader17.Width = 148;
            // 
            // columnHeader18
            // 
            this.columnHeader18.Text = "Dispatch Function Name";
            this.columnHeader18.Width = 222;
            // 
            // columnHeader24
            // 
            this.columnHeader24.Text = "IRP_MJ Code Hooked";
            this.columnHeader24.Width = 153;
            // 
            // columnHeader19
            // 
            this.columnHeader19.Text = "Address";
            this.columnHeader19.Width = 94;
            // 
            // columnHeader20
            // 
            this.columnHeader20.Text = "Anomaly";
            this.columnHeader20.Width = 71;
            // 
            // columnHeader21
            // 
            this.columnHeader21.Text = "Detour Target";
            this.columnHeader21.Width = 106;
            // 
            // columnHeader22
            // 
            this.columnHeader22.Text = "Malicious Module";
            this.columnHeader22.Width = 227;
            // 
            // columnHeader23
            // 
            this.columnHeader23.Text = "Disassembly";
            this.columnHeader23.Width = 313;
            // 
            // groupBox12
            // 
            this.groupBox12.BackColor = System.Drawing.Color.Transparent;
            this.groupBox12.Controls.Add(this.Win32ApiDetoursListview);
            this.groupBox12.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox12.ForeColor = System.Drawing.Color.Red;
            this.groupBox12.Location = new System.Drawing.Point(6, 282);
            this.groupBox12.Name = "groupBox12";
            this.groupBox12.Size = new System.Drawing.Size(965, 268);
            this.groupBox12.TabIndex = 2;
            this.groupBox12.TabStop = false;
            this.groupBox12.Text = "Win32 API";
            // 
            // Win32ApiDetoursListview
            // 
            this.Win32ApiDetoursListview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader8,
            this.columnHeader1,
            this.columnHeader2,
            this.columnHeader5,
            this.columnHeader14,
            this.columnHeader6,
            this.columnHeader15});
            this.Win32ApiDetoursListview.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Win32ApiDetoursListview.FullRowSelect = true;
            this.Win32ApiDetoursListview.GridLines = true;
            this.Win32ApiDetoursListview.Location = new System.Drawing.Point(6, 19);
            this.Win32ApiDetoursListview.Name = "Win32ApiDetoursListview";
            this.Win32ApiDetoursListview.Size = new System.Drawing.Size(953, 243);
            this.Win32ApiDetoursListview.SmallImageList = this.AnomaliesIcons;
            this.Win32ApiDetoursListview.TabIndex = 0;
            this.Win32ApiDetoursListview.UseCompatibleStateImageBehavior = false;
            this.Win32ApiDetoursListview.View = System.Windows.Forms.View.Details;
            // 
            // columnHeader8
            // 
            this.columnHeader8.Text = "Module";
            this.columnHeader8.Width = 220;
            // 
            // columnHeader1
            // 
            this.columnHeader1.Text = "Export Name";
            this.columnHeader1.Width = 222;
            // 
            // columnHeader2
            // 
            this.columnHeader2.Text = "Export Addr";
            this.columnHeader2.Width = 94;
            // 
            // columnHeader5
            // 
            this.columnHeader5.Text = "Anomaly";
            this.columnHeader5.Width = 71;
            // 
            // columnHeader14
            // 
            this.columnHeader14.Text = "Detour Target";
            this.columnHeader14.Width = 106;
            // 
            // columnHeader6
            // 
            this.columnHeader6.Text = "Malicious Module";
            this.columnHeader6.Width = 227;
            // 
            // columnHeader15
            // 
            this.columnHeader15.Text = "Disassembly";
            this.columnHeader15.Width = 313;
            // 
            // groupBox10
            // 
            this.groupBox10.BackColor = System.Drawing.Color.Transparent;
            this.groupBox10.Controls.Add(this.SSDTAnomaliesListview);
            this.groupBox10.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox10.ForeColor = System.Drawing.Color.Red;
            this.groupBox10.Location = new System.Drawing.Point(6, 8);
            this.groupBox10.Name = "groupBox10";
            this.groupBox10.Size = new System.Drawing.Size(965, 268);
            this.groupBox10.TabIndex = 1;
            this.groupBox10.TabStop = false;
            this.groupBox10.Text = "SSDT";
            // 
            // SSDTAnomaliesListview
            // 
            this.SSDTAnomaliesListview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.SSDTIndex,
            this.SSDTFuncAddr,
            this.SSDTAnomaly,
            this.SSDTFuncExpected,
            this.SSDTFuncFound,
            this.SSDTSuspectMod,
            this.SSDTDetourTarget,
            this.SSDTFuncDisassembly});
            this.SSDTAnomaliesListview.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SSDTAnomaliesListview.FullRowSelect = true;
            this.SSDTAnomaliesListview.GridLines = true;
            this.SSDTAnomaliesListview.Location = new System.Drawing.Point(6, 19);
            this.SSDTAnomaliesListview.Name = "SSDTAnomaliesListview";
            this.SSDTAnomaliesListview.Size = new System.Drawing.Size(953, 243);
            this.SSDTAnomaliesListview.SmallImageList = this.AnomaliesIcons;
            this.SSDTAnomaliesListview.TabIndex = 0;
            this.SSDTAnomaliesListview.UseCompatibleStateImageBehavior = false;
            this.SSDTAnomaliesListview.View = System.Windows.Forms.View.Details;
            // 
            // SSDTIndex
            // 
            this.SSDTIndex.Text = "Idx";
            this.SSDTIndex.Width = 42;
            // 
            // SSDTFuncAddr
            // 
            this.SSDTFuncAddr.Text = "Addr";
            this.SSDTFuncAddr.Width = 79;
            // 
            // SSDTAnomaly
            // 
            this.SSDTAnomaly.Text = "Anomaly";
            // 
            // SSDTFuncExpected
            // 
            this.SSDTFuncExpected.Text = "Expected";
            this.SSDTFuncExpected.Width = 123;
            // 
            // SSDTFuncFound
            // 
            this.SSDTFuncFound.Text = "Found";
            this.SSDTFuncFound.Width = 117;
            // 
            // SSDTSuspectMod
            // 
            this.SSDTSuspectMod.Text = "Module";
            this.SSDTSuspectMod.Width = 244;
            // 
            // SSDTDetourTarget
            // 
            this.SSDTDetourTarget.Text = "Detour Target";
            this.SSDTDetourTarget.Width = 96;
            // 
            // SSDTFuncDisassembly
            // 
            this.SSDTFuncDisassembly.Text = "Disassembly";
            this.SSDTFuncDisassembly.Width = 187;
            // 
            // LowLevelAnomaliesTabPage
            // 
            this.LowLevelAnomaliesTabPage.Location = new System.Drawing.Point(4, 22);
            this.LowLevelAnomaliesTabPage.Name = "LowLevelAnomaliesTabPage";
            this.LowLevelAnomaliesTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.LowLevelAnomaliesTabPage.Size = new System.Drawing.Size(998, 403);
            this.LowLevelAnomaliesTabPage.TabIndex = 6;
            this.LowLevelAnomaliesTabPage.Text = "Low-level Anomalies";
            this.LowLevelAnomaliesTabPage.UseVisualStyleBackColor = true;
            // 
            // RecentAgentsTreeview
            // 
            this.RecentAgentsTreeview.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.RecentAgentsTreeview.ForeColor = System.Drawing.Color.Chartreuse;
            this.RecentAgentsTreeview.ImageIndex = 5;
            this.RecentAgentsTreeview.ImageList = this.MainMenuIcons;
            this.RecentAgentsTreeview.Location = new System.Drawing.Point(3, 82);
            this.RecentAgentsTreeview.Margin = new System.Windows.Forms.Padding(3, 25, 3, 3);
            this.RecentAgentsTreeview.Name = "RecentAgentsTreeview";
            this.RecentAgentsTreeview.SelectedImageIndex = 0;
            this.RecentAgentsTreeview.Size = new System.Drawing.Size(158, 381);
            this.RecentAgentsTreeview.TabIndex = 2;
            // 
            // LogWindow
            // 
            this.LogWindow.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(37)))), ((int)(((byte)(42)))), ((int)(((byte)(56)))));
            this.LogWindow.ForeColor = System.Drawing.Color.White;
            this.LogWindow.Location = new System.Drawing.Point(163, 489);
            this.LogWindow.MaxLength = 24000000;
            this.LogWindow.Multiline = true;
            this.LogWindow.Name = "LogWindow";
            this.LogWindow.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.LogWindow.Size = new System.Drawing.Size(1006, 170);
            this.LogWindow.TabIndex = 1;
            // 
            // ConnectAgentToolstrip
            // 
            this.ConnectAgentToolstrip.BackColor = System.Drawing.SystemColors.ButtonFace;
            this.ConnectAgentToolstrip.CanOverflow = false;
            this.ConnectAgentToolstrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.ConnectToAgentIP,
            this.ConnectToAgentPort,
            this.ConnectAgentButton,
            this.toolStripSeparator1,
            this.StartScanButton,
            this.UpdateAgentButton,
            this.DownloadEvidenceButton,
            this.PerformMitigationTasksButton,
            this.SetAdminConsoleCredentialsButton,
            this.DisconnectAgentButton,
            this.HaltAgentButton});
            this.ConnectAgentToolstrip.LayoutStyle = System.Windows.Forms.ToolStripLayoutStyle.HorizontalStackWithOverflow;
            this.ConnectAgentToolstrip.Location = new System.Drawing.Point(3, 3);
            this.ConnectAgentToolstrip.Name = "ConnectAgentToolstrip";
            this.ConnectAgentToolstrip.Size = new System.Drawing.Size(1167, 54);
            this.ConnectAgentToolstrip.Stretch = true;
            this.ConnectAgentToolstrip.TabIndex = 0;
            this.ConnectAgentToolstrip.Text = "toolStrip1";
            // 
            // ConnectToAgentIP
            // 
            this.ConnectToAgentIP.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.ConnectToAgentIP.Margin = new System.Windows.Forms.Padding(1, 5, 1, 5);
            this.ConnectToAgentIP.Name = "ConnectToAgentIP";
            this.ConnectToAgentIP.Size = new System.Drawing.Size(100, 44);
            this.ConnectToAgentIP.Text = "192.168.85.129";
            this.ConnectToAgentIP.TextChanged += new System.EventHandler(this.ConnectToAgentIP_TextChanged);
            // 
            // ConnectToAgentPort
            // 
            this.ConnectToAgentPort.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.ConnectToAgentPort.Margin = new System.Windows.Forms.Padding(5, 5, 1, 5);
            this.ConnectToAgentPort.Name = "ConnectToAgentPort";
            this.ConnectToAgentPort.Size = new System.Drawing.Size(35, 44);
            this.ConnectToAgentPort.Text = "41014";
            this.ConnectToAgentPort.TextChanged += new System.EventHandler(this.ConnectToAgentIP_TextChanged);
            // 
            // ConnectAgentButton
            // 
            this.ConnectAgentButton.AutoSize = false;
            this.ConnectAgentButton.BackColor = System.Drawing.Color.DimGray;
            this.ConnectAgentButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.ConnectAgentButton.Enabled = false;
            this.ConnectAgentButton.ForeColor = System.Drawing.Color.White;
            this.ConnectAgentButton.Image = ((System.Drawing.Image)(resources.GetObject("ConnectAgentButton.Image")));
            this.ConnectAgentButton.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.ConnectAgentButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.ConnectAgentButton.Margin = new System.Windows.Forms.Padding(5, 1, 0, 2);
            this.ConnectAgentButton.Name = "ConnectAgentButton";
            this.ConnectAgentButton.Size = new System.Drawing.Size(55, 20);
            this.ConnectAgentButton.Text = "Connect";
            this.ConnectAgentButton.Click += new System.EventHandler(this.ConnectAgentButton_Click);
            // 
            // toolStripSeparator1
            // 
            this.toolStripSeparator1.Margin = new System.Windows.Forms.Padding(10, 0, 10, 0);
            this.toolStripSeparator1.Name = "toolStripSeparator1";
            this.toolStripSeparator1.Size = new System.Drawing.Size(6, 54);
            // 
            // StartScanButton
            // 
            this.StartScanButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.StartScanButton.Enabled = false;
            this.StartScanButton.Image = global::CwHandler.Properties.Resources.cw_play_button;
            this.StartScanButton.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.StartScanButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.StartScanButton.Margin = new System.Windows.Forms.Padding(0, 1, 10, 2);
            this.StartScanButton.Name = "StartScanButton";
            this.StartScanButton.Size = new System.Drawing.Size(44, 51);
            this.StartScanButton.Text = "toolStripButton1";
            this.StartScanButton.ToolTipText = "Start a new scan";
            this.StartScanButton.Click += new System.EventHandler(this.StartScanButton_Click);
            // 
            // UpdateAgentButton
            // 
            this.UpdateAgentButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.UpdateAgentButton.Enabled = false;
            this.UpdateAgentButton.Image = global::CwHandler.Properties.Resources.gears;
            this.UpdateAgentButton.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.UpdateAgentButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.UpdateAgentButton.Name = "UpdateAgentButton";
            this.UpdateAgentButton.Size = new System.Drawing.Size(44, 51);
            this.UpdateAgentButton.Text = "toolStripButton1";
            this.UpdateAgentButton.ToolTipText = "Update agent signatures";
            this.UpdateAgentButton.Click += new System.EventHandler(this.UpdateAgentButton_Click);
            // 
            // DownloadEvidenceButton
            // 
            this.DownloadEvidenceButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.DownloadEvidenceButton.Enabled = false;
            this.DownloadEvidenceButton.Image = global::CwHandler.Properties.Resources.dload;
            this.DownloadEvidenceButton.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.DownloadEvidenceButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.DownloadEvidenceButton.Margin = new System.Windows.Forms.Padding(10, 1, 0, 2);
            this.DownloadEvidenceButton.Name = "DownloadEvidenceButton";
            this.DownloadEvidenceButton.Size = new System.Drawing.Size(44, 51);
            this.DownloadEvidenceButton.Text = "toolStripButton1";
            this.DownloadEvidenceButton.ToolTipText = "Review and download evidence";
            this.DownloadEvidenceButton.Click += new System.EventHandler(this.DownloadEvidenceButton_Click);
            // 
            // PerformMitigationTasksButton
            // 
            this.PerformMitigationTasksButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.PerformMitigationTasksButton.Enabled = false;
            this.PerformMitigationTasksButton.Image = global::CwHandler.Properties.Resources.clipboard;
            this.PerformMitigationTasksButton.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.PerformMitigationTasksButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.PerformMitigationTasksButton.Margin = new System.Windows.Forms.Padding(10, 1, 0, 2);
            this.PerformMitigationTasksButton.Name = "PerformMitigationTasksButton";
            this.PerformMitigationTasksButton.Size = new System.Drawing.Size(44, 51);
            this.PerformMitigationTasksButton.Text = "toolStripButton1";
            this.PerformMitigationTasksButton.ToolTipText = "Review and perform mitigation tasks";
            this.PerformMitigationTasksButton.Click += new System.EventHandler(this.PerformMitigationTasksButton_Click);
            // 
            // SetAdminConsoleCredentialsButton
            // 
            this.SetAdminConsoleCredentialsButton.Alignment = System.Windows.Forms.ToolStripItemAlignment.Right;
            this.SetAdminConsoleCredentialsButton.AutoSize = false;
            this.SetAdminConsoleCredentialsButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.SetAdminConsoleCredentialsButton.Image = global::CwHandler.Properties.Resources.keys;
            this.SetAdminConsoleCredentialsButton.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.SetAdminConsoleCredentialsButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.SetAdminConsoleCredentialsButton.Margin = new System.Windows.Forms.Padding(1, 1, 0, 2);
            this.SetAdminConsoleCredentialsButton.Name = "SetAdminConsoleCredentialsButton";
            this.SetAdminConsoleCredentialsButton.Size = new System.Drawing.Size(48, 51);
            this.SetAdminConsoleCredentialsButton.Text = "Set Admin Console Credentials";
            this.SetAdminConsoleCredentialsButton.Click += new System.EventHandler(this.SetAdminConsoleCredentialsButton_Click);
            // 
            // DisconnectAgentButton
            // 
            this.DisconnectAgentButton.AutoSize = false;
            this.DisconnectAgentButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.DisconnectAgentButton.Enabled = false;
            this.DisconnectAgentButton.Image = global::CwHandler.Properties.Resources.exit;
            this.DisconnectAgentButton.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.DisconnectAgentButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.DisconnectAgentButton.Margin = new System.Windows.Forms.Padding(10, 0, 0, 2);
            this.DisconnectAgentButton.Name = "DisconnectAgentButton";
            this.DisconnectAgentButton.Size = new System.Drawing.Size(52, 52);
            this.DisconnectAgentButton.Text = "Disconnect from this agent";
            this.DisconnectAgentButton.Click += new System.EventHandler(this.DisconnectAgentButton_Click);
            // 
            // HaltAgentButton
            // 
            this.HaltAgentButton.AutoSize = false;
            this.HaltAgentButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.HaltAgentButton.Enabled = false;
            this.HaltAgentButton.Image = global::CwHandler.Properties.Resources.stop;
            this.HaltAgentButton.ImageScaling = System.Windows.Forms.ToolStripItemImageScaling.None;
            this.HaltAgentButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.HaltAgentButton.Margin = new System.Windows.Forms.Padding(10, 1, 0, 2);
            this.HaltAgentButton.Name = "HaltAgentButton";
            this.HaltAgentButton.Size = new System.Drawing.Size(48, 51);
            this.HaltAgentButton.Text = "Halt and remove this agent";
            this.HaltAgentButton.Click += new System.EventHandler(this.HaltAgentButton_Click);
            // 
            // EnterprisePullTabPage
            // 
            this.EnterprisePullTabPage.BackColor = System.Drawing.Color.Black;
            this.EnterprisePullTabPage.Location = new System.Drawing.Point(4, 22);
            this.EnterprisePullTabPage.Name = "EnterprisePullTabPage";
            this.EnterprisePullTabPage.Size = new System.Drawing.Size(1173, 659);
            this.EnterprisePullTabPage.TabIndex = 2;
            this.EnterprisePullTabPage.Text = "Enterprise Pull";
            // 
            // columnHeader35
            // 
            this.columnHeader35.Text = "PID";
            this.columnHeader35.Width = 59;
            // 
            // columnHeader37
            // 
            this.columnHeader37.Text = "Size";
            this.columnHeader37.Width = 87;
            // 
            // columnHeader38
            // 
            this.columnHeader38.Text = "Strings";
            this.columnHeader38.Width = 793;
            // 
            // checkBox3
            // 
            this.checkBox3.AutoSize = true;
            this.checkBox3.Location = new System.Drawing.Point(40, 46);
            this.checkBox3.Name = "checkBox3";
            this.checkBox3.Size = new System.Drawing.Size(143, 17);
            this.checkBox3.TabIndex = 7;
            this.checkBox3.Text = "Install agent as a service";
            this.checkBox3.UseVisualStyleBackColor = true;
            // 
            // label37
            // 
            this.label37.AutoSize = true;
            this.label37.Location = new System.Drawing.Point(31, 103);
            this.label37.Name = "label37";
            this.label37.Size = new System.Drawing.Size(43, 13);
            this.label37.TabIndex = 6;
            this.label37.Text = "Stealth:";
            // 
            // checkBox4
            // 
            this.checkBox4.AutoSize = true;
            this.checkBox4.Location = new System.Drawing.Point(40, 249);
            this.checkBox4.Name = "checkBox4";
            this.checkBox4.Size = new System.Drawing.Size(149, 17);
            this.checkBox4.TabIndex = 5;
            this.checkBox4.Text = "Distribute this file with MSI";
            this.checkBox4.UseVisualStyleBackColor = true;
            // 
            // textBox5
            // 
            this.textBox5.Location = new System.Drawing.Point(103, 220);
            this.textBox5.Name = "textBox5";
            this.textBox5.Size = new System.Drawing.Size(293, 20);
            this.textBox5.TabIndex = 4;
            // 
            // label39
            // 
            this.label39.AutoSize = true;
            this.label39.Location = new System.Drawing.Point(37, 223);
            this.label39.Name = "label39";
            this.label39.Size = new System.Drawing.Size(60, 13);
            this.label39.TabIndex = 3;
            this.label39.Text = "Arguments:";
            // 
            // button1
            // 
            this.button1.ForeColor = System.Drawing.Color.Black;
            this.button1.Location = new System.Drawing.Point(393, 212);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(95, 23);
            this.button1.TabIndex = 2;
            this.button1.Text = "Browse...";
            this.button1.UseVisualStyleBackColor = true;
            // 
            // textBox6
            // 
            this.textBox6.Location = new System.Drawing.Point(40, 189);
            this.textBox6.Name = "textBox6";
            this.textBox6.Size = new System.Drawing.Size(356, 20);
            this.textBox6.TabIndex = 1;
            // 
            // label65
            // 
            this.label65.AutoSize = true;
            this.label65.Location = new System.Drawing.Point(23, 160);
            this.label65.Name = "label65";
            this.label65.Size = new System.Drawing.Size(293, 13);
            this.label65.TabIndex = 0;
            this.label65.Text = "Run the following command line program after Codeword:";
            // 
            // ToolTipShowAnExample
            // 
            this.ToolTipShowAnExample.AutoPopDelay = 5000;
            this.ToolTipShowAnExample.InitialDelay = 200;
            this.ToolTipShowAnExample.IsBalloon = true;
            this.ToolTipShowAnExample.ReshowDelay = 75;
            this.ToolTipShowAnExample.ToolTipIcon = System.Windows.Forms.ToolTipIcon.Info;
            this.ToolTipShowAnExample.ToolTipTitle = "Dynamic GUIDs";
            // 
            // CwAdminConsole
            // 
            this.AccessibleName = "Codeword Admin Console";
            this.BackColor = System.Drawing.Color.Black;
            this.ClientSize = new System.Drawing.Size(1181, 709);
            this.Controls.Add(this.TopLevelTabControl);
            this.Controls.Add(this.menuStrip);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.IsMdiContainer = true;
            this.MainMenuStrip = this.menuStrip;
            this.MaximizeBox = false;
            this.Name = "CwAdminConsole";
            this.SizeGripStyle = System.Windows.Forms.SizeGripStyle.Hide;
            this.Text = "Codeword Admin Console";
            this.Load += new System.EventHandler(this.CwAdminConsole_Load);
            this.Shown += new System.EventHandler(this.CwAdminConsole_Shown);
            this.FileSignaturesTabPage.ResumeLayout(false);
            this.FileSignaturesTabPage.PerformLayout();
            this.RegistrySignaturesTabPage.ResumeLayout(false);
            this.RegistrySignaturesTabPage.PerformLayout();
            this.SignaturesTabContainer.ResumeLayout(false);
            this.RegistryGuidSignaturesTabPage.ResumeLayout(false);
            this.RegistryGuidSignaturesTabPage.PerformLayout();
            this.MemorySignaturesTabPage.ResumeLayout(false);
            this.MemorySignaturesTabPage.PerformLayout();
            this.HeuristicsTabContainer.ResumeLayout(false);
            this.ProcessThreadTabPage.ResumeLayout(false);
            this.groupBox14.ResumeLayout(false);
            this.groupBox14.PerformLayout();
            this.ModuleTab.ResumeLayout(false);
            this.ModuleTab.PerformLayout();
            this.groupBox19.ResumeLayout(false);
            this.groupBox19.PerformLayout();
            this.groupBox18.ResumeLayout(false);
            this.groupBox18.PerformLayout();
            this.BHOToolbarTabPage.ResumeLayout(false);
            this.BHOToolbarTabPage.PerformLayout();
            this.RegistryHeuristicsTabPage.ResumeLayout(false);
            this.RegistryHeuristicsTabPage.PerformLayout();
            this.KernelTabPage.ResumeLayout(false);
            this.groupBox11.ResumeLayout(false);
            this.groupBox11.PerformLayout();
            this.groupBox7.ResumeLayout(false);
            this.groupBox7.PerformLayout();
            this.groupBox9.ResumeLayout(false);
            this.groupBox9.PerformLayout();
            this.groupBox8.ResumeLayout(false);
            this.groupBox8.PerformLayout();
            this.GDI32SubsystemTabPage.ResumeLayout(false);
            this.groupBox13.ResumeLayout(false);
            this.groupBox13.PerformLayout();
            this.DriversTabPage.ResumeLayout(false);
            this.DriversTabPage.PerformLayout();
            this.NdisTdiTabPage.ResumeLayout(false);
            this.NdisTdiTabPage.PerformLayout();
            this.menuStrip.ResumeLayout(false);
            this.menuStrip.PerformLayout();
            this.TopLevelTabControl.ResumeLayout(false);
            this.CreateNewAgentTabPage.ResumeLayout(false);
            this.CreateNewAgentTabPage.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            this.GeneralSettingsTabContainer.ResumeLayout(false);
            this.AgentStartupTabPage.ResumeLayout(false);
            this.groupBox5.ResumeLayout(false);
            this.groupBox5.PerformLayout();
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.AgentConnectionTabPage.ResumeLayout(false);
            this.groupBox6.ResumeLayout(false);
            this.groupBox6.PerformLayout();
            this.groupBox4.ResumeLayout(false);
            this.groupBox4.PerformLayout();
            this.AgentPersistenceAndStealthTabPage.ResumeLayout(false);
            this.groupBox3.ResumeLayout(false);
            this.groupBox3.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.MitigationTabPage.ResumeLayout(false);
            this.MitigationTabPage.PerformLayout();
            this.CollectionModeTabPage.ResumeLayout(false);
            this.CollectionModeTabPage.PerformLayout();
            this.ReportingTabPage.ResumeLayout(false);
            this.ReportingTabPage.PerformLayout();
            this.ReportingAuthPanel.ResumeLayout(false);
            this.ReportingAuthPanel.PerformLayout();
            this.ReportingTlsPanel.ResumeLayout(false);
            this.ReportingTlsPanel.PerformLayout();
            this.ReportingWebPanel.ResumeLayout(false);
            this.ReportingWebPanel.PerformLayout();
            this.ReportingEmailPanel.ResumeLayout(false);
            this.ReportingEmailPanel.PerformLayout();
            this.ReportingFtpPanel.ResumeLayout(false);
            this.ReportingFtpPanel.PerformLayout();
            this.ReportingNetworkSharePanel.ResumeLayout(false);
            this.ReportingNetworkSharePanel.PerformLayout();
            this.InformationTabPage.ResumeLayout(false);
            this.InformationTabPage.PerformLayout();
            this.AdvancedTabPage.ResumeLayout(false);
            this.AdvancedTabPage.PerformLayout();
            this.ConnectExistingAgentTabPage.ResumeLayout(false);
            this.ConnectExistingAgentTabPage.PerformLayout();
            this.FindingsTabContainer.ResumeLayout(false);
            this.SystemInfoTabPage.ResumeLayout(false);
            this.SystemInfoTabPage.PerformLayout();
            this.RegistryFindingsTabPage.ResumeLayout(false);
            this.FileFindingsTabPage.ResumeLayout(false);
            this.MemoryFindingsTabPage.ResumeLayout(false);
            this.UserModeAnomaliesTabPage.ResumeLayout(false);
            this.groupBox21.ResumeLayout(false);
            this.groupBox20.ResumeLayout(false);
            this.KernelModeAnomaliesTabPage.ResumeLayout(false);
            this.groupBox17.ResumeLayout(false);
            this.groupBox12.ResumeLayout(false);
            this.groupBox10.ResumeLayout(false);
            this.ConnectAgentToolstrip.ResumeLayout(false);
            this.ConnectAgentToolstrip.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion


        #region TOOLSTRIP FUCKUP CODE

        /*
         this.ConnectAgentToolstrip.Items.Add(ConnectAgentButton);
            this.ConnectAgentToolstrip.Items.Add(toolStripSeparator1);
            this.ConnectAgentToolstrip.Items.Add(StartScanButton);
            this.ConnectAgentToolstrip.Items.Add(UpdateAgentButton);
            this.ConnectAgentToolstrip.Items.Add(DownloadEvidenceButton);
            this.ConnectAgentToolstrip.Items.Add(PerformMitigationTasksButton);
        this.ConnectAgentToolstrip.Items.Add(SetAdminConsoleCredentialsButton);
        this.ConnectAgentToolstrip.Items.Add(DisconnectAgentButton);
        this.ConnectAgentToolstrip.Items.Add(HaltAgentButton);
         */

        #endregion

        ///////////////////////////////////////////////////////////////////////////////////
        //
        //
        //                      REGISTRY SIGNATURES TAB FUNCTIONS
        //
        //
        ///////////////////////////////////////////////////////////////////////////////////

        #region SIGNATURES -- REGISTRY TAB

        //
        //-----------------------------
        //ADD/UPDATE REGISTRY SIGNATURE
        //-----------------------------
        //
        private void AddRegistrySignatureButton_Click(object sender, EventArgs e)
        {
            Dictionary<string, string> thisSignature = new Dictionary<string, string>();
            string err;

            thisSignature["KeyName"] = RegistrySignatures_NewKeyName.Text;
            thisSignature["ValueName"] = RegistrySignatures_NewValueName.Text;
            thisSignature["ValueData"] = RegistrySignatures_ValueData.Text;
            thisSignature["ChangeValueData"] = RegistrySignatures_ChangeValueData.Text;
            thisSignature["Action"] = "";
            if (RegistrySignatures_NewAction.SelectedItem != null)
                thisSignature["Action"] = RegistrySignatures_NewAction.SelectedItem.ToString();
                
            //cancel edit mode and leave if validation failed
            if ((err = ValidateRegistrySignature(thisSignature)) != null)
            {
                MessageBox.Show(err);
                return;
            }

            //valid..

            //UPDATE a registry indicator in the listview
            if (AddRegistrySignatureButton.Text == "Update")
            {
                RegistrySignatures_Listview.Items[RegistrySignatures_Listview.SelectedIndices[0]] = new ListViewItem((new string[] { thisSignature["KeyName"], thisSignature["ValueName"], thisSignature["ValueData"], thisSignature["ChangeValueData"], thisSignature["Action"] }), -1);
            }
            else
            {
                ListViewItem newItem = null;
                newItem = new ListViewItem(new string[] { thisSignature["KeyName"], thisSignature["ValueName"], thisSignature["ValueData"], thisSignature["ChangeValueData"], thisSignature["Action"] }, -1);

                //if the target registry key is already in the listview, cancel - cant have more than one action per registry key
                if (RegistrySignatures_Listview.Items.Contains(newItem))
                {
                    MessageBox.Show("There is already a registry indicator for that registry key.  You can only perform one action per key.");
                    return;
                }
                else
                    RegistrySignatures_Listview.Items.Add(newItem);
            }

            RegistrySignatures_Listview.Refresh();
            return;
        }

        //
        //-----------------------------
        //DELETE REGISTRY SIGNATURE
        //-----------------------------
        //
        private void DeleteRegistrySignatureButton_Click(object sender, EventArgs e)
        {
            //prompt for confirmation of delete
            if (MessageBox.Show("Delete " + RegistrySignatures_Listview.SelectedItems.Count + " items?", "Delete indicators?", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            //delete the items
            foreach (ListViewItem selectedItem in RegistrySignatures_Listview.SelectedItems)
                RegistrySignatures_Listview.Items.Remove(selectedItem);

            return;
        }

        //
        //-----------------------------
        //MISC FORM FUNCTIONS
        //-----------------------------
        //
        //
        //Enable the add new registry signature as user types a registry key name
        //
        private void RegistrySignatures_NewKeyName_TextChanged(object sender, EventArgs e)
        {
            string key = RegistrySignatures_NewKeyName.Text;

            if (key != "")
                AddRegistrySignatureButton.Enabled = true;
        }  

        internal void RegistrySignatures_Listview_SelectedIndexChanged(object sender, EventArgs e)
        {
            //if no item is selected, clear the text fields and set buttons appropriately
            if (RegistrySignatures_Listview.SelectedItems.Count == 0)
            {
                RegistrySignaturesResetAll();
                return;
            }

            DeleteRegistrySignatureButton.Enabled = true;

            //set the form fields to the selected subitem
            //note:  we have to loop over selectedItems, even though this listview only allows
            //one item to be selected at a time ... .NET retardedness in action
            foreach (ListViewItem selectedIndicator in RegistrySignatures_Listview.SelectedItems)
            {
                //get the values of each indicator field from the listview
                ListViewItem.ListViewSubItem subitem_key = selectedIndicator.SubItems[0];
                ListViewItem.ListViewSubItem subitem_valuename = selectedIndicator.SubItems[1];
                ListViewItem.ListViewSubItem subitem_valuedata = selectedIndicator.SubItems[2];
                ListViewItem.ListViewSubItem subitem_changevaluedata = selectedIndicator.SubItems[3];
                ListViewItem.ListViewSubItem subitem_action = selectedIndicator.SubItems[4];

                //populate the text fields and drop-down boxes with the appropriate value from listview
                //note:  for drop-down boxes we change the selected index, dont set a text value
                RegistrySignatures_NewKeyName.Text = subitem_key.Text;
                RegistrySignatures_NewValueName.Text = subitem_valuename.Text;
                RegistrySignatures_ValueData.Text = subitem_valuedata.Text;
                RegistrySignatures_ChangeValueData.Text = subitem_changevaluedata.Text;
                RegistrySignatures_NewAction.SelectedIndex = RegistrySignatures_NewAction.Items.IndexOf(subitem_action.Text);

                //change the "add new" button to read "Update"
                AddRegistrySignatureButton.Text = "Update";
            }
        }

        internal void RegistrySignaturesResetAll()
        {
            RegistrySignatures_NewAction.SelectedIndex = 0;
            RegistrySignatures_NewKeyName.Text = "";
            RegistrySignatures_NewValueName.Text = "";
            RegistrySignatures_ValueData.Text = "";
            RegistrySignatures_ChangeValueData.Text = "";
            AddRegistrySignatureButton.Text = "Add";
            return;
        }

        #endregion

        #region SIGNATURES -- REGISTRY GUID TAB

        private void AddRegGuidButton_Click(object sender, EventArgs e)
        {
            Dictionary<string, string> thisGuidSignature = new Dictionary<string, string>();
            string err = null;

            //user can either specify a static or a dynamic GUID value
            //a static value is a valid GUID number
            //a dynamic value is a registry key whose value is a valid GUID
            string dynamic_keyname = DynRegGuidKeyName.Text;
            string dynamic_keyvaluename = DynRegGuidValueName.Text;
            string static_guid_value = StaticRegGuidValue.Text;

            //figure out what values to use for "Guid Type"
            string use_value = "";
            string use_type = "";

            if (dynamic_keyname != "")
            {
                use_value = dynamic_keyname + "\\" + dynamic_keyvaluename;
                use_type = "Dynamic";
            }
            else
            {
                use_value = static_guid_value;
                use_type = "Static";
            }

            thisGuidSignature["GuidValue"] = use_value;
            thisGuidSignature["GuidType"] = use_type;

            //cancel edit mode and leave if validation failed
            if ((err = ValidateRegistryGuidSignature(thisGuidSignature)) != null)
            {
                MessageBox.Show(err);
                return;
            }

            //UPDATE a registry indicator in the listview
            if (AddRegGuidButton.Text == "Update")
            {
                RegistryGuidSignatures_Listview.Items[RegistryGuidSignatures_Listview.SelectedIndices[0]] = new ListViewItem(new string[] { use_value, use_type }, -1);
            }
            else
            {
                ListViewItem newItem = new ListViewItem(new string[] { use_value, use_type }, -1);

                //if the target registry key is already in the listview, cancel - cant have more than one action per registry key
                if (RegistryGuidSignatures_Listview.Items.Contains(newItem))
                {
                    MessageBox.Show("That GUID already exists.");
                    return;
                }
                else
                    RegistryGuidSignatures_Listview.Items.Add(newItem);
            }

            RegistryGuidSignaturesResetAll();
            RegistryGuidSignatures_Listview.Refresh();
            return;
        }

        private void DeleteSelectedGuidButton_Click(object sender, EventArgs e)
        {
            //prompt for confirmation of delete
            if (MessageBox.Show("Delete " + RegistryGuidSignatures_Listview.SelectedIndices.Count + " items?", "Delete GUID signatures?", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                //delete the items
                foreach (ListViewItem selectedItem in RegistryGuidSignatures_Listview.SelectedItems)
                    RegistryGuidSignatures_Listview.Items.Remove(selectedItem);
                RegistryGuidSignatures_Listview.Refresh();
            }
        }

        internal void RegistryGuidSignatures_Listview_SelectedIndexChanged(object sender, EventArgs e)
        {
            //if no item is selected, clear the text fields and set buttons appropriately
            if (RegistryGuidSignatures_Listview.SelectedItems.Count == 0)
            {
                RegistryGuidSignaturesResetAll();
                return;
            }

            DeleteSelectedGuidButton.Enabled = true;

            //set the form fields to the selected subitem
            //note:  we have to loop over selectedItems, even though this listview only allows
            //one item to be selected at a time ... .NET retardedness in action
            foreach (ListViewItem selectedIndicator in RegistryGuidSignatures_Listview.SelectedItems)
            {
                //get the values of each indicator field from the listview
                string guid = selectedIndicator.SubItems[0].Text;
                string guidtype = selectedIndicator.SubItems[1].Text;

                if (guidtype == "Static")
                {
                    DynRegGuidKeyName.Text = "";
                    DynRegGuidValueName.Text = "";
                    StaticRegGuidValue.Text = guid;
                    StaticRegGuidValue.Focus();
                }
                else
                {
                    string firstpart = guid;
                    string secondpart = "";

                    //if (Default) is NOT in the GUID, get the last slash to find the value name
                    if (guid.IndexOf("(Default)") == -1)
                    {
                        int lastIndex = guid.LastIndexOf("\\");
                        firstpart = guid.Substring(0, lastIndex);
                        secondpart = guid.Substring(lastIndex + 1, (guid.Length - (lastIndex + 1)));
                    }
                    //otherwise, (Default) is in the GUID, split that part out
                    else
                    {
                        firstpart = guid.Replace("(Default)", "");
                        secondpart = "(Default)";
                    }

                    DynRegGuidKeyName.Text = firstpart;
                    DynRegGuidValueName.Text = secondpart;
                    DynRegGuidKeyName.Focus();
                }
            }

            DeleteSelectedGuidButton.Enabled = true;
            AddRegGuidButton.Enabled = true;

            //change the "add new" button to read "Update"
            AddRegGuidButton.Text = "Update";
        }

        //
        //when the user types something in the static GUID field, disable the dynamic GUID fields
        //
        private void StaticRegGuidValue_TextChanged(object sender, EventArgs e)
        {
            bool enableDynamic=false;

            if (StaticRegGuidValue.Text == "")
            {
                enableDynamic = true;
                if (AddRegGuidButton.Text == "Update")
                    AddRegGuidButton.Text = "Add";
            }

            DynRegGuidKeyName.Enabled = enableDynamic;
            DynRegGuidValueName.Enabled = enableDynamic;

        }

        //
        //when the user types something in the dynamic GUID field, disable the static GUID fields
        //
        private void DynRegGuidKeyName_TextChanged(object sender, EventArgs e)
        {
            bool enableStatic = false;

            if (DynRegGuidKeyName.Text == "")
                enableStatic = true;
            if (AddRegGuidButton.Text == "Update")
                AddRegGuidButton.Text = "Add";

            StaticRegGuidValue.Enabled = enableStatic;
        }

        internal void RegistryGuidSignaturesResetAll()
        {
            DeleteSelectedGuidButton.Enabled = false;
            DynRegGuidKeyName.Text = "";
            DynRegGuidValueName.Text = "";
            StaticRegGuidValue.Text = "";
            AddRegGuidButton.Text = "Add";

            return;
        }


        #endregion

        ///////////////////////////////////////////////////////////////////////////////////
        //
        //
        //                      FILE SIGNATURES TAB FUNCTIONS
        //
        //
        ///////////////////////////////////////////////////////////////////////////////////
        #region SIGNATURES -- FILES TAB

        private void AddFileSignatureButton_Click(object sender, EventArgs e)
        {
            Dictionary<string, string> thisSignature = new Dictionary<string, string>();
            string filename = FileSignatures_NewFilename.Text;
            string filehash = FileSignatures_NewFileHash.Text;
            string filehashType = "";
            string filesize = FileSignatures_NewFileSize.Text;
            string filePESig = FileSignatures_NewFilePESignature.Text;
            string err = "", action = "";

            if (FileSignatures_NewAction.SelectedItem != null)
                action = FileSignatures_NewAction.SelectedItem.ToString();

            //if file or PE hashes were given, extract their hash type (MD5 or SHA1)
            if (filehash != "")
            {
                if (FileSignatures_NewFileHashTypeMD5.Checked)
                    filehashType = "MD5";
                else
                    filehashType = "SHA1";
            }

            thisSignature["FileName"] = filename;
            thisSignature["FileHash"] = filehash;
            thisSignature["FileHashType"] = filehashType;
            thisSignature["FileSize"] = filesize;
            thisSignature["FilePESignature"] = filePESig;
            thisSignature["Action"] = action;

            //validate
            if ((err = ValidateFileSignature(thisSignature)) != null)
            {
                MessageBox.Show(err);
                return;
            }

            //valid.

            //UPDATE a file signature in the listview
            if (AddFileSignatureButton.Text == "Update")
            {
                FileSignatures_Listview.Items[FileSignatures_Listview.SelectedIndices[0]] = new ListViewItem(new string[] { filename, filehash, filehashType, filesize, filePESig, action }, -1);
            }
            else
            {
                ListViewItem newItem = new ListViewItem(new string[] { filename, filehash, filehashType, filesize, filePESig, action }, -1);

                //if the target file name is already in the listview, cancel - cant have more than one action per file name
                if (FileSignatures_Listview.Items.Contains(newItem))
                {
                    MessageBox.Show("There is already a file signature for that file name.  You can only perform one action per file name.");
                    return;
                }

                FileSignatures_Listview.Items.Add(newItem);
            }

            FileSignaturesResetAll();
            FileSignatures_Listview.Refresh();
        }

        private void DeleteSelectedFileSignatureButton_Click(object sender, EventArgs e)
        {
            //prompt for confirmation of delete
            if (MessageBox.Show("Delete " + FileSignatures_Listview.SelectedItems.Count + " items?", "Delete signatures?", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            //delete the items
            foreach (ListViewItem selectedItem in FileSignatures_Listview.SelectedItems)
                FileSignatures_Listview.Items.Remove(selectedItem);

            return;
        }

        private void FileSignatures_Listview_SelectedIndexChanged(object sender, EventArgs e)
        {
            //if no item is selected, clear the text fields and set buttons appropriately
            if (FileSignatures_Listview.SelectedItems.Count == 0)
            {
                FileSignaturesResetAll();
                return;
            }

            DeleteSelectedFileSignature.Enabled = true;

            //set the form fields to the selected subitem
            //note:  we have to loop over selectedItems, even though this listview only allows
            //one item to be selected at a time ... .NET retardedness in action
            foreach (ListViewItem selectedSignature in FileSignatures_Listview.SelectedItems)
            {
                //get the values of each signature field from the listview
                ListViewItem.ListViewSubItem subitem_filename = selectedSignature.SubItems[0];
                ListViewItem.ListViewSubItem subitem_filehash = selectedSignature.SubItems[1];
                ListViewItem.ListViewSubItem subitem_filehashType = selectedSignature.SubItems[2];
                ListViewItem.ListViewSubItem subitem_filesize = selectedSignature.SubItems[3];
                ListViewItem.ListViewSubItem subitem_filePEhash = selectedSignature.SubItems[4];
                ListViewItem.ListViewSubItem subitem_action = selectedSignature.SubItems[5];

                //populate the text fields and drop-down boxes with the appropriate value from listview
                //note:  for drop-down boxes we change the selected index, dont set a text value
                FileSignatures_NewFilename.Text = subitem_filename.Text;
                FileSignatures_NewFileHash.Text = subitem_filehash.Text;
                FileSignatures_NewFileSize.Text = subitem_filesize.Text;
                FileSignatures_NewFilePESignature.Text = subitem_filePEhash.Text;

                //file hash type
                if (subitem_filehashType.Text == "MD5")
                    FileSignatures_NewFileHashTypeMD5.Checked = true;
                else if (subitem_filehashType.Text == "SHA1")
                    FileSignatures_NewFileHashTypeSHA1.Checked = true;

                FileSignatures_NewAction.SelectedIndex = FileSignatures_NewAction.Items.IndexOf(subitem_action.Text);
            }

            //change the "add new" button to read "Update"
            AddFileSignatureButton.Text = "Update";
        }

        internal void FileSignaturesResetAll()
        {
            FileSignatures_NewAction.SelectedIndex = 0;
            FileSignatures_NewFilename.Text = "";
            FileSignatures_NewFileHash.Text = "";
            FileSignatures_NewFileSize.Text = "";
            FileSignatures_NewFilePESignature.Text = "";
            FileSignatures_NewFileHashTypeMD5.Checked = false;
            FileSignatures_NewFileHashTypeSHA1.Checked = false;
            AddFileSignatureButton.Text = "Add";
            return;
        }

        #endregion

        ///////////////////////////////////////////////////////////////////////////////////
        //
        //
        //                      MEMORY SIGNATURES TAB FUNCTIONS
        //
        //
        ///////////////////////////////////////////////////////////////////////////////////
        #region "SIGNATURES -- MEMORY TAB"

        private void AddMemorySignatureButton_Click(object sender, EventArgs e)
        {
            Dictionary<string, string> thisSignature = new Dictionary<string, string>();
            string processname = MemorySignatures_NewProcessName.Text;
            string action="",err = "";
            if (MemorySignatures_NewAction.SelectedItem != null)
                action = MemorySignatures_NewAction.SelectedItem.ToString();
            string keywords = MemorySignatures_NewKeywords.Text;

            thisSignature["ProcessName"] = processname;
            thisSignature["Keywords"] = keywords;
            thisSignature["Action"] = action;

            //validate
            if ((err = ValidateMemorySignature(thisSignature)) != null)
            {
                MessageBox.Show(err);
                return;
            }

            //valid.

            //UPDATE a registry signature in the listview
            if (AddMemorySignatureButton.Text == "Update")
            {
                MemorySignatures_Listview.Items[MemorySignatures_Listview.SelectedIndices[0]] = new ListViewItem(new string[] { processname, keywords, action }, -1);
            }
            else
            {
                ListViewItem newItem = new ListViewItem(new string[] { processname, keywords, action }, -1);

                //if the target process name is already in the listview, cancel - cant have more than one action per process name
                if (MemorySignatures_Listview.Items.Contains(newItem))
                {
                    MessageBox.Show("There is already a memory signature for that process name.  You can only perform one action per process name.");
                    return;
                }

                MemorySignatures_Listview.Items.Add(newItem);
            }

            MemorySignaturesResetAll();
            MemorySignatures_Listview.Refresh();
        }

        private void DeleteSelectedMemorySignatureButton_Click(object sender, EventArgs e)
        {
            //prompt for confirmation of delete
            if (MessageBox.Show("Delete " + MemorySignatures_Listview.SelectedItems.Count + " items?", "Delete signatures?", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            //delete the items
            foreach (ListViewItem selectedItem in MemorySignatures_Listview.SelectedItems)
                MemorySignatures_Listview.Items.Remove(selectedItem);

            return;
        }

        private void MemorySignatures_Listview_SelectedIndexChanged(object sender, EventArgs e)
        {
            //if no item is selected, clear the text fields and set buttons appropriately
            if (MemorySignatures_Listview.SelectedItems.Count == 0)
            {
                MemorySignaturesResetAll();
                return;
            }

            DeleteSelectedMemorySignatureButton.Enabled = true;

            //set the form fields to the selected subitem
            //note:  we have to loop over selectedItems, even though this listview only allows
            //one item to be selected at a time ... .NET retardedness in action
            foreach (ListViewItem selectedSignature in MemorySignatures_Listview.SelectedItems)
            {
                //get the values of each signature field from the listview
                ListViewItem.ListViewSubItem subitem_processname = selectedSignature.SubItems[0];
                ListViewItem.ListViewSubItem subitem_keywords = selectedSignature.SubItems[1];
                ListViewItem.ListViewSubItem subitem_action = selectedSignature.SubItems[2];

                //populate the text fields and drop-down boxes with the appropriate value from listview
                //note:  for drop-down boxes we change the selected index, dont set a text value
                MemorySignatures_NewProcessName.Text = subitem_processname.Text;
                MemorySignatures_NewKeywords.Text = subitem_keywords.Text;
                MemorySignatures_NewAction.SelectedIndex = MemorySignatures_NewAction.Items.IndexOf(subitem_action.Text);
            }

            //change the "add new" button to read "Update"
            AddMemorySignatureButton.Text = "Update";
        }

        private void MemorySignatures_NewProcessName_TextChanged(object sender, EventArgs e)
        {
            string processName = MemorySignatures_NewProcessName.Text;

            if (processName != "")
                AddMemorySignatureButton.Enabled = true;
            else
                AddMemorySignatureButton.Enabled = false;
        }

        protected void MemoryTabPage_Click(object sender, EventArgs e)
        {
            MemorySignaturesResetAll();
        }

        internal void MemorySignaturesResetAll()
        {
            MemorySignatures_NewAction.SelectedIndex = 0;
            MemorySignatures_NewProcessName.Text = "";
            MemorySignatures_NewKeywords.Text = "";
            return;
        }

        #endregion

        ///////////////////////////////////////////////////////////////////////////////////
        //
        //
        //                      REPORTING TAB FUNCTIONS
        //
        //
        ///////////////////////////////////////////////////////////////////////////////////

        #region "Reporting" tab functions

        private void Reporting_EnableAutoReporting_MouseDown(object sender, MouseEventArgs e)
        {
            //first determine what startup mode is selected..
            //
            //in ENTERPRISE MODE and REMOTE CONTROL MODE, auto reporting is DISABLED
            if (StartupEnterpriseMode.Checked || StartupRemoteControlMode.Checked)
            {
                MessageBox.Show("Automatic reporting is only enabled for FIRE AND FORGET agent startup mode.  Please select that startup mode if you want automatic reporting.");
                //note, we dont have to set the checked state to false to cancel the user's click,
                //because the AutoCheck property of this checkbox is set to FALSE..therefore, unless
                //the code after this block is executed, the checked state won't change..
                return;
            }
            //if FIRE AND FORGET startup mode is set, FORCE user to do reporting
            //
            if (StartupFireAndForgetMode.Checked)
            {
                MessageBox.Show("Automatic reporting is required for FIRE AND FORGET startup mode.  Otherwise, results would just be left on disk!?");
                return;
            }

            //set the state of the checked box to the opposite of its current state
            if (Reporting_EnableAutoReporting.Checked)
                Reporting_EnableAutoReporting.Checked = false;
            else
                Reporting_EnableAutoReporting.Checked = true;

            Reporting_EnableAutoReporting.Refresh();

            //determine whether to enable or disable panels based on checked state.
            bool set = false;
            if (Reporting_EnableAutoReporting.Checked)
                set = true;

            ToggleReportingPanels(set, null);
        }

        private void Reporting_Method_NetworkShare_TextChanged(object sender, EventArgs e)
        {
            //if the user just cleared the text in this field, enable all panels
            if (Reporting_Method_NetworkShare.Text == "")
                ToggleReportingPanels(true, null);
            else
                ToggleReportingPanels(false, ReportingNetworkSharePanel);
        }

        private void Reporting_Method_FTPServer_TextChanged(object sender, EventArgs e)
        {
            //if the user just cleared the text in this field, enable all panels
            if (Reporting_Method_FTPServer.Text == "")
                ToggleReportingPanels(true, null);
            else
                ToggleReportingPanels(false, ReportingFtpPanel);
        }

        private void Reporting_Method_EmailAddress_TextChanged(object sender, EventArgs e)
        {
            //if the user just cleared the text in this field, enable all panels
            if (Reporting_Method_EmailAddress.Text == "")
                ToggleReportingPanels(true, null);
            else
                ToggleReportingPanels(false, ReportingEmailPanel);
        }

        private void Reporting_Method_WebServer_URI_TextChanged(object sender, EventArgs e)
        {
            //if the user just cleared the text in this field, enable all panels
            if (Reporting_Method_WebServer_URI.Text == "")
                ToggleReportingPanels(true, null);
            else
                ToggleReportingPanels(false, ReportingWebPanel);
        }

        private void Reporting_Use_TLS_CheckedChanged(object sender, EventArgs e)
        {
            //clear and disable the port textfield for SMTP and Web if its checked
            if (Reporting_Use_TLS.Checked)
            {
                Reporting_SMTP_Port.Text = "";
                Reporting_SMTP_Port.Enabled = false;
                Reporting_WebServer_Port.Text = "";
                Reporting_WebServer_Port.Enabled = false;
                Reporting_Auth_Server_PubKey.Enabled = true;
                BrowseButton1.Enabled = true;
            }
            else
            {
                Reporting_SMTP_Port.Enabled = true;
                Reporting_WebServer_Port.Enabled = true;
                Reporting_Auth_Server_PubKey.Enabled = false;
                BrowseButton1.Enabled = false;
            }
        }

        private void BrowseButton1_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog();
            openFileDialog1.Title = "Select a public key file";

            // If the user clicked OK in the dialog
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                Reporting_Auth_Server_PubKey.Text = openFileDialog1.FileName;
            }
        }

        private void BrowseButton2_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog();
            openFileDialog1.Filter = "PKCS-12 Files|*.p12;*.pfx;*.pkcs12";
            openFileDialog1.Title = "Select a PKCS-12 formatted file";

            // If the user clicked OK in the dialog
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                AgentPFXFile.Text = openFileDialog1.FileName;
            }
        }

        private void ToggleReportingPanels(bool value, Panel exclusion)
        {
            //we will set the exclusion panel to the opposite value of "value"
            bool exclusionValue = true;
            if (value)
                exclusionValue = false;

            //if exclusion is NULL there is no exclusion, meaning set ALL panels to "value"
            //cheat ... create a dummy panel
            if (exclusion == null)
            {
                exclusion = new Panel();
                exclusion.Name = "Dummy";
            }

            //
            //set ALL the reporting panels to "value" except "exclusion"
            //
            if (exclusion.Name == "ReportingNetworkSharePanel")
                ReportingNetworkSharePanel.Enabled = exclusionValue;
            else
                ReportingNetworkSharePanel.Enabled = value;
            if (exclusion.Name == "ReportingFtpPanel")
                ReportingFtpPanel.Enabled = exclusionValue;
            else
                ReportingFtpPanel.Enabled = value;
            if (exclusion.Name == "ReportingEmailPanel")
                ReportingEmailPanel.Enabled = exclusionValue;
            else
                ReportingEmailPanel.Enabled = value;
            if (exclusion.Name == "ReportingTlsPanel")
                ReportingTlsPanel.Enabled = exclusionValue;
            else
                ReportingTlsPanel.Enabled = value;
            if (exclusion.Name == "ReportingWebPanel")
                ReportingWebPanel.Enabled = exclusionValue;
            else
                ReportingWebPanel.Enabled = value;
            if (exclusion.Name == "ReportingAuthPanel")
                ReportingAuthPanel.Enabled = exclusionValue;
            else
                ReportingAuthPanel.Enabled = value;
        }

        #endregion


        ///////////////////////////////////////////////////////////////////////////////////
        //
        //
        //                      GUI EVENT HANDLER FUNCTIONS
        //
        //
        ///////////////////////////////////////////////////////////////////////////////////

        #region Gui event handler functions

        protected void Button_GenerateMSI_Click(object sender, EventArgs e)
        {
            //********************************************************
            //              VALIDATE FORM
            //********************************************************
            //
            if (!IsValidForm())
                return;

            //********************************************************
            //              GENERATE AGENT CONFIGURATION FILE
            //********************************************************
            //
            //send configuration file as 'CwAgentConfiguration.xml'.
            //
            try
            {
                CwXML.SaveSettingsXML("CwAgentConfiguration.xml", (string[])CrawlTabPages("GetElementNames", null, null), (string[])CrawlTabPages("GetElementValues", null, null));
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to generate agent configuration file:  "+ex.Message+" - build process terminated");
                return;
            }

            //********************************************************
            //              GENERATE AGENT SIGNATURES FILE
            //********************************************************
            //
            //pass silent=true to SaveSettingsXML() to generate the agent's
            //configuration file as 'CwAgentConfiguration.xml'.
            //
            CwXML.RegistryGuidSignature[] rsg = GetAllRegistryGuidSignatures();
            CwXML.RegistrySignature[] rs = GetAllRegistrySignatures();
            CwXML.FileSignature[] fs = GetAllFileSignatures();
            CwXML.MemorySignature[] ms = GetAllMemorySignatures();

            try
            {
                CwXML.ExportSignatureTemplate("CwAgentSignatures.xml",rsg, rs, fs, ms);
            }
            catch(Exception ex)
            {
                MessageBox.Show("Failed to generate agent signatures file:  "+ex.Message+" - build process terminated.");
                return;
            }

            //********************************************************
            //              LAUNCH PROGRESS WINDOW
            //                 TO GENERATE MSI
            //********************************************************
            //we need to determine the number of steps in the msi generation
            //process.  this is calculated as 2+num_cabs.
            //      -2 is for extracting the template msi and CABARC.EXE
            //      -num_cabs is how many cabs the user will need to add
            //      to the msi.  this defaults to 1 because we will at least
            //      need to make 1 cab for the config file (txt)
            int numSteps = 4;
            int stepSize = 25;

            //get any x509 certificates to embed in our msi
            ArrayList certs = new ArrayList();
            if (Reporting_Auth_Server_PubKey.Text != "")
                certs.Add(Reporting_Auth_Server_PubKey.Text);
            if (AgentPFXFile.Text != "")
                certs.Add(AgentPFXFile.Text);

            //get any third party apps we need to embed in our msi
            ArrayList thirdPartyApps = new ArrayList();
            if (Advanced_3rdPartyApp_Filename.Text != "" && Advanced_3rdPartyApp_Distribute.Checked)
                thirdPartyApps.Add(Advanced_3rdPartyApp_Filename.Text);

            //this spawns a new thread to do the work while a GUI 
            //progress window gets incremental updates on status
            //** add new GUI options to this constructor! **
            CwProgressWindow pWin = new CwProgressWindow(numSteps,stepSize,Stealth_No_Dotnet.Checked,certs,thirdPartyApps);
            pWin.ShowDialog();

            return;
        }

        private void FileSignatures_NewFileHashTypeMD5_CheckedChanged(object sender, EventArgs e)
        {
            //if we just unchecked the checkbox, dont call this again
            if (!FileSignatures_NewFileHashTypeMD5.Checked)
                return;

            if (!validateMD5(FileSignatures_NewFileHash.Text))
            {
                MessageBox.Show("That is not a valid MD-5 string.");
                FileSignatures_NewFileHash.Select();
                FileSignatures_NewFileHashTypeMD5.Checked = false;
            }
        }

        private void FileSignatures_NewFileHashTypeSHA1_CheckedChanged(object sender, EventArgs e)
        {
            //if we just unchecked the checkbox, dont call this again
            if (!FileSignatures_NewFileHashTypeSHA1.Checked)
                return;

            if (!validateSHA1(FileSignatures_NewFileHash.Text))
            {
                MessageBox.Show("That is not a valid SHA-1 string.");
                FileSignatures_NewFileHash.Select();
                FileSignatures_NewFileHashTypeSHA1.Checked = false;
            }
        }

        #endregion

        #region menu toolbar event processing functions

        protected void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void saveSettingsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //-----------------------------------------------
            //              VALIDATE FORM
            //-----------------------------------------------
            //
            if (!IsValidForm())
                return;

            //-----------------------------------------------
            //              DETERMINE SAVE FILENAME
            //-----------------------------------------------
            //
            SaveFileDialog dlg = new SaveFileDialog();
            dlg.CheckFileExists = false;
            dlg.CheckPathExists = true;
            dlg.DefaultExt = ".xml"; //default extension
            dlg.Title = "Select settings file";
            dlg.Filter = "XML Files|*.xml";

            //the user clicked cancel
            if (dlg.ShowDialog() != DialogResult.OK)
                return;

            //-----------------------------------------------
            //              TRY SERIALIZATION
            //-----------------------------------------------
            //
            try
            {
                CwXML.SaveSettingsXML(dlg.FileName, (string[])CrawlTabPages("GetElementNames", null, null), (string[])CrawlTabPages("GetElementValues", null, null));
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                return;
            }
            
            MessageBox.Show("Settings saved.");
        }

        private void loadSettingsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //-----------------------------------------------
            //              DETERMINE IMPORT FILENAME
            //-----------------------------------------------
            //show browse dialog to select file
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.CheckFileExists = true;
            dlg.CheckPathExists = true;
            dlg.DefaultExt = ".xml"; //default extension
            dlg.Title = "Select settings file";
            dlg.Filter = "XML Files|*.xml";
            dlg.Multiselect = false;
            CwXML xml = new CwXML();
            CwXML.CodewordSettingsTemplate cst=new CwXML.CodewordSettingsTemplate();

            //the user clicked cancel
            if (dlg.ShowDialog() != DialogResult.OK)
                return;

            string filename = dlg.FileName;

            try
            {
                cst=xml.LoadSettingsXML(filename);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                return;
            }

            //we successfully deserialized the XML document, now load it into
            //the GUI form at the appropriate locations
            //
            int numInvalid = 0, numSuccess = 0, count = 0;

            //
            //loop through form element names stored in the settings document
            //and try to set them in the Window's form.
            //
            foreach (string elementName in cst.FormElementNames)
            {
                //if we looped through all tab pages and didnt find this element name,
                //it must be deprecated - store for error msg later
                if (!((bool)CrawlTabPages("SetFormValue", elementName, cst.FormElementValues[count])))
                    numInvalid++;
                else
                    numSuccess++;
                count++;
            }

            MessageBox.Show("Successfully loaded " + numSuccess + " settings!\n\nThere were " + numInvalid + " invalid setting items.");
        }

        //
        //Allows the user to select a template file that represents predefined file, registry,
        //and memory signatures for a given piece of malware
        //
        private void loadSignatureTemplateToolStripMenuItem_Click(object sender, EventArgs e)
        {
            int numRegImported = 0;
            int numRegGuidImported = 0;
            int numFileImported = 0;
            int numMemoryImported = 0;
            int numDuplicatesIgnored = 0;
            int numErrorSkipped = 0;

            //-----------------------------------------------
            //              DETERMINE IMPORT FILENAME
            //-----------------------------------------------
            //show browse dialog to select file
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.CheckFileExists = true;
            dlg.CheckPathExists = true;
            dlg.DefaultExt = ".xml"; //default extension
            dlg.Title = "Select signature template file";
            dlg.Filter = "XML Files|*.xml";
            dlg.Multiselect = true;

            //the user clicked cancel
            if (dlg.ShowDialog() != DialogResult.OK)
                return;

            int filecount = dlg.FileNames.Length;
            CwXML.CodewordSignatureTemplate cwt = new CwXML.CodewordSignatureTemplate();
            CwXML xml = new CwXML();

            //
            //loop through list of filenames selected and deserialize each XML
            //document into an instantation of the CwTemplate class
            //
            foreach (string filename in dlg.FileNames)
            {
                //deserialize the data stored in this signature file
                try
                {
                    cwt = xml.ImportSignatureTemplate(filename);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message);
                    return;
                }

                //we successfully deserialized the XML document, now load it into
                //the GUI form at the appropriate locations
                CwXML.RegistrySignature[] regSigs = cwt.RegistrySignatures;
                CwXML.RegistryGuidSignature[] regGuidSigs = cwt.RegistryGuidSignatures;
                CwXML.FileSignature[] fileSigs = cwt.FileSignatures;
                CwXML.MemorySignature[] memSigs = cwt.MemorySignatures;

                //REG sigs
                foreach (CwXML.RegistrySignature rs in regSigs)
                {
                    ListViewItem lvi = new ListViewItem(new string[] { rs.KeyName, rs.ValueName, rs.ValueData, rs.ChangeValueData, rs.Action });

                    if (RegistrySignatures_Listview.Items.Contains(lvi))
                    {
                        numDuplicatesIgnored++;
                        continue;
                    }
                    RegistrySignatures_Listview.Items.Add(lvi);
                    numRegImported++;
                }
                //REG GUID sigs
                foreach (CwXML.RegistryGuidSignature rsg in regGuidSigs)
                {
                    ListViewItem lvi = new ListViewItem(new string[] { rsg.GuidValue, rsg.GuidType });
                    if (RegistryGuidSignatures_Listview.Items.Contains(lvi))
                    {
                        numDuplicatesIgnored++;
                        continue;
                    }
                    RegistryGuidSignatures_Listview.Items.Add(lvi);
                    numRegGuidImported++;
                }
                //FILE sigs
                foreach (CwXML.FileSignature fs in fileSigs)
                {
                    ListViewItem lvi = new ListViewItem(new string[] { fs.FileName, fs.FileHash, fs.FileHashType, fs.FileSize.ToString(), fs.FilePEHeaderSignature, fs.Action });
                    if (FileSignatures_Listview.Items.Contains(lvi))
                    {
                        numDuplicatesIgnored++;
                        continue;
                    }
                    FileSignatures_Listview.Items.Add(lvi);
                    numFileImported++;
                }
                //MEM sigs
                foreach (CwXML.MemorySignature ms in memSigs)
                {
                    ListViewItem lvi = new ListViewItem(new string[] { ms.ProcessName, ms.Keywords, ms.Action });
                    if (MemorySignatures_Listview.Items.Contains(lvi))
                    {
                        numDuplicatesIgnored++;
                        continue;
                    }
                    MemorySignatures_Listview.Items.Add(lvi);
                    numMemoryImported++;
                }
            }

            MessageBox.Show("Successfully imported signatures from " + filecount + " files!\n\nSignatures imported:\nRegistry:  " + numRegImported + "\nRegistry GUID:  " + numRegGuidImported + "\nFile:  " + numFileImported + "\nMemory:  " + numMemoryImported + "\n\nDuplicates ignored:  " + numDuplicatesIgnored + "\nSkipped due to errors:  " + numErrorSkipped);
        }

        private void allToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //-----------------------------------------------
            //                  VALIDATION
            //-----------------------------------------------
            if (NoSignatures())
            {
                MessageBox.Show("There are no signatures to export!  Please add at least one registry, file or memory signature.");
                return;
            }

            //-----------------------------------------------
            //              DETERMINE EXPORT FILENAME
            //-----------------------------------------------
            string filename = GetSignatureExportFilename();
            if (filename == null)
                return;

            //-----------------------------------------------
            //            GENERATE SERIALIZABLE
            //              DATA STRUCTURES
            //-----------------------------------------------
            CwXML.RegistryGuidSignature[] rsg = GetAllRegistryGuidSignatures();
            CwXML.RegistrySignature[] rs = GetAllRegistrySignatures();
            CwXML.FileSignature[] fs = GetAllFileSignatures();
            CwXML.MemorySignature[] ms = GetAllMemorySignatures();

            //-----------------------------------------------
            //            SERIALIZE THE OBJECTS TO XML
            //-----------------------------------------------
            CwXML.ExportSignatureTemplate(filename,rsg, rs, fs, ms);
        }

        private void registryToolStripMenuItem_Click(object sender, EventArgs e)
        {
            int numRegSigs = RegistrySignatures_Listview.Items.Count;

            if (numRegSigs == 0)
            {
                MessageBox.Show("There are no registry signatures to export!");
                return ;
            }

            string filename = GetSignatureExportFilename();
            if (filename == null)
                return;

            CwXML.RegistryGuidSignature[] rsg = GetAllRegistryGuidSignatures();
            CwXML.RegistrySignature[] rs = GetAllRegistrySignatures();
            CwXML.ExportSignatureTemplate(filename, rsg, rs, null, null);
        }

        private void fileToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            int numFileSigs = FileSignatures_Listview.Items.Count;

            if (numFileSigs == 0)
            {
                MessageBox.Show("There are no file signatures to export!");
                return;
            }

            string filename = GetSignatureExportFilename();
            if (filename == null)
                return;

            CwXML.FileSignature[] fs = GetAllFileSignatures();
            CwXML.ExportSignatureTemplate(filename, null, null, fs, null);
        }

        private void memoryToolStripMenuItem_Click(object sender, EventArgs e)
        {
            int numMemSigs = MemorySignatures_Listview.Items.Count;

            if (numMemSigs == 0)
            {
                MessageBox.Show("There are no memory signatures to export!");
                return;
            }

            string filename = GetSignatureExportFilename();
            if (filename == null)
                return;

            CwXML.MemorySignature[] ms = GetAllMemorySignatures();
            CwXML.ExportSignatureTemplate(filename, null, null, null, ms);
        }

        private CwXML.RegistryGuidSignature[] GetAllRegistryGuidSignatures()
        {
            int numRegGuidSigs = RegistryGuidSignatures_Listview.Items.Count;
            CwXML.RegistryGuidSignature[] rsg = new CwXML.RegistryGuidSignature[numRegGuidSigs];
            for (int i= 0; i < numRegGuidSigs; i++)
            {
                rsg[i] = new CwXML.RegistryGuidSignature();
                rsg[i].GuidValue = RegistryGuidSignatures_Listview.Items[i].SubItems[0].Text;
                rsg[i].GuidType = RegistryGuidSignatures_Listview.Items[i].SubItems[1].Text;
            }

            return rsg;
        }

        private CwXML.RegistrySignature[] GetAllRegistrySignatures()
        {
            int numRegSigs = RegistrySignatures_Listview.Items.Count;
            CwXML.RegistrySignature[] rs = new CwXML.RegistrySignature[numRegSigs];
            for (int i = 0; i < numRegSigs; i++)
            {
                rs[i] = new CwXML.RegistrySignature();
                rs[i].KeyName = RegistrySignatures_Listview.Items[i].SubItems[0].Text.ToString();
                rs[i].ValueName = RegistrySignatures_Listview.Items[i].SubItems[1].Text.ToString();
                rs[i].ValueData = RegistrySignatures_Listview.Items[i].SubItems[2].Text.ToString();
                rs[i].ChangeValueData = RegistrySignatures_Listview.Items[i].SubItems[3].Text.ToString();
                rs[i].Action = RegistrySignatures_Listview.Items[i].SubItems[4].Text;
            }

            return rs;
        }

        private CwXML.FileSignature[] GetAllFileSignatures()
        {
            int numFileSigs = FileSignatures_Listview.Items.Count;
            CwXML.FileSignature[] fs = new CwXML.FileSignature[numFileSigs];

            //FILE sigs
            for (int i = 0; i < numFileSigs; i++)
            {
                fs[i] = new CwXML.FileSignature();
                fs[i].FileName = FileSignatures_Listview.Items[i].SubItems[0].Text;
                fs[i].FileHash = FileSignatures_Listview.Items[i].SubItems[1].Text;
                fs[i].FileHashType = FileSignatures_Listview.Items[i].SubItems[2].Text;
                long sz=0;
                long.TryParse(FileSignatures_Listview.Items[i].SubItems[3].Text, out sz);
                fs[i].FileSize = sz.ToString();
                fs[i].FilePEHeaderSignature = FileSignatures_Listview.Items[i].SubItems[4].Text;
                fs[i].Action = FileSignatures_Listview.Items[i].SubItems[5].Text;
            }

            return fs;
        }

        private CwXML.MemorySignature[] GetAllMemorySignatures()
        {
            int numMemSigs = MemorySignatures_Listview.Items.Count;
            CwXML.MemorySignature[] ms = new CwXML.MemorySignature[numMemSigs];
            for (int i = 0; i < numMemSigs; i++)
            {
                ms[i] = new CwXML.MemorySignature();
                ms[i].ProcessName = MemorySignatures_Listview.Items[i].SubItems[0].Text;
                ms[i].Keywords = MemorySignatures_Listview.Items[i].SubItems[1].Text;
                ms[i].Action = MemorySignatures_Listview.Items[i].SubItems[2].Text;
            }

            return ms;
        }

        private void Button_ScanLocalHost_Click(object sender, EventArgs e)
        {
            //dont even proceed if this host is 64-bit
            if (CwAgent.Win32Helper.Is64bit())
            {
                MessageBox.Show("This machine has a 64-bit operating system, which Codeword currently does not support.");
                return;
            }
        }

        #endregion


        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new CwAdminConsole());
        }

        private void Option_No_Dotnet_CheckedChanged(object sender, EventArgs e)
        {
            if (Stealth_No_Dotnet.Checked)
                MessageBox.Show("WARNING!!\n\nThis application requires .NET to be installed on the target hosts.\n\nYou have chosen not to check if .NET framework is installed.  Only do this if you are absolutely certain all of the target hosts already have the framework installed.");
        }

        private void Advanced_File_Browse_Button_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.CheckFileExists = true;
            ofd.InitialDirectory = "%SYSTEM_ROOT%";
            ofd.Multiselect = false;
            ofd.Title = "Choose file...";
            if (ofd.ShowDialog() == DialogResult.OK)
                Advanced_3rdPartyApp_Filename.Text = ofd.FileName;
        }

        private void CwAdminConsole_Shown(object sender, EventArgs e)
        {
            //make sure no menu items are selected
            MainMenuTreeview.SelectedNode = null;
            MainMenuTreeview.Refresh();
            GeneralSettingsTabContainer.Visible = false;
            GeneralSettingsTabContainer.Refresh();
            this.Refresh();
        }

        //
        //display the appropriate tab container based on the treenode selected from the menu
        //
        private void MainMenuTreeview_NodeMouseClick(object sender, TreeNodeMouseClickEventArgs e)
        {
            string SelectedNodeName;

            //first, hide all tab containers
            GeneralSettingsTabContainer.Visible = false;
            SignaturesTabContainer.Visible = false;
            HeuristicsTabContainer.Visible = false;

            if (e.Node == null)
                return;

            //next, hide welcome image and text
            MainLogoTextbox.Visible = false;

            //
            //if it is a CHILD NODE, use the parent's text label for deciding what
            //tab container and selected tab page to show...if it is a PARENT NODE, 
            //only show the tab container, do not adjust selected index..
            //
            if (e.Node.GetNodeCount(false) == 0)
                SelectedNodeName = e.Node.Parent.Text;
            else
                SelectedNodeName = e.Node.Text;

            //
            //Show the GENERAL SETTINGS tab container
            //
            if (SelectedNodeName == "Agent Settings")
            {
                GeneralSettingsTabContainer.Visible = true;
                GeneralSettingsTabContainer.SelectedIndex = e.Node.Index;
                GeneralSettingsTabContainer.Refresh();
            }
            //
            //Show the SIGNATURES tab container
            //
            else if (SelectedNodeName == "Signatures")
            {
                SignaturesTabContainer.Visible = true;
                SignaturesTabContainer.SelectedIndex = e.Node.Index;
                SignaturesTabContainer.Refresh();
            }
            //
            //Show the USER MODE INTEGRITY tab container
            //
            else if (SelectedNodeName == "Heuristics")
            {
                HeuristicsTabContainer.Visible = true;
                HeuristicsTabContainer.SelectedIndex = e.Node.Index;
                HeuristicsTabContainer.Refresh();
            }
            //
            //either a root node with only child-root nodes was selected,
            //or this is the call just after the app loads and no node
            //has been selected.  in either case, show welcome stuff.
            //
            else
            {
                //next, hide welcome image and text
                MainLogoTextbox.Visible = true;
            }
        }

        private void AgentRandomizeListeningPort_CheckedChanged(object sender, EventArgs e)
        {
            if (AgentRandomizeListeningPort.Checked)
                AgentListeningPort.Enabled = false;
            else
                AgentListeningPort.Enabled = true;
        }

        private void StartupEnterpriseMode_CheckedChanged(object sender, EventArgs e)
        {
            ConfigureFormForStartupMode("StartupEnterpriseMode");
        }

        private void StartupRemoteControlMode_CheckedChanged(object sender, EventArgs e)
        {
            ConfigureFormForStartupMode("StartupRemoteControlMode");
        }

        private void StartupFireAndForgetMode_CheckedChanged(object sender, EventArgs e)
        {
            ConfigureFormForStartupMode("StartupFireAndForgetMode");
        }

        private void AgentSelfProtectionRunKernelHeuristicsFirst_CheckedChanged(object sender, EventArgs e)
        {
            //force a startup mode of StartupRemoteControlMode
            if (AgentSelfProtectionRunKernelHeuristicsFirst.Checked)
            {
                StartupFireAndForgetMode.Checked = true;
                //programmatically checking this radio button will cause this to fire:
                //ConfigureFormForStartupMode("StartupFireAndForgetMode");
            }
            else
            {
                StartupEnterpriseMode.Checked = true;
                //reset to default, Enterprise Mode
                //
                //programmatically checking this radio button will cause this to fire:
                //ConfigureFormForStartupMode("StartupEnterpriseMode");
            }
        }

        private void ConfigureFormForStartupMode(string RadioButtonNameChecked)
        {
            //------------------------------
            //  StartupFireAndForgetMode
            //------------------------------
            if (RadioButtonNameChecked == "StartupFireAndForgetMode")
            {
                if (StartupFireAndForgetMode.Checked)
                {
                    //disable listening port options b/c the agent will not listen
                    AgentListeningPort.Enabled = false;
                    AgentRandomizeListeningPort.Checked = false;
                    AgentRandomizeListeningPort.Enabled = false;

                    //set persistence to RUN ONCE
                    PersistenceRunOnce.Checked = true;
                    PersistenceInstallAsService.Checked = false;
                    PersistenceInstallAsService.Enabled = false;
                    AgentServiceName.Text = "";
                    AgentServiceName.Enabled = false;

                    //toggle the reporting panels appropriately
                    ToggleReportingPanels(true, null);
                    //have to manually set the checked state of Reporting_EnableAutoReporting 
                    //since we turned off the AutoCheck property!
                    Reporting_EnableAutoReporting.Checked = true;
                }
                else
                {
                    //enable listening port options
                    AgentListeningPort.Enabled = true;
                    AgentRandomizeListeningPort.Enabled = true;

                    //restore persistence to Start Service
                    PersistenceRunOnce.Checked = false;
                    PersistenceInstallAsService.Checked = true;
                    PersistenceInstallAsService.Enabled = true;
                    AgentServiceName.Text = "CwAgent";
                    AgentServiceName.Enabled = true;

                    //toggle the reporting panels appropriately
                    ToggleReportingPanels(false, null);
                    //have to manually set the checked state of Reporting_EnableAutoReporting 
                    //since we turned off the AutoCheck property!
                    Reporting_EnableAutoReporting.Checked = false;
                }
            }
            //------------------------------
            //  StartupEnterpriseMode
            //------------------------------
            else if (RadioButtonNameChecked == "StartupEnterpriseMode")
            {
                //toggle all reporting
                if (StartupEnterpriseMode.Checked)
                {
                    ToggleReportingPanels(false, null);
                    //have to manually set the checked state of Reporting_EnableAutoReporting 
                    //since we turned off the AutoCheck property!
                    Reporting_EnableAutoReporting.Checked = false;
                }
                else
                {
                    ToggleReportingPanels(true, null);
                    //have to manually set the checked state of Reporting_EnableAutoReporting 
                    //since we turned off the AutoCheck property!
                    Reporting_EnableAutoReporting.Checked = true;
                }
            }
            //------------------------------
            //  StartupRemoteControlMode
            //------------------------------
            else if (RadioButtonNameChecked == "StartupRemoteControlMode")
            {
                //toggle reporting panel
                if (StartupRemoteControlMode.Checked)
                {
                    ToggleReportingPanels(false, null);
                    //have to manually set the checked state of Reporting_EnableAutoReporting 
                    //since we turned off the AutoCheck property!
                    Reporting_EnableAutoReporting.Checked = false;
                }
                else
                {
                    ToggleReportingPanels(true, null);
                    //have to manually set the checked state of Reporting_EnableAutoReporting 
                    //since we turned off the AutoCheck property!
                    Reporting_EnableAutoReporting.Checked = true;
                }
            }
        }

        private void CwAdminConsole_Load(object sender, EventArgs e)
        {
            
        }

        private void RetrieveChildFormDataCallback(string elementName, string elementValue)
        {
            if (elementName == "AC_CRED_PFX_FILENAME")
                AC_CRED_PFX_FILENAME = elementValue;
            else if (elementName == "AC_CRED_PFX_PASSWORD")
                AC_CRED_PFX_PASSWORD = elementValue;
            else if (elementName == "AC_CRED_IGNORE_REMOTE_CERT_NAME_MISMATCH")
                AC_CRED_IGNORE_REMOTE_CERT_NAME_MISMATCH = bool.Parse(elementValue);
            else if (elementName == "AC_CRED_IGNORE_REMOTE_CERT_CHAIN_ERRORS")
                AC_CRED_IGNORE_REMOTE_CERT_CHAIN_ERRORS = bool.Parse(elementValue);
        }

        private void SetAdminConsoleCredentialsButton_Click(object sender, EventArgs e)
        {
            ArrayList parms = new ArrayList();

            //only pass parameters if we've opened this window before (indicating the values are meaningful)
            if (numCredButtonClicks > 0)
            {
                //setup parameters to pass to the child window to prefill its form
                parms.Add(AC_CRED_PFX_FILENAME);
                parms.Add(AC_CRED_PFX_PASSWORD);
                parms.Add(AC_CRED_IGNORE_REMOTE_CERT_NAME_MISMATCH);
                parms.Add(AC_CRED_IGNORE_REMOTE_CERT_CHAIN_ERRORS);
            }

            CwAdminCredentialsWindow credWin = new CwAdminCredentialsWindow(parms);

            //register a callback so we are notified when the user changes the form element values
            credWin.SetParameterValueCallback = new CwAdminCredentialsWindow.SetParameterValueDelegate(RetrieveChildFormDataCallback);
            credWin.ShowDialog();
        }

        private void ConnectToAgentIP_TextChanged(object sender, EventArgs e)
        {
            int i = 0;

            if (ConnectToAgentIP.Text == "" || !IsValidIP(ConnectToAgentIP.Text) || !int.TryParse(ConnectToAgentPort.Text, out i))
                ConnectAgentButton.Enabled = false;
            else
                ConnectAgentButton.Enabled = true;
        }

        private void RegistrySignatures_NewAction_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (RegistrySignatures_NewAction.SelectedItem != null)
            {
                if (RegistrySignatures_NewAction.SelectedItem.ToString() == "Change...")
                    RegistrySignatures_ChangeValueData.Enabled = true;
                else
                    RegistrySignatures_ChangeValueData.Enabled = false;
            }
        }

        private void AgentResults_RegistryListview_ItemCheck(object sender, ItemCheckEventArgs e)
        {
            try
            {
                //if the item has already been mitigated, dont allow it to be checked
                if (AgentResults_RegistryListview.Items[e.Index].SubItems[6].Text == "True")
                {
                    MessageBox.Show("That item has already been mitigated.  It is no longer available for further tasks.");
                    e.NewValue = CheckState.Unchecked;
                }
            }
            catch (Exception) { }
        }

        private void AgentResults_FileListview_ItemCheck(object sender, ItemCheckEventArgs e)
        {
            try
            {
                //if the item has already been mitigated, dont allow it to be checked
                if (AgentResults_FileListview.Items[e.Index].SubItems[9].Text == "True")
                {
                    MessageBox.Show("That item has already been mitigated.  It is no longer available for further tasks.");
                    e.NewValue = CheckState.Unchecked;
                }
            }
            catch (Exception) { }
        }

        private void AgentResults_MemoryListview_ItemCheck(object sender, ItemCheckEventArgs e)
        {
            try
            {
                //if the item has already been mitigated, dont allow it to be checked
                if (AgentResults_MemoryListview.Items[e.Index].SubItems[8].Text == "True")
                {
                    MessageBox.Show("That item has already been mitigated.  It is no longer available for further tasks.");
                    e.NewValue = CheckState.Unchecked;
                }
            }
            catch (Exception) { }
        }

        private void AddDriverButton_Click(object sender, EventArgs e)
        {
            if (AddDriverModule.Text == "" || AddDriverDevice.Text == "")
            {
                MessageBox.Show("Both a driver module name and device name are required.");
                return;
            }
            /*
            Regex filenameRegex = new Regex("^([_a-zA-Z0-9]+\\.[_a-zA-Z0-9]{0,3})$");
            Regex deviceNameRegex = new Regex("^(\\Device\\[_a-zA-Z0-9]+$");

            if (!filenameRegex.Match(AddDriverModule.Text).Success)
            {
                MessageBox.Show("Invalid module name specified.");
                return;
            }
            if (!deviceNameRegex.Match(AddDriverDevice.Text).Success)
            {
                MessageBox.Show("Invalid device name specified.");
                return;
            }
            */
            ListViewItem lvi = new ListViewItem(new string[] { AddDriverModule.Text, AddDriverDevice.Text });
            AddDriverListview.Items.Add(lvi);
        }
    }
}