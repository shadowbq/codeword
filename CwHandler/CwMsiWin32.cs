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
using System.Text;
using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace CwHandler
{
    public static class CwMsiWin32
    {
        public static string GetLastError32()
        {
            uint errcode = GetLastError();
            IntPtr lpBuffer = Marshal.AllocHGlobal(4096);
            FormatMessage(0x00001000, (IntPtr)0, errcode, 0, lpBuffer, 1024, (IntPtr)0);
            string ret = Marshal.PtrToStringAnsi(lpBuffer);
            Marshal.FreeHGlobal(lpBuffer);
            return ret;
        }

        ////////////////////////////////////////////////////////////////////////////////////////
        //
        //          Win32 API unmanaged DLL imports
        //
        //
        ////////////////////////////////////////////////////////////////////////////////////////
        [DllImportAttribute("kernel32.dll", EntryPoint = "GetLastError")]
        public static extern uint GetLastError();

        [DllImportAttribute("kernel32.dll", EntryPoint = "FormatMessage")]
        public static extern uint FormatMessage(uint dwFlags, [InAttribute()] System.IntPtr lpSource, uint dwMessageId, uint dwLanguageId, [OutAttribute()] IntPtr lpBuffer, uint nSize, System.IntPtr Arguments);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint MsiDatabaseOpenViewW(IntPtr hDatabase, [MarshalAs(UnmanagedType.LPWStr)] string szQuery, out IntPtr phView);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint MsiViewExecute(IntPtr hView, IntPtr hRecord);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint MsiViewFetch(IntPtr hView, out IntPtr phRecord);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint MsiRecordGetStringW(IntPtr hRecord, uint iField, IntPtr szValueBuf, ref uint pcchValueBuf);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint MsiRecordSetStringW(IntPtr hRecord, uint iField, [MarshalAsAttribute(UnmanagedType.LPTStr)] string szValue);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr MsiCreateRecord(uint cParams);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint MsiViewModify(IntPtr hView, int eModifyMode, IntPtr hRecord);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint MsiOpenDatabaseW([MarshalAs(UnmanagedType.LPWStr)] string szDatabasePath, uint szPersist, out IntPtr phDatabase);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint MsiGetSummaryInformationW(IntPtr hDatabase, [MarshalAs(UnmanagedType.LPWStr)] string szDatabasePath, uint uiUpdateCount, out IntPtr phSummaryInfo);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint MsiSummaryInfoSetPropertyW(IntPtr hSummaryInfo, uint uiProperty, uint uiDataType, int iValue, IntPtr pftValue, [MarshalAs(UnmanagedType.LPWStr)] string szValue);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint MsiSummaryInfoPersist(IntPtr hSummaryInfo);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint MsiDatabaseCommit(IntPtr hDatabase);

        [DllImport("msi.dll", CharSet = CharSet.Unicode)]
        internal static extern uint MsiCloseHandle(IntPtr hSummaryInfo);

        [DllImport("msi.dll")]
        internal static extern uint MsiRecordGetFieldCount(IntPtr hRecord);

        [DllImport("msi.dll")]
        internal static extern uint MsiViewGetColumnInfo(IntPtr hView, uint eColumnInfoFlags, out IntPtr phRecord);

        [DllImport("msi.dll")]
        internal static extern uint MsiRecordGetInteger(IntPtr hRecord, uint iField);

        [DllImport("msi.dll")]
        internal static extern uint MsiRecordSetInteger(IntPtr hRecord, uint iField, int iValue);

        [DllImport("msi.dll")]
        internal static extern IntPtr MsiGetLastErrorRecord();

        [DllImport("msi.dll")]
        internal static extern uint MsiFormatRecord([InAttribute()] IntPtr hInstall, [InAttribute()] IntPtr hRecord, [OutAttribute()] IntPtr szResultBuf, ref uint pcchResultBuf);

        [DllImport("msi.dll")]
        internal static extern uint MsiRecordSetStreamW(IntPtr hRecord, uint iField, [MarshalAsAttribute(UnmanagedType.LPTStr)] string szFilePath);

        [DllImport("msi.dll")]
        internal static extern uint MsiOpenPackage([MarshalAs(UnmanagedType.LPWStr)] string szDatabasePath, IntPtr hProduct);

        [DllImport("msi.dll")]
        internal static extern uint MsiSetProperty(IntPtr hInstall, [MarshalAs(UnmanagedType.LPWStr)] string szName, [MarshalAs(UnmanagedType.LPWStr)] string szValue);

        ////////////////////////////////////////////////////////////////////////////////////////
        //
        //          private data
        //
        //
        ////////////////////////////////////////////////////////////////////////////////////////

        internal const ushort PROCESSOR_ARCHITECTURE_INTEL = 0;
        internal const ushort PROCESSOR_ARCHITECTURE_IA64 = 6;
        internal const ushort PROCESSOR_ARCHITECTURE_AMD64 = 9;
        internal const ushort PROCESSOR_ARCHITECTURE_UNKNOWN = 0xFFFF;

        internal const uint MSIDBOPEN_READONLY = 0;      // database open read-only, no persistent changes
        internal const uint MSIDBOPEN_TRANSACT = 1;      // database read/write in transaction mode
        internal const uint MSIDBOPEN_DIRECT = 2;        // database direct read/write without transaction
        internal const uint MSIDBOPEN_CREATE = 3;        // create new database, transact mode read/write
        internal const uint MSIDBOPEN_CREATEDIRECT = 4;  // create new database, direct mode read/write

        internal const uint MSICOLINFO_NAMES = 0;
        internal const uint MSICOLINFO_TYPES = 1;

        internal const uint MSI_NULL_INTEGER = 0x80000000;

        internal const uint PID_TEMPLATE = 7;
        internal const uint VT_LPSTR = 30;

        internal const uint MB_ABORTRETRYIGNORE = 0x00000002;
        internal const uint MB_OK = 0x00000000;
        internal const uint MB_OKCANCEL = 0x00000001;
        internal const uint MB_RETRYCANCEL = 0x00000005;
        internal const uint MB_YESNO = 0x00000004;
        internal const uint MB_YESNOCANCEL = 0x00000003;

        internal const uint MB_ICONEXCLAMATION = 0x00000030;
        internal const uint MB_ICONWARNING = MB_ICONEXCLAMATION;
        internal const uint MB_ICONINFORMATION = MB_ICONASTERISK;
        internal const uint MB_ICONASTERISK = 0x00000040;
        internal const uint MB_ICONQUESTION = 0x00000020;
        internal const uint MB_ICONSTOP = MB_ICONHAND;
        internal const uint MB_ICONERROR = MB_ICONHAND;
        internal const uint MB_ICONHAND = 0x00000010;

        internal const uint MB_DEFBUTTON1 = 0x00000000;
        internal const uint MB_DEFBUTTON2 = 0x00000100;
        internal const uint MB_DEFBUTTON3 = 0x00000200;
        internal const uint MB_DEFBUTTON4 = 0x00000300;

        internal const uint MB_TYPEMASK = 0x0000000F;
        internal const uint MB_ICONMASK = 0x000000F0;
        internal const uint MB_DEFMASK = 0x00000F00;
        internal const uint MB_MODEMASK = 0x00003000;
        internal const uint MB_MISCMASK = 0x0000C000;

        internal const ushort LANG_NEUTRAL = 0;

        internal const int IDOK = 1;
        internal const int IDCANCEL = 2;

        internal const uint INSTALLMESSAGE_FATALEXIT = 0x00000000;          // premature termination, possibly fatal OOM
        internal const uint INSTALLMESSAGE_ERROR = 0x01000000;              // formatted error message
        internal const uint INSTALLMESSAGE_WARNING = 0x02000000;            // formatted warning message
        internal const uint INSTALLMESSAGE_USER = 0x03000000;               // user request message
        internal const uint INSTALLMESSAGE_INFO = 0x04000000;               // informative message for log
        internal const uint INSTALLMESSAGE_FILESINUSE = 0x05000000;         // list of files in use that need to be replaced
        internal const uint INSTALLMESSAGE_RESOLVESOURCE = 0x06000000;      // request to determine a valid source location
        internal const uint INSTALLMESSAGE_OUTOFDISKSPACE = 0x07000000;     // insufficient disk space message
        internal const uint INSTALLMESSAGE_ACTIONSTART = 0x08000000;        // start of action: action name & description
        internal const uint INSTALLMESSAGE_ACTIONDATA = 0x09000000;         // formatted data associated with individual action item
        internal const uint INSTALLMESSAGE_PROGRESS = 0x0A000000;           // progress gauge info: units so far, total
        internal const uint INSTALLMESSAGE_COMMONDATA = 0x0B000000;         // product info for dialog: language Id, dialog caption
        internal const uint INSTALLMESSAGE_INITIALIZE = 0x0C000000;         // sent prior to UI initialization, no string data
        internal const uint INSTALLMESSAGE_TERMINATE = 0x0D000000;          // sent after UI termination, no string data
        internal const uint INSTALLMESSAGE_SHOWDIALOG = 0x0E000000;         // sent prior to display or authored dialog or wizard

        internal const uint INSTALLLOGMODE_FATALEXIT = ((uint)1 << (int)(INSTALLMESSAGE_FATALEXIT >> 24));
        internal const uint INSTALLLOGMODE_ERROR = ((uint)1 << (int)(INSTALLMESSAGE_ERROR >> 24));
        internal const uint INSTALLLOGMODE_WARNING = ((uint)1 << (int)(INSTALLMESSAGE_WARNING >> 24));
        internal const uint INSTALLLOGMODE_USER = ((uint)1 << (int)(INSTALLMESSAGE_USER >> 24));
        internal const uint INSTALLLOGMODE_INFO = ((uint)1 << (int)(INSTALLMESSAGE_INFO >> 24));
        internal const uint INSTALLLOGMODE_RESOLVESOURCE = ((uint)1 << (int)(INSTALLMESSAGE_RESOLVESOURCE >> 24));
        internal const uint INSTALLLOGMODE_OUTOFDISKSPACE = ((uint)1 << (int)(INSTALLMESSAGE_OUTOFDISKSPACE >> 24));
        internal const uint INSTALLLOGMODE_ACTIONSTART = ((uint)1 << (int)(INSTALLMESSAGE_ACTIONSTART >> 24));
        internal const uint INSTALLLOGMODE_ACTIONDATA = ((uint)1 << (int)(INSTALLMESSAGE_ACTIONDATA >> 24));
        internal const uint INSTALLLOGMODE_COMMONDATA = ((uint)1 << (int)(INSTALLMESSAGE_COMMONDATA >> 24));
        internal const uint INSTALLLOGMODE_PROPERTYDUMP = ((uint)1 << (int)(INSTALLMESSAGE_PROGRESS >> 24)); // log only
        internal const uint INSTALLLOGMODE_VERBOSE = ((uint)1 << (int)(INSTALLMESSAGE_INITIALIZE >> 24)); // log only
        internal const uint INSTALLLOGMODE_EXTRADEBUG = ((uint)1 << (int)(INSTALLMESSAGE_TERMINATE >> 24)); // log only
        internal const uint INSTALLLOGMODE_PROGRESS = ((uint)1 << (int)(INSTALLMESSAGE_PROGRESS >> 24)); // external handler only
        internal const uint INSTALLLOGMODE_INITIALIZE = ((uint)1 << (int)(INSTALLMESSAGE_INITIALIZE >> 24)); // external handler only
        internal const uint INSTALLLOGMODE_TERMINATE = ((uint)1 << (int)(INSTALLMESSAGE_TERMINATE >> 24)); // external handler only
        internal const uint INSTALLLOGMODE_SHOWDIALOG = ((uint)1 << (int)(INSTALLMESSAGE_SHOWDIALOG >> 24)); // external handler only

        internal const uint INSTALLUILEVEL_NOCHANGE = 0;           // UI level is unchanged
        internal const uint INSTALLUILEVEL_DEFAULT = 1;           // default UI is used
        internal const uint INSTALLUILEVEL_NONE = 2;           // completely silent installation
        internal const uint INSTALLUILEVEL_BASIC = 3;           // simple progress and error handling
        internal const uint INSTALLUILEVEL_REDUCED = 4;           // authored UI; wizard dialogs suppressed
        internal const uint INSTALLUILEVEL_FULL = 5;           // authored UI with wizards; progress; errors
        internal const uint INSTALLUILEVEL_ENDDIALOG = 0x80;    // display success/failure dialog at end of install
        internal const uint INSTALLUILEVEL_PROGRESSONLY = 0x40;    // display only progress dialog
        internal const uint INSTALLUILEVEL_HIDECANCEL = 0x20;    // do not display the cancel button in basic UI
        internal const uint INSTALLUILEVEL_SOURCERESONLY = 0x100;  // force display of source resolution even if quiet

        internal const int MSIMODIFY_SEEK = -1;             // reposition to current record primary key
        internal const int MSIMODIFY_REFRESH = 0;           // refetch current record data
        internal const int MSIMODIFY_INSERT = 1;            // insert new record, fails if matching key exists
        internal const int MSIMODIFY_UPDATE = 2;            // update existing non-key data of fetched record
        internal const int MSIMODIFY_ASSIGN = 3;            // insert record, replacing any existing record
        internal const int MSIMODIFY_REPLACE = 4;           // update record, delete old if primary key edit
        internal const int MSIMODIFY_MERGE = 5;             // fails if record with duplicate key not identical
        internal const int MSIMODIFY_DELETE = 6;            // remove row referenced by this record from table
        internal const int MSIMODIFY_INSERT_TEMPORARY = 7;  // insert a temporary record
        internal const int MSIMODIFY_VALIDATE = 8;          // validate a fetched record
        internal const int MSIMODIFY_VALIDATE_NEW = 9;      // validate a new record
        internal const int MSIMODIFY_VALIDATE_FIELD = 10;   // validate field(s) of an incomplete record
        internal const int MSIMODIFY_VALIDATE_DELETE = 11;  // validate before deleting record

        internal const uint FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100;
        internal const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x200;
        internal const uint FORMAT_MESSAGE_FROM_STRING = 0x400;
        internal const uint FORMAT_MESSAGE_FROM_HMODULE = 0x800;
        internal const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x1000;
        internal const uint FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x2000;

        internal const int MAX_PATH = 260;
        internal const uint SHGFP_TYPE_CURRENT = 0;
        internal const uint SHGFP_TYPE_DEFAULT = 1;

        internal const uint CSIDL_PROGRAM_FILES = 0x0026;  // C:\Program Files
        internal const uint CSIDL_FLAG_CREATE = 0x8000;    // new for Win2K, or this in to force creation of folder

        //error codes as defined in msi.h
        internal const uint ERROR_SUCCESS = 0;
        internal const uint ERROR_SUCCESS_REBOOT_REQUIRED = 3010;
        internal const uint ERROR_NO_MORE_ITEMS = 259;
        internal const uint ERROR_INSTALL_USEREXIT = 1602;  // User cancel installation.
        internal const uint ERROR_INSTALL_FAILURE = 1603; //Fatal error during installation.
        internal const uint ERROR_INSTALL_SUSPEND = 1604; // Installation suspended, incomplete.
        internal const uint ERROR_UNKNOWN_PRODUCT = 1605; // This action is only valid for products that are currently installed.
        internal const uint ERROR_UNKNOWN_FEATURE = 1606; // Feature ID not registered.
        internal const uint ERROR_UNKNOWN_COMPONENT = 1607; // Component ID not registered.
        internal const uint ERROR_UNKNOWN_PROPERTY = 1608; // Unknown property.
        internal const uint ERROR_INVALID_HANDLE_STATE = 1609; // Handle is in an invalid state.
        internal const uint ERROR_BAD_CONFIGURATION = 1610; // The configuration data for this product is corrupt.  Contact your support personnel.
        internal const uint ERROR_INDEX_ABSENT = 1611; // Component qualifier not present.
        internal const uint ERROR_INSTALL_SOURCE_ABSENT = 1612; // The installation source for this product is not available.  Verify that the source exists and that you can access it.
        internal const uint ERROR_PRODUCT_UNINSTALLED = 1614; // Product is uninstalled.
        internal const uint ERROR_BAD_QUERY_SYNTAX = 1615; // SQL query syntax invalid or unsupported.
        internal const uint ERROR_INVALID_FIELD = 1616; // Record field does not exist.
        internal const uint ERROR_INSTALL_SERVICE_FAILURE = 1601; // The Windows Installer Service could not be accessed. This can occur if the Windows Installer is not correctly installed. Contact your support personnel for assistance.
        internal const uint ERROR_INSTALL_PACKAGE_VERSION = 1613; // This installation package cannot be installed by the Windows Installer service.  You must install a Windows service pack that contains a newer version of the Windows Installer service.
        internal const uint ERROR_INSTALL_ALREADY_RUNNING = 1618; // Another program is being installed. Please wait until that installation is complete, and then try installing this software again.
        internal const uint ERROR_INSTALL_PACKAGE_OPEN_FAILED = 1619; // This installation package could not be opened.  Verify that the package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer package.
        internal const uint ERROR_INSTALL_PACKAGE_INVALID = 1620; // This installation package could not be opened.  Contact the application vendor to verify that this is a valid Windows Installer package.
        internal const uint ERROR_INSTALL_UI_FAILURE = 1621; // There was an error starting the Windows Installer service user interface.  Contact your support personnel.
        internal const uint ERROR_INSTALL_LOG_FAILURE = 1622; // Error opening installation log file.  Verify that the specified log file location exists and is writable.
        internal const uint ERROR_INSTALL_LANGUAGE_UNSUPPORTED = 1623; // This language of this installation package is not supported by your system.
        internal const uint ERROR_INSTALL_PACKAGE_REJECTED = 1625; // The system administrator has set policies to prevent this installation.
        internal const uint ERROR_FUNCTION_NOT_CALLED = 1626; // Function could not be executed.
        internal const uint ERROR_FUNCTION_FAILED = 1627; // Function failed during execution.
        internal const uint ERROR_INVALID_TABLE = 1628; // Invalid or unknown table specified.
        internal const uint ERROR_DATATYPE_MISMATCH = 1629; // Data supplied is of wrong type.
        internal const uint ERROR_UNSUPPORTED_TYPE = 1630; // Data of this type is not supported.
        internal const uint ERROR_CREATE_FAILED = 1631; // The Windows Installer service failed to start.  Contact your support personnel.
        internal const uint ERROR_INSTALL_TEMP_UNWRITABLE = 1632; // The Temp folder is on a drive that is full or is inaccessible. Free up space on the drive or verify that you have write permission on the Temp folder.
        internal const uint ERROR_INSTALL_PLATFORM_UNSUPPORTED = 1633; // This installation package is not supported by this processor type. Contact your product vendor.
        internal const uint ERROR_INSTALL_NOTUSED = 1634; // Component not used on this machine
        internal const uint ERROR_INSTALL_TRANSFORM_FAILURE = 1624; // Error applying transforms.  Verify that the specified transform paths are valid.
        internal const uint ERROR_PATCH_PACKAGE_OPEN_FAILED = 1635; // This patch package could not be opened.  Verify that the patch package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer patch package.
        internal const uint ERROR_PATCH_PACKAGE_INVALID = 1636; // This patch package could not be opened.  Contact the application vendor to verify that this is a valid Windows Installer patch package.
        internal const uint ERROR_PATCH_PACKAGE_UNSUPPORTED = 1637; // This patch package cannot be processed by the Windows Installer service.  You must install a Windows service pack that contains a newer version of the Windows Installer service.
        internal const uint ERROR_PRODUCT_VERSION = 1638; // Another version of this product is already installed.  Installation of this version cannot continue.  To configure or remove the existing version of this product, use Add/Remove Programs on the Control Panel.
        internal const uint ERROR_INVALID_COMMAND_LINE = 1639; // Invalid command line argument.  Consult the Windows Installer SDK for detailed command line help.
        internal const uint ERROR_INSTALL_REMOTE_DISALLOWED = 1640; // Only administrators have permission to add, remove, or configure server software during a Terminal services remote session. If you want to install or configure software on the server, contact your network administrator.
        internal const uint ERROR_SUCCESS_REBOOT_INITIATED = 1641; // The requested operation completed successfully.  The system will be restarted so the changes can take effect.
        internal const uint ERROR_PATCH_TARGET_NOT_FOUND = 1642; // The upgrade patch cannot be installed by the Windows Installer service because the program to be upgraded may be missing, or the upgrade patch may update a different version of the program. Verify that the program to be upgraded exists on your computer and that you have the correct upgrade patch.
        internal const uint ERROR_PATCH_PACKAGE_REJECTED = 1643; // The patch package is not permitted by software restriction policy.
        internal const uint ERROR_INSTALL_TRANSFORM_REJECTED = 1644; // One or more customizations are not permitted by software restriction policy.
        internal const uint ERROR_INSTALL_REMOTE_PROHIBITED = 1645; // The Windows Installer does not permit installation from a Remote Desktop Connection.
        internal const uint ERROR_PATCH_REMOVAL_UNSUPPORTED = 1646; // Uninstallation of the patch package is not supported.
        internal const uint ERROR_UNKNOWN_PATCH = 1647; // The patch is not applied to this product.
        internal const uint ERROR_PATCH_NO_SEQUENCE = 1648; // No valid sequence could be found for the set of patches.
        internal const uint ERROR_PATCH_REMOVAL_DISALLOWED = 1649; // Patch removal was disallowed by policy.
        internal const uint ERROR_INVALID_PATCH_XML = 1650; // The XML patch data is invalid.
        internal const uint ERROR_PATCH_MANAGED_ADVERTISED_PRODUCT = 1651; // Windows Installer does not permit patching of managed advertised products. At least one feature of the product must be installed before applying the patch.
        internal const uint ERROR_INSTALL_SERVICE_SAFEBOOT = 1652; // The Windows Installer service is not accessible in Safe Mode. Please try again when your computer is not in Safe Mode or you can use System Restore to return your machine to a previous good state.
    }
}
