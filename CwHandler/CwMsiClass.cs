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
using System.Text;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Windows.Forms;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using Microsoft.Win32;

namespace CwHandler
{
    public class CwMsiClass
    {
        public CwMsiClass()
        {
        }

        ////////////////////////////////////////////////////////////////////////////////////////
        //
        //                      MSICLASS FUNCTION DEFINITIONS
        //
        //
        ////////////////////////////////////////////////////////////////////////////////////////

        public void Start(BackgroundWorker workerThread, int pStep, DoWorkEventArgs workEventArgs)
        {
            string msiName = "Codeword_Installer.msi";
            int progress = 0;
            ArrayList FilesToAddToMsi = new ArrayList();
            string tmpCabName = "tmp.cab";

            //arguments passed in from GUI
            ArrayList args = (ArrayList)workEventArgs.Argument;
            bool skipDotNetFxAssembly = (bool)args[0];
            ArrayList x509certs = (ArrayList)args[1];
            ArrayList thirdPartyApps = (ArrayList)args[2];

            //add any x509 certificates now
            if (x509certs.Count > 0)
                foreach (string x in x509certs)
                    if (x != "")
                        FilesToAddToMsi.Add(x);

            //add any third party apps we should run post-scan
            if (thirdPartyApps.Count > 0)
                foreach (string filename in thirdPartyApps)
                    if (filename != "")
                        FilesToAddToMsi.Add(filename);

            //********************************************************
            //              EXTRACT DOTNETFX
            //********************************************************
            //while dotnetfx.exe (21mb) .NET 2.0 installer is included
            //in the Handler assembly itself, we do not always necessarily
            //write it to the generated MSI installer -- the only time
            //we DONT is when the user has checked the appropriate checkbox
            if (!skipDotNetFxAssembly)
            {
                try
                {
                    CwUtilitiesHelperClass.ExtractInternalResource("CwHandler.Resources.dotnetfx.exe", "dotnetfx.exe");
                }
                catch (Exception ex)
                {
                    workEventArgs.Result = false;
                    throw new Exception("The .NET 2.0 Framework installer file (dotnetfx.exe) was not found.  If you do not want to deploy .NET, please select the appropriate checkbox on the Options tab.\n\nError text:  '"+ex.Message);
                }

                FilesToAddToMsi.Add("dotnetfx.exe");
                workerThread.ReportProgress(25);
            }

            //********************************************************
            //              EXTRACT TEMPLATE MSI
            //********************************************************
            //rather than create an MSI from scratch, we will use and build
            //upon the MSI created in Visual Studio for our tool (CwInstaller.msi).
            //this MSI is stored in our own internal assembly (in memory) 
            //It initially contains:
            //      (1) CwAgent.exe - the actual program binary
            //      (2) Ionic.Utils.Zip.dll - zipping library needed
            //We will add to it:
            //      (1) CwAgentConfiguration.xml - the config file the admin just generated
            //      (2) dotnetfx.exe - .NET installer that setup.exe expects to be in same folder
            //      (3) any other files specified by the admin
            //  this MSI will wrap all these files into an installer database msi file
            //  which can be pushed out and executed on host systems using SMS or other distro system
            try
            {
                CwUtilitiesHelperClass.ExtractInternalResource("CwHandler.Resources.CwInstaller.msi", msiName);
            }
            catch (Exception ex)
            {
                workEventArgs.Result = false;
                throw new Exception(ex.Message);
            }

            workerThread.ReportProgress(25);

            //********************************************************
            //              SET MSI PROPERTIES
            //********************************************************
            //setup projects are retarded.  one example of this retardedness
            //is that the setup project will not install over older versions
            //unless the version number has changed (this is set in the Setup Project's properties in VS)
            //a hack , as described here http://www.tech-archive.net/Archive/DotNet/microsoft.public.dotnet.framework/2009-01/msg00161.html
            //is to set the REINSTALLMODE to "amus" ...?
            IntPtr hProduct = IntPtr.Zero;
            CwMsiWin32.MsiOpenPackage(msiName, hProduct);
            CwMsiWin32.MsiSetProperty(hProduct, "REINSTALLMODE", "amus");
            //also, set the product code to a new version, so taht when the MSI is installed,
            //it removes the other version.  See:  http://msdn.microsoft.com/en-us/library/aafz9hx4(VS.80).aspx
            CwMsiWin32.MsiSetProperty(hProduct, "PRODUCTCODE", Guid.NewGuid().ToString().ToUpper());
            CwMsiWin32.MsiCloseHandle(hProduct);

            //********************************************************
            //              EXTRACT CABARC UTILITY
            //********************************************************
            try
            {
                CwUtilitiesHelperClass.ExtractInternalResource("CwHandler.Resources.CABARC.EXE", "CABARC.EXE");
            }
            catch (Exception ex)
            {
                workEventArgs.Result = false;
                throw new Exception(ex.Message);
            }

            workerThread.ReportProgress(50);

            //manually add two files we know will exist at this point-
            //  -CwAgentConfiguration.xml - agent config
            //  -CwAgentSignatures.xml - signatures
            FilesToAddToMsi.Add("CwAgentConfiguration.xml");
            FilesToAddToMsi.Add("CwAgentSignatures.xml");

            progress = 50;
            int progressPerFile = progress / FilesToAddToMsi.Count;

            foreach (string filename in FilesToAddToMsi)
            {
                //process cancelation request?
                if (workerThread.CancellationPending)
                    workEventArgs.Cancel = true;
                else
                {
                    try
                    {
                        MsiAddFile(msiName, filename, tmpCabName);
                        progress += progressPerFile;
                        workerThread.ReportProgress(progress);
                    }
                    catch (Exception e)
                    {
                        MsiCleanUpOnFailure(tmpCabName);
                        workEventArgs.Result = false;
                        throw new Exception("Failed to add '" + filename + "' to the MSI database in '" + msiName + "'.  This MSI is most likely corrupt now.\n\n" + e.Message);
                    }
                }
            }

            return;
        }

        public void MsiCleanUp(string tmpCabName)
        {
            
            try
            {
                File.Delete(tmpCabName);
            }
            catch { };
        }

        public void MsiCleanUpOnFailure(string tmpCabName)
        {
            //delete the CAB creation utility
            try
            {
                //first delete files we KNOW will exist
                File.Delete("CABARC.EXE");
                File.Delete("CwAgentConfiguration.xml");

                //next try to delete ones that are more likely to throw an exception
                //because they werent created yet...
                File.Delete(tmpCabName);
            }
            catch { };
        }

        public void MsiThrowOnFailure(IntPtr hDatabase, uint retVal, string message)
        {
            if (retVal != CwMsiWin32.ERROR_SUCCESS)
            {
                IntPtr hView=IntPtr.Zero;
                IntPtr hRecord = IntPtr.Zero;
                hRecord = CwMsiWin32.MsiGetLastErrorRecord();  //try to get a handle to the error record
                string retString = message + "( SYSTEM ERROR CODE " + retVal + ").";

                if (hRecord != IntPtr.Zero)
                {
                    uint errCode = CwMsiWin32.MsiRecordGetInteger(hRecord, 1); //MSDN says field 1 is the err code
                    retString += "\n\nError Table data (code=" + errCode + ")";
                    IntPtr lpBuffer = Marshal.AllocHGlobal(4096);
                    uint pcchResultBuf = 4096;

                    //format the record string
                    CwMsiWin32.MsiFormatRecord(IntPtr.Zero, hRecord, lpBuffer, ref pcchResultBuf);

                    //add it to our main return string
                    retString += "'" + Marshal.PtrToStringAnsi(lpBuffer) + "'";

                    //cleanup duty
                    Marshal.FreeHGlobal(lpBuffer);
                    CwMsiWin32.MsiCloseHandle(hRecord); //discard the error record handle now that we have the code
                    hRecord = IntPtr.Zero;
                }

                throw new Exception(retString);
            }
        }

        public void MsiAddFile(string msiName, string absoluteFilename, string tmpCabName)
        {
            string tmpCabFullName = Environment.CurrentDirectory + "\\" + tmpCabName;
            //create a random cab key which will be used when referencing the cab internally
            Random r = new Random((int)DateTime.Now.Ticks);
            int rand = r.Next(65535); //valid cab ids are 0-65535
            string cabId = rand.ToString();
            uint retCode = 0;
            
            //Get some basic info on the requested file
            FileInfo f = new FileInfo(absoluteFilename);
            int filenameSize = (int)f.Length;
            string filenameExt = f.Extension;
            string basename = f.Name;

            //
            //*NOTE*:
            //
            //the overarching process to get the new file into our MSI is as follows:
            //
            //  1) generate a new CAB file using CABARC.EXE w/ file inside
            //  2) open the template MSI for editing
            //  3) add the necessary table entries for the new file
            //  4) add the binary data stream from CAB on disk to the internal MSI database
            //  5) close MSI and flush to disk
            //  6) cleanup any files
            //
            //see MSDN article:  http://msdn.microsoft.com/en-us/library/aa369279(VS.85).aspx
            //and this one: http://www.symantec.com/community/tip/3024/add-file-msi-using-orca

            //********************************************************
            //              GENERATE A NEW CAB FILE
            //********************************************************
            //this cab file will contain only our new file in compressed format.
            //it's necessary to create a new CAB, b/c only compressed cabs
            //can be added as an internal stream inside an MSI file.

            //launch a silent process to make the cab
            Process p = new Process();
            p.StartInfo.FileName = "CABARC.EXE";
            p.StartInfo.Arguments = " -i " + cabId + " n \"" + tmpCabName + "\" \"" + absoluteFilename+"\"";
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            p.Start();

            //wait for the process to finish
            while (!p.HasExited)
            {
                //chase tail...
            }

            //********************************************************
            //              EDIT MSI DATABASE
            //********************************************************
            //we will use unmanaged win32 API's in msi.dll to open the the MSI database for editing
            //we will add only fields necessary to include this file as a necessary install file

            //----------------------------------------------------------------------
            //1.  open the msi for editing
            //----------------------------------------------------------------------
            IntPtr hDatabase = (IntPtr)(0);
            retCode = CwMsiWin32.MsiOpenDatabaseW(msiName, CwMsiWin32.MSIDBOPEN_TRANSACT, out hDatabase);
            if (retCode != CwMsiWin32.ERROR_SUCCESS)
            {
                throw new Exception("Failed to open MSI database for file '" + msiName + "'.  Error:  " + CwMsiWin32.GetLastError32());
            }

            //----------------------------------------------------------------------
            //2.  Initialize our data tables for the new record in MSI database
            //----------------------------------------------------------------------
            
            Int16 maxDiskId = MsiGetMaxDiskIdFromMediaTable(hDatabase);
            Int16 lastSequenceNumber = MsiGetLastFileSequenceFromMediaTable(hDatabase, maxDiskId);

            //Component Table
            MsiComponentTable ComponentTable = new MsiComponentTable();
            ComponentTable.Component = "C__" + basename;
            ComponentTable.ComponentId = "";
            ComponentTable.Directory_ = "TARGETDIR";
            ComponentTable.Attributes = 0;
            ComponentTable.Condition = "";
            ComponentTable.KeyPath = basename;
            //Media Table
            MsiMediaTable MediaTable = new MsiMediaTable();
            MediaTable.DiskId = maxDiskId;
            MediaTable.DiskId++;
            MediaTable.LastSequence = lastSequenceNumber;
            MediaTable.LastSequence++;
            MediaTable.DiskPrompt = basename;
            MediaTable.Cabinet = "#_"+cabId;
            MediaTable.VolumeLabel="";
            MediaTable.Source="";
            //File Table
            MsiFileTable FileTable = new MsiFileTable();
            FileTable.File = basename;
            FileTable.Component_ = "C__" + basename;
            FileTable.FileName = basename.Substring(0, 6).ToUpper() + "~1." + filenameExt.ToUpper() + "|" + basename;
            FileTable.FileSize = filenameSize;
            FileTable.Version = "1.2.3.4";
            FileTable.Language = "0";
            FileTable.Attributes = 512;
            FileTable.Sequence = lastSequenceNumber;
            FileTable.Sequence++;
            //Feature Table
            MsiFeatureComponentsTable FeatureComponentsTable = new MsiFeatureComponentsTable();
            FeatureComponentsTable.Feature_ = "DefaultFeature";
            FeatureComponentsTable.Component_ = "C__" + basename;
            //MsiAssembly Table
            MsiAssemblyTable AssemblyTable = new MsiAssemblyTable();
            AssemblyTable.Component_ = "C__" + basename;
            AssemblyTable.Feature_ = "DefaultFeature";
            AssemblyTable.File_Manifest = basename;
            AssemblyTable.File_Application = basename;
            AssemblyTable.Attributes = 0;
            //MsiAssemblyName Table - 4 different tables
            MsiAssemblyNameTable AssemblyNameTable_Name = new MsiAssemblyNameTable();
            AssemblyNameTable_Name.Component_ = "C__" + basename;
            AssemblyNameTable_Name.Name = "Name";
            AssemblyNameTable_Name.Value = basename;
            MsiAssemblyNameTable AssemblyNameTable_Version = new MsiAssemblyNameTable();
            AssemblyNameTable_Version.Component_ = "C__" + basename;
            AssemblyNameTable_Version.Name = "Version";
            AssemblyNameTable_Version.Value = "1.2.3.4";
            MsiAssemblyNameTable AssemblyNameTable_Culture = new MsiAssemblyNameTable();
            AssemblyNameTable_Culture.Component_ = "C__" + basename;
            AssemblyNameTable_Culture.Name = "Culture";
            AssemblyNameTable_Culture.Value = "neutral";
            MsiAssemblyNameTable AssemblyNameTable_ProcessorArchitecture = new MsiAssemblyNameTable();
            AssemblyNameTable_ProcessorArchitecture.Component_ = "C__" + basename;
            AssemblyNameTable_ProcessorArchitecture.Name = "ProcessorArchitecture";
            AssemblyNameTable_ProcessorArchitecture.Value = "MSIL";

            //----------------------------------------------------------------------
            //3.  create an entry in the Component table 
            //----------------------------------------------------------------------
            try
            {
                MsiCreateRecordFromMsiTable(hDatabase,"Component",ComponentTable,6);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to create record in the Component Table.\n\n" + ex.Message);
            }
            //----------------------------------------------------------------------
            //4.  create an entry in the File table
            //----------------------------------------------------------------------
            //this entry is for the file INSIDE our CAB file
            try
            {
                MsiCreateRecordFromMsiTable(hDatabase, "File", FileTable,8);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to create record in the File Table.\n\n" + ex.Message);
            }
            //----------------------------------------------------------------------
            //5.  create an entry in the FeatureComponents table 
            //----------------------------------------------------------------------
            try
            {
                MsiCreateRecordFromMsiTable(hDatabase, "FeatureComponents", FeatureComponentsTable,2);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to create record in the FeatureComponents Table.\n\n" + ex.Message);
            }
            //----------------------------------------------------------------------------------------
            //6.  create an entry in the media table for the CAB file that will contain this new file
            //----------------------------------------------------------------------------------------
            try
            {
                MsiCreateRecordFromMsiTable(hDatabase, "Media", MediaTable,6);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to create record in the Media Table.\n\n" + ex.Message);
            }
            //----------------------------------------------------------------------
            //7.  load the binary data from the CAB file as a stream in MSI db
            //----------------------------------------------------------------------
            try
            {
                MsiAddInternalBinaryStream(hDatabase, tmpCabName, "_" + cabId, tmpCabFullName);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to add binary stream from CAB to MSI database!\n\n" + ex.Message);
            }
            //----------------------------------------------------------------------
            //8.  create an entry in the MsiAssembly table
            //----------------------------------------------------------------------
            try
            {
                MsiCreateRecordFromMsiTable(hDatabase, "MsiAssembly", AssemblyTable,5);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to create record in the MsiAssembly Table.\n\n" + ex.Message);
            }
            //----------------------------------------------------------------------
            //9.  create an entry in the MsiAssemblyName table
            //----------------------------------------------------------------------
            try
            {
                MsiCreateRecordFromMsiTable(hDatabase, "MsiAssemblyName", AssemblyNameTable_Name,3);
                MsiCreateRecordFromMsiTable(hDatabase, "MsiAssemblyName", AssemblyNameTable_Version,3);
                MsiCreateRecordFromMsiTable(hDatabase, "MsiAssemblyName", AssemblyNameTable_Culture,3);
                MsiCreateRecordFromMsiTable(hDatabase, "MsiAssemblyName", AssemblyNameTable_ProcessorArchitecture,3);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to create a record in the MsiAssemblyName Table.\n\n" + ex.Message);
            }

            //----------------------------------------------------------------------
            //10.  Finalize
            //----------------------------------------------------------------------
            //dump the table values for debugging purposes
            MsiDumpAllTables(hDatabase);

            //commit all changes and cleanup
            CwMsiWin32.MsiDatabaseCommit(hDatabase);
            CwMsiWin32.MsiCloseHandle(hDatabase);

            //cleanup
            MsiCleanUp(tmpCabName);
        }

        public void MsiCreateRecordFromMsiTable(IntPtr hDatabase, string tableName, object tableStruct, int numfields)
        {
            uint retVal = CwMsiWin32.ERROR_SUCCESS;
            IntPtr hView = IntPtr.Zero;
            string q = "SELECT * FROM `" + tableName + "`";
            IntPtr hRecord = (IntPtr)(0);
            int fieldnum = 1;

            //create a view to be used later for the operation
            retVal = CwMsiWin32.MsiDatabaseOpenViewW(hDatabase, q, out hView);
            MsiThrowOnFailure(hDatabase, retVal, "MsiDatabaseOpenViewW('" + q + "')");

            //execute the view
            retVal = CwMsiWin32.MsiViewExecute(hView, IntPtr.Zero);
            MsiThrowOnFailure(hDatabase, retVal, "MsiViewExecute()");

            //create the record
            hRecord = CwMsiWin32.MsiCreateRecord((uint)numfields);

            if (hRecord == IntPtr.Zero)
                throw new Exception("MsiCreateRecord");

            //get the fields for this table - note we can't use [type].GetType().GetFields()
            //because this function returns the fields in an unpredictable order!
            string[] fields = MsiTableGetFieldNames(tableName);

            if (fields == null)
                throw new Exception("No fields for table '" + tableName + "'.");
            if (fields.Length != numfields)
                throw new Exception("Field count mismatch:  fields.Length=" + fields.Length.ToString() + " / numfields=" + numfields.ToString());

            foreach (string thisfield in fields)
            {
                FieldInfo fi = tableStruct.GetType().GetField(thisfield);
                object value = fi.GetValue(tableStruct);

                if (value.GetType() == typeof(string))
                    retVal = CwMsiWin32.MsiRecordSetStringW(hRecord, (uint)fieldnum, (string)value);
                else if (value.GetType() == typeof(int))
                    retVal = CwMsiWin32.MsiRecordSetInteger(hRecord, (uint)fieldnum, (int)value);
                else if (value.GetType() == typeof(Int16))
                    retVal = CwMsiWin32.MsiRecordSetInteger(hRecord, (uint)fieldnum, (Int16)value);

                MsiThrowOnFailure(hDatabase, retVal, "MsiRecordSetStringW(" + fieldnum.ToString() + ", '" + value.ToString() + "')");
                fieldnum++;
            }

            //perform the operation on the MSI database
            retVal = CwMsiWin32.MsiViewModify(hView, CwMsiWin32.MSIMODIFY_INSERT, hRecord);
            MsiThrowOnFailure(hDatabase, retVal, "MsiViewModify - failed to alter/create record");

            //cleanup
            retVal = CwMsiWin32.MsiCloseHandle(hRecord);
            MsiThrowOnFailure(hDatabase, retVal, "MsiCloseHandle(hRecord)");
            retVal = CwMsiWin32.MsiCloseHandle(hView);
            MsiThrowOnFailure(hDatabase, retVal, "MsiCloseHandle(hView)");
            retVal = CwMsiWin32.MsiDatabaseCommit(hDatabase);
            MsiThrowOnFailure(hDatabase, retVal, "MsiDatabaseCommit(hDatabase)");
        }

        public string[] MsiTableGetFieldNames(string tbl)
        {
            if (tbl == "Component")
                return new string[] { "Component","ComponentId","Directory_","Attributes","Condition","KeyPath" };
            else if (tbl == "File")
                return new string[] {"File","Component_","FileName","FileSize","Version","Language","Attributes","Sequence" };
            else if (tbl == "Media")
                return new string[] { "DiskId","LastSequence","DiskPrompt","Cabinet","VolumeLabel","Source" };
            else if (tbl == "FeatureComponents")
                return new string[] { "Feature_","Component_" };
            else if (tbl == "MsiAssembly")
                return new string[] { "Component_", "Feature_", "File_Manifest", "File_Application", "Attributes" };
            else if (tbl == "MsiAssemblyName")
                return new string[] { "Component_","Name","Value" };
            else
                return null;
        }

        public Int16 MsiGetMaxDiskIdFromMediaTable(IntPtr hDatabase)
        {
            Dictionary<int, Dictionary<string, string>> allMediaTableRecords = new Dictionary<int, Dictionary<string, string>>();
            Dictionary<string, string> lastRecordInMediaTable = new Dictionary<string, string>();

            //get all values in Media table
            try
            {
                allMediaTableRecords = MsiGetTableRows(hDatabase, "Media");
            }
            catch (Exception ex)
            {
                throw new Exception("Could not open Media table!\n\n" + ex.Message);
            }

            //get the last record in the media table
            lastRecordInMediaTable = allMediaTableRecords[allMediaTableRecords.Count - 1];

            //our sequence number will be caclulated as follows (MSDN):
            //  To arrive at the sequence number for the first file in the cabinet, do the following. 
            //  Find the existing record in the Media table having the greatest value in the DiskID column. 
            //  The LastSequence field of this record gives the last file sequence number used on the media. 
            //  In the File table, assign the first file of the new cabinet a sequence number that is greater than this. 
            //  Assign sequence numbers to all of the remaining files in the same order as in the cabinet file
            Int16[] diskIds = new Int16[allMediaTableRecords.Count];
            int count = 0;

            //collect all Disk Ids for all entries in the Media table
            foreach (KeyValuePair<int, Dictionary<string, string>> record in allMediaTableRecords)
            {
                int idx = (int)record.Key;
                Dictionary<string, string> recordData = record.Value;

                foreach (KeyValuePair<string, string> kvp in recordData)
                {
                    if (kvp.Key.ToString() == "DiskId")
                    {
                        diskIds[count] = Int16.Parse(kvp.Value.ToString());
                        count++;
                    }
                }
            }

            //get the max disk id
            Int16 maxDiskId = diskIds[0];
            foreach (Int16 value in diskIds)
                if (value > maxDiskId)
                    maxDiskId = value;

            return maxDiskId;
        }

        public Int16 MsiGetLastFileSequenceFromMediaTable(IntPtr hDatabase, Int16 maxDiskId)
        {
            //the last file sequence is derived from the Media Table field "LastSequence"
            //the first file in the new Cab file must have its Sequence field in the File table
            //equal to this value + 1

            Dictionary<int, Dictionary<string, string>> allMediaTableRecords = new Dictionary<int, Dictionary<string, string>>();
            bool done = false;
            Int16 lastSequenceNumber = 0;

            //get all values in Media table
            try
            {
                allMediaTableRecords = MsiGetTableRows(hDatabase, "Media");
            }
            catch (Exception ex)
            {
                throw new Exception("Could not open Media table!\n\n" + ex.Message);
            }

            //now loop through the Media records and find the record with this diskId
            //when we find it, we record the LastSequence value for us to use
            foreach (KeyValuePair<int, Dictionary<string, string>> record in allMediaTableRecords)
            {
                int idx = (int)record.Key;
                Dictionary<string, string> recordData = record.Value;

                //loop through each field in this record
                foreach (KeyValuePair<string, string> kvp in recordData)
                {
                    //if we are on the DiskId field of this record
                    if (kvp.Key.ToString() == "DiskId")
                    {
                        //and its value is equal to the max value we found
                        if (Int16.Parse(kvp.Value.ToString()) == maxDiskId)
                        {
                            //then grab this record's LastSequence and bail
                            string lastSeq = recordData["LastSequence"].ToString();
                            lastSequenceNumber = Int16.Parse(lastSeq);
                            done = true;
                            break;
                        }
                    }
                }
                if (done)
                    break;
            }

            return lastSequenceNumber;
        }

        public bool MsiAddInternalBinaryStream(IntPtr hDatabase, string cabname, string cabId, string cabfullpath)
        {
            //for info on the _Streams table, see MSDN:
            //  http://msdn.microsoft.com/en-us/library/aa372919(VS.85).aspx

            Dictionary<int, Dictionary<string, string>> tableRecords = new Dictionary<int, Dictionary<string, string>>();
            Dictionary<string, string> record = new Dictionary<string, string>();
            uint retVal = CwMsiWin32.ERROR_SUCCESS;
            string selectQuery = "SELECT * FROM `_Streams`";
            IntPtr hView = IntPtr.Zero;
            IntPtr hRecord = IntPtr.Zero;

            //open the database view
            retVal = CwMsiWin32.MsiDatabaseOpenViewW(hDatabase, selectQuery, out hView);
            MsiThrowOnFailure(hDatabase,retVal, "MsiDatabaseOpenViewW()");

            //create a new record
            hRecord = CwMsiWin32.MsiCreateRecord(2); //2 fields:  Name and Data

            //set the Name column of the _Streams table to the Cabinet name (file name on disk)
            retVal = CwMsiWin32.MsiRecordSetStringW(hRecord, 1, cabId);
            MsiThrowOnFailure(hDatabase, retVal, "MsiRecordSetStringW:  Failed to set the Name column in the _Streams table to '"+cabname+"'");

            //set the Data column of the _Streams table to the Cabinet name (full file path location on disk)
            retVal = CwMsiWin32.MsiRecordSetStreamW(hRecord, 2, cabfullpath);
            MsiThrowOnFailure(hDatabase, retVal, "MsiRecordSetStream:  Failed to set the Data column in the _Streams table to '" + cabfullpath + "'");

            //apply the update
            retVal = CwMsiWin32.MsiViewModify(hView, CwMsiWin32.MSIMODIFY_INSERT, hRecord);
            MsiThrowOnFailure(hDatabase, retVal, "MsiViewModify:  Failed to apply update to CAB '" + cabId + "'");

            //commit database
            retVal = CwMsiWin32.MsiDatabaseCommit(hDatabase);
            MsiThrowOnFailure(hDatabase, retVal, "MsiDatabaseCommit:  Could not commit msi db.");

            CwMsiWin32.MsiCloseHandle(hView);
            CwMsiWin32.MsiCloseHandle(hRecord);

            return true;
        }

        public void MsiDumpAllTables(IntPtr hDatabase)
        {
            Dictionary<int, Dictionary<string, string>> AllRecords = new Dictionary<int, Dictionary<string, string>>();
            string[] tables = new string[] { "Component", "Directory", "File", "Media", "Feature", "FeatureComponents", "Registry", "Sequence", "InstallExecuteSequence", "InstallUISequence", "AdminExecuteSequence", "AdminUISequence", "AdvtExecuteSequence", "MsiAssembly", "MsiAssemblyName"};
            StringBuilder sb = new StringBuilder();

            foreach (string table in tables)
            {
                sb.AppendLine("----------------");
                sb.AppendLine(table + " Table:");
                sb.AppendLine("----------------");
                try
                {
                    AllRecords = MsiGetTableRows(hDatabase, table);
                }
                catch (Exception ex)
                {
                    if (ex.InnerException != null)
                        throw new Exception("Error querying database:  '" + ex.Message + "', '" + ex.InnerException.Message + "'");
                    else
                        throw new Exception("Error querying database:  '" + ex.Message + "'");
                }

                //if we got a null back, this means an error prob occured with the table name being invalid
                if (AllRecords == null)
                {
                    sb.AppendLine("[no results]");
                    continue;
                }

                foreach (KeyValuePair<int,Dictionary<string,string>> kvp in AllRecords)
                {
                    int recnum = kvp.Key;
                    Dictionary<string, string> record = kvp.Value;

                    sb.AppendLine("[" + recnum.ToString() + "]");

                    //loop through record fields
                    foreach (KeyValuePair<string,string> fields in record)
                        sb.AppendLine("    " + fields.Key.ToString() + "=" + fields.Value.ToString());
                }
            }

            /*
             * UNCOMMENT THIS BLOCK TO DUMP THE TABLES TO A FILE
             * 
            if (sb.Length > 1)
            {
                StreamWriter sw = new StreamWriter("tbldmp.txt");
                sw.WriteLine(sb.ToString());
                sw.Close();
            }*/
        }

        public Dictionary<int, Dictionary<string, string>> MsiGetTableRows(IntPtr hDatabase, string tableName)
        {
            Dictionary<int, Dictionary<string, string>> tableRecords = new Dictionary<int, Dictionary<string, string>>();
            Dictionary<string, string> record = new Dictionary<string, string>();
            int fieldcount=0;
            uint retVal = CwMsiWin32.ERROR_SUCCESS;
            string propertyFieldValue;
            string selectQuery = "SELECT * FROM `" + tableName + "`";
            int recordCount = 0;
            IntPtr hView = IntPtr.Zero;
            IntPtr hRecord = IntPtr.Zero;
            IntPtr hColnames = IntPtr.Zero;

            retVal = CwMsiWin32.MsiDatabaseOpenViewW(hDatabase, selectQuery, out hView);
            //if we get bad syntax here, just keep going b/c it could just be an invalid table name..?
            if (retVal != CwMsiWin32.ERROR_BAD_QUERY_SYNTAX && retVal != CwMsiWin32.ERROR_SUCCESS)
                MsiThrowOnFailure(hDatabase,retVal, "MsiDatabaseOpenViewW()");
            if (retVal == CwMsiWin32.ERROR_BAD_QUERY_SYNTAX)
                return null;

            retVal = CwMsiWin32.MsiViewExecute(hView, IntPtr.Zero);
            MsiThrowOnFailure(hDatabase,retVal, "MsiViewExecute()");

            // Loop through the properties and copy the ones passed in to this function
            do
            {
                //clear the record var
                record = new Dictionary<string, string>();

                //fetch the view
                retVal = CwMsiWin32.MsiViewFetch(hView, out hRecord);
                if (retVal != CwMsiWin32.ERROR_SUCCESS && retVal != CwMsiWin32.ERROR_NO_MORE_ITEMS)
                    MsiThrowOnFailure(hDatabase,retVal, "MsiViewFetch");
                if (retVal == CwMsiWin32.ERROR_NO_MORE_ITEMS)
                    break;

                //get the field count
                fieldcount = (int)CwMsiWin32.MsiRecordGetFieldCount(hRecord) + 1; //must add 1 b/c it ignores column 0..?!

                //get the column names
                retVal = CwMsiWin32.MsiViewGetColumnInfo(hView, CwMsiWin32.MSICOLINFO_NAMES, out hColnames);
                MsiThrowOnFailure(hDatabase,retVal, "MsiViewGetColumnInfo");
                string [] colnames = new string[fieldcount];

                //loop the number of times there are fields and get a column name for each
                for (int i = 0; i < fieldcount; i++)
                {
                    string thisColName = "";
                    MsiRecordGetStringW(hColnames, (uint)i, out thisColName);
                    if (thisColName == "" && i == 0) //primary key is 0
                        thisColName = "Primary Key";
                    else if (thisColName == "")
                        thisColName = "[unknown]";
                    colnames[i] = thisColName;
                }

                //loop through all fields, get the column name, and store in our dictionary
                for (int i = 0; i < fieldcount; i++)
                {
                    retVal = MsiRecordGetStringW(hRecord, (uint)i, out propertyFieldValue);
                    MsiThrowOnFailure(hDatabase,retVal, "MsiRecordGetStringW(hRecord," + i.ToString() + "," + propertyFieldValue + ")");
                    record[colnames[i]] = propertyFieldValue;
                }

                //save the record in our table of records
                tableRecords[recordCount] = record;

                retVal = CwMsiWin32.MsiCloseHandle(hRecord);
                MsiThrowOnFailure(hDatabase,retVal, "MsiCloseHandle(hRecord)");
                recordCount++;
            }
            while (retVal != CwMsiWin32.ERROR_NO_MORE_ITEMS);

            retVal = CwMsiWin32.MsiCloseHandle(hView);
            MsiThrowOnFailure(hDatabase,retVal, "MsiCloseHandle");

            return tableRecords;
        }

        public IntPtr MsiGetRecordHandle(IntPtr hDatabase, IntPtr hView, int desiredRecordNumber)
        {
            int index,rowcount = 0;
            IntPtr hRecord = IntPtr.Zero;
            string propertyFieldValue;
            uint retVal = CwMsiWin32.ERROR_SUCCESS;
            //string colname;
            //IntPtr hColNames;

            //get first record
            retVal = CwMsiWin32.MsiViewFetch(hView, out hRecord);
            MsiThrowOnFailure(hDatabase,retVal, "MsiViewFetch");

            //loop through all records in this view
            do
            {
                index=0;
                Dictionary<int, string> values = new Dictionary<int, string>();

                //get all fields in this record
                while (MsiRecordGetStringW(hRecord, (uint)index, out propertyFieldValue) == CwMsiWin32.ERROR_SUCCESS && propertyFieldValue != "")
                {
                    //string colname = MsiViewGetColumnInfo(hView, MSICOLINFO_NAMES, hColNames);
                    values[(int)index] = propertyFieldValue;
                    index++;
                }

                if (rowcount == desiredRecordNumber)
                    break;

                retVal = CwMsiWin32.MsiViewFetch(hView, out hRecord);
                rowcount++;
            }
            while (retVal != CwMsiWin32.ERROR_NO_MORE_ITEMS);

            return hRecord;
        }

        public void MsiCreateEditRecordInTable(IntPtr hDatabase, string tableName, string action, int recordnumber, int[] fieldnumbers, ArrayList fieldvalues)
        {
            uint retVal = CwMsiWin32.ERROR_SUCCESS;
            int numfields = fieldvalues.Count;
            int msiAction = -1;

            //create a view to be used later for the operation
            IntPtr hView = IntPtr.Zero;
            string q = "SELECT * FROM `" + tableName + "`";
            retVal = CwMsiWin32.MsiDatabaseOpenViewW(hDatabase, q, out hView);
            MsiThrowOnFailure(hDatabase,retVal, "MsiDatabaseOpenViewW('" + q + "')");

            //execute the view
            retVal = CwMsiWin32.MsiViewExecute(hView, IntPtr.Zero);
            MsiThrowOnFailure(hDatabase,retVal, "MsiViewExecute()");

            IntPtr hRecord = (IntPtr)(0);

            //create a record ptr with numfields
            if (action == "CreateRecord")
            {
                hRecord = CwMsiWin32.MsiCreateRecord((uint)numfields);
                msiAction = CwMsiWin32.MSIMODIFY_INSERT;

                if (hRecord == IntPtr.Zero)
                {
                    throw new Exception("MsiCreateRecord");
                }

                int fieldnum = 1;  //note:  not a zero-based index!

                //loop through each field in this record and set it
                foreach (object val in fieldvalues)
                {
                    if (val.GetType() == typeof(string))
                        retVal = CwMsiWin32.MsiRecordSetStringW(hRecord, (uint)fieldnum, (string)val);
                    else if (val.GetType() == typeof(Int32))
                        retVal = CwMsiWin32.MsiRecordSetInteger(hRecord, (uint)fieldnum, (Int32)val);
                    else if (val.GetType() == typeof(Int16))
                        retVal = CwMsiWin32.MsiRecordSetInteger(hRecord, (uint)fieldnum, (Int16)val);

                    MsiThrowOnFailure(hDatabase,retVal, "MsiRecordSetStringW(" + fieldnum.ToString() + ", '" + val + "')");
                    fieldnum++;
                }
            }
            else if (action == "ChangeFieldsInRecord")
            {
                //make sure the fieldnumbers size and fieldvalues size match
                if (fieldnumbers.Length != fieldvalues.Count)
                {
                    retVal = CwMsiWin32.MsiCloseHandle(hView);
                    MsiThrowOnFailure(hDatabase,retVal, "MsiCloseHandle(hView)");
                    throw new Exception("fieldnumbers and fieldvalues are not equal.");
                }

                hRecord = MsiGetRecordHandle(hDatabase, hView, recordnumber);
                int i = 0;
                //loop through all field numbers we want to change in this record
                //and alter those fields in the record we just retrieved
                foreach (int fieldnum in fieldnumbers)
                {
                    retVal = CwMsiWin32.MsiRecordSetStringW(hRecord, (uint)fieldnum, fieldvalues[i].ToString());
                    MsiThrowOnFailure(hDatabase,retVal, "MsiRecordSetStringW(hRecord," + fieldnum.ToString() + "," + fieldvalues[i] + ")");
                    i++;
                }

                msiAction = CwMsiWin32.MSIMODIFY_UPDATE;
            }
            else
            {
                retVal = CwMsiWin32.MsiCloseHandle(hView);
                MsiThrowOnFailure(hDatabase,retVal, "MsiCloseHandle(hView)");
                throw new Exception("Error:  Invalid action specified '" + msiAction + "'!");
            }

            if (hRecord == (IntPtr)(-1))
                throw new Exception("Failed to retrieve hRecord!");

            //perform the operation on the MSI database
            retVal = CwMsiWin32.MsiViewModify(hView, msiAction, hRecord);
            MsiThrowOnFailure(hDatabase,retVal, "MsiViewModify - failed to alter/create record");

            //cleanup
            retVal = CwMsiWin32.MsiCloseHandle(hRecord);
            MsiThrowOnFailure(hDatabase,retVal, "MsiCloseHandle(hRecord)");
            retVal = CwMsiWin32.MsiCloseHandle(hView);
            MsiThrowOnFailure(hDatabase,retVal, "MsiCloseHandle(hView)");
            retVal = CwMsiWin32.MsiDatabaseCommit(hDatabase);
            MsiThrowOnFailure(hDatabase,retVal, "MsiDatabaseCommit(hDatabase)");
        }

        internal uint MsiRecordGetStringW(IntPtr hRecord, uint iField, out string szValueBuf)
        {
            uint len = 256;
            string sz = new string(' ', (int)len);
            IntPtr bstr = Marshal.StringToBSTR(sz);
            uint retVal = CwMsiWin32.MsiRecordGetStringW(hRecord, iField, bstr, ref len);

            if (retVal == CwMsiWin32.ERROR_SUCCESS)
            {
                szValueBuf = Marshal.PtrToStringUni(bstr);
            }
            else
            {
                szValueBuf = null;
            }

            Marshal.FreeBSTR(bstr);
            bstr = IntPtr.Zero;

            return retVal;
        }


        ////////////////////////////////////////////////////////////////////////////////////////
        //
        //                      MSICLASS PRIVATE DATA
        //
        //
        ////////////////////////////////////////////////////////////////////////////////////////

        internal struct MsiFileTable
        {
            public string File;
            public string Component_;
            public string FileName;
            public int FileSize;
            public string Version;
            public string Language;
            public Int16 Attributes;
            public Int16 Sequence;
        }
        internal struct MsiComponentTable
        {
            public string Component;
            public string ComponentId;
            public string Directory_;
            public Int16 Attributes;
            public string Condition;
            public string KeyPath;
        }
        internal struct MsiMediaTable
        {
            public Int16 DiskId;
            public Int16 LastSequence;
            public string DiskPrompt;
            public string Cabinet;
            public string VolumeLabel;
            public string Source;
        }
        internal struct MsiFeatureComponentsTable
        {
            public string Feature_;
            public string Component_;
        }
        internal struct MsiAssemblyTable
        {
            public string Component_;
            public string Feature_;
            public string File_Manifest;
            public string File_Application;
            public Int16 Attributes;
        }
        internal struct MsiAssemblyNameTable
        {
            public string Component_;
            public string Name;
            public string Value;
        }
    }
}
