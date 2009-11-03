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
using System.Xml;
using System.Xml.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;
using System.Net.Security;
using System.Threading;

namespace CwHandler
{
    internal partial class CwAdminConsole : Form
    {
        //--------------------------
        //      PRIVATE DATA
        //--------------------------
        //tcp/ssl client object used across function handlers
        SslTcpClient CurrentClient = null;
        //background worker thread used in lengthy operations
        BackgroundWorker AgentTaskBackgroundWorker;
        //when sending new signature update file to agent, this
        //requires two consecutive backgroundworker thread creations, 
        //so we will need to maintain the file name selected originally.
        string UpdateFilename = "";
        //remember what folder the admin selected to save collected evidence files to.
        string SaveCollectionEvidenceToFolder = "";

        #region CONNECT TO EXISTING AGENT -- TOOLBAR BUTTON HANDLERS

        /////////////////////////////////////////////////////
        //                                                 //
        // DownloadEvidenceButton_Click()                  //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void DownloadEvidenceButton_Click(object sender, EventArgs e)
        {
            //make sure we are connected first
            if (!CurrentClient.IsConnected())
            {
                MessageBox.Show("Error:  Connection to remote agent has been lost.");
                ToggleButtons(false, false);
                return;
            }

            if (LastAnomalyReport == null)
            {
                MessageBox.Show("There are is no evidence available to download.");
                return;
            }
            if (LastAnomalyReport.SignatureMatches == null)
            {
                MessageBox.Show("There are is no evidence available to download.");
                return;
            }

            FolderBrowserDialog fbd = new FolderBrowserDialog();
            fbd.ShowNewFolderButton = true;

            if (fbd.ShowDialog() != DialogResult.OK)
                return;

            //save the selected file name in a global variable in our main GUI thread
            //it will be picked up again in the second thread, when the file is actually sent.
            SaveCollectionEvidenceToFolder = fbd.SelectedPath;

            //set our own socket's read timeout to something high - a scan can take some time
            CurrentClient.SetStreamTimeout("read", CwConstants.STREAM_COLLECT_TASK_TIMEOUT);

            //prepare an anomaly report object for collection tasks.
            CwXML.CodewordAgentAnomalyReport report = new CwXML.CodewordAgentAnomalyReport();
            //parse GUI listview items into an XML structure for transport.
            string outputMsg = "";
            CwXML.CodewordAgentSignatureMatches matches = GetCollectMitigateItems(ref outputMsg, "collect");

            //if none were selected, and the user declined to collect all items, just bail.
            if (matches == null)
                return;

            //verify the operation
            if (MessageBox.Show("The following collection operations are about to be issued:\n\n" + outputMsg + "\n\nAre you SURE?", "Review collection tasks", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            report.SignatureMatches = matches;
            report.HeuristicMatches = new CwXML.CodewordAgentHeuristicMatches(); //empty

            //save for later
            LastCollectionTask = report;

            //disable buttons until response is received.  
            //this prevents duplicate or conflicting commands from being issued
            ToggleButtons(false, true);

            //do lengthy operation in background worker thread
            //here we will need to setup any args the lengthy operation will need in the separate thread
            ArrayList args = new ArrayList();
            args.Add(CurrentClient);
            args.Add(CwConstants.AGENTCMD_COLLECT);
            args.Add(new string[] { "" });
            args.Add(CwConstants.STREAM_COLLECT_TASK_TIMEOUT);
            args.Add(true);
            args.Add(report); //a special 6th argument for collection commands.
            AgentTaskBackgroundWorker = new BackgroundWorker();
            AgentTaskBackgroundWorker.WorkerReportsProgress = true;
            AgentTaskBackgroundWorker.DoWork += new DoWorkEventHandler(BackgroundWorker_DoWork);
            AgentTaskBackgroundWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(BackgroundWorker_RunWorkerCompleted);
            AgentTaskBackgroundWorker.ProgressChanged += new ProgressChangedEventHandler(BackgroundWorker_ProgressChanged);
            AgentTaskBackgroundWorker.RunWorkerAsync(args);
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // PerformMitigationTasksButton_Click()            //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Applies mitigation actions to selected
        //              rows of listviews.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void PerformMitigationTasksButton_Click(object sender, EventArgs e)
        {
            //make sure we are connected first
            if (!CurrentClient.IsConnected())
            {
                MessageBox.Show("Error:  Connection to remote agent has been lost.");
                ToggleButtons(false, false);
                return;
            }

            if (LastAnomalyReport == null)
            {
                MessageBox.Show("There are no signature matches to mitigate.");
                return;
            }
            if (LastAnomalyReport.SignatureMatches == null)
            {
                MessageBox.Show("There are no signature matches to mitigate.");
                return;
            }

            //set our own socket's read timeout to something high - a scan can take some time
            CurrentClient.SetStreamTimeout("read", CwConstants.STREAM_MITIGATE_TASK_TIMEOUT);

            //prepare an anomaly report object for mitigation tasks.
            CwXML.CodewordAgentAnomalyReport report = new CwXML.CodewordAgentAnomalyReport();
            //parse GUI listview items into an XML structure for transport.
            string outputMsg = "";
            CwXML.CodewordAgentSignatureMatches matches = GetCollectMitigateItems(ref outputMsg, "mitigate");

            //if none were selected, and the user declined to mitigate all items, just bail.
            if (matches == null)
                return;

            //verify the operation
            if (MessageBox.Show("The following irreversible mitigation operations are about to be issued:\n\n" + outputMsg + "\n\nAre you SURE?", "Review mitigation tasks", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            report.SignatureMatches = matches;
            report.HeuristicMatches = new CwXML.CodewordAgentHeuristicMatches(); //empty

            //disable buttons until response is received.  
            //this prevents duplicate or conflicting commands from being issued
            ToggleButtons(false, true);

            //do lengthy operation in background worker thread
            //here we will need to setup any args the lengthy operation will need in the separate thread
            ArrayList args = new ArrayList();
            args.Add(CurrentClient);
            args.Add(CwConstants.AGENTCMD_MITIGATE);
            args.Add(new string[]{""});
            args.Add(CwConstants.STREAM_MITIGATE_TASK_TIMEOUT);
            args.Add(true);
            args.Add(report); //a special 6th argument for mitigation commands.
            AgentTaskBackgroundWorker = new BackgroundWorker();
            AgentTaskBackgroundWorker.WorkerReportsProgress = true;
            AgentTaskBackgroundWorker.DoWork += new DoWorkEventHandler(BackgroundWorker_DoWork);
            AgentTaskBackgroundWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(BackgroundWorker_RunWorkerCompleted);
            AgentTaskBackgroundWorker.ProgressChanged += new ProgressChangedEventHandler(BackgroundWorker_ProgressChanged);
            AgentTaskBackgroundWorker.RunWorkerAsync(args);
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetMitigateItems()                              //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Crawls the GUI listview controls that
        //              hold the registry, file and memory
        //              signature matches.  It builds an XML
        //              structure from these values in preparation
        //              for sending them to the agent for mitigation.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private CwXML.CodewordAgentSignatureMatches GetCollectMitigateItems(ref string outputMessage, string mitigateOrCollectMsg)
        {
            int numRegMitigate = 0,numFileMitigate=0,numMemMitigate=0;
            int count = 0;
            bool mitigateAll = false;
            CwXML.CodewordAgentSignatureMatches matches = new CwXML.CodewordAgentSignatureMatches();
            outputMessage = "";

            //-------------------------------------
            //          CALCULATE COUNTS
            //-------------------------------------
            foreach (ListViewItem lvi in AgentResults_RegistryListview.Items)
                if (lvi.Checked)
                    numRegMitigate++;
            foreach (ListViewItem lvi in AgentResults_FileListview.Items)
                if (lvi.Checked)
                    numFileMitigate++;
            foreach (ListViewItem lvi in AgentResults_MemoryListview.Items)
                if (lvi.Checked)
                    numMemMitigate++;

            //if there were no items selected, prompt to mitigate all findings
            if ((numRegMitigate + numFileMitigate + numMemMitigate) == 0)
            {
                if (MessageBox.Show("No findings were selected.  Would you like to "+mitigateOrCollectMsg+" all findings?", mitigateOrCollectMsg+" all findings?", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question) != DialogResult.Yes)
                    return null;
                numRegMitigate = AgentResults_RegistryListview.Items.Count;
                numFileMitigate = AgentResults_FileListview.Items.Count;
                numMemMitigate = AgentResults_MemoryListview.Items.Count;
                mitigateAll = true;
            }

            CwXML.RegistrySignatureMatch[] regMatchesToMitigate = new CwXML.RegistrySignatureMatch[numRegMitigate];
            CwXML.FileSignatureMatch[] fileMatchesToMitigate = new CwXML.FileSignatureMatch[numFileMitigate];
            CwXML.MemorySignatureMatch[] memMatchesToMitigate = new CwXML.MemorySignatureMatch[numMemMitigate];

            //-------------------------------------
            //              REGISTRY
            //-------------------------------------
            if (numRegMitigate > 0)
            {
                outputMessage += "Registry findings (" + numRegMitigate + "):\n";

                //build list of registry signature matches to mitigate
                foreach (ListViewItem lvi in AgentResults_RegistryListview.Items)
                {
                    if (!lvi.Checked && !mitigateAll)
                        continue;

                    //add to display based on action selected for this finding
                    outputMessage += "     " + lvi.SubItems[0].Text + "\\" + lvi.SubItems[1] + " :  " + lvi.SubItems[5].Text + "\n";

                    regMatchesToMitigate[count] = new CwXML.RegistrySignatureMatch();
                    regMatchesToMitigate[count].RegistryKeyName = lvi.SubItems[0].Text;
                    regMatchesToMitigate[count].RegistryValueName = lvi.SubItems[1].Text;
                    regMatchesToMitigate[count].RegistryValueData = lvi.SubItems[2].Text;
                    regMatchesToMitigate[count].RegistryChangeValueData = lvi.SubItems[3].Text;
                    try
                    {
                        regMatchesToMitigate[count].IsFileOnDisk = bool.Parse(lvi.SubItems[4].Text);
                    }
                    catch (Exception)
                    {
                        regMatchesToMitigate[count].IsFileOnDisk = false;
                    }
                    regMatchesToMitigate[count].Action = lvi.SubItems[5].Text;
                    try
                    {
                        regMatchesToMitigate[count].ActionSuccessful = bool.Parse(lvi.SubItems[6].Text);
                    }
                    catch (Exception)
                    {
                        regMatchesToMitigate[count].ActionSuccessful = false;
                    }
                    count++;
                }
                count = 0;
            }

            //-------------------------------------
            //              FILE
            //-------------------------------------
            if (numFileMitigate > 0)
            {
                outputMessage += "File findings (" + numFileMitigate + "):\n";

                //build list of registry signature matches to mitigate
                foreach (ListViewItem lvi in AgentResults_FileListview.Items)
                {
                    if (!lvi.Checked && !mitigateAll)
                        continue;

                    //add to display based on action selected for this finding
                    if (lvi.SubItems[0].Text != "") //filename
                        outputMessage += "     " + lvi.SubItems[1].Text + " :  " + lvi.SubItems[8].Text + "\n";
                    else if (lvi.SubItems[3].Text != "") //hash
                        outputMessage += "     [Hash=" + lvi.SubItems[3].Text + "] :  " + lvi.SubItems[8].Text + "\n";
                    else if (lvi.SubItems[2].Text != "") //filesize
                        outputMessage += "     [FileSize=" + lvi.SubItems[2].Text + "] :  " + lvi.SubItems[8].Text + "\n";

                    fileMatchesToMitigate[count] = new CwXML.FileSignatureMatch();
                    fileMatchesToMitigate[count].FileName = lvi.SubItems[0].Text;
                    fileMatchesToMitigate[count].FullPath = lvi.SubItems[1].Text;
                    long.TryParse(lvi.SubItems[2].Text, out fileMatchesToMitigate[count].FileSize);
                    fileMatchesToMitigate[count].FileHash = lvi.SubItems[3].Text;
                    fileMatchesToMitigate[count].FilePEHeaderSignature = lvi.SubItems[4].Text;
                    fileMatchesToMitigate[count].FileCreationDate = lvi.SubItems[5].Text;
                    fileMatchesToMitigate[count].FileLastAccessDate = lvi.SubItems[6].Text;
                    fileMatchesToMitigate[count].FileLastModifiedDate = lvi.SubItems[7].Text;
                    fileMatchesToMitigate[count].Action = lvi.SubItems[8].Text;
                    try
                    {
                        fileMatchesToMitigate[count].ActionSuccessful = bool.Parse(lvi.SubItems[9].Text);
                    }
                    catch (Exception)
                    {
                        fileMatchesToMitigate[count].ActionSuccessful = false;
                    }
                    count++;
                }
                count = 0;
            }

            //-------------------------------------
            //              MEMORY
            //-------------------------------------
            if (numMemMitigate > 0)
            {
                outputMessage += "Memory findings (" + numMemMitigate + "):\n";

                //build list of registry signature matches to mitigate
                foreach (ListViewItem lvi in AgentResults_MemoryListview.Items)
                {
                    if (!lvi.Checked && !mitigateAll)
                        continue;

                    outputMessage += "     " + lvi.SubItems[2].Text + " (" + lvi.SubItems[0].Text + ") :  " + lvi.SubItems[7].Text;

                    //we cant populate all the fields of the memorysignaturematch structure,
                    //because we didn't populate the GUI listview with all these fields (there are too many)
                    //however, memory mitigation consists of killing the process by name/pid or suspending the thread.
                    //so we dont need all that crap anyway.
                    memMatchesToMitigate[count] = new CwXML.MemorySignatureMatch();
                    uint.TryParse(lvi.SubItems[0].Text, out memMatchesToMitigate[count].ProcessId);
                    uint.TryParse(lvi.SubItems[1].Text, out memMatchesToMitigate[count].ParentProcessId);
                    memMatchesToMitigate[count].ProcessName = lvi.SubItems[2].Text;
                    memMatchesToMitigate[count].ChildThreadIds = lvi.SubItems[6].Text;
                    memMatchesToMitigate[count].Action = lvi.SubItems[7].Text;
                    try
                    {
                        memMatchesToMitigate[count].ActionSuccessful = bool.Parse(lvi.SubItems[8].Text);
                    }
                    catch (Exception)
                    {
                        memMatchesToMitigate[count].ActionSuccessful = false;
                    }
                    count++;
                }
            }

            matches.RegistrySignatureMatches = regMatchesToMitigate;
            matches.FileSignatureMatches = fileMatchesToMitigate;
            matches.MemorySignatureMatches = memMatchesToMitigate;

            return matches;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // UpdateAgentButton_Click()                       //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Prompts the admin for a new signature
        //              file and then sends that over to the
        //              remote agent.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void UpdateAgentButton_Click(object sender, EventArgs e)
        {
            //make sure we are connected first
            if (!CurrentClient.IsConnected())
            {
                MessageBox.Show("Error:  Connection to client has been lost.");
                ToggleButtons(false, false);
                return;
            }

            //prompt admin for a new sig file
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.CheckFileExists = true;
            ofd.Multiselect = false;
            ofd.Filter = "XML Files|*.xml";
            ofd.Title = "Select a new signature file";

            if (ofd.ShowDialog() != DialogResult.OK)
                return;

            //save the selected file name in a global variable in our main GUI thread
            //it will be picked up again in the second thread, when the file is actually sent.
            UpdateFilename = ofd.FileName;

            //set our own socket's read timeout to something high - a scan can take some time
            CurrentClient.SetStreamTimeout("read", CwConstants.STREAM_UPDATE_SIGNATURES_TIMEOUT);

            //disable buttons until response is received.  
            //this prevents duplicate or conflicting commands from being issued
            ToggleButtons(false, true);

            //CREATE FIRST THREAD - notify agent we are sending a file in a SECOND THREAD
            //the second thread is created in the first thread in the WorkCompleted() function below.
            ArrayList args = new ArrayList();
            args.Add(CurrentClient);
            args.Add(CwConstants.AGENTCMD_UPDATESIG);
            args.Add(new string[] { "" });
            args.Add(CwConstants.STREAM_UPDATE_SIGNATURES_TIMEOUT);
            args.Add(true);
            AgentTaskBackgroundWorker = new BackgroundWorker();
            AgentTaskBackgroundWorker.WorkerReportsProgress = true;
            AgentTaskBackgroundWorker.DoWork += new DoWorkEventHandler(BackgroundWorker_DoWork);
            AgentTaskBackgroundWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(BackgroundWorker_RunWorkerCompleted);
            AgentTaskBackgroundWorker.ProgressChanged += new ProgressChangedEventHandler(BackgroundWorker_ProgressChanged);
            AgentTaskBackgroundWorker.RunWorkerAsync(args);
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // StartScanButton_Click()                         //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Tells the remote agent to initiate a scan.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void StartScanButton_Click(object sender, EventArgs e)
        {
            //make sure we are connected first
            if (!CurrentClient.IsConnected())
            {
                MessageBox.Show("Error:  Connection to remote agent has been lost.");
                ToggleButtons(false,false);
                return;
            }

            //make sure we are connected first
            if (!CurrentClient.IsConnected())
            {
                MessageBox.Show("Error:  Connection to client has been lost.");
                ToggleButtons(false, false);
                return;
            }

            //set our own socket's read timeout to something high - a scan can take some time
            CurrentClient.SetStreamTimeout("read", CwConstants.STREAM_SCAN_TASK_TIMEOUT);

            //disable buttons until response is received.  
            //this prevents duplicate or conflicting commands from being issued
            ToggleButtons(false, true);

            //do lengthy operation in background worker thread
            //here we will need to setup any args the lengthy operation will need in the separate thread
            ArrayList args = new ArrayList();
            args.Add(CurrentClient);
            args.Add(CwConstants.AGENTCMD_STARTSCAN);
            args.Add(new string[] { "" });
            args.Add(CwConstants.STREAM_SCAN_TASK_TIMEOUT);
            args.Add(true);
            AgentTaskBackgroundWorker = new BackgroundWorker();
            AgentTaskBackgroundWorker.WorkerReportsProgress = true;
            AgentTaskBackgroundWorker.DoWork += new DoWorkEventHandler(BackgroundWorker_DoWork);
            AgentTaskBackgroundWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(BackgroundWorker_RunWorkerCompleted);
            AgentTaskBackgroundWorker.ProgressChanged += new ProgressChangedEventHandler(BackgroundWorker_ProgressChanged);
            AgentTaskBackgroundWorker.RunWorkerAsync(args);
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // HaltAgentButton_Click()                         //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Sends an AGENT_EXIT command to the remote
        //              agent, informing it to shutdown.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void HaltAgentButton_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show("Are you sure you want to halt the agent at " + ConnectToAgentIP.Text + "?\n\nThis operation will result in the agent terminating and uninstalling on the remote host.  This operation is irreversible.", "Halt agent?", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            //make sure we are connected first
            if (!CurrentClient.IsConnected())
            {
                MessageBox.Show("Error:  Connection to client has been lost.");
                ToggleButtons(false, false);
                return;
            }

            //disable all buttons to prevent duplicate commands
            ToggleButtons(false, false);

            //do lengthy operation in background worker thread
            //here we will need to setup any args the lengthy operation will need in the separate thread
            ArrayList args = new ArrayList();
            args.Add(CurrentClient);
            args.Add(CwConstants.AGENTCMD_EXIT);
            args.Add(new string[] { "" });
            args.Add(CwConstants.STREAM_DEFAULT_READ_TIMEOUT);
            args.Add(true);
            AgentTaskBackgroundWorker = new BackgroundWorker();
            AgentTaskBackgroundWorker.WorkerReportsProgress = true;
            AgentTaskBackgroundWorker.DoWork += new DoWorkEventHandler(BackgroundWorker_DoWork);
            AgentTaskBackgroundWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(BackgroundWorker_RunWorkerCompleted);
            AgentTaskBackgroundWorker.ProgressChanged += new ProgressChangedEventHandler(BackgroundWorker_ProgressChanged);
            AgentTaskBackgroundWorker.RunWorkerAsync(args);
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // DisconnectAgentButton_Click()                   //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Terminates the active TCP/SSL connection
        //              with the remote agent.  The agent continues
        //              to listen for connections.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void DisconnectAgentButton_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show("Are you sure you want to disconnect from " + ConnectToAgentIP.Text + "?", "Disconnect from agent?", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            //make sure we are connected first
            if (!CurrentClient.IsConnected())
            {
                MessageBox.Show("Error:  Connection to client has been lost.");
                ToggleButtons(false, false);
                return;
            }

            //disable all buttons to prevent duplicate commands
            ToggleButtons(false, false);

            //do lengthy operation in background worker thread
            //here we will need to setup any args the lengthy operation will need in the separate thread
            ArrayList args = new ArrayList();
            args.Add(CurrentClient);
            args.Add(CwConstants.AGENTCMD_NOMORECOMMANDS);
            args.Add(new string[] { "" });
            args.Add(CwConstants.STREAM_DEFAULT_READ_TIMEOUT);
            args.Add(true);
            AgentTaskBackgroundWorker = new BackgroundWorker();
            AgentTaskBackgroundWorker.WorkerReportsProgress = true;
            AgentTaskBackgroundWorker.DoWork += new DoWorkEventHandler(BackgroundWorker_DoWork);
            AgentTaskBackgroundWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(BackgroundWorker_RunWorkerCompleted);
            AgentTaskBackgroundWorker.ProgressChanged += new ProgressChangedEventHandler(BackgroundWorker_ProgressChanged);
            AgentTaskBackgroundWorker.RunWorkerAsync(args);
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // ConnectAgentButton_Click()                      //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Attempts to establish a new TCP/SSL
        //              connection with the remote server (ie, agent)
        //              using the PFX credentials.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void ConnectAgentButton_Click(object sender, EventArgs e)
        {
            //make sure the admin has supplied a PFX keystore file and password
            if (AC_CRED_PFX_FILENAME == null || AC_CRED_PFX_FILENAME == "" || AC_CRED_PFX_PASSWORD == null || AC_CRED_PFX_PASSWORD == "")
            {
                MessageBox.Show("You must supply a PFX/PKCS-12 certificate store file and password for this admin console.  This is required to communicate with the deployed agents securely.");
                return;
            }

            //make sure the PFX password is valid
            if (!CwCryptoHelper.IsValidPFXPassword(AC_CRED_PFX_FILENAME, AC_CRED_PFX_PASSWORD))
            {
                MessageBox.Show("The password supplied for the selected PFX file is invalid.");
                return;
            }

            //------------------------------------------
            //          CONNECT TO REMOTE AGENT
            //------------------------------------------
            string agentIP = ConnectToAgentIP.Text;
            int agentPort = int.Parse(ConnectToAgentPort.Text);

            //instantiate our SSL/TCP client class
            CurrentClient = new SslTcpClient();

            //set TCP client options for connection, encryption, and cert validation rules.
            CurrentClient.SetOptions(agentIP, agentPort, AC_CRED_IGNORE_REMOTE_CERT_NAME_MISMATCH, AC_CRED_IGNORE_REMOTE_CERT_CHAIN_ERRORS, AC_CRED_PFX_FILENAME, AC_CRED_PFX_PASSWORD);

            //connect to the agent
            try
            {
                CurrentClient.OpenConnection();
            }
            catch (Exception ex)
            {
                string err = ex.Message;
                if (CurrentClient.sslErrors != SslPolicyErrors.None)
                    err += "\n\nSSL errors:  " + CurrentClient.sslErrors.ToString();
                MessageBox.Show(err);
                return;
            }

            //go ahead and toggle the buttons to enabled
            ToggleButtons(true, false);

            //clear all panes/listviews/etc
            LogWindow.Clear();
            LastCommandPane.Clear();
            AgentResults_RegistryListview.Items.Clear();
            AgentResults_FileListview.Items.Clear();
            AgentResults_MemoryListview.Items.Clear();

            //set our own socket's read timeout to something high - a scan can take some time
            CurrentClient.SetStreamTimeout("read", CwConstants.STREAM_GETSYSTEMINFO_TASK_TIMEOUT);

            //------------------------------------------
            //          GET SYSTEM INFORMATION
            //------------------------------------------
            //do lengthy operation in background worker thread
            //here we will need to setup any args the lengthy operation will need in the separate thread
            ArrayList args = new ArrayList();
            args.Add(CurrentClient);
            args.Add(CwConstants.AGENTCMD_GETSYSTEMINFO);
            args.Add(new string[] { "" });
            args.Add(CwConstants.STREAM_GETSYSTEMINFO_TASK_TIMEOUT);
            args.Add(true);
            AgentTaskBackgroundWorker = new BackgroundWorker();
            AgentTaskBackgroundWorker.WorkerReportsProgress = true;
            AgentTaskBackgroundWorker.DoWork += new DoWorkEventHandler(BackgroundWorker_DoWork);
            AgentTaskBackgroundWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(BackgroundWorker_RunWorkerCompleted);
            AgentTaskBackgroundWorker.ProgressChanged += new ProgressChangedEventHandler(BackgroundWorker_ProgressChanged);
            AgentTaskBackgroundWorker.RunWorkerAsync(args);
        }

        #endregion

        #region GUI tasks

        /////////////////////////////////////////////////////
        //                                                 //
        // UpdateResultsListviews()                        //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Refreshes GUI listviews after scan 
        //              results are updated.  Uses global object
        //              'LastAnomalyReport.SignatureMatches'.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void UpdateResultsListviews()
        {
            AgentResults_RegistryListview.Items.Clear();
            AgentResults_FileListview.Items.Clear();
            AgentResults_MemoryListview.Items.Clear();
            SSDTAnomaliesListview.Items.Clear();
            Win32ApiDetoursListview.Items.Clear();
            DriverAnomaliesListview.Items.Clear();
            ProcessAnomaliesListview.Items.Clear();
            ProcessResourcesAnomaliesListview.Items.Clear();

            //-----------------------------------------------
            //           POPULATE SIGNATURE MATCHES
            //-----------------------------------------------
            #region POPULATE SIGNATURE MATCHES

            if (LastAnomalyReport.SignatureMatches != null)
            {
                //populate registry signature matches
                if (LastAnomalyReport.SignatureMatches.RegistrySignatureMatches != null)
                {
                    foreach (CwXML.RegistrySignatureMatch match in LastAnomalyReport.SignatureMatches.RegistrySignatureMatches)
                    {
                        ListViewItem lvi = new ListViewItem(new string[] { match.RegistryKeyName, match.RegistryValueName, match.RegistryValueData, match.RegistryChangeValueData, match.IsFileOnDisk.ToString(), match.Action, match.ActionSuccessful.ToString() });
                        AgentResults_RegistryListview.Items.Add(lvi);
                        
                        //set row icon
                        if (match.ActionSuccessful)
                            lvi.ImageIndex = 1;
                        else if (!match.ActionSuccessful)
                            lvi.ImageIndex = 0;
                        else
                            lvi.ImageIndex = 2;
                    }
                }
                //populate file signature matches
                if (LastAnomalyReport.SignatureMatches.FileSignatureMatches != null)
                {
                    foreach (CwXML.FileSignatureMatch match in LastAnomalyReport.SignatureMatches.FileSignatureMatches)
                    {
                        ListViewItem lvi = new ListViewItem(new string[] { match.FileName, match.FullPath, match.FileSize.ToString(), match.FileHash, match.FilePEHeaderSignature, match.FileCreationDate, match.FileLastAccessDate, match.FileLastModifiedDate, match.Action, match.ActionSuccessful.ToString() });
                        AgentResults_FileListview.Items.Add(lvi);

                        //set row icon
                        if (match.ActionSuccessful)
                            lvi.ImageIndex = 1;
                        else if (!match.ActionSuccessful)
                            lvi.ImageIndex = 0;
                        else
                            lvi.ImageIndex = 2;
                    }
                }
                //populate memory signature matches
                if (LastAnomalyReport.SignatureMatches.MemorySignatureMatches != null)
                {
                    foreach (CwXML.MemorySignatureMatch match in LastAnomalyReport.SignatureMatches.MemorySignatureMatches)
                    {
                        ListViewItem lvi = new ListViewItem(new string[] { match.ProcessId.ToString(), match.ParentProcessId.ToString(), match.ProcessName, match.MatchingBlock, match.SuspiciousHeapBlockRange, match.Keywords, match.ChildThreadIds, match.Action, match.ActionSuccessful.ToString() });
                        AgentResults_MemoryListview.Items.Add(lvi);

                        //set row icon
                        if (match.ActionSuccessful)
                            lvi.ImageIndex = 1;
                        else if (!match.ActionSuccessful)
                            lvi.ImageIndex = 0;
                        else
                            lvi.ImageIndex = 2;
                    }
                }
            }
            #endregion

            //-----------------------------------------------
            //           POPULATE HEURISTIC MATCHES
            //-----------------------------------------------
            #region POPULATE HEURISTIC MATCHES

            if (LastAnomalyReport.HeuristicMatches != null)
            {
                //populate KERNEL MODE heuristic matches
                if (LastAnomalyReport.HeuristicMatches.KernelModeMatches != null)
                {
                    CwXML.KernelModeHeuristicMatches matches = LastAnomalyReport.HeuristicMatches.KernelModeMatches;
                    CwXML.UserModeHeuristicMatches matches2 = LastAnomalyReport.HeuristicMatches.UserModeMatches;

                    #region KERNEL MODE HEURISTIC MATCHES

                    //-----------
                    //SSDT HOOKS
                    //-----------
                    //since there's only one SSDT, we only have one result
                    CwStructures.HOOKED_SSDT_TABLE SSDTHooks = matches.SSDTHookTable;
                    for (int i = 0; i < SSDTHooks.NumHookedEntries; i++)
                    {
                        CwStructures.HOOKED_SSDT_ENTRY he = SSDTHooks.HookedEntries[i];

                        ListViewItem lvi = new ListViewItem(new string[] { he.ServiceIndex.ToString(), "0x"+he.ServiceFunctionAddress.ToString("x").ToUpper(), "Hook", he.ServiceFunctionNameExpected, he.ServiceFunctionNameFound, he.ContainingModule, "N/A", "N/A" });
                        SSDTAnomaliesListview.Items.Add(lvi);

                        //set row icon (0=Hook)
                        lvi.ImageIndex = 0;
                    }
                    //-----------
                    //SSDT DETOURS
                    //-----------
                    //since there's only one SSDT, we only have one result
                    CwStructures.DETOURED_SSDT_TABLE SSDTDetours = matches.SSDTDetourTable;
                    for (int i = 0; i < SSDTDetours.NumDetouredEntries; i++)
                    {
                        CwStructures.DETOURED_SSDT_ENTRY de = SSDTDetours.DetouredEntries[i];

                        ListViewItem lvi = new ListViewItem(new string[] { de.ServiceIndex.ToString(), "0x" + de.ServiceFunctionAddress.ToString("x").ToUpper(), "Detour", de.ServiceFunctionNameExpected, de.ServiceFunctionNameFound, de.ContainingModule, "0x" + de.TargetAddress.ToString("x"), de.Disassembly });
                        SSDTAnomaliesListview.Items.Add(lvi);

                        //set row icon (1=Detour)
                        lvi.ImageIndex = 1;
                    }
                    //-----------
                    //WIN32 API DETOURS
                    //-----------
                    //since we can pass multiple DLLs to be checked, there's an array of results
                    if (matches.Win32DetourTable != null)
                    {
                        CwStructures.WIN32API_DETOUR_TABLE[] Win32DetourTables = matches.Win32DetourTable;
                        for (int j = 0; j < Win32DetourTables.Length; j++)
                        {
                            if (Win32DetourTables[j].NumDetours == 0)
                                continue;

                            //get the detours for this DLL
                            CwStructures.WIN32API_DETOUR_ENTRY[] entries = Win32DetourTables[j].Win32Detours;

                            //create listview row for each detour in this module
                            for (int i = 0; i < entries.Length; i++)
                            {
                                CwStructures.WIN32API_DETOUR_ENTRY de = entries[i];

                                string anomalytype = "";
                                if (de.IsDetoured)
                                    anomalytype = "Detour";
                                else if (de.IsUnknown)
                                    anomalytype = "Unnamed";

                                ListViewItem lvi = new ListViewItem(new string[] { Win32DetourTables[j].ModuleName, de.ExportName, "0x" + de.ExportAddress.ToString("x").ToUpper(), anomalytype, "0x" + de.TargetAddress.ToString("x").ToUpper(), de.DetouringModule, de.Disassembly });

                                Win32ApiDetoursListview.Items.Add(lvi);

                                //set row icon (1=Detour)
                                lvi.ImageIndex = 1;
                            }
                        }
                    }
                    //-----------
                    //IRP HOOKS
                    //-----------
                    //since we can pass multiple drivers to be checked, there's an array of results
                    if (matches.DriverIrpHooksTable != null)
                    {
                        CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE[] IrpHooks = matches.DriverIrpHooksTable;
                        foreach (CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE HookTable in IrpHooks)
                        {
                            if (HookTable.NumHookedEntries == 0)
                                continue;

                            CwStructures.HOOKED_DISPATCH_FUNCTION_ENTRY[] entries = HookTable.HookedEntries;

                            //create listview row for each detour in this module
                            for (int i = 0; i < entries.Length; i++)
                            {
                                CwStructures.HOOKED_DISPATCH_FUNCTION_ENTRY de = entries[i];

                                string anomalytype = "";
                                if (de.IrpMajorFunctionHooked != 0)
                                    anomalytype = "Hook";
                                else //skip normal entries
                                    continue;

                                ListViewItem lvi = new ListViewItem(new string[] { HookTable.DriverName.Buffer + " (" + HookTable.DriverDeviceName.Buffer + ")", de.DispatchFunctionName, CwAgent.Win32Helper.GetIrpMjNameFromCode(de.IrpMajorFunctionHooked), "0x" + de.DispatchFunctionAddress.ToString("x").ToUpper(), anomalytype, "N/A", de.ContainingModule, "N/A" });

                                DriverAnomaliesListview.Items.Add(lvi);

                                //set row icon (0=Hook)
                                lvi.ImageIndex = 0;
                            }
                        }
                    }
                    //-----------
                    //IRP DETOURS
                    //-----------
                    //since we can pass multiple drivers to be checked, there's an array of results
                    if (matches.DriverIrpDetoursTable != null)
                    {
                        CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE[] IrpDetoursTable = matches.DriverIrpDetoursTable;
                        for (int j = 0; j < IrpDetoursTable.Length; j++)
                        {
                            if (IrpDetoursTable[j].NumDetours == 0)
                                continue;

                            //get the detours for this DLL
                            CwStructures.DETOURED_DISPATCH_FUNCTION_ENTRY[] entries = IrpDetoursTable[j].DetouredEntries;

                            //create listview row for each detour in this module
                            for (int i = 0; i < entries.Length; i++)
                            {
                                CwStructures.DETOURED_DISPATCH_FUNCTION_ENTRY de = entries[i];

                                string anomalytype = "";
                                if (de.IsDetoured)
                                    anomalytype = "Detour";
                                else if (de.IsUnknown)
                                    anomalytype = "Unnamed";
                                else //skip normal entries
                                    continue;

                                ListViewItem lvi = new ListViewItem(new string[] { IrpDetoursTable[j].DriverName.Buffer + " (" + IrpDetoursTable[j].DriverDeviceName.Buffer + ")", de.DispatchFunctionName, "N/A", "0x" + de.DispatchFunctionAddress.ToString("x").ToUpper(), anomalytype, "0x" + de.TargetAddress.ToString("x").ToUpper(), de.DetouringModule, de.Disassembly });

                                DriverAnomaliesListview.Items.Add(lvi);

                                //set row icon (1=Detour)
                                lvi.ImageIndex = 1;
                            }
                        }
                    }
                    #endregion

                    #region USER MODE HEURISTIC MATCHES

                    //-----------
                    //IRP DETOURS
                    //-----------
                    //since we can pass multiple drivers to be checked, there's an array of results
                    if (matches2 != null && matches2.ProcessListing != null)
                    {
                        CwStructures.CWPROCESS_RECORD[] ProcessListing = matches2.ProcessListing;
                        for (int j = 0; j < ProcessListing.Length; j++)
                        {
                            string anomalytype = "";
                            if (ProcessListing[j].NotInList == null)
                                anomalytype = "<none>";
                            else
                                anomalytype = string.Join(",", ProcessListing[j].NotInList);

                            ListViewItem lvi = new ListViewItem(new string[] { ProcessListing[j].pid.ToString(), ProcessListing[j].ppid.ToString(), ProcessListing[j].name, anomalytype, ProcessListing[j].modulePath });

                            ProcessAnomaliesListview.Items.Add(lvi);

                            //3=hidden process
                            if (anomalytype != "<none>")
                                lvi.ImageIndex = 3;
                            //2=normal process
                            else
                                lvi.ImageIndex = 2;
                        }
                    }

                    #endregion

                }
                //populate USER MODE heuristic matches
                if (LastAnomalyReport.HeuristicMatches.UserModeMatches != null)
                {

                }
            }

            #endregion

        }

        /////////////////////////////////////////////////////
        //                                                 //
        // UpdateSystemInformationListview()               //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Refreshes GUI listview for system
        //              information after we first connects 
        //              to the remote agent.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void UpdateSystemInformationListview()
        {
            systemInfoTextarea.Text = "";

            if (LatestSystemInformation != null)
            {
                CwXML.HostInformation hostinfo = LatestSystemInformation.HostInformation;
                CwXML.AgentInformation agentinfo = LatestSystemInformation.AgentInformation;

                systemInfoTextarea.Text = "\r\n++++++++++++++++++++++++++++++++++++++++++++\r\n";
                systemInfoTextarea.Text += "                    HOST INFORMATION\r\n";
                systemInfoTextarea.Text += "\r\n++++++++++++++++++++++++++++++++++++++++++++\r\n";
                //HOSTINFO
                foreach (FieldInfo f in hostinfo.GetType().GetFields())
                    systemInfoTextarea.Text += f.Name + ":  " + (string)f.GetValue(hostinfo) + "\r\n";

                systemInfoTextarea.Text += "\r\n++++++++++++++++++++++++++++++++++++++++++++\r\n";
                systemInfoTextarea.Text += "                    AGENT INFORMATION\r\n";
                systemInfoTextarea.Text += "\r\n++++++++++++++++++++++++++++++++++++++++++++\r\n";
                //AGENTINFO
                CwXML.CodewordSettingsTemplate cst = agentinfo.AgentSettings;
                CwXML.CodewordSignatureTemplate sigs = agentinfo.AgentSignatures;
                systemInfoTextarea.Text += "Agent version:  " + agentinfo.Version + "\r\n";
                systemInfoTextarea.Text += "Agent settings:\r\n";
                int count = 0;
                foreach (string s in cst.FormElementNames)
                {
                    systemInfoTextarea.Text += s + ":  " + cst.FormElementValues[count] + "\r\n";
                    count++;
                }
                systemInfoTextarea.Text += "Agent signatures:\r\n";
                MemoryStream ms = new MemoryStream();
                XmlSerializer xml = new XmlSerializer(typeof(CwXML.CodewordSignatureTemplate));
                xml.Serialize(ms, sigs);
                char[] xmldata = Encoding.UTF8.GetChars(ms.ToArray());
                systemInfoTextarea.Text += new string(xmldata);
                ms.Close();
                systemInfoTextarea.Refresh();
            }
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // CopyResponseToLogWindow()                       //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  copies the fields of the given response
        //              object to the log window pane.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void CopyResponseToLogWindow(CwXML.CodewordAgentResponse response)
        {
            string currentLogWindowText = LogWindow.Text;
            string newLogText = "";

            LastCommandPane.Text = "";
            LastCommandPane.Text += "COMMAND:  " + response.CommandCodeReceived.ToString() + "\r\n";
            LastCommandPane.Text += "RESPONSE:  " + response.ResponseCode + "\r\n";

            //ResponseInfo is optional, so check for null
            if (response.ResponseInfo != null)
                LastCommandPane.Text += "INFO:  " + response.ResponseInfo + "\r\n";

            //ResponseLog is optional, so check for null
            if (response.ResponseLog != null)
                newLogText += response.ResponseLog.Replace("\n", "\r\n");
            //ResponseData is optional
            if (response.ResponseData != null)
                newLogText += response.ResponseData.Replace("\n", "\r\n");

            //tack on the new info to the top of the log window
            if (newLogText != "")
                newLogText += "\r\n\r\n++++++++++++++++++++++++++++++\r\n";

            LogWindow.Text = newLogText+currentLogWindowText+"\r\n";
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // ToggleButtons()                                 //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Enables/disables GUI elements as the
        //              connection is created/closed.
        //
        //              note:  if applyToAll is TRUE, then the
        //              value in isConnected is applied to all
        //              buttons in the control.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void ToggleButtons(bool isConnected, bool applyToAll)
        {
            bool buttonsEnabled = false;
            bool connectFormElementsEnabled = true;

            if (isConnected)
            {
                buttonsEnabled = true;
                connectFormElementsEnabled = false;
            }

            if (applyToAll)
            {
                buttonsEnabled = isConnected;
                connectFormElementsEnabled = isConnected;
            }

            //enable toolbar buttons
            StartScanButton.Enabled = buttonsEnabled;
            UpdateAgentButton.Enabled = buttonsEnabled;
            DownloadEvidenceButton.Enabled = buttonsEnabled;
            PerformMitigationTasksButton.Enabled = buttonsEnabled;
            DisconnectAgentButton.Enabled = buttonsEnabled;
            HaltAgentButton.Enabled = buttonsEnabled;

            //disable connect button
            ConnectToAgentIP.Enabled = connectFormElementsEnabled;
            ConnectToAgentPort.Enabled = connectFormElementsEnabled;
            ConnectAgentButton.Enabled = connectFormElementsEnabled;

            ConnectAgentToolstrip.Refresh();
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // FindAndUpdateMatchRecord()                      //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Updates the signature findings listviews
        //              with the result of a mitigation operation
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void FindAndUpdateMatchRecords(CwXML.CodewordAgentSignatureMatches updatedMatchRecords)
        {
            //--------------------------------------
            //                REGISTRY
            //--------------------------------------
            if (updatedMatchRecords.RegistrySignatureMatches != null)
            {
                CwXML.RegistrySignatureMatch[] regMatches = updatedMatchRecords.RegistrySignatureMatches;

                //loop through all registry signature matches that were mitigated, trying to find a 
                //corresponding signature match in our old global var.
                foreach (CwXML.RegistrySignatureMatch rNew in regMatches)
                {
                    int matchIndex = 0;
                    //loop through all the signature matches currently stored in our global var.
                    foreach (CwXML.RegistrySignatureMatch rOld in LastAnomalyReport.SignatureMatches.RegistrySignatureMatches)
                    {
                        if (rOld.RegistryKeyName == rNew.RegistryKeyName &&
                            rOld.RegistryValueName == rNew.RegistryValueName &&
                            rOld.Action == rNew.Action)
                        {
                            LastAnomalyReport.SignatureMatches.RegistrySignatureMatches[matchIndex].ActionSuccessful = rNew.ActionSuccessful;
                            break;
                        }
                        matchIndex++;
                    }
                }
            }
            //--------------------------------------
            //                FILE
            //--------------------------------------
            if (updatedMatchRecords.FileSignatureMatches != null)
            {
                CwXML.FileSignatureMatch[] fileMatches = updatedMatchRecords.FileSignatureMatches;

                //loop through all file signature matches that were mitigated, trying to find a 
                //corresponding signature match in our old global var.
                foreach (CwXML.FileSignatureMatch fNew in fileMatches)
                {
                    int matchIndex = 0;
                    //loop through all the signature matches currently stored in our global var.
                    foreach (CwXML.FileSignatureMatch fOld in LastAnomalyReport.SignatureMatches.FileSignatureMatches)
                    {
                        if (fOld.FullPath == fNew.FullPath &&
                            fOld.FileSize == fNew.FileSize &&
                            fOld.FileHash == fNew.FileHash &&
                            fOld.Action == fNew.Action)
                        {
                            LastAnomalyReport.SignatureMatches.FileSignatureMatches[matchIndex].ActionSuccessful = fNew.ActionSuccessful;
                            break;
                        }
                        matchIndex++;
                    }
                }
            }
            //--------------------------------------
            //                MEMORY
            //--------------------------------------
            if (updatedMatchRecords.MemorySignatureMatches != null)
            {
                CwXML.MemorySignatureMatch[] memMatches = updatedMatchRecords.MemorySignatureMatches;

                //loop through all memory signature matches that were mitigated, trying to find a 
                //corresponding signature match in our old global var.
                foreach (CwXML.MemorySignatureMatch mNew in memMatches)
                {
                    int matchIndex = 0;
                    //loop through all the signature matches currently stored in our global var.
                    foreach (CwXML.MemorySignatureMatch mOld in LastAnomalyReport.SignatureMatches.MemorySignatureMatches)
                    {
                        if (mOld.ProcessId == mNew.ProcessId &&
                            mOld.ProcessName == mNew.ProcessName)
                        {
                            LastAnomalyReport.SignatureMatches.MemorySignatureMatches[matchIndex].ActionSuccessful = mNew.ActionSuccessful;
                            break;
                        }
                        matchIndex++;
                    }
                }
            }
        }

        #endregion

        #region background worker thread

        /////////////////////////////////////////////////////
        //                                                 //
        // BackgroundWorker_RunWorkerCompleted()           //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  This function is called when the background
        //              worker thread signals that it is finished.
        //              It runs in the context of the main thread,
        //              so it is safe to modify GUI or reference
        //              main thread global variables here.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void BackgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            ArrayList result = (ArrayList)e.Result;
            int commandSent = (int)result[0];
            //cast the response object from the thread's result object
            CwXML.CodewordAgentResponse response = (CwXML.CodewordAgentResponse)result[1];

            //if there are 3 objects in this arraylist, we KNOW the command failed.
            //if (result.Count == 3)
            if (response == null)
            {
                /*
                int errorCode = (int)result[1];
                string errMsg = (string)result[2];

                if (errorCode == CwConstants.ADMINCONSOLE_ERROR_CMDFAILED)
                    MessageBox.Show("Failed to send command " + commandSent.ToString() + ":  " + errMsg);
                else
                    MessageBox.Show("Failed to receive response:  " + errMsg);
                */

                MessageBox.Show("No response was sent from the client.");
                if (!CurrentClient.IsConnected())
                    ToggleButtons(false, false);

                AgentTaskProgressBarLabel.Text = "Task complete.";
                AgentTaskProgressBar.Value = 0;
                AgentTaskProgressBar.Refresh();
                AgentTaskProgressBarLabel.Refresh();

                //always re-enable all buttons if the command failed
                ToggleButtons(true, false);

                return;
            }

            //-------------------------------------------------------------
            //                                                            
            //                  GET SYSTEM INFORMATION
            //
            //-------------------------------------------------------------
            #region GET SYSTEM INFORMATION
            if (commandSent == CwConstants.AGENTCMD_GETSYSTEMINFO)
            {
                //extract the agent results object
                if (response.ResponseSystemInformation != null)
                {
                    //save in our global variable
                    LatestSystemInformation = response.ResponseSystemInformation;
                    //force GUI update
                    UpdateSystemInformationListview();
                }

                CopyResponseToLogWindow(response);

                //add to recently viewed agents
                string agentIP = ConnectToAgentIP.Text;
                int agentPort = int.Parse(ConnectToAgentPort.Text);
                bool addToList = true;
                foreach (TreeNode node in RecentAgentsTreeview.Nodes)
                    if (node.Text == agentIP)
                        addToList = false;
                if (addToList)
                    RecentAgentsTreeview.Nodes.Add(agentIP);
            }
            #endregion
            //-------------------------------------------------------------
            //                                                            
            //                  START A NEW SCAN
            //
            //-------------------------------------------------------------
            #region START A NEW SCAN
            else if (commandSent == CwConstants.AGENTCMD_STARTSCAN)
            {
                //extract the agent results object
                if (response.ResponseAnomalyReport != null)
                {
                    //save in our global variable
                    LastAnomalyReport = response.ResponseAnomalyReport;
                    //force GUI update
                    UpdateResultsListviews();
                }
            }
            #endregion
            //-------------------------------------------------------------
            //                                                            
            //              SEND NEW SIGNATURE FILE
            //
            //-------------------------------------------------------------
            #region SEND NEW SIGNATURE FILE
            else if (commandSent == CwConstants.AGENTCMD_UPDATESIG)
            {
                //CASE 1:  we are arriving from the first thread completing, in which case we need
                //to send the actual update file
                if (response.ResponseCode == CwConstants.AGENTRESPONSE_OK_SENDFILE)
                {
                    //we have to do something tricky here, so that our DoWork() function
                    //doesnt send the internal command AGENTCMD_SENDUPDATEFILE to the remote agent.
                    //create a second thread to actually send the update file.
                    //we previously created a thread to send the command to notify the agent we are
                    //about to send a file.  we are at the point right now where the response from
                    //the agent has been received, and it is awaiting the actual file.  so send it.
                    ArrayList args = new ArrayList();
                    args.Add(CurrentClient);
                    args.Add(CwConstants.AGENTCMD_SENDUPDATEFILE);
                    args.Add(new string[] { "" });
                    args.Add(CwConstants.STREAM_UPDATE_SIGNATURES_TIMEOUT);
                    args.Add(true);
                    AgentTaskBackgroundWorker = new BackgroundWorker();
                    AgentTaskBackgroundWorker.WorkerReportsProgress = true;
                    AgentTaskBackgroundWorker.DoWork += new DoWorkEventHandler(BackgroundWorker_DoWork);
                    AgentTaskBackgroundWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(BackgroundWorker_RunWorkerCompleted);
                    AgentTaskBackgroundWorker.ProgressChanged += new ProgressChangedEventHandler(BackgroundWorker_ProgressChanged);
                    AgentTaskBackgroundWorker.RunWorkerAsync(args);
                }
                //CASE 2:  we are arriving from the second thread completing, in which case
                //we are done; the update file was sent and received successfully.
                else
                {
                    //..and we dont need to do anything!
                }
            }
            #endregion
            //-------------------------------------------------------------
            //                                                            
            //                      MITIGATE ITEMS
            //
            //-------------------------------------------------------------
            #region MITIGATE ITEMS
            else if (commandSent == CwConstants.AGENTCMD_MITIGATE)
            {
                if (LastAnomalyReport == null)
                    LastAnomalyReport = new CwXML.CodewordAgentAnomalyReport();

                if (response.ResponseAnomalyReport != null)
                {
                    //update our signatures listview with the copy we got back.
                    //the copy sent back to us contains ONLY THE FINDINGS THAT WERE MITIGATED.
                    //since the user has the option of selecting only a few for mitigation, we must
                    //search through all of the results in the GUI and update the ones that were changed.
                    FindAndUpdateMatchRecords(response.ResponseAnomalyReport.SignatureMatches);

                    //now repopulate the listviews with the udpated match records.
                    UpdateResultsListviews();
                }
            }
            #endregion
            //-------------------------------------------------------------
            //                                                            
            //                 COLLECT EVIDENCE ITEMS
            //
            //-------------------------------------------------------------
            #region COLLECT EVIDENCE ITEMS
            else if (commandSent == CwConstants.AGENTCMD_COLLECT)
            {
                //CASE 1:  we are arriving from the first thread completing, in which case we need
                //to prepare to receive the evidence files - send an internal msg to ourselves
                if (response.ResponseCode == CwConstants.AGENTRESPONSE_OK_RECVFILE)
                {
                    //we have to do something tricky here, so that our DoWork() function
                    //doesnt send the internal command AGENTCMD_RECVEVIDENCEFILE to the remote agent.
                    //create a second thread to actually receive the evidence file.
                    //we previously created a thread to send the command to notify the agent we want it
                    //to find and send us a file.  we are at the point right now where the response from
                    //the agent has been received, and it is waiting to send us the file.  so grab it!
                    ArrayList args = new ArrayList();
                    args.Add(CurrentClient);
                    args.Add(CwConstants.AGENTCMD_RECVEVIDENCEFILES);
                    args.Add(new string[] { "" });
                    args.Add(CwConstants.STREAM_COLLECT_TASK_TIMEOUT);
                    args.Add(true);
                    args.Add(LastCollectionTask);
                    AgentTaskBackgroundWorker = new BackgroundWorker();
                    AgentTaskBackgroundWorker.WorkerReportsProgress = true;
                    AgentTaskBackgroundWorker.DoWork += new DoWorkEventHandler(BackgroundWorker_DoWork);
                    AgentTaskBackgroundWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(BackgroundWorker_RunWorkerCompleted);
                    AgentTaskBackgroundWorker.ProgressChanged += new ProgressChangedEventHandler(BackgroundWorker_ProgressChanged);
                    AgentTaskBackgroundWorker.RunWorkerAsync(args);
                }
                //CASE 2:  we are arriving from the second thread completing, in which case
                //we are done downloading.
                else
                {
                    //nothing to do..
                }
            }
            #endregion
            //-------------------------------------------------------------
            //                                                            
            //                      DISCONNECT 
            //
            //-------------------------------------------------------------
            #region DISCONNECT
            else if (commandSent == CwConstants.AGENTCMD_NOMORECOMMANDS)
            {
                //make sure the remote end didnt terminate first
                if (CurrentClient.IsConnected())
                    CurrentClient.CloseConnection();

                CurrentClient = null;
            }
            #endregion

            CopyResponseToLogWindow(response);

            AgentTaskProgressBarLabel.Text = "Task complete.";
            AgentTaskProgressBar.Value = 0;
            AgentTaskProgressBar.Refresh();
            AgentTaskProgressBarLabel.Refresh();

            //always re-enable toolbar buttons unless this was a disconnect or halt command
            if (commandSent == CwConstants.AGENTCMD_EXIT || commandSent == CwConstants.AGENTCMD_NOMORECOMMANDS)
                ToggleButtons(false, false);
            else
                ToggleButtons(true, false);
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // BackgroundWorker_DoWork()                       //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  This function is called as the entry point
        //              to the background worker thread which handles
        //              lengthy operations on behalf of the main
        //              GUI thread, so that the UI doesn't stall.
        //
        //              NOTE:  Since this function runs in a separate
        //              thread, it does not have access to any global
        //              variables or GUI controls from the main thread.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void BackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            //get arguments
            ArrayList args = (ArrayList)e.Argument;
            SslTcpClient client = (SslTcpClient)args[0];
            int agentCommand = (int)args[1];
            string[] parameters = (string[])args[2];
            int timeout = (int)args[3];
            bool required = (bool)args[4];
            CwXML.CodewordAgentAnomalyReport CollectionOrMitigationTask = new CwXML.CodewordAgentAnomalyReport();
            //this 6th argument is ONLY used when we are sending a MITIGATION command
            if (args.Count == 6)
                CollectionOrMitigationTask = (CwXML.CodewordAgentAnomalyReport)args[5];

            //setup return object
            //return the agent command issued even if an error occurs
            ArrayList result = new ArrayList();
            result.Add(agentCommand);

            //send command
            try
            {
                //------------------------------------------------
                //          AGENT COMMAND PRE-PROCESSING
                //------------------------------------------------
                //*DO NOT* forward this command to the agent. 
                //send the XML update file the agent is waiting on.
                if (agentCommand == CwConstants.AGENTCMD_SENDUPDATEFILE)
                {
                    client.SendFile(UpdateFilename);
                }
                //*DO NOT* forward this command to the agent. 
                //receive the evidence files the agent is waiting to send us.
                else if (agentCommand == CwConstants.AGENTCMD_RECVEVIDENCEFILES)
                {
                    //get the file names and file sizes to download - this will be used in ReceiveFiles()
                    CwXML.FileSignatureMatch[] fileSigsToDownload = CollectionOrMitigationTask.SignatureMatches.FileSignatureMatches;
                    client.ReceiveFiles(SaveCollectionEvidenceToFolder,fileSigsToDownload);
                }
                //*DO* forward this command to the agent for direct processing.
                else
                {
                    client.SendCommand(agentCommand, parameters, timeout, required, CollectionOrMitigationTask);
                }
            }
            catch (Exception ex)
            {
                /*
                result.Add(CwConstants.ADMINCONSOLE_ERROR_CMDFAILED);
                result.Add(ex.Message);
                e.Result = result;
                return;
                 * */
            }

            AgentTaskBackgroundWorker.ReportProgress(50);

            //receive response
            CwXML.CodewordAgentResponse response = null;

            try
            {
                response = client.ReadResponse();
            }
            catch (Exception ex)
            {
                /*
                result.Add(CwConstants.ADMINCONSOLE_ERROR_RESPONSEFAILED);
                result.Add(ex.Message);
                e.Result = result;
                return;
                 * */
            }

            AgentTaskBackgroundWorker.ReportProgress(100);

            //add the response object to the return
            result.Add(response);
            e.Result = result;
            return;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // BackgroundWorker_ProgressChanged()              //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  This function is called by the background
        //              worker thread whenever there is an update
        //              for the main thread to process.  It runs in
        //              the context of the main GUI thread, so it is
        //              safe to reference main thread vars/controls.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void BackgroundWorker_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            if (e.ProgressPercentage == 50)
                AgentTaskProgressBarLabel.Text = "Command sent, awaiting response...";
            else
                AgentTaskProgressBarLabel.Text = "Response received, processing...";
            
            AgentTaskProgressBarLabel.Refresh();
            AgentTaskProgressBar.Value = e.ProgressPercentage;
            AgentTaskProgressBar.Refresh();
        }

        #endregion

    }
}
