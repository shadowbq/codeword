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
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;





/*








                NOTE:  This file is not used in this project, but is kept on file as a good example
 *              of a popup window communicating values with the parent window.  Please do not remove.




below is the code to call this class:
 * 
            CwAdminMitigationWindow mitigateWindow = new CwAdminMitigationWindow(LastAnomalyReport.SignatureMatches,CurrentClient);

            //register a callback so we are notified when the child form is closing
            //this is because we want to save the CwAgentMatches object
            mitigateWindow.SetParameterValueCallback = new CwAdminMitigationWindow.SetParameterValueDelegate(SaveMitigationTaskResult);
            mitigateWindow.ShowDialog();












*/







namespace CwHandler
{
    public partial class CwAdminMitigationWindow : Form
    {
        public delegate void SetParameterValueDelegate(CwXML.CodewordAgentSignatureMatches m);
        public SetParameterValueDelegate SetParameterValueCallback;
        private CwXML.CodewordAgentSignatureMatches matches;
        private SslTcpClient CurrentClient;

        /////////////////////////////////////////////////////
        //                                                 //
        // CwAdminMitigationWindow()                       //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Constructor
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        internal CwAdminMitigationWindow(CwXML.CodewordAgentSignatureMatches m, SslTcpClient c)
        {
            InitializeComponent();
            matches=m;
            CurrentClient = c;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // MitigationTasksGoButton_Click()                 //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Carries out mitigation tasks.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void MitigationTasksGoButton_Click(object sender, EventArgs e)
        {
            

            
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // CwAdminMitigationWindow_FormClosing()           //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Notifies parent window we are closing
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void CwAdminMitigationWindow_FormClosing(object sender, FormClosingEventArgs e)
        {
            //notify our parent form of the new values via registered callback
            SetParameterValueCallback(matches);
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // MitigationTasksCloseButton_Click()              //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Closes the window
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void MitigationTasksCloseButton_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // CwAdminMitigationWindow_Shown()                 //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Called when the window loads.  This
        //              function populates the listview.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        private void CwAdminMitigationWindow_Shown(object sender, EventArgs e)
        {
            CwXML.RegistrySignatureMatch[] regMatches = matches.RegistrySignatureMatches;
            CwXML.FileSignatureMatch[] fileMatches = matches.FileSignatureMatches;
            CwXML.MemorySignatureMatch[] memMatches = matches.MemorySignatureMatches;

            foreach (CwXML.RegistrySignatureMatch r in regMatches)
            {
                ListViewItem lvi = new ListViewItem(new string[] { "Registry", r.Action, r.RegistryKeyName });

                //only show unique mitigation actions - we may have multiple results in findings for a single action
                if (!MitigationTasksListview.Items.Contains(lvi))
                    MitigationTasksListview.Items.Add(lvi);
            }
            foreach (CwXML.FileSignatureMatch f in fileMatches)
            {
                ListViewItem lvi = new ListViewItem(new string[] { "File", f.Action, f.FullPath });

                //only show unique mitigation actions - we may have multiple results in findings for a single action
                if (!MitigationTasksListview.Items.Contains(lvi))
                    MitigationTasksListview.Items.Add(lvi);
            }
            foreach (CwXML.MemorySignatureMatch m in memMatches)
            {
                ListViewItem lvi = new ListViewItem(new string[] { "Memory", m.Action, m.ProcessName+"("+m.ProcessId.ToString()+")" });

                //only show unique mitigation actions - we may have multiple results in findings for a single action
                if (!MitigationTasksListview.Items.Contains(lvi))
                    MitigationTasksListview.Items.Add(lvi);
            }
        }
    }
}
