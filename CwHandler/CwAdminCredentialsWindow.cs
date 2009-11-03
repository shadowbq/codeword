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
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace CwHandler
{
    public partial class CwAdminCredentialsWindow : Form
    {
        public delegate void SetParameterValueDelegate(string name, string value);
        public SetParameterValueDelegate SetParameterValueCallback;

        public CwAdminCredentialsWindow(ArrayList parms)
        {
            InitializeComponent();

            if (parms.Count == 0)
                return;

            //load the values we stored last time, or the defaults if empty
            AdminConsolePFXFilename.Text = (string)parms[0];
            AdminConsolePFXPassword.Text = (string)parms[1];
            IgnoreCertError_RemoteCertificateNameMismatch.Checked = (bool)parms[2];
            IgnoreCertError_RemoteCertificateChainErrors.Checked = (bool)parms[3];
        }

        private void CwAdminCredentialsWindow_FormClosing(object sender, FormClosingEventArgs e)
        {
            //notify our parent form of the new values via registered callback
            SetParameterValueCallback("AC_CRED_PFX_FILENAME", AdminConsolePFXFilename.Text);
            SetParameterValueCallback("AC_CRED_PFX_PASSWORD", AdminConsolePFXPassword.Text);
            SetParameterValueCallback("AC_CRED_IGNORE_REMOTE_CERT_NAME_MISMATCH", IgnoreCertError_RemoteCertificateNameMismatch.Checked.ToString());
            SetParameterValueCallback("AC_CRED_IGNORE_REMOTE_CERT_CHAIN_ERRORS", IgnoreCertError_RemoteCertificateChainErrors.Checked.ToString());
        }

        private void CwCredSetButton_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void CwCredBrowseButton_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.CheckFileExists = true;
            ofd.Multiselect = false;
            ofd.Filter = "PKCS-12 Files|*.p12;*.pfx;*.pkcs12";
            ofd.Title = "Select a PKCS-12 formatted file";

            if (ofd.ShowDialog() == DialogResult.OK)
            {
                if (!CwCryptoHelper.IsValidPFX(ofd.FileName))
                {
                    MessageBox.Show("Invalid PFX file.");
                    return;
                }
                else
                    AdminConsolePFXFilename.Text = ofd.FileName;
            }
        }
    }
}