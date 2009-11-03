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

namespace CwHandler
{
    internal partial class CwAdminConsole
    {
        ///////////////////////////////////////////////////////////////////////////////////
        //
        //
        //                      GENERIC HELPER FUNCTIONS
        //
        //
        ///////////////////////////////////////////////////////////////////////////////////

        #region Generic Helper functions

        //
        //verifies the given string is an MD5 hash, returning true if so
        //
        private bool validateMD5(string MD5_HashToValidate)
        {
            Regex md5validator = new Regex("^[0-9a-fA-F]{32}$");
            if (md5validator.IsMatch(MD5_HashToValidate))
                return true;
            else
                return false;
        }

        //
        //verifies the given string is a SHA-1 hash, returning true if so
        //
        private bool validateSHA1(string SHA1_HashToValidate)
        {
            Regex sha1validator = new Regex("^[0-9a-fA-F]{40}$");
            if (sha1validator.IsMatch(SHA1_HashToValidate))
                return true;
            else
                return false;
        }

        //
        //searches the given STRING array for specified value, returning true if found
        //
        internal bool InArray(string needle, string[] haystack)
        {
            foreach (string s in haystack)
                if (s.Equals(needle))
                    return true;
            return false;
        }

        //
        //returns the index of the item within the given combobox that matches the supplied string
        //
        internal int GetComboBoxIndex(string value, ComboBox c)
        {
            int ct = 0;
            foreach (string s in c.Items)
            {
                if (s == value)
                    return ct;
                ct++;
            }
            return 0;
        }

        //
        //this function crawls all tab pages to extract information/data for loading/saving
        //an XML settings document that can be retrieved later.
        //the second and third arguments are optional, only used for setting form value when loading
        //
        internal object CrawlTabPages(string command, string elementName, string elementValue)
        {
            int count = 0;

            //if the command is to get form name/value, we will use this array
            ArrayList returnArray = new ArrayList();

            //this is for debugging purposes only.
            //StreamWriter sw = new StreamWriter("FormObjects.txt");

            //Now loop through the controls for the main settings tab container
            foreach (Control c in CreateNewAgentTabPage.Controls)
            {
                //sw.WriteLine("+CreateNewAgentTabPage [TabPage]");

                //if it's a tab control (a container for tabpages)...
                if (c is TabControl)
                {
                    //sw.WriteLine("  +" + c.Name + " [TabControl]");

                    //..then search all of its subordinate tabpages for the types we care about.
                    foreach (Control c2 in c.Controls)
                    {
                        if (c2 is TabPage)
                        {
                            //sw.WriteLine("    +" + c2.Name + " [TabPage]");

                            //loop through all controls in this tab page for the types we care about.
                            foreach (Control c3 in c2.Controls)
                            {
                                //skip all other controls..
                                if (!(c3 is CheckBox) && !(c3 is RadioButton) &&
                                    !(c3 is TextBox) && !(c3 is ComboBox) &&
                                    !(c3 is GroupBox) && !(c3 is Panel) && !(c3 is ListView))
                                {
                                    //sw.WriteLine("      -" + c3.Name + " [" + c3.GetType().ToString() + "] - SKIPPED");
                                    continue;
                                }

                                ArrayList ChildItems = new ArrayList();

                                //if the control is a GroupBox or a Panel, we want to get to its child controls
                                if (c3 is GroupBox || c3 is Panel)
                                {
                                    foreach (Control c4 in c3.Controls)
                                    {
                                        //skip all other controls..
                                        if (!(c4 is CheckBox) && !(c4 is RadioButton) &&
                                            !(c4 is TextBox) && !(c4 is ComboBox))
                                        {
                                            //sw.WriteLine("        -" + c4.Name + " [" + c4.GetType().ToString() + "] - SKIPPED");
                                            continue;
                                        }

                                        //otherwise, add it to our list
                                        //sw.WriteLine("        -" + c4.Name + " [" + c4.GetType().ToString() + "] - ADDED");
                                        ChildItems.Add(c4);
                                    }
                                }
                                //if the control is a listview, this is a special case.  join all of the listview values
                                //into a string[] array and assign it to the listview name.
                                else if (c3 is ListView)
                                {
                                    //only do this for AddDriverListview for now
                                    if (c3.Name == "AddDriverListview")
                                        ChildItems.Add(c3);
                                    else
                                        continue;
                                }
                                //otherwise, we are on a form control that represents a combobox, textbox, checkbox, or radiobutton
                                else
                                {
                                    //sw.WriteLine("        -" + c3.Name + " [" + c3.GetType().ToString() + "] - ADDED");
                                    ChildItems.Add(c3);
                                }

                                //now loop through all child items and store them
                                foreach (Control c5 in (Control[])ChildItems.ToArray(typeof(Control)))
                                {
                                    //------------------------------------
                                    //      GET ELEMENT NAMES
                                    //------------------------------------
                                    if (command == "GetElementNames")
                                    {
                                        //store form element name - always the same for any control
                                        returnArray.Add(c5.Name);
                                    }
                                    //------------------------------------
                                    //      GET ELEMENT VALUES
                                    //------------------------------------
                                    else if (command == "GetElementValues")
                                    {
                                        //store form element value - changes based on control type
                                        if (c5 is CheckBox)
                                        {
                                            returnArray.Add(((CheckBox)c5).Checked.ToString());
                                        }
                                        else if (c5 is RadioButton)
                                        {
                                            returnArray.Add(((RadioButton)c5).Checked.ToString());
                                        }
                                        else if (c5 is TextBox)
                                        {
                                            returnArray.Add(c5.Text);
                                        }
                                        else if (c5 is ComboBox)
                                        {
                                            if (((ComboBox)c5).SelectedItem != null)
                                                returnArray.Add(((ComboBox)c5).SelectedItem.ToString());
                                            else
                                                returnArray.Add("");
                                        }
                                        else if (c5 is ListView)
                                        {
                                            foreach (ListViewItem lvi in ((ListView)c5).Items)
                                            {
                                                ArrayList subitems = new ArrayList();
                                                for (int x = 0; x < lvi.SubItems.Count; x++)
                                                    subitems.Add(lvi.SubItems[x].Text);
                                                returnArray.Add(string.Join(",", (string[])subitems.ToArray(typeof(string))));
                                            }
                                        }                                        
                                    }
                                    //------------------------------------
                                    //      SET FORM VALUE
                                    //------------------------------------
                                    else if (command == "SetFormValue")
                                    {
                                        //make sure we are on the right element before we set its value
                                        if (c5.Name == elementName)
                                        {
                                            //how we restore the value depends on the control type
                                            if (c5 is CheckBox)
                                            {
                                                //if the corresponding element value from the XML setting is TRUE
                                                //then check the checkbox; otherwise, clear it.
                                                if (elementValue == "True")
                                                    ((CheckBox)c5).Checked = true;
                                                else
                                                    ((CheckBox)c5).Checked = false;
                                            }
                                            else if (c5 is RadioButton)
                                            {
                                                if (elementValue == "True")
                                                    ((RadioButton)c5).Checked = true;
                                                else
                                                    ((RadioButton)c5).Checked = false;
                                            }
                                            else if (c5 is TextBox)
                                            {
                                                c5.Text = elementValue;
                                            }
                                            else if (c5 is ComboBox)
                                            {
                                                ((ComboBox)c5).SelectedIndex = GetComboBoxIndex(elementValue, ((ComboBox)c5));
                                            }
                                            else if (c5 is ListView)
                                            {
                                                //only one listview is handled right now
                                                if (c5.Name != "AddDriverListview")
                                                    continue;

                                                //values were stored as comma-separated list
                                                string[] items = elementValue.Split(new char[] { ',' });
                                                int ct=0;
                                                ListViewItem lvi;
                                                ArrayList subitems=new ArrayList();
                                                foreach (string s in items)
                                                {
                                                    if (ct == 2)
                                                    {
                                                        lvi = new ListViewItem((string[])subitems.ToArray(typeof(string)));
                                                        AddDriverListview.Items.Add(lvi);
                                                        subitems.Clear();
                                                        ct = 0;
                                                    }
                                                    subitems.Add(s);
                                                    ct++;
                                                }
                                            }
                                            //we are done!
                                            return true;
                                        }
                                    }

                                    count++;
                                } //end loop over childItems
                            } //end loop over c2.controls
                        }//end if (c2 is TabPage)
                        //else
                        //sw.WriteLine("    -" + c2.Name + " [" + c2.GetType().ToString() + "]");
                    } //end loop over c.controls
                }//end if (c is TabControl)
                //else
                //sw.WriteLine("  -" + c.Name + " [" + c.GetType().ToString() + "]");
            }//end loop over CreateNewAgentTabPage.Controls

            //sw.Close();

            //if we got to this point for a SET operation, we failed to find the right control.
            if (command == "SetFormValue")
                return false;

            //if we got to this point for a GET operation, return a string[] from the ArrayList
            return (string[])returnArray.ToArray(typeof(string));
        }

        private string GetSignatureExportFilename()
        {
            //show browse dialog to select file
            SaveFileDialog dlg = new SaveFileDialog();
            dlg.CheckFileExists = false;
            dlg.CheckPathExists = true;
            dlg.DefaultExt = ".xml"; //default extension
            dlg.Title = "Select export signature file name";
            dlg.Filter = "XML Files|*.xml";

            //the user clicked cancel
            if (dlg.ShowDialog() != DialogResult.OK)
                return null;

            return dlg.FileName;
        }

        #endregion

        #region Form validation

        //
        //this function validates the entire windows form for the application;
        //it is called when the user clicks "Generate MSI" to build a new agent installer
        //and also when the user clicks "Save settings" menu item
        //
        internal bool IsValidForm()
        {
            string errMsg = null;

            //
            //-----------------------------------------------
            //          VALIDATE GENERAL SETTINGS
            //-----------------------------------------------
            //
            errMsg = ValidateGeneralSettingsTab();

            //
            //-----------------------------------------------
            //          THERE MUST BE AT LEAST ONE
            //          TYPE OF SIGNATURE SUPPLIED
            //-----------------------------------------------
            //
            if (NoSignatures())// && NoHeuristics())
                errMsg = "Error:  You must provide at least one type of signature or heuristic!";

            //
            //-----------------------------------------------
            //          OUTPUT ANY ERROR MSGS
            //-----------------------------------------------
            //
            if (errMsg != null)
            {
                MessageBox.Show("Error:  " + errMsg + "\n\nPlease correct the error and try again.");
                return false;
            }

            return true;
        }

        #endregion

        #region TAB VALIDATION

        internal string ValidateGeneralSettingsTab()
        {
            //reporting - if auto reporting is enabled, validate those form items.
            if (Reporting_EnableAutoReporting.Checked)
            {
                GeneralSettingsTabContainer.SelectedIndex = 3;

                //if either a user name or pwd was given, the other must exist
                if (Reporting_Auth_UserName.Text != "" && Reporting_Auth_Password.Text == "" ||
                    Reporting_Auth_Password.Text != "" && Reporting_Auth_UserName.Text == "")
                    return "Both a user name and a password are required if authentication will be used.";

                if (Reporting_Method_NetworkShare.Text == "" && Reporting_Method_FTPServer.Text == "" && Reporting_Method_EmailAddress.Text == "" && Reporting_Method_WebServer_URI.Text == "")
                    return "You must choose a reporting method.";

                //FTP and SMTP require user name and password
                if (Reporting_Method_FTPServer.Text != "" && NoCredentials())
                    return "You must specify a user name and password.";

                if (Reporting_Method_EmailAddress.Text != "")
                {
                    if (NoCredentials())
                        return "You must specify a user name and password.";
                    if (Reporting_SMTP_Server.Text == "")
                        return "An SMTP Server address is required to use E-mail.";
                    if (Reporting_SMTP_Port.Text == "" && Reporting_TLS_Port.Text == "")
                        return "An SMTP Server port (or TLS port) is required to use E-mail.";
                }

                if (Reporting_Method_WebServer_URI.Text != "")
                {
                    if (Reporting_WebServer_Port.Text == "" && Reporting_TLS_Port.Text == "")
                        return "A web server port (or TLS port) is required to use the web reporting option.";
                    if (Reporting_Auth_UserName.Text != "" && Reporting_Auth_Type.SelectedItem == null)
                        return "You must specify the HTTP Authentication Type.";
                }

                if (Reporting_Use_TLS.Checked)
                {
                    //if the client pkcs-12 file is specified, the server's public key must be as well
                    if (AgentPFXFile.Text != "" && Reporting_Auth_Server_PubKey.Text == "")
                        return "If you want to authenticate the client, you must also authenticate the server.  Please provide the server's public key.";

                    //if client pkcs12 file is specified, the password must be specified as well
                    if (AgentPFXFile.Text != "" && AgentPFXPassword.Text == "")
                        return "A password is required for PKCS-12 files.";
                }

                if (Reporting_Archive_Password.Text == "")
                    return "An archive password is required.";
            }

            //if the startup mode is not fire-and-forget,
            //and random port is not checked,
            //and the port number is empty..
            if (!StartupFireAndForgetMode.Checked)
                if (!AgentRandomizeListeningPort.Checked)
                    if (AgentListeningPort.Text == "")
                        return "You must specify a port to listen on.";

            //if persistence is set to "install as a service", a service name and install folder must be given
            if (PersistenceInstallAsService.Checked && AgentServiceName.Text == "")
                return "You must provide a service name for the agent to install as a service.";

            //a client PFX/PKCS-12 file is required in Connection tab
            if (AgentPFXFile.Text == "" || AgentPFXPassword.Text == "")
                return "You must specify a PFX key store filename and password to use on the Connection tab.";

            //PFX must be valid
            if (!CwCryptoHelper.IsValidPFX(AgentPFXFile.Text))
                return "The selected PFX file is invalid.";
            //PFX password must work
            if (!CwCryptoHelper.IsValidPFXPassword(AgentPFXFile.Text, AgentPFXPassword.Text))
                return "The password for the supplied PFX file is incorrect.";

            return null;
        }

        private bool NoCredentials()
        {
            if (Reporting_Auth_UserName.Text == "")
                return true;
            else if (Reporting_Auth_Password.Text == "")
                return true;

            return false;
        }

        internal bool IsValidIP(string ip)
        {
            string pattern = @"^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$";
            Regex check = new Regex(pattern);

            if (ip == "")
                return false;
            else
                return check.IsMatch(ip, 0);
        }

        #endregion

        #region SIGNATURE VALIDATION

        internal bool NoSignatures()
        {
            int numRegSigs = RegistrySignatures_Listview.Items.Count;
            int numFileSigs = FileSignatures_Listview.Items.Count;
            int numMemSigs = MemorySignatures_Listview.Items.Count;
            int numRegGuidSigs = RegistryGuidSignatures_Listview.Items.Count;
            int total = numRegSigs + numFileSigs + numMemSigs + numRegGuidSigs;

            //make sure there's something to do
            if (total == 0)
                return true;

            return false;
        }

        internal string ValidateRegistrySignature(Dictionary<string, string> signature)
        {
            //key name is always required
            if (signature["KeyName"].Trim() == "")
                return "You must specify a registry key name.\n\nExample:  HKLM\\Software\\Microsoft";

            //if the target registry key is already in the gridview, cancel - cant have more than one action per registry key
            foreach (ListViewItem lvi in RegistrySignatures_Listview.Items)
            {
                if (lvi.SubItems[0].Text.Trim() == signature["KeyName"].Trim())
                {
                    //was a value name specified in the GUI?
                    if (signature.ContainsKey("ValueName"))
                    {
                        if (signature["ValueName"].Trim() == lvi.SubItems[1].Text.Trim())
                            return "There is already a registry signature for that registry key and value name.  You can only perform one action per key.";
                    }
                    else
                        return "There is already a signature for that key.  You can only perform one action per key.";
                }
            }

            //an action is required
            if (signature["Action"] == "")
                return "You must select an action.";

            //if Action is set to "Change...", new value data must be supplied
            if (signature["Action"] == "Change..." && signature["ChangeValueData"] == "")
                return "If you wish to change the value data for this registry key, you must supply the new data.";

            return null;
        }

        internal string ValidateRegistryGuidSignature(Dictionary<string, string> signature)
        {
            //user can either specify a static or a dynamic GUID value
            //a static value is a valid GUID number
            //a dynamic value is a registry key whose value is a valid GUID
            if (signature["GuidType"] == "" || signature["GuidValue"] == "")
                return "You must specify either a static GUID value or the registry key name for the dynamic GUID to be extracted at runtime.";

            return null;
        }

        internal string ValidateFileSignature(Dictionary<string, string> signature)
        {
            int dummy = 0;

            //one of file name, size or hash must be supplied
            if (signature["FileName"] == "")
                if (signature["FileSize"] == "")
                    if (signature["FileHash"] == "")
                        return "A file name, size, or hash is required.";

            //action is required
            if (signature["Action"] == "")
                return "You must specify an action.";

            //if they specify a file hash, they must check MD-5 or SHA-1 for hash type
            if (signature["FileHash"] != "" && !FileSignatures_NewFileHashTypeMD5.Checked && !FileSignatures_NewFileHashTypeSHA1.Checked)
                return "You must indicate if the file hash is MD-5 or SHA-1.";

            //if they specify a PE header signature, make sure it's in the right format
            if (signature["FilePESignature"] != "")
                if (!IsValidPEHeaderSignature(signature["FilePESignature"]))
                    return "The PE header signature supplied is invalid.";

            //file size must be a number
            if (signature["FileSize"] != "")
                if (!int.TryParse(signature["FileSize"], out dummy))
                    return "File size must be an integer.";

            return null;
        }

        internal string ValidateMemorySignature(Dictionary<string, string> signature)
        {
            //process name and action are required fields.
            if (signature["ProcessName"] == "" || signature["Action"] == "")
                return "You must specify a process name and an action.";

            //they shouldnt be specifying a keyword
            if (signature["Action"] == "Terminate process if exists")
                if (signature["Keywords"] != "")
                    return "Keywords are not required if you just want to kill an existing process.\n\nAre you sure you selected the correct option?";

            //if they selected an action involving keywords, at least one keyword is required!
            if (signature["Action"].Contains("if keyword found") && signature["Keywords"] == "")
                return "You must supply a comma-separated list of keywords.";

            return null;
        }

        internal bool IsValidPEHeaderSignature(string signature)
        {
            /*
             *  FORMAT OF PE SIGNATURE:
             * 
             *   +-----------------------------------------+
             *   |1|0|0|0|0|0|1|0|0|0|8|0|0|3|0|0|0|0|.|.|.|
             *   +-----------------------------------------+
             *   |___|_______________|_______________|_____|
             *     |          |               |         |
             *   # dd    dd #1 vsize     dd #2 vsize   ....
             *   
             *   this means there are :
             *     -16 data directories (10d = 16h)
             *     -the first dd is 1000h bytes in size
             *     -the second dd is 80030000h in size
             *     
             *   ALL VALUES STORED IN HEX!!
            */

            //minimum length is 10
            if (signature.Length < 10)
                return false;

            //only hex numeric
            Regex r = new Regex(@"^[A-Fa-f0-9]*$");

            if (!r.IsMatch(signature))
                return false;

            //first two bits must be less than hex 10, dec 16
            //this is because there are max 16 data directories
            //in COFF/PE files.
            int numDirectories = int.Parse(signature.Substring(0, 2), System.Globalization.NumberStyles.HexNumber);

            if (numDirectories > 0x10)
                return false;

            //parse out the rest of the signature, which should consist of
            //8-bit virtual size numbers for each section
            string restOfSignature = signature.Substring(2, signature.Length - 2);

            //to validate that each virtual size is an 8-bit hex number,
            //the length of the string should be divisible by 8 with no remainder
            if (restOfSignature.Length % 8 != 0)
                return false;

            return true;
        }

        #endregion

        #region HEURISTIC VALIDATION

        internal bool NoHeuristics()
        {
            return false;
        }

        #endregion

    }
}
