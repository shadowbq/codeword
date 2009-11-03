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
using System.Diagnostics;
using System.Management;
using System.Management.Instrumentation;
using System.Collections.Generic;
using System.Collections;
using System.Text;
using System.IO;
using System.Reflection;
using System.ComponentModel;
using System.Threading;
using System.Security.Principal;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Ionic.Utils.Zip;
using Microsoft.Win32;
using CwHandler;

namespace CwAgent
{
    public partial class AgentScanner
    {
        public class RegistryHelper
        {
            internal StringBuilder RegistryHelperLog;

            public RegistryHelper()
            {
                RegistryHelperLog = new StringBuilder();
            }
            ~RegistryHelper()
            {

            }

            /////////////////////////////////////////////////////
            //                                                 //
            // ScanForRegistrySignatures()                     //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Scans the registry for the given 
            //              signatures, storing any findings in
            //              the passed-in matches structure.
            //Returns:      none
            /////////////////////////////////////////////////////
            internal void ScanForRegistrySignatures(CwXML.RegistrySignature[] signatures, CwXML.RegistryGuidSignature[] guidSignatures, ref CwXML.RegistrySignatureMatch[] matches)
            {
                string keyName, valueName, valueData, action, hive, keyWithoutHive;
                int firstSlashInKeyName = 0;
                RegistryKey key;
                Regex filePathValidator = new Regex(@"^(([a-zA-Z]\:)|(\\))(\\{1}|((\\{1})[^\\]([^/:*?<>""|]*))+)$");
                string[] expandedKeys;
                ArrayList matchList = new ArrayList();

                //loop through all registry indicators - admin and user
                foreach (CwXML.RegistrySignature signature in signatures)
                {
                    //extract values from object
                    keyName = signature.KeyName;
                    valueName = signature.ValueName;
                    valueData = signature.ValueData;
                    action = signature.Action;

                    firstSlashInKeyName = keyName.IndexOf('\\');
                    hive = keyName.Substring(0, firstSlashInKeyName);
                    keyWithoutHive = keyName.Substring(firstSlashInKeyName, keyName.Length - firstSlashInKeyName);

                    if (hive == "HKLM")
                        key = Registry.LocalMachine;
                    else if (hive == "HKCR")
                        key = Registry.ClassesRoot;
                    else if (hive == "HKU")
                        key = Registry.Users;
                    else if (hive == "HKCC")
                        key = Registry.CurrentConfig;
                    else
                    {
                        RegistryHelperLog.AppendLine("WARNING:  Invalid hive detected in registry indicator:");
                        RegistryHelperLog.AppendLine("          Key:  '" + keyName + "'");
                        RegistryHelperLog.AppendLine("          Parsed hive:  '" + hive + "'");
                        RegistryHelperLog.AppendLine("WARNING:  Skipping this indicator...");
                        continue; //skip if bad hive
                    }

                    RegistryHelperLog.AppendLine("SCAN:  Using hive '" + hive + "'.");

                    //expand any {<var>} expandable values in registry key string
                    expandedKeys = ExpandRegistryKey(keyWithoutHive, guidSignatures);

                    //only returns null if there was a malformed var, so skip that check
                    if (expandedKeys == null)
                        continue;

                    //loop through the record/checks we built, or didn't build - if there was no var
                    //to expand, we just got the same record back.
                    foreach (string expandedKey in expandedKeys)
                    {
                        if (expandedKey == null)
                            continue;

                        //remove leading and trailing slashes
                        keyName = expandedKey.Trim(new char[] { ' ', '\\' });

                        RegistryHelperLog.AppendLine("SCAN:  Scanning for signature '" + hive + "\\" + keyName + "\\" + valueName + "'...");
                        RegistryKey parentKey = key.OpenSubKey(keyName, true);

                        //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                        //                SIGNATURE HIT
                        //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                        //if the key exists, we have a match.
                        if (parentKey != null)
                        {
                            try
                            {
                                ArrayList valnames = new ArrayList();

                                //build an arraylist of value names to look for
                                //if the valueName supplied in the signature is empty, we will copy
                                //all valueName's in this registry key.
                                if (valueName == "" || valueName == null)
                                {
                                    foreach (string valname in parentKey.GetValueNames())
                                        valnames.Add(valname);
                                    //if there are no value names, add the (Default) one, represented by "" in .net
                                    if (valnames.Count == 0)
                                        valnames.Add("");
                                }
                                else
                                {
                                    //otherwise we just want a single value name underneath this key
                                    valnames.Add(valueName);
                                }

                                //loop thru all value names to look for and add a new match record
                                foreach (string v in valnames)
                                {
                                    //get the value name
                                    object obj = parentKey.GetValue(v);

                                    //parse the value data - binary, expand string, etc...
                                    if (obj != null)
                                    {
                                        string displayData = "";
                                        string valdata = "";

                                        RegistryHelperLog.AppendLine("SCAN:  Signature matched on host!");

                                        //create a new RegistrySignatureMatch object
                                        CwXML.RegistrySignatureMatch matchRecord = new CwXML.RegistrySignatureMatch();
                                        matchRecord.RegistryKeyName = hive+"\\"+keyName; //the expanded registry key name plus hive
                                        matchRecord.RegistryValueName = v;
                                        matchRecord.Action = action;

                                        //get the value data of this value name based on type
                                        if (parentKey.GetValueKind(v) == RegistryValueKind.Binary)
                                        {
                                            StringBuilder str = GetEncodingsFromBinaryRegData((byte[])parentKey.GetValue(v));
                                            valdata = str.ToString();
                                            displayData = valdata;
                                        }
                                        //handle DWORD and QWORD reg data
                                        else if (parentKey.GetValueKind(v) == RegistryValueKind.DWord || parentKey.GetValueKind(v) == RegistryValueKind.QWord)
                                        {
                                            valdata = parentKey.GetValue(v).ToString();
                                            //first value will be in decimal, hex in parenthesis
                                            displayData = "'" + int.Parse(valdata).ToString() + "' (0x" + int.Parse(valdata).ToString("x") + ")";
                                        }
                                        else
                                        {
                                            valdata = parentKey.GetValue(v).ToString();
                                            displayData = "'" + valdata + "'";
                                        }

                                        matchRecord.RegistryValueData = valdata;

                                        //if it's a file, mark the appropriate field in the registry signature entry.
                                        //later on , these files will be deleted if settings dictate it.
                                        if (filePathValidator.IsMatch(valdata))
                                            matchRecord.IsFileOnDisk = true;
                                        else
                                            matchRecord.IsFileOnDisk = false;

                                        //log it in pretty format
                                        RegistryHelperLog.AppendLine("       " + v + " = '" + displayData + "'");

                                        //add it to our result set
                                        matchList.Add(matchRecord);
                                    }
                                    //otherwise teh value name coudl not be retrieved, so no real match here.
                                    else
                                    {
                                        RegistryHelperLog.AppendLine("SCAN:  The value name '" + keyName + "\\" + v + "' doesn't exist.");
                                    }
                                }
                            }
                            catch (Exception e)
                            {
                                RegistryHelperLog.AppendLine("SCAN:  Caught exception '" + e.Message + "', can't get this value name.");
                            }
                        }
                        else
                        {
                            RegistryHelperLog.AppendLine("SCAN:  The parent key '" + keyName + "' doesn't exist.");
                        }
                    } //end looping through expanded reg values for this reg indicator
                } // end looping through ALL registry indicators  
      
                //re-initialize our return object to the number of items in arraylist
                int i = 0;

                matches = new CwXML.RegistrySignatureMatch[matchList.Count];

                //add all registry findings in the arraylist to our matches object
                foreach (CwXML.RegistrySignatureMatch match in matchList)
                {
                    matches[i] = new CwXML.RegistrySignatureMatch();
                    matches[i] = match;
                    i++;
                }
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // CleanRegistryFindings()                         //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Applies desired action to all registry
            //              findings and stores the result in 
            //              the passed-in structure (success/fail).
            //Returns:      none
            /////////////////////////////////////////////////////
            internal void CleanRegistryFindings(ref CwXML.RegistrySignatureMatch[] matches, bool RemoveFileReferencesFromDisk)
            {
                //the line below is added for compatibility when calling this function
                //over remote channels from the admin console
                if (RegistryHelperLog == null)
                    RegistryHelperLog = new StringBuilder();

                RegistryHelperLog.AppendLine("CLEAN:  Cleaning "+matches.Length.ToString()+" registry findings...");

                RegistryKey key;
                int count = 0;

                //*************************************
                //      DELETE ANY BAD FILES FROM DISK
                //      THAT WERE FOUND IN REGISTRY
                //*************************************
                if (RemoveFileReferencesFromDisk)
                {
                    RegistryHelperLog.AppendLine("CLEAN:  Removing any malware files referenced in registry findings...");

                    //loop through all registry findings and if "ISFileOnDisk" = "true", then delete it
                    foreach (CwXML.RegistrySignatureMatch match in matches)
                    {
                        if (match.IsFileOnDisk)
                        {
                            try
                            {
                                File.Delete(match.RegistryValueData);
                            }
                            catch(Exception ex)
                            {
                                RegistryHelperLog.AppendLine("CLEAN:  Failed to delete file '"+match.RegistryValueData+"':  "+ex.Message);
                                matches[count].ActionSuccessful = false;
                                count++;
                                continue;
                            }
                            matches[count].ActionSuccessful = true;
                        }
                        count++;
                    }
                }

                count = 0;

                //*************************************
                //      APPLY GIVEN ACTION TO MATCH
                //*************************************
                //now loop thru the value names again and delete as necessary
                foreach (CwXML.RegistrySignatureMatch match in matches)
                {
                    string keyName = match.RegistryKeyName;
                    string valueName = match.RegistryValueName;
                    string action = match.Action;
                    string valueData = match.RegistryValueData;
                    string changeValueData = match.RegistryChangeValueData;

                    int firstSlashInKeyName = keyName.IndexOf('\\');
                    string hive = keyName.Substring(0, firstSlashInKeyName).ToUpper();
                    string keyWithoutHive = keyName.Substring(firstSlashInKeyName+1, keyName.Length - (firstSlashInKeyName+1));
                    keyName = keyWithoutHive;

                    if (hive == "HKLM")
                        key = Registry.LocalMachine;
                    else if (hive == "HKCR")
                        key = Registry.ClassesRoot;
                    else if (hive == "HKU")
                        key = Registry.Users;
                    else if (hive == "HKCC")
                        key = Registry.CurrentConfig;
                    else
                    {
                        RegistryHelperLog.AppendLine("WARNING:  Invalid hive detected in registry indicator:");
                        RegistryHelperLog.AppendLine("          Key:  '" + keyName + "'");
                        RegistryHelperLog.AppendLine("          Parsed hive:  '" + hive + "'");
                        RegistryHelperLog.AppendLine("WARNING:  Skipping this indicator...");
                        continue; //skip if bad hive
                    }

                    RegistryKey parentKey = key.OpenSubKey(keyName, true);

                    if (parentKey != null)
                    {
                        try
                        {
                            object obj = parentKey.GetValue(valueName);

                            if (obj != null)
                            {
                                //try to delete just this value name
                                if (action == "Delete" || action == "Delete All")
                                {
                                    RegistryHelperLog.AppendLine("SCAN:  Deleting '" + keyName + "\\" + valueName + "'...");

                                    try
                                    {
                                        parentKey.DeleteValue(valueName);
                                    }
                                    catch (Exception e)
                                    {
                                        matches[count].ActionSuccessful = false;
                                        count++;
                                        RegistryHelperLog.AppendLine("ERROR:  Caught exception '" + e.Message + "', not deleting this value name.");
                                        continue;
                                    }
                                    matches[count].ActionSuccessful = true;
                                }
                                else if (action == "Change...")
                                {
                                    //the value data will be what we want to change it to
                                    RegistryHelperLog.AppendLine("SCAN:  Setting '" + keyName + "\\" + valueName + "' = '" + changeValueData + "'...");

                                    try
                                    {
                                        parentKey.SetValue(valueName, changeValueData);
                                    }
                                    catch (Exception e)
                                    {
                                        matches[count].ActionSuccessful = false;
                                        count++;
                                        RegistryHelperLog.AppendLine("ERROR:  Caught exception '" + e.Message + "', not changing this value name.");
                                        continue;
                                    }
                                    matches[count].ActionSuccessful = true;
                                }
                                else if (action == "Clear")
                                {
                                    //the value data will be what we want to change it to
                                    RegistryHelperLog.AppendLine("SCAN:  Clearing '" + keyName + "\\" + valueName + "'...");

                                    try
                                    {
                                        parentKey.SetValue(valueName, "");
                                    }
                                    catch (Exception e)
                                    {
                                        matches[count].ActionSuccessful = false;
                                        count++;
                                        RegistryHelperLog.AppendLine("ERROR:  Caught exception '" + e.Message + "', not clearing this value name.");
                                        continue;
                                    }
                                    matches[count].ActionSuccessful = true;
                                }
                            }
                            else
                            {
                                RegistryHelperLog.AppendLine("SCAN:  The value name '" + keyName + "\\" + valueName + "' doesn't exist, not modifying.");
                                matches[count].ActionSuccessful = false;
                            }
                        }
                        catch (Exception e)
                        {
                            RegistryHelperLog.AppendLine("SCAN:  Caught exception '" + e.Message + "', can't get this value name.");
                            matches[count].ActionSuccessful = false;
                            count++;
                            continue;
                        }
                    }
                    else
                    {
                        matches[count].ActionSuccessful = false;
                        RegistryHelperLog.AppendLine("SCAN:  Failed to open parent key '" + keyName + "'...");
                    }
                    count++;
                }

                // ** EXTREMELY IMPORTANT ** //
                //must FLUSH the registry to force oS to synch in-memory cached registry
                //to the on-disk registry so that subsequent scans dont pick up results
                //that were cleaned but not synched yet. 
                //This "out of synch" issue occasionally happens and shouldn't according to MSDN:
                /*
                 * "It is not necessary to call Flush to write out changes to a key. Registry changes are flushed 
                 * to disk when the registry uses its lazy flusher. Lazy flushing occurs automatically and 
                 * regularly after a system-specified time interval. Registry changes are also flushed to disk at system shutdown.
                 * Unlike Close, the Flush function returns only when all the data has been written to the registry.
                 * The Flush function might also write out parts of or all of the other keys. Calling this function excessively 
                 * can have a negative effect on an application's performance.
                 * An application should only call Flush if it must be absolute certain that registry changes are recorded to disk. 
                 * In general, Flush rarely, if ever, need be used."
                 * */
                //flush them all, even if we didn't write to them.
                Registry.LocalMachine.Flush();
                Registry.ClassesRoot.Flush();
                Registry.Users.Flush();
                Registry.CurrentConfig.Flush();
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // PrintRegistryFindings()                         //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  stores findings in passed-in stringbuilder
            //Returns:      nothing
            /////////////////////////////////////////////////////
            internal void PrintRegistryFindings(CwXML.RegistrySignatureMatch[] matches, ref StringBuilder output)
            {
                output.AppendLine("");
                output.AppendLine("REPORT:  ******************************");
                output.AppendLine("REPORT:  Registry Findings");
                output.AppendLine("REPORT:  ******************************");
                output.AppendLine("");
                output.AppendLine("Key Name\t\tValue Name\t\tValue Data\t\tAction\t\tAction Successful\t\tOn Disk?");

                if (matches.Length == 0)
                {
                    output.AppendLine("REPORT:  No registry signatures were found.");
                }
                else
                {
                    //loop through all match records
                    foreach (CwXML.RegistrySignatureMatch match in matches)
                    {
                        output.AppendLine("");
                        output.Append(match.RegistryKeyName + "\t\t");
                        output.Append(match.RegistryValueName + "\t\t");
                        output.Append(match.RegistryValueData + "\t\t");
                        output.Append(match.Action + "\t\t");
                        output.Append(match.ActionSuccessful.ToString() + "\t\t");
                        output.Append(match.IsFileOnDisk.ToString());
                    }
                }

                output.AppendLine("");
                output.AppendLine("REPORT:  ******************************");
                output.AppendLine("");
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetEncodingsFromBinaryRegData()                 //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Converts binary registry data to an 
            //              ASCII-encoded string and a hex string
            //Returns:      a stringbuilder object that contains 
            //              both representations of the binary data
            /////////////////////////////////////////////////////
            internal StringBuilder GetEncodingsFromBinaryRegData(byte[] byteData)
            {
                StringBuilder returnData = new StringBuilder("");
                returnData.Append("[multiple encodings]:  ");

                //first get as sequence of hex bytes
                StringBuilder hex = new StringBuilder(byteData.Length * 2);
                foreach (byte b in byteData)
                    hex.AppendFormat("{0:x2}", b);
                returnData.Append("[HEX]:'" + hex.ToString() + "'");

                //then get as ASCII-encoded string
                string sString = System.Text.Encoding.ASCII.GetString(byteData);
                string[] sArray = sString.Split('\0');
                sString = "";
                foreach (string s in sArray)
                    sString += s;
                returnData.Append("[ASCII]:'" + sString + "'");

                return returnData;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // ExpandRegistryKey()                             //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Takes a registry key string and replaces
            //              {<var>} with expanded value
            //Returns:      an array of expanded registry key strings or
            //              null if invalid value passed in
            /////////////////////////////////////////////////////
            internal string[] ExpandRegistryKey(string key, CwXML.RegistryGuidSignature[] GuidSignatures)
            {
                int varBegin = key.IndexOf("{<");
                int varEnd = key.IndexOf(">}");

                //there's no opening tag
                if (varBegin < 0)
                {
                    //and no closing tag, so no prob
                    if (varEnd < 0)
                        return new string[] { key };
                    //er..there was a closing tag but no opening tag..
                    else
                        return null;  //remove malformed indicator entry
                }
                //there's an opening tag but no closing tag
                if (varEnd < 0)
                    return null;  //remove malformed indicator entry

                string var = key.Substring(varBegin + 2, varEnd - (varBegin + 2));

                RegistryHelperLog.AppendLine("SCAN:  Expanding registry key '" + key + "'...");

                //EXPAND GUID
                if (var == "GUID")
                {
                    int count = 0;

                    //if there are no static GUIDs to replace {<GUID>} with, return
                    if (GuidSignatures.Length == 0)
                    {
                        RegistryHelperLog.AppendLine("SCAN:  No GUIDs were supplied, skipping this indicator check..");
                        return null;
                    }

                    string[] expandedKeys = new string[GuidSignatures.Length];
                    string tmpKey = key;

                    //loop through static GUIDs we have and insert into given registry key string
                    foreach (CwXML.RegistryGuidSignature sig in GuidSignatures)
                    {
                        //only consider static GUIDs
                        if (sig.GuidType == "Dynamic")
                            continue;

                        //replace {<GUID>} with this GUID
                        tmpKey = key.Replace("<GUID>", sig.GuidValue);

                        RegistryHelperLog.AppendLine("SCAN:  Created expanded registry indicator '" + tmpKey + "'.");
                        expandedKeys[count] = tmpKey;
                        count++;
                    }

                    return expandedKeys;
                }
                //EXPAND SID
                else if (var == "SID")
                {
                    RegistryHelperLog.AppendLine("SCAN:  Expanding SIDs...");

                    //we need to get a list of user account SIDs using WMI,
                    //loop through that list, and generate new registry
                    //indicator checks for each account SID
                    SelectQuery sQuery = new SelectQuery("Win32_UserAccount", "Domain='" + Environment.UserDomainName + "'");
                    ManagementObjectSearcher mSearcher = new ManagementObjectSearcher(sQuery);

                    //start inserting new indicators at the end of the list
                    int count = 0;
                    string[] expandedKeys = new string[mSearcher.Get().Count];

                    //loop through all user accounts and create new indicator
                    foreach (ManagementObject mObject in mSearcher.Get())
                    {
                        string SID = mObject["SID"].ToString();
                        string UserName = mObject["Name"].ToString();
                        string thisExpandedKey = key;

                        //replace var in this expanded key with current SID
                        thisExpandedKey = thisExpandedKey.Replace("{<SID>}", SID);

                        RegistryHelperLog.AppendLine("SCAN:  Created expanded registry indicator  '" + thisExpandedKey + "'...");
                        expandedKeys[count] = thisExpandedKey;
                        count++;
                    }

                    RegistryHelperLog.AppendLine("SCAN:  Successfully created " + count + " new registry indicators.");

                    return expandedKeys;
                }
                else
                {
                    RegistryHelperLog.AppendLine("ERROR:  Invalid embedded variable '" + var + "' in key '" + key + "', skipping this registry indicator.");
                    return null;
                }
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // FormatLongRegValue()                            //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  formats a long value in 50-char chunks
            //Returns:      formatted string
            /////////////////////////////////////////////////////
            internal string FormatLongRegValue(string value)
            {
                char[] charArray = value.ToCharArray();
                int numlinebreaks = charArray.Length / 50;
                int numlinebreaksdone = 0;
                int i = 0;
                string retStr="",str = "";

                //loop through string and store 50 chars per line
                foreach (char c in charArray)
                {
                    i++;
                    if (i == 50)
                    {
                        retStr += str+"\n";
                        str = "";
                        i = 0;
                        numlinebreaksdone++;
                    }
                    else
                        str += c;
                }

                //if we haven't done all the line breaks, that means
                //we have left out soem characters, so print them
                if (numlinebreaksdone != numlinebreaks)
                {
                    //the characters we left out 
                    string leftout = value.Substring(numlinebreaksdone * 50, i);
                    retStr += leftout;
                }

                return retStr;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // LoadDynamicGUIDs()                              //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  loads all dynamic GUIDs supplied and adds
            //              a static guid to our registry guid signatures
            //              object for each expanded value.
            //
            //Returns:      true if successful
            /////////////////////////////////////////////////////
            internal bool LoadDynamicGUIDs(ref CwXML.RegistryGuidSignature[] GuidSignatures)
            {
                Regex GUIDvalidator = new Regex(@"^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$", RegexOptions.Compiled);

                //first get a count of how many Dynamic Guids there are
                int NumDynamicGuids = 0;
                foreach (CwXML.RegistryGuidSignature sig in GuidSignatures)
                    if (sig.GuidType == "Dynamic")
                        NumDynamicGuids++;

                //none to process.
                if (NumDynamicGuids == 0)
                    return true;

                //allocate a new object to store that many dynamic guids
                ArrayList DynamicSigsToAdd = new ArrayList(NumDynamicGuids);
                
                //loop through all our GUID signatures and extract GUIDs from this live system's registry
                //that are stored at the registry key indicated by the given Dynamic GUID signature
                foreach (CwXML.RegistryGuidSignature sig in GuidSignatures)
                {
                    string keyName = sig.GuidValue;
                    string type = sig.GuidType;//"Static" or "Dynamic"
                    string GUID = keyName;  //by default, we assume it's static
                    string valueName = "";

                    //skip any static Guid Signatures -- our goal here is to MAKE static sigs
                    //from dynamic sigs that must be populated at runtime
                    if (type == "Static")
                        continue;

                    //hive parsing vars
                    int firstSlashInKeyName = keyName.IndexOf('\\');
                    string hive = keyName.Substring(0, firstSlashInKeyName);
                    string keyWithoutHive = keyName.Substring(firstSlashInKeyName, keyName.Length - firstSlashInKeyName);
                    keyName = keyWithoutHive;
                    RegistryKey key;

                    if (hive == "HKLM")
                        key = Registry.LocalMachine;
                    else if (hive == "HKCR")
                        key = Registry.ClassesRoot;
                    else if (hive == "HKU")
                        key = Registry.Users;
                    else if (hive == "HKCC")
                        key = Registry.CurrentConfig;
                    else
                    {
                        RegistryHelperLog.AppendLine("ERROR:  Invalid hive supplied in GUID:  '" + keyName + "', skipping..");
                        continue;
                    }

                    //it is possible this Dynamic Guid signature has an embedded {SID} expansion var.
                    //so try to expand this key.
                    string[] expandedKeys = ExpandRegistryKey(keyName, GuidSignatures);
                    string thisKeyName;

                    //if nothing was expanded, use the original key
                    if (expandedKeys == null)
                        expandedKeys = new string[] { keyName };

                    //loop through all resulting records that were expanded, 
                    foreach (string expandedKey in expandedKeys)
                    {
                        thisKeyName = expandedKey.Trim(new char[] { ' ', '\\' });

                        //try to open the (by now chopped up) keyName ..
                        RegistryKey loadedKey = key.OpenSubKey(thisKeyName);

                        //bail if cant open key
                        if (loadedKey == null)
                        {
                            RegistryHelperLog.AppendLine("ERROR:  Could not load GUID, invalid key specified: '" + thisKeyName + "', skipping...");
                            continue;
                        }

                        //great!  loaded the key.. now try to get the value data stored at the value Name
                        object obj = loadedKey.GetValue(valueName);

                        if (obj == null)
                        {
                            RegistryHelperLog.AppendLine("ERROR:  Could not load GUID, invalid value name specified: '" + valueName + "', skipping...");
                            continue;
                        }

                        //sweet!  got the value name data..make sure it's a legit GUID
                        if (!GUIDvalidator.IsMatch(obj.ToString()))
                        {
                            RegistryHelperLog.AppendLine("ERROR:  Found a GUID value, but it's invalid: '" + obj.ToString() + "', skipping...");
                            continue;
                        }

                        //store the value
                        GUID = (string)obj.ToString();

                        //strip out curly braces from GUID if present
                        GUID = GUID.Replace("{", "");
                        GUID = GUID.Replace("}", "");

                        //add it as a static GUID to our tmp signatures
                        CwXML.RegistryGuidSignature g = new CwXML.RegistryGuidSignature();
                        g.GuidType = "Static";
                        g.GuidValue = GUID;
                        DynamicSigsToAdd.Add(g);
                    }
                }
               
                //add all dynamic guids that are now static guids into our guid sigs array
                foreach (CwXML.RegistryGuidSignature g in DynamicSigsToAdd)
                {
                    if (g.GuidType != null && g.GuidValue != null)
                    {
                        //resize our permanent array by 1
                        Array.Resize(ref GuidSignatures, GuidSignatures.Length + 1);
                        GuidSignatures[GuidSignatures.Length] = g;
                    }
                }

                return true;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // LoadNtUserDatFiles()                            //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Loads all NTUSER.DAT files located in
            //              C:\documents and settings\, c:\Users (vista),
            //              and system32\config\default (default profile).
            //              this is necessary so that during registry
            //              scan, if some indicators must look into
            //              individual user SID hives, they must be preloaded.
            //
            //              Note:  this function FAILS if we don't
            //              have elevated privileges.
            //
            //Returns:      void
            /////////////////////////////////////////////////////
            internal void LoadNtUserDatFiles(bool unload)
            {
                uint HKEY_USERS = 0x80000003;
                if (unload)
                    RegistryHelperLog.AppendLine("SCAN:  Unloading NTUSER.DAT files from HKEY_USERS...");
                else
                    RegistryHelperLog.AppendLine("SCAN:  Loading NTUSER.DAT files into HKEY_USERS...");

                //get all user SIDs and account names
                SelectQuery sQuery = new SelectQuery("Win32_UserAccount", "Domain='" + Environment.UserDomainName + "'");
                ManagementObjectSearcher mSearcher = new ManagementObjectSearcher(sQuery);

                //loop through all user accounts and create new indicator
                foreach (ManagementObject mObject in mSearcher.Get())
                {
                    string SID = mObject["SID"].ToString();
                    string UserName = mObject["Name"].ToString();
                    string UserProfileDirectory = "";

                    //skip the currently logged in user - no need to load/unload their hive!
                    if (UserName == Environment.UserName)
                        continue;

                    //what disk drive is the profile directory stored on?
                    string myProfileDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                    string profileDrive = myProfileDir.Substring(0, 1);

                    //on win vista, it's C:\Users\
                    if (EnvironmentHelper.GetOSName() == "Windows Vista")
                        UserProfileDirectory = profileDrive + ":\\Users\\" + UserName + "\\NTUSER.DAT";
                    else
                        UserProfileDirectory = profileDrive + ":\\Documents and Settings\\" + UserName + "\\NTUSER.DAT";

                    try
                    {
                        FileInfo f = new FileInfo(UserProfileDirectory);

                        if (!f.Exists)
                            continue;
                    }
                    catch { }

                    //LOAD the hive
                    if (!unload)
                    {
                        if (Win32Helper.RegLoadKey(HKEY_USERS, SID, UserProfileDirectory) > 0)
                        {
                            RegistryHelperLog.AppendLine("WARNING:  Couldn't load profile in '" + UserProfileDirectory + "'.");
                            RegistryHelperLog.AppendLine("WARNING:  Error data = '" + Win32Helper.GetLastError32() + "'");
                            continue;
                        }
                        RegistryHelperLog.AppendLine("SCAN:  Successfully loaded '" + UserProfileDirectory + "' to hive!");
                    }
                    //UNLOAD the hive
                    else
                    {
                        if (Win32Helper.RegUnLoadKey(HKEY_USERS, SID) != 0)
                            continue;
                        else
                            RegistryHelperLog.AppendLine("SCAN:  Successfully unloaded profile hive '" + UserProfileDirectory + "'");
                    }
                }
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // ScanForMaliciousGUIDs()                         //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  using basic heuristics to determine if
            //              a GUID entry in HKCR is potentially
            //              malicious:
            //              1) it points to non-existent file
            //              2) it points to non-authenticode-signed file
            //              3) it points to a file that has matching
            //                 attributes of a file in file indicators list
            //Returns:      true if successful
            /////////////////////////////////////////////////////
            internal bool ScanForMaliciousGUIDs()
            {

                return true;
            }
        }
    }
}
