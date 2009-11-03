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
using System.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Serialization;
using CwAgent;

namespace CwHandler
{
    public class CwXML
    {
        #region GLOBAL XML SCHEMA DEFINITIONS

        /////////////////////////////////////////////////////
        //                                                 //
        // CodewordSignatureTemplate XML Root Attribute    //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Describes a set of registry, registry GUID,
        //              file and memory signatures for scanning.
        /////////////////////////////////////////////////////
        [XmlRootAttribute("CodewordSignatureTemplate", Namespace = "http://www.sippysworld.org", IsNullable = false)]
        public class CodewordSignatureTemplate
        {
            [XmlArrayAttribute("RegistrySignatures")]
            public RegistrySignature[] RegistrySignatures;
            [XmlArrayAttribute("RegistryGuidSignatures")]
            public RegistryGuidSignature[] RegistryGuidSignatures;
            [XmlArrayAttribute("FileSignatures")]
            public FileSignature[] FileSignatures;
            [XmlArrayAttribute("MemorySignatures")]
            public MemorySignature[] MemorySignatures;
        }
        public class RegistrySignature
        {
            [XmlElement("KeyName")]
            public string KeyName;
            [XmlElement("ValueName")]
            public string ValueName;
            [XmlElement("ValueData")]
            public string ValueData;
            [XmlElement("ChangeValueData")]
            public string ChangeValueData;
            [XmlElement("Action")]
            public string Action;
        }
        public class RegistryGuidSignature
        {
            [XmlElement("GuidValue")]
            public string GuidValue;
            [XmlElement("GuidType")]
            public string GuidType;
        }
        public class FileSignature
        {
            [XmlElement("FileName")]
            public string FileName;
            [XmlElement("FileHash")]
            public string FileHash;
            [XmlElement("FileHashType")]
            public string FileHashType;
            [XmlElement("FileSize")]
            public string FileSize;
            [XmlElement("FilePEHeaderSignature")]
            public string FilePEHeaderSignature;
            [XmlElement("Action")]
            public string Action;
        }
        public class MemorySignature
        {
            [XmlElement("ProcessName")]
            public string ProcessName;
            [XmlElement("Keywords")]
            public string Keywords;
            [XmlElement("Action")]
            public string Action;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // CodewordSettingsTemplate XML Root Attribute     //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Describes the settings for an agent.
        /////////////////////////////////////////////////////
        [XmlRootAttribute("CodewordSettingsTemplate", Namespace = "http://www.sippysworld.org", IsNullable = false)]
        public class CodewordSettingsTemplate
        {
            [XmlArrayAttribute("FormElementNames")]
            public string[] FormElementNames;
            [XmlArrayAttribute("FormElementValues")]
            public string[] FormElementValues;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // CodewordAgentCommand XML Root Attribute         //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Describes a command sent from the admin
        //              console to a remote agent.
        /////////////////////////////////////////////////////
        [XmlRootAttribute("CodewordAgentCommand", Namespace = "http://www.sippysworld.org", IsNullable = false)]
        public class CodewordAgentCommand
        {
            [XmlElement("CommandCode")]
            public int CommandCode;
            [XmlArrayAttribute("CommandParameters")]
            public string[] CommandParameters;
            [XmlElement("ResponseRequired")]
            public bool ResponseRequired;
            [XmlElement("CommandTimeout")]
            public int CommandTimeout;
            [XmlElement("CommandCollectOrMitigationTask")]
            public CodewordAgentAnomalyReport CommandCollectOrMitigationTask;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // CodewordAgentResponse XML Root Attribute        //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Describes a response sent from an agent
        //              to the admin console.
        /////////////////////////////////////////////////////
        [XmlRootAttribute("CodewordAgentResponse", Namespace = "http://www.sippysworld.org", IsNullable = false)]
        public class CodewordAgentResponse
        {
            [XmlElement("CommandReceived")]
            public int CommandCodeReceived;
            [XmlElement("CommandReceiveDate")]
            public string CommandReceiveDate;
            [XmlElement("CommandProcessingStartDate")]
            public string CommandProcessingStartDate;
            [XmlElement("CommandProcessingEndDate")]
            public string CommandProcessingEndDate;
            [XmlElement("ResponseAnomalyReport")]
            public CodewordAgentAnomalyReport ResponseAnomalyReport;
            [XmlElement("ResponseSystemInformation")]
            public CodewordSystemInformation ResponseSystemInformation;
            [XmlElement("ResponseData")]
            public string ResponseData;
            [XmlElement("ResponseCode")]
            public int ResponseCode;
            [XmlElement("ResponseInfo")]
            public string ResponseInfo;
            [XmlElement("ResponseLog")]
            public string ResponseLog;
        }
        public class CodewordAgentAnomalyReport
        {
            [XmlElement("SignatureMatches")]
            public CodewordAgentSignatureMatches SignatureMatches;
            [XmlElement("HeuristicMatches")]
            public CodewordAgentHeuristicMatches HeuristicMatches;
        }
        public class CodewordAgentHeuristicMatches
        {
            [XmlElement("KernelModeMatches")]
            public KernelModeHeuristicMatches KernelModeMatches;
            [XmlElement("UserModeMatches")]
            public UserModeHeuristicMatches UserModeMatches;
        }
        public class KernelModeHeuristicMatches
        {
            [XmlElement("SSDTHookTable")]
            public CwStructures.HOOKED_SSDT_TABLE SSDTHookTable;
            [XmlElement("SSDTDetourTable")]
            public CwStructures.DETOURED_SSDT_TABLE SSDTDetourTable;
            [XmlArrayAttribute("Win32DetourTable")]
            public CwStructures.WIN32API_DETOUR_TABLE[] Win32DetourTable;
            [XmlArrayAttribute("DriverIrpHooksTable")]
            public CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE[] DriverIrpHooksTable;
            [XmlArrayAttribute("DriverIrpDetoursTable")]
            public CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE[] DriverIrpDetoursTable;
        }
        public class UserModeHeuristicMatches
        {
            [XmlArrayAttribute("ProcessListing")]
            public CwStructures.CWPROCESS_RECORD[] ProcessListing;
        }

        public class CodewordAgentSignatureMatches
        {
            [XmlArrayAttribute("RegistrySignatureMatches")]
            public RegistrySignatureMatch[] RegistrySignatureMatches;
            [XmlArrayAttribute("FileSignatureMatches")]
            public FileSignatureMatch[] FileSignatureMatches;
            [XmlArrayAttribute("MemorySignatureMatches")]
            public MemorySignatureMatch[] MemorySignatureMatches;
        }
        public class RegistrySignatureMatch
        {
            public string RegistryKeyName;
            public string RegistryValueName;
            public string RegistryValueData;
            public string RegistryChangeValueData;
            public string Action;
            public bool ActionSuccessful;
            public bool IsFileOnDisk; //is this registry value name an actual file on disk?
        }
        public class FileSignatureMatch
        {
            public string FileName;
            public string FullPath;
            public long FileSize;
            public string FileHash;
            public string FileHashType;
            public string FilePEHeaderSignature;
            public string FileCreationDate;
            public string FileLastAccessDate;
            public string FileLastModifiedDate;
            public string Action;
            public bool ActionSuccessful;
        }
        public class MemorySignatureMatch
        {
            public string ProcessName;
            public uint ProcessId;
            public uint ParentProcessId;
            public string Keywords;
            public string Action;
            public string MatchingBlock;
            public string ChildThreadIds;
            public string MaliciousLoadedModuleName;
            public string MaliciousLoadedModuleBaseAddr;
            public string MaliciousLoadedModuleEndAddr;
            public string MaliciousLoadedModuleSize;
            public string MaliciousLoadedModulePath;
            public string SuspiciousHeapBlockRange;
            public bool ActionSuccessful;
        }
        public class CodewordSystemInformation
        {
            [XmlElement("HostInformation")]
            public HostInformation HostInformation;
            [XmlElement("AgentInformation")]
            public AgentInformation AgentInformation;
        }
        public class HostInformation
        {
            [XmlElement("MachineName")]
            public string MachineName;
            [XmlElement("UserDomainName")]
            public string UserDomainName;
            [XmlElement("IPAddresses")]
            public string IPAddresses;
            [XmlElement("UserName")]
            public string UserName;
            [XmlElement("OSVersionShort")]
            public string OSVersionShort;
            [XmlElement("OSVersionLong")]
            public string OSVersionLong;
            [XmlElement("AgentCurrentDirectory")]
            public string AgentCurrentDirectory;
            [XmlElement("LogicalDrives")]
            public string LogicalDrives;
            [XmlElement("NumProcessors")]
            public string NumProcessors;
            [XmlElement("WorkingSetSize")]
            public string WorkingSetSize;
        }
        public class AgentInformation
        {
            [XmlElement("Version")]
            public string Version;
            [XmlElement("AgentSettings")]
            public CodewordSettingsTemplate AgentSettings;
            [XmlElement("AgentSignatures")]
            public CodewordSignatureTemplate AgentSignatures;
        }

        #endregion

        #region FUNCTIONS

        ////////////////////////////////////////////////////////////////////////////////////
        //
        //                      IMPORT SIGNATURE TEMPLATE
        //
        ////////////////////////////////////////////////////////////////////////////////////
        public CodewordSignatureTemplate ImportSignatureTemplate(string filename)
        {
            //-----------------------------------------------
            //              DESERIALIZE XML FILES
            //-----------------------------------------------
            XmlSerializer serializer;

            //initiate serialization object
            try
            {
                serializer = new XmlSerializer(typeof(CodewordSignatureTemplate));
            }
            catch (Exception ex)
            {
                throw new Exception("Failed processing XML from template file.\n\n" + ex.Message);
            }

            //handle unknown XML nodes/attributes
            serializer.UnknownNode += new XmlNodeEventHandler(ImportErrorUnknownXMLNode);
            serializer.UnknownAttribute += new XmlAttributeEventHandler(ImportErrorUnknownXMLAttribute);

            FileStream fstream;

            //attempt to read XML document
            try
            {
                fstream = new FileStream(filename, FileMode.Open);
            }
            catch (Exception ex)
            {
                throw new Exception("File read error:  " + ex.Message);
            }

            //try to deserialize
            CodewordSignatureTemplate cwt;

            try
            {
                //restore the object's state with data from the XML document
                cwt = (CodewordSignatureTemplate)serializer.Deserialize(fstream);
            }
            catch (Exception ex)
            {
                throw new Exception("Deserialization error:  " + ex.Message);
            }

            fstream.Close();

            return cwt;
        }

        public void ImportErrorUnknownXMLNode(object sender, XmlNodeEventArgs e)
        {
            throw new Exception("Invalid XML Node:\n" +
                                   "Line number:  " + e.LineNumber +
                                   "Line position:  " + e.LinePosition +
                                   "Local name:  " + e.LocalName +
                                   "Name:  " + e.Name +
                                   "Namespace URI:  " + e.NamespaceURI +
                                   "Node type:  " + e.NodeType +
                                   "Deserialization object:  " + e.ObjectBeingDeserialized.ToString() +
                                   "Text:  " + e.Text);
        }

        public void ImportErrorUnknownXMLAttribute(object sender, XmlAttributeEventArgs e)
        {
            throw new Exception("Invalid XML Attribute:\n" +
                                   "Line number:  " + e.LineNumber +
                                   "Line position:  " + e.LinePosition +
                                   "Allowed attributes:  " + e.ExpectedAttributes +
                                   "Found attribute:  " + e.Attr.InnerXml +
                                   "Deserialization object:  " + e.ObjectBeingDeserialized.ToString());
        }

        ////////////////////////////////////////////////////////////////////////////////////
        //
        //                      EXPORT SIGNATURE TEMPLATE
        //
        ////////////////////////////////////////////////////////////////////////////////////
        public static void ExportSignatureTemplate(string filename, RegistryGuidSignature[] rgs, RegistrySignature[] rs, FileSignature[] fs, MemorySignature[] ms)
        {
            CodewordSignatureTemplate cwTemplate = new CodewordSignatureTemplate();
            cwTemplate.RegistryGuidSignatures = rgs;
            cwTemplate.RegistrySignatures = rs;
            cwTemplate.FileSignatures = fs;
            cwTemplate.MemorySignatures = ms;

            //serialize the objects into an XML document
            try
            {
                XmlSerializer serializer = new XmlSerializer(typeof(CodewordSignatureTemplate));
                TextWriter writer = new StreamWriter(filename);
                serializer.Serialize(writer, cwTemplate);
                writer.Close();
            }
            catch (Exception e)
            {
                throw new Exception("Serialization error:  " + e.Message);
            }
        }

        //
        //this function generates an XML settings file by serializing a CodewordSettingsTemplate
        //object, which simply stores the values of all form elements.
        //
        //argument 'silent' is optional and only used internally to generate the settings file
        //that the deployed agent uses.  using this option suppresses the dialog box and automatically
        //saves the settings file to CwAgentConfiguration.xml
        //
        public static void SaveSettingsXML(string filename, string[] ElementNames, string[] ElementValues)
        {
            //-----------------------------------------------
            //            GENERATE SERIALIZABLE
            //              DATA STRUCTURES
            //-----------------------------------------------
            CodewordSettingsTemplate cwSettings = new CodewordSettingsTemplate();
            cwSettings.FormElementNames = ElementNames;
            cwSettings.FormElementValues = ElementValues;

            //-----------------------------------------------
            //            ENCRYPT SENSITIVE FIELDS
            //-----------------------------------------------
            //encrypt any sensitive items before serializing to an XML file
            //
            string[] EncryptElementValues = new string[]{ 
                "Reporting_Auth_UserName","Reporting_Auth_Password","AgentPFXPassword","Reporting_Archive_Password"};

            int count = 0;
            foreach (string formElementName in cwSettings.FormElementNames)
            {
                //once we find the element value for one of the element names, encrypt it.
                if (Array.IndexOf(EncryptElementValues, formElementName) >= 0)
                {
                    string plainText = cwSettings.FormElementValues[count];
                    cwSettings.FormElementValues[count] = CwBasicEncryption.Encrypt(plainText);
                }
                count++;
            }

            //serialize the objects into an XML document
            try
            {
                XmlSerializer serializer = new XmlSerializer(typeof(CodewordSettingsTemplate));
                TextWriter writer = new StreamWriter(filename);
                serializer.Serialize(writer, cwSettings);
                writer.Close();
            }
            catch (Exception e)
            {
                throw new Exception("Serialization error:  " + e.Message);
            }
        }

        public CodewordSettingsTemplate LoadSettingsXML(string filename)
        {
            //-----------------------------------------------
            //              DESERIALIZE XML FILE
            //-----------------------------------------------
            XmlSerializer serializer;

            //
            //deserialize the XML settings file into an instantation of the CwSettings class
            try
            {
                serializer = new XmlSerializer(typeof(CodewordSettingsTemplate));
            }
            catch (Exception ex)
            {
                throw new Exception("Failed processing XML from settings file.\n\n" + ex.Message);
            }

            //handle unknown XML nodes/attributes
            serializer.UnknownNode += new XmlNodeEventHandler(ImportErrorUnknownXMLNode);
            serializer.UnknownAttribute += new XmlAttributeEventHandler(ImportErrorUnknownXMLAttribute);

            FileStream fstream;

            //attempt to read XML document
            try
            {
                fstream = new FileStream(filename, FileMode.Open);
            }
            catch (Exception ex)
            {
                throw new Exception("File read error:  " + ex.Message);
            }

            //try to deserialize
            CodewordSettingsTemplate cst;

            try
            {
                //restore the object's state with data from the XML document
                cst = (CodewordSettingsTemplate)serializer.Deserialize(fstream);
            }
            catch (Exception ex)
            {
                fstream.Close();
                throw new Exception("Deserialization error:  " + ex.Message);
            }

            //make sure there are just as many form names as there are form values
            if (cst.FormElementNames.Length != cst.FormElementValues.Length)
            {
                fstream.Close();
                throw new Exception("Error:  length mismatch!");
            }

            fstream.Close();

            //-----------------------------------------------
            //            DECRYPT SENSITIVE FIELDS
            //-----------------------------------------------
            //decrypt any sensitive items before deserializing into the form
            //
            string[] EncryptElementValues = new string[]{ 
                "Reporting_Auth_UserName","Reporting_Auth_Password","AgentPFXPassword","Reporting_Archive_Password"};

            int count = 0;
            foreach (string formElementName in cst.FormElementNames)
            {
                //once we find the element value for one of the element names, encrypt it.
                if (Array.IndexOf(EncryptElementValues, formElementName) >= 0)
                {
                    string cypherText = cst.FormElementValues[count];
                    cst.FormElementValues[count] = CwBasicEncryption.GetStringFromSecureString(CwBasicEncryption.Decrypt(cypherText));
                }
                count++;
            }

            return cst;
        }


        public static bool IsValidXmlCharacter(char c)
        {
            if ((c == 0x9) || (c == 0xA) || (c == 0xD) || ((c >= 0x20) && (c <= 0xD7FF)) ||

                    ((c >= 0xE000) && (c <= 0xFFFD)) || ((c >= 0x10000) && (c <= 0x10FFFF)))
                return true;
            return false;
        }

        public static string ReplaceInvalidXmlChars(string s)
        {
            if (s.Length == 0)
                return "";

            StringBuilder ret = new StringBuilder(s.Length, s.Length);
            foreach (char c in s.ToCharArray())
            {
                if (IsValidXmlCharacter(c))
                    ret.Append(c);
                else
                    ret.Append('-');
            }
            return ret.ToString();
        }
        #endregion

    }
}