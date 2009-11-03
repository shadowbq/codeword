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
using System.Security.Cryptography;
using System.IO;
using System.Collections;
using System.Runtime.InteropServices;
using System.Globalization;
using CwHandler;

namespace CwAgent
{
    public partial class AgentScanner
    {
        public class FileHelper
        {
            internal StringBuilder FileHelperLog;

            public FileHelper()
            {
                FileHelperLog = new StringBuilder();
            }
            ~FileHelper()
            {

            }

            /////////////////////////////////////////////////////
            //                                                 //
            // ScanForFileSignatures()                         //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Scans all logical drives for the given
            //              file signatures.
            //Returns:      nothing; side-effect on passed-in results
            /////////////////////////////////////////////////////
            internal void ScanForFileSignatures(CwXML.FileSignature[] FileSignatures, ref CwXML.FileSignatureMatch[] matches)
            {
                //get list of logical drives
                string[] drives = Environment.GetLogicalDrives();
                int numMalware=0;
                ArrayList matchList;
                ArrayList matchRecordsList=new ArrayList();

                AgentScanLog.AppendLine("SCAN:  Drives:  " + string.Join(",", drives));

                //-----------------------------------------------------------
                //      SCAN DISKS FOR FILE SIGNATURE MATCHES
                //-----------------------------------------------------------
                //loop through all our disk drives - returns it as C:\, D:\, F:\
                foreach (string drive in drives)
                {
                    AgentScanLog.AppendLine("SCAN:  Scanning " + drive + "...");

                    //loop through all signatures
                    foreach (CwXML.FileSignature signature in FileSignatures)
                    {
                        //perform search based on parameters above (some may be empty)
                        try
                        {
                            matchList = FileSearch(drive, signature.FileName, signature.FileHash, signature.FileHashType, signature.FileSize.ToString(), signature.FilePEHeaderSignature);
                        }
                        catch (Exception ex)
                        {
                            AgentScanLog.AppendLine("SCAN:  Failed to scan drive:  " + ex.Message);
                            break; //dont continue scanning for signatures on this drive.
                        }

                        AgentScanLog.AppendLine("SCAN:  There were "+matchList.Count.ToString()+" matches for this signature.");

                        //if we got a match, add those results to our array of arrays
                        if (matchList.Count > 0)
                        {
                            AgentScanLog.AppendLine("file search matches:  " + string.Join(",", (string[])matchList.ToArray(typeof(string))));

                            foreach (string fullPathToMatch in matchList)
                            {
                                //get info about this file
                                FileInfo f;
                                try
                                {
                                    f = new FileInfo(fullPathToMatch);
                                }
                                catch (Exception ex)
                                {
                                    AgentScanLog.AppendLine("SCAN:  Error querying file '" + fullPathToMatch + "':  " + ex.Message);
                                    continue;
                                }

                                CwXML.FileSignatureMatch fm = new CwXML.FileSignatureMatch();
                                fm.FileName = f.Name;
                                fm.FileSize = f.Length;
                                fm.FullPath = f.FullName;
                                //if no file hash was specified in the signature, create one now (MD5 only)
                                if (signature.FileHash == "")
                                {
                                    fm.FileHash = GetMD5HashOfFile(f.FullName);
                                    fm.FileHashType = "MD5";
                                }
                                else
                                {
                                    fm.FileHash = signature.FileHash;
                                    fm.FileHashType = signature.FileHashType;
                                }
                                //if PE header signature was given in signature, save it
                                if (signature.FilePEHeaderSignature != "")
                                    fm.FilePEHeaderSignature = signature.FilePEHeaderSignature;
                                fm.Action = signature.Action;
                                //get various file attribs
                                fm.FileLastAccessDate = f.LastAccessTime.ToLongDateString();
                                fm.FileLastModifiedDate = f.LastWriteTime.ToLongDateString();
                                fm.FileCreationDate = f.CreationTime.ToLongDateString();

                                //add it to list
                                matchRecordsList.Add(fm);
                            }
                            numMalware++;
                        }
                    }

                    AgentScanLog.AppendLine("SCAN:  Scan of " + drive + " complete (" + numMalware.ToString() + " malicious files found).");
                    numMalware = 0;
                }

                //we've scanned all disks for all file signatures.
                //if we got matches, create a match record for them
                if (matchRecordsList.Count > 0)
                {
                    matches = new CwXML.FileSignatureMatch[matchRecordsList.Count];
                    int i = 0;

                    foreach (CwXML.FileSignatureMatch matchRecord in matchRecordsList)
                    {
                        matches[i] = new CwXML.FileSignatureMatch();
                        matches[i] = matchRecord;
                        i++;
                    }
                }
                else
                    matches = new CwXML.FileSignatureMatch[0];
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // CleanFileFindings()                             //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  deletes any files from disk if indicated.
            //Returns:      nothing; side-effect on passed-in results
            /////////////////////////////////////////////////////
            internal bool CleanFileFindings(ref CwXML.FileSignatureMatch[] FileSignatureMatches)
            {
                //the line below is added for compatibility when calling this function
                //over remote channels from the admin console
                if (AgentScanLog == null)
                    AgentScanLog = new StringBuilder();

                int count = 0;
                //
                //clean files as directed for file sig matches
                //
                foreach (CwXML.FileSignatureMatch match in FileSignatureMatches)
                {
                    string action = match.Action;

                    //try to delete the file
                    if (action == "Delete if found")
                    {
                        try
                        {
                            File.Delete(match.FullPath);
                        }
                        catch(Exception ex)
                        {
                            string t = ex.Message;
                            AgentScanLog.AppendLine("CLEAN:  Failed to remove file '"+match.FullPath+"'!");
                            FileSignatureMatches[count].ActionSuccessful = false;
                            count++;
                            continue;
                        }
                        FileSignatureMatches[count].ActionSuccessful = true;
                    }
                    count++;
                }

                return true;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // PrintFileFindings()                             //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  prints file signature findings
            //Returns:      nothing
            /////////////////////////////////////////////////////
            internal void PrintFileFindings(CwXML.FileSignatureMatch[] matches, ref StringBuilder output)
            {
                output.AppendLine("");
                output.AppendLine("REPORT:  ******************************");
                output.AppendLine("REPORT:  File Findings");
                output.AppendLine("REPORT:  ******************************");
                output.AppendLine("");
                output.AppendLine("Full Path\t\tSize\t\tHash (Type)\t\tPE Sig.\t\tCreated\t\tAccessed\t\tModified\t\tAction\t\tAction Successful\t\tOn Disk?");

                if (matches.Length == 0)
                {
                    output.AppendLine("REPORT:  No file signatures were found.");
                }
                else
                {
                    //loop through all match records
                    foreach (CwXML.FileSignatureMatch match in matches)
                    {
                        output.AppendLine("");
                        output.Append(match.FullPath + "\t\t");
                        output.Append(match.FileSize.ToString() + "\t\t");
                        output.Append(match.FileHash+" ("+match.FileHashType+")" + "\t\t");
                        output.Append(match.FilePEHeaderSignature + "\t\t");
                        output.Append(match.FileCreationDate + "\t\t");
                        output.Append(match.FileLastAccessDate + "\t\t");
                        output.Append(match.FileLastModifiedDate + "\t\t");
                        output.Append(match.Action + "\t\t");
                        output.Append(match.ActionSuccessful.ToString() + "\t\t");
                    }
                }

                output.AppendLine("");
                output.AppendLine("REPORT:  ******************************");
                output.AppendLine("");
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // FileSearch()                                    //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Searches for the given filename starting
            //              from the given root path (incl. drive)
            //Returns:      ArrayList structure of matching paths+filenames
            //
            //Notes:
            //
            //search combinations:
            //  1. filename only
            //  2. filename and hash only
            //  3. filename, hash and file size only
            //  4. filename, hash, file size and PE header signature
            //  5. file hash only
            //  6. file hash and file size only
            //  7. file hash, file size and PE sig
            //  8. file hash and PE sig
            //
            //note:  it is only gauranteed that the user supplied a file name OR a file hash
            //but these rules are enforced on the GUI during user input, so assume safe here.
            /////////////////////////////////////////////////////
            internal ArrayList FileSearch(string rootpath, string searchfilename, string searchfilehash, string searchfilehashtype, string searchfilesize, string searchfilepesig)
            {
                ArrayList filematches = new ArrayList();

                //get all folders but "System Volume Information"
                string[] topLevelFolders = Directory.GetDirectories(rootpath, "*", SearchOption.TopDirectoryOnly);
                ArrayList folders = new ArrayList();
                foreach (string fldr in topLevelFolders)
                {
                    FileInfo f = new FileInfo(fldr);
                    if ((f.Attributes & FileAttributes.System) == FileAttributes.System)
                        continue;
                    folders.Add(fldr);
                }

                //if no file name was given, retrieve ALL files then limit by size, hash, etc
                if (searchfilename == "")
                    searchfilename = "*";

                //search list of folders retrieved from top-level root folder (e.g., C:\)
                foreach (string dir in folders)
                {
                    try
                    {
                        foreach (string file in Directory.GetFiles(dir, searchfilename, SearchOption.AllDirectories))
                        {
                            FileInfo f = new FileInfo(file);

                            //FILESIZE SEARCH - if a file size was given, and this size doesn't match, skip it.
                            if (searchfilesize != "" && searchfilesize != "0")
                            {
                                int size = -1;
                                if (int.TryParse(searchfilesize, out size))
                                    if (f.Length != size)
                                        continue;
                            }
                            //FILE HASH SEARCH - if a file hash (md5/sha1) was given, and this file doesn't match, skip it.
                            if (searchfilehash != "")
                            {
                                if (searchfilehashtype == "SHA1")
                                {
                                    if (GetSHA1HashOfFile(f.FullName).Replace("-", "").ToUpper() != searchfilehash.ToUpper())
                                        continue;
                                }
                                else if (searchfilehashtype == "MD5")
                                {
                                    if (GetMD5HashOfFile(f.FullName) != searchfilehash.ToUpper())
                                        continue;
                                }
                            }
                            //PE HEADER SIG SEARCH
                            if (searchfilepesig != "")
                            {
                                if (!CheckPEHeaderSignature(f.FullName, searchfilepesig))
                                    continue;
                            }

                            //it passed all constraints given - add it to our list of matches
                            filematches.Add(f.FullName);
                        }
                    }
                    catch (Exception ex)
                    {
                        AgentScanLog.AppendLine("SCAN:  FileSearch():  " + ex.Message);
                        continue;
                    } //gulp..
                }

                return filematches;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetSHA1HashOfFile()                             //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Returns the sha-1 hash of a file
            //Returns:      string representation of hash
            /////////////////////////////////////////////////////
            internal string GetSHA1HashOfFile(string filename)
            {
                using (HashAlgorithm hashAlg = new SHA1Managed())
                {
                    using (Stream file = new FileStream(filename, FileMode.Open, FileAccess.Read))
                    {
                        byte[] hash = hashAlg.ComputeHash(file);

                        return (BitConverter.ToString(hash));
                    }
                }
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // CheckPEHeaderSignature()                        //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  checks the # of data directories and
            //              size of each directory matches the values
            //              supplied in the given signature
            //Returns:      true if match
            /////////////////////////////////////////////////////
            internal bool CheckPEHeaderSignature(string filename, string PESignatureToMatch)
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

                //passing 0 as third parameter (STYLE) means read access
                IntPtr pFileHandle=Win32Helper.CreateFile(filename,Win32Helper.GENERIC_READ,0,IntPtr.Zero,3,0,IntPtr.Zero);

                //fail gracefully
                if (pFileHandle == IntPtr.Zero)
                {
                    AgentScanLog.AppendLine("SCAN:  CheckPEHeaderSignature() failed on CreateFile() - "+Win32Helper.GetLastError32());
                    return false;
                }

                //create a file mapping for importing into our process address space
                IntPtr phMappingObject=Win32Helper.CreateFileMapping(pFileHandle,IntPtr.Zero,Win32Helper.PAGE_READONLY,0,0,null);

                if (phMappingObject == IntPtr.Zero)
                {
                    Win32Helper.CloseHandle(pFileHandle);
                    AgentScanLog.AppendLine("SCAN:  CheckPEHeaderSignature() failed on CreateFileMapping() - "+Win32Helper.GetLastError32());
                    return false;
                }

                //map the file mapping into our process
                IntPtr StartAddress=Win32Helper.MapViewOfFile(phMappingObject,Win32Helper.FILE_MAP_READ,0,0,0);

                if (StartAddress == IntPtr.Zero)
                {
                    Win32Helper.CloseHandle(pFileHandle);
                    Win32Helper.CloseHandle(phMappingObject);
                    AgentScanLog.AppendLine("SCAN:  CheckPEHeaderSignature() failed on MapViewOfFile() - "+Win32Helper.GetLastError32());
                    return false;
                }

                //get the PE header
                IntPtr pNtHeader=Win32Helper.ImageNtHeader(StartAddress);

                if (pNtHeader == IntPtr.Zero)
                {
                    Win32Helper.CloseHandle(pFileHandle);
                    Win32Helper.UnmapViewOfFile(StartAddress);
                    Win32Helper.CloseHandle(phMappingObject);

                    AgentScanLog.AppendLine("SCAN:  CheckPEHeaderSignature() failed on ImageNtHeader() - "+Win32Helper.GetLastError32());
                    return false;
                }

                //attempt to marshal the returned pointer to an IMAGE_NT_HEADERS32 struct
                Win32Helper.IMAGE_NT_HEADERS32 NtHeader=new Win32Helper.IMAGE_NT_HEADERS32();

                try
                {
                    Marshal.PtrToStructure(pNtHeader,NtHeader);
                }
                catch(Exception ex)
                {
                    Win32Helper.CloseHandle(pFileHandle);
                    Win32Helper.UnmapViewOfFile(StartAddress);
                    Win32Helper.CloseHandle(phMappingObject);
                    AgentScanLog.AppendLine("SCAN:  CheckPEHeaderSignature() failed marshaling pNtHeader:  "+ex.Message);
                    return false;
                }

                //extract the number of section directories from the Win32Helper.IMAGE_NT_HEADERS32 structure
                int numSections=NtHeader.FileHeader.NumberOfSections;

                //extract the number of sections from our signature -- first two 
                int numSigSections=0;
                try
                {
                    numSigSections = int.Parse(PESignatureToMatch.Substring(0,2));
                }
                catch(Exception ex)
                {
                    Win32Helper.CloseHandle(pFileHandle);
                    Win32Helper.UnmapViewOfFile(StartAddress);
                    Win32Helper.CloseHandle(phMappingObject);
                    AgentScanLog.AppendLine("SCAN:  CheckPEHeaderSignature() failed parsing PESignatureToMatch:  "+ex.Message);
                    return false;
                }

                //MATCH RULE #1
                //# of sections does not match, quit.
                if (numSigSections != numSections)
                {
                    Win32Helper.CloseHandle(pFileHandle);
                    Win32Helper.UnmapViewOfFile(StartAddress);
                    Win32Helper.CloseHandle(phMappingObject);
                    AgentScanLog.AppendLine("SCAN:  CheckPEHeaderSignature() succeeded - match not found because signature # sections ("+numSigSections.ToString()+") not equal to that found in this file ("+ numSigSections.ToString()+").");
                    return false;
                }

                //if we got here, then rule #1 passed (the binary matches the # of sections in our sig)
                //
                //now, loop through all section directories and test rule #2
                //
                Win32Helper.IMAGE_OPTIONAL_HEADER32 ImageOptionalHeader=NtHeader.OptionalHeader;
                Win32Helper.IMAGE_DATA_DIRECTORY[] DataDirectories=ImageOptionalHeader.DataDirectory;

                int startSig=2; //start parsing directory sizes from 3rd character
                string thisSigDataDirectory;
                int thisSigDataDirectoryVsize=0;
                int dircount=0;

                //there are 16 data directories in a standard PE binary - IAT, EAT, etc..
                //but if it's packed or compressed this is not true (in which case it's not a PE!)
                foreach (Win32Helper.IMAGE_DATA_DIRECTORY DataDirectory in DataDirectories)
                {
                    //the PE signature we are scanning for stores sizes as 8-bit hex values
                    try
                    {
                        thisSigDataDirectory=PESignatureToMatch.Substring(startSig,8);
                        thisSigDataDirectoryVsize=int.Parse(thisSigDataDirectory,NumberStyles.HexNumber);
                    }
                    catch(Exception ex)
                    {
                        Win32Helper.CloseHandle(pFileHandle);
                        Win32Helper.UnmapViewOfFile(StartAddress);
                        Win32Helper.CloseHandle(phMappingObject);
                        AgentScanLog.AppendLine("SCAN:  CheckPEHeaderSignature() failed parsing PESignatureToMatch (2):  "+ex.Message);
                        return false;
                    }

                    startSig+=8;

                    //MATCH RULE #2
                    //the VIRTUAL size of each section in this binary must match our signature
                    if (thisSigDataDirectoryVsize != DataDirectory.Size)
                    {
                        Win32Helper.CloseHandle(pFileHandle);
                        Win32Helper.UnmapViewOfFile(StartAddress);
                        Win32Helper.CloseHandle(phMappingObject);
                        AgentScanLog.AppendLine("SCAN:  CheckPEHeaderSignature() succeeded.  Virtual size in signature for data directory at offset 0x"+DataDirectory.VirtualAddress.ToString()+" does not match that supplied in the signature for data directory #"+dircount.ToString()+" ("+thisSigDataDirectoryVsize.ToString()+").");
                        return false;
                    }
                    dircount++;
                }

                AgentScanLog.AppendLine("SCAN:  CheckPEHeaderSignature() succeeded and found a match for file '"+filename+"'!");

                Win32Helper.CloseHandle(pFileHandle);
                Win32Helper.UnmapViewOfFile(StartAddress);
                Win32Helper.CloseHandle(phMappingObject);

                //match!
                return true;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetMD5HashOfFile()                              //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  calculates an MD5 hash of a file by
            //              reading each byte from the stream
            //Returns:      string representation in upper case
            /////////////////////////////////////////////////////
            internal string GetMD5HashOfFile(string filename)
            {
                MD5 md5 = MD5.Create();
                StringBuilder sb = new StringBuilder();

                using (FileStream fs = File.Open(filename, FileMode.Open))
                {
                    foreach (byte b in md5.ComputeHash(fs))
                        sb.Append(b.ToString("x2").ToUpper());
                }

                return sb.ToString();
            }
        }
    }
}
