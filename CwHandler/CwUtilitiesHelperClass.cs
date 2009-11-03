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
using System.Reflection;
using System.IO;

namespace CwHandler
{
    internal static class CwUtilitiesHelperClass
    {
        public static bool ExtractInternalResource(string resourceName, string outputFilename)
        {
            //extract internal assembly that holds config file
            //we will read in these settings and scope our action based on them
            Assembly a = Assembly.GetExecutingAssembly();

            Stream byteStream;

            try
            {
                //get the file byte stream from the ASM manifest rsrc
                byteStream = a.GetManifestResourceStream(resourceName);
            }
            catch (System.IO.FileNotFoundException e)
            {
                throw new FileNotFoundException("FileNotFoundException:  Unable to locate the embedded resource.  " + e.Message);
            }

            if (byteStream == null)
            {
                string errmsg = "The file extraction stream for the embedded resource '" + resourceName + "' was empty.";
                errmsg += "\n\nAvailable assemblies:";
                foreach (string Name in a.GetManifestResourceNames())
                    errmsg += "\nName: " + Name;
                throw new Exception("Error:  " + errmsg);
            }

            //read the stream data and store in a Byte[] array
            byte[] buf = new byte[byteStream.Length];
            int bytesToRead = (int)byteStream.Length;
            int bytesRead = 0;

            while (bytesToRead > 0)
            {
                int n = byteStream.Read(buf, bytesRead, bytesToRead);
                if (n == 0)
                    break;
                bytesRead += n;
                bytesToRead -= n;
            }

            byteStream.Close();

            //save the file to disk using global file name
            try
            {
                BinaryWrite(outputFilename, buf);
            }
            catch (Exception e)
            {
                throw new Exception(e.InnerException.Message);
            }

            return true;
        }

        public static bool BinaryWrite(string filename, byte[] data)
        {
            FileStream outfile;
            BinaryWriter bw;

            //create the file on disk - auto overwrite if exists
            try
            {
                outfile = File.Create(filename);
            }
            catch (Exception e)
            {
                throw new Exception("Fatal error occurred.  Could not create file '" + filename + "':  " + e.Message);
            }

            //write to the file
            try
            {
                bw = new BinaryWriter(outfile);
                bw.Write(data);
                bw.Flush();
                bw.Close();
            }
            catch (Exception e)
            {
                outfile.Close();
                throw new Exception("Fatal error occurred.  Could not write to file '" + filename + "':  " + e.Message);
            }

            return true;
        }
    }
}
