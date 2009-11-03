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
using System.Windows;
using System.Windows.Forms;
using System.Timers;
using System.Reflection;
using System.Threading;

namespace CwHandler
{
    public class CwProgressWindow : Form
    {
        private ProgressBar pbar;
        private Label ProgressBarLabel;
        private BackgroundWorker workerThread = new BackgroundWorker();
        private System.ComponentModel.IContainer components = null;
        private bool DONT_AddDotNextFxAssembly;
        private ArrayList x509certs;
        private ArrayList thirdPartyApps;

        #region gui form mgmt funcs
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(CwProgressWindow));
            this.pbar = new System.Windows.Forms.ProgressBar();
            this.ProgressBarLabel = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // ProgressBar
            // 
            this.pbar.Location = new System.Drawing.Point(89, 39);
            this.pbar.Name = "ProgressBar";
            this.pbar.Size = new System.Drawing.Size(308, 28);
            this.pbar.TabIndex = 0;
            this.pbar.UseWaitCursor = true;
            // 
            // ProgressBarLabel
            // 
            this.ProgressBarLabel.AutoSize = true;
            this.ProgressBarLabel.Location = new System.Drawing.Point(220, 79);
            this.ProgressBarLabel.Name = "ProgressBarLabel";
            this.ProgressBarLabel.Size = new System.Drawing.Size(70, 13);
            this.ProgressBarLabel.TabIndex = 1;
            this.ProgressBarLabel.Text = "Please wait...";
            this.ProgressBarLabel.UseWaitCursor = true;
            // 
            // ProgressWindow
            // 
            this.ClientSize = new System.Drawing.Size(470, 123);
            this.ControlBox = false;
            this.Controls.Add(this.ProgressBarLabel);
            this.Controls.Add(this.pbar);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "ProgressWindow";
            this.ShowInTaskbar = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "Loading...";
            this.UseWaitCursor = true;
            this.ResumeLayout(false);
            this.PerformLayout();
        }
        #endregion

        //constructor
        public CwProgressWindow(int numSteps, int stepSize, bool _DONT_AddDotNetFxAssembly, ArrayList certs, ArrayList thirdPartyAppList)
        {
            InitializeComponent();

            //setup progress bar
            pbar.Visible = true;
            pbar.Minimum = 1;
            pbar.Maximum = numSteps * stepSize;
            pbar.Step = stepSize;
            pbar.Value = 1;

            //add new custom options here!
            this.DONT_AddDotNextFxAssembly = _DONT_AddDotNetFxAssembly;
            this.x509certs = certs;
            this.thirdPartyApps = thirdPartyAppList;

            //setup worker thread
            workerThread.WorkerReportsProgress = true;
            workerThread.WorkerSupportsCancellation = true;
            workerThread.DoWork += new DoWorkEventHandler(WorkerThread_DoWork);
            workerThread.ProgressChanged += new ProgressChangedEventHandler(WorkerThread_ProgressChanged);
            workerThread.RunWorkerCompleted += new RunWorkerCompletedEventHandler(WorkerThread_RunWorkerCompleted);

            //add any arguments the MSI class needs to know about here!
            ArrayList args = new ArrayList();
            args.Add(DONT_AddDotNextFxAssembly);
            args.Add(x509certs);
            args.Add(thirdPartyAppList);

            //launch it - when this is serviced, it calls directly into our DoWork() function below
            workerThread.RunWorkerAsync(args);
        }

        private void CancelButton_Clicked(object sender, EventArgs e)
        {
            if (workerThread.WorkerSupportsCancellation)
                workerThread.CancelAsync();
        }

        #region Worker thread functions

        private void WorkerThread_DoWork(object sender, DoWorkEventArgs e)
        {
            //create a new msi class and do the work!
            CwMsiClass msi = new CwMsiClass();

            try
            {
                msi.Start(workerThread, pbar.Step, e);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void WorkerThread_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            ProgressBarLabel.Text = "Generating MSI...";

            pbar.Value = e.ProgressPercentage;
            pbar.Refresh();
            ProgressBarLabel.Text += e.ProgressPercentage.ToString() + "%";
            ProgressBarLabel.Refresh();
        }

        private void WorkerThread_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Cancelled)
            {
                this.Close();
            }
            //if there was an internal error (rare)
            else if (e.Error != null)
            {
                MessageBox.Show(e.Error.Message);
            }
            //if we manually set the result to FALSE, an error was thrown
            //which we have already displayed to the user - just quit.
            else if (e.Result != null)
            {
            }
            else
            {
                pbar.Value = pbar.Maximum;
                pbar.Refresh();
                MessageBox.Show("MSI generated successfully!");
            }

            this.Close();
        }

        #endregion

    }
}