namespace CwHandler
{
    partial class CwAdminCredentialsWindow
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.label1 = new System.Windows.Forms.Label();
            this.AdminConsolePFXFilename = new System.Windows.Forms.TextBox();
            this.CwCredBrowseButton = new System.Windows.Forms.Button();
            this.AdminConsolePFXPassword = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.IgnoreCertError_RemoteCertificateNameMismatch = new System.Windows.Forms.CheckBox();
            this.label3 = new System.Windows.Forms.Label();
            this.IgnoreCertError_RemoteCertificateChainErrors = new System.Windows.Forms.CheckBox();
            this.CwCredSetButton = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(21, 28);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(207, 13);
            this.label1.TabIndex = 0;
            this.label1.Text = "Public/Private keypair file (PKCS-12/PFX):";
            // 
            // AdminConsolePFXFilename
            // 
            this.AdminConsolePFXFilename.Location = new System.Drawing.Point(24, 56);
            this.AdminConsolePFXFilename.Name = "AdminConsolePFXFilename";
            this.AdminConsolePFXFilename.Size = new System.Drawing.Size(315, 20);
            this.AdminConsolePFXFilename.TabIndex = 1;
            this.AdminConsolePFXFilename.Text = "C:\\development\\Codeword\\Documentation\\certs\\CwAdminConsoleTestPFX.pfx";
            // 
            // CwCredBrowseButton
            // 
            this.CwCredBrowseButton.Location = new System.Drawing.Point(345, 54);
            this.CwCredBrowseButton.Name = "CwCredBrowseButton";
            this.CwCredBrowseButton.Size = new System.Drawing.Size(75, 23);
            this.CwCredBrowseButton.TabIndex = 2;
            this.CwCredBrowseButton.Text = "Browse...";
            this.CwCredBrowseButton.UseVisualStyleBackColor = true;
            this.CwCredBrowseButton.Click += new System.EventHandler(this.CwCredBrowseButton_Click);
            // 
            // AdminConsolePFXPassword
            // 
            this.AdminConsolePFXPassword.Location = new System.Drawing.Point(121, 93);
            this.AdminConsolePFXPassword.Name = "AdminConsolePFXPassword";
            this.AdminConsolePFXPassword.Size = new System.Drawing.Size(218, 20);
            this.AdminConsolePFXPassword.TabIndex = 3;
            this.AdminConsolePFXPassword.Text = "test";
            this.AdminConsolePFXPassword.UseSystemPasswordChar = true;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(21, 96);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(94, 13);
            this.label2.TabIndex = 4;
            this.label2.Text = "PFX file password:";
            // 
            // IgnoreCertError_RemoteCertificateNameMismatch
            // 
            this.IgnoreCertError_RemoteCertificateNameMismatch.AutoSize = true;
            this.IgnoreCertError_RemoteCertificateNameMismatch.Checked = true;
            this.IgnoreCertError_RemoteCertificateNameMismatch.CheckState = System.Windows.Forms.CheckState.Checked;
            this.IgnoreCertError_RemoteCertificateNameMismatch.ForeColor = System.Drawing.Color.Red;
            this.IgnoreCertError_RemoteCertificateNameMismatch.Location = new System.Drawing.Point(45, 160);
            this.IgnoreCertError_RemoteCertificateNameMismatch.Name = "IgnoreCertError_RemoteCertificateNameMismatch";
            this.IgnoreCertError_RemoteCertificateNameMismatch.Size = new System.Drawing.Size(183, 17);
            this.IgnoreCertError_RemoteCertificateNameMismatch.TabIndex = 5;
            this.IgnoreCertError_RemoteCertificateNameMismatch.Text = "RemoteCertificateNameMismatch";
            this.IgnoreCertError_RemoteCertificateNameMismatch.UseVisualStyleBackColor = true;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(21, 133);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(153, 13);
            this.label3.TabIndex = 6;
            this.label3.Text = "Ignore remote certificate errors:";
            // 
            // IgnoreCertError_RemoteCertificateChainErrors
            // 
            this.IgnoreCertError_RemoteCertificateChainErrors.AutoSize = true;
            this.IgnoreCertError_RemoteCertificateChainErrors.Checked = true;
            this.IgnoreCertError_RemoteCertificateChainErrors.CheckState = System.Windows.Forms.CheckState.Checked;
            this.IgnoreCertError_RemoteCertificateChainErrors.ForeColor = System.Drawing.Color.Red;
            this.IgnoreCertError_RemoteCertificateChainErrors.Location = new System.Drawing.Point(45, 183);
            this.IgnoreCertError_RemoteCertificateChainErrors.Name = "IgnoreCertError_RemoteCertificateChainErrors";
            this.IgnoreCertError_RemoteCertificateChainErrors.Size = new System.Drawing.Size(164, 17);
            this.IgnoreCertError_RemoteCertificateChainErrors.TabIndex = 7;
            this.IgnoreCertError_RemoteCertificateChainErrors.Text = "RemoteCertificateChainErrors";
            this.IgnoreCertError_RemoteCertificateChainErrors.UseVisualStyleBackColor = true;
            // 
            // CwCredSetButton
            // 
            this.CwCredSetButton.Location = new System.Drawing.Point(196, 216);
            this.CwCredSetButton.Name = "CwCredSetButton";
            this.CwCredSetButton.Size = new System.Drawing.Size(75, 23);
            this.CwCredSetButton.TabIndex = 8;
            this.CwCredSetButton.Text = "Save";
            this.CwCredSetButton.UseVisualStyleBackColor = true;
            this.CwCredSetButton.Click += new System.EventHandler(this.CwCredSetButton_Click);
            // 
            // CwAdminCredentialsWindow
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(453, 251);
            this.Controls.Add(this.CwCredSetButton);
            this.Controls.Add(this.IgnoreCertError_RemoteCertificateChainErrors);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.IgnoreCertError_RemoteCertificateNameMismatch);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.AdminConsolePFXPassword);
            this.Controls.Add(this.CwCredBrowseButton);
            this.Controls.Add(this.AdminConsolePFXFilename);
            this.Controls.Add(this.label1);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedToolWindow;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "CwAdminCredentialsWindow";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "Set Admin Console Credentials";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.CwAdminCredentialsWindow_FormClosing);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox AdminConsolePFXFilename;
        private System.Windows.Forms.Button CwCredBrowseButton;
        private System.Windows.Forms.TextBox AdminConsolePFXPassword;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.CheckBox IgnoreCertError_RemoteCertificateNameMismatch;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.CheckBox IgnoreCertError_RemoteCertificateChainErrors;
        private System.Windows.Forms.Button CwCredSetButton;
    }
}