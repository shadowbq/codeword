namespace CwHandler
{
    partial class CwAdminMitigationWindow
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(CwAdminMitigationWindow));
            this.MitigationTasksListview = new System.Windows.Forms.ListView();
            this.MitigationTasksType = new System.Windows.Forms.ColumnHeader();
            this.MitigationTasksAction = new System.Windows.Forms.ColumnHeader();
            this.MitigationTasksName = new System.Windows.Forms.ColumnHeader();
            this.MitigationTasksGoButton = new System.Windows.Forms.Button();
            this.MitigationTasksCloseButton = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // MitigationTasksListview
            // 
            this.MitigationTasksListview.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.MitigationTasksType,
            this.MitigationTasksAction,
            this.MitigationTasksName});
            this.MitigationTasksListview.FullRowSelect = true;
            this.MitigationTasksListview.GridLines = true;
            this.MitigationTasksListview.Location = new System.Drawing.Point(12, 12);
            this.MitigationTasksListview.Name = "MitigationTasksListview";
            this.MitigationTasksListview.Size = new System.Drawing.Size(503, 279);
            this.MitigationTasksListview.TabIndex = 0;
            this.MitigationTasksListview.UseCompatibleStateImageBehavior = false;
            this.MitigationTasksListview.View = System.Windows.Forms.View.Details;
            // 
            // MitigationTasksType
            // 
            this.MitigationTasksType.Text = "Type";
            this.MitigationTasksType.Width = 114;
            // 
            // MitigationTasksAction
            // 
            this.MitigationTasksAction.Text = "Action";
            this.MitigationTasksAction.Width = 132;
            // 
            // MitigationTasksName
            // 
            this.MitigationTasksName.Text = "Name";
            this.MitigationTasksName.Width = 243;
            // 
            // MitigationTasksGoButton
            // 
            this.MitigationTasksGoButton.Location = new System.Drawing.Point(165, 309);
            this.MitigationTasksGoButton.Name = "MitigationTasksGoButton";
            this.MitigationTasksGoButton.Size = new System.Drawing.Size(75, 23);
            this.MitigationTasksGoButton.TabIndex = 1;
            this.MitigationTasksGoButton.Text = "Go";
            this.MitigationTasksGoButton.UseVisualStyleBackColor = true;
            this.MitigationTasksGoButton.Click += new System.EventHandler(this.MitigationTasksGoButton_Click);
            // 
            // MitigationTasksCloseButton
            // 
            this.MitigationTasksCloseButton.Location = new System.Drawing.Point(279, 309);
            this.MitigationTasksCloseButton.Name = "MitigationTasksCloseButton";
            this.MitigationTasksCloseButton.Size = new System.Drawing.Size(75, 23);
            this.MitigationTasksCloseButton.TabIndex = 2;
            this.MitigationTasksCloseButton.Text = "Close";
            this.MitigationTasksCloseButton.UseVisualStyleBackColor = true;
            this.MitigationTasksCloseButton.Click += new System.EventHandler(this.MitigationTasksCloseButton_Click);
            // 
            // CwAdminMitigationWindow
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(527, 354);
            this.Controls.Add(this.MitigationTasksCloseButton);
            this.Controls.Add(this.MitigationTasksGoButton);
            this.Controls.Add(this.MitigationTasksListview);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedToolWindow;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "CwAdminMitigationWindow";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "Mitigation Tasks";
            this.Shown += new System.EventHandler(this.CwAdminMitigationWindow_Shown);
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.CwAdminMitigationWindow_FormClosing);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.ListView MitigationTasksListview;
        private System.Windows.Forms.ColumnHeader MitigationTasksType;
        private System.Windows.Forms.ColumnHeader MitigationTasksAction;
        private System.Windows.Forms.ColumnHeader MitigationTasksName;
        private System.Windows.Forms.Button MitigationTasksGoButton;
        private System.Windows.Forms.Button MitigationTasksCloseButton;
    }
}