/*
This product includes software developed by James Landis of Fishnet Security.
All use and distribution of this software is subject to Version 2.0
of the Apache License (http://www.apache.org/licenses/LICENSE-2.0).
*/

using System;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Threading;
using AppScan;
using AppScan.Scan.Data;
using AppScan.Extensions;
using AppScan.Events;

namespace IssueVariantTree
{
    /// <summary>
    /// Context Menu for Fuzzer main implementation class.
    /// implementing the IExtensionLogic interface
    /// </summary>
    public class ContextMenu : IExtensionLogic
    {

        #region data members

        Version extensionVersion = new Version(0,9,1);
        VersionRange extensionVersionRange = new VersionRange(new Version(7,5), new Version(8,0));
        Uri downloadURI = new Uri("http://notspecifiedyet.com");

        const string contextMenuLabel = "Copy Issue Tree";

        Object clipboardObject;

        IMenuItem<IssuesEventArgs> mainIssuesExtMenuItem;
        ICollection<IMenuItem<IssuesEventArgs>> IssueMenuItems;


        #endregion data members

        #region Initialization

        /// <summary>
        /// extension initialization. typically called on AppScan's startup
        /// </summary>
        /// <param name="appScan">main application object the extension is loaded into</param>
        /// <param name="extensionDir">extension's working directory</param>
        public void Load(IAppScan appscan, IAppScanGui appScanGui, string extensionDir)
        {
            InitGuiHooks();
            RegisterGuiHooks(appScanGui);
        }

        /// <summary>
        /// Creates the menu entries objects
        /// </summary>
        private void InitGuiHooks()
        {
            IssueMenuItems = CreateIssueContextMenuItems(); // Create a context-menu entry collection
        }

        /// <summary>
        ///  Add menu entries to AppScan
        /// </summary>
        /// <param name="appScanGui"></param>
        private void RegisterGuiHooks(IAppScanGui appScanGui)
        {
            foreach (IMenuItem<IssuesEventArgs> item in IssueMenuItems)
                appScanGui.IssueContextMenu.Add(item);
        }

        #endregion Initialization

        #region GUI items construction


        private ICollection<IMenuItem<IssuesEventArgs>> CreateIssueContextMenuItems()
        {
            mainIssuesExtMenuItem = new MenuItem<IssuesEventArgs>(contextMenuLabel, DelegateContextMenuAction);
            List<IMenuItem<IssuesEventArgs>> items = new List<IMenuItem<IssuesEventArgs>>();
            items.Add(mainIssuesExtMenuItem);
            return items;
        }


        #endregion GUI items construction

        #region delegates

        /// <summary>
        /// Issue-context menu entry action
        /// </summary>
        /// <param name="args"></param>
        private void DelegateContextMenuAction(IssuesEventArgs args)
        {
            if (args.issues != null)
            {
                String clip = args.issues.Count + " issue(s) will be copied to the clipboard\r\n";

                foreach (IIssue ii in args.issues)
                    clip += issueTreeOutput(ii);
                clipboardObject = clip;

                // spawn a new thread to set the clipboard object (requires STA)
                Thread t = new Thread(new ThreadStart(writeToClipboard));
                t.SetApartmentState(ApartmentState.STA);
                t.Start();
            }
        }

        #endregion delegates

        #region outputcode

        private void writeToClipboard()
        {
            Clipboard.SetDataObject(clipboardObject, true);
        }

        /// <summary>
        /// Generate issue tree as String (Windows CRLF line breaks)
        /// Level 
        /// </summary>
        /// <param name="issue"></param>
        private String issueTreeOutput(IIssue issue)
        {
            String s = issue.AppTreeNode.Path + "\r\n";
            bool entityWritten = false;
            foreach (ITest t in issue.Variants)
            {
                foreach (IDifference d in t.Differences)
                {
                    if (!entityWritten)
                    {
                        s += "\t" + d.Name + "\r\n";
                        entityWritten = true;
                    }
                    s += "\t\t" + d.Altered + "\r\n";
                }
            }
            return s;
        }


        #endregion outputcode

        #region other

        /// <summary>
        /// retrieves data about current available ext-version
        /// </summary>
        /// <param name="targetApp">app this extension is designated for</param>
        /// <param name="targetAppVersion">current version of targetApp</param>
        /// <returns>update data of most recent extension version, or null if no data was found, or feature isn't supported. it is valid to return update data of current version. extension-update will take place only if returned value indicaes a newer version</returns>
        public ExtensionVersionInfo GetUpdateData(Edition targetApp, System.Version targetAppVersion)
        {
            return new ExtensionVersionInfo(extensionVersion, extensionVersionRange, downloadURI);
        }

        #endregion other

    }
}
