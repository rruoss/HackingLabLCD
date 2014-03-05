###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smartermail_multiple_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SmarterMail Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could allow attackers to conduct cross site scripting,
  shell upload and directory traversal attacks.
  Impact Level: Application";
tag_affected = "SmarterTools SmarterMail versions 7.4 and prior.";
tag_insight = "Input passed in the 'path' parameter to Main/frmStoredFiles.aspx, the 'edit'
  parameter to UserControls/Popups/frmAddFileStorageFolder.aspx, the
  'SubjectBox_SettingText' parameter to Main/Calendar/frmEvent.aspx, the 'url'
  parameter to UserControls/Popups/frmHelp.aspx, the 'folder' parameter to
  UserControls/Popups/frmDeleteConfirm.aspx, the 'editfolder' parameter to
  UserControls/Popups/frmEventGroup.aspx, the 'deletefolder' parameter to
  UserControls/Popups/frmEventGroup.aspx, and the 'bygroup' parameter to
  Main/Alerts/frmAlerts.aspx is not properly sanitised before being returned
  to the user.";
tag_solution = "Upgrade to SmarterTools SmarterMail 8.0 or later,
  For updates refer to http://www.smartertools.com/smartermail/mail-server-software.aspx";
tag_summary = "This host is running SmarterMail and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(901196);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("SmarterMail Multiple Vulnerabilities");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41677/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41485/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16955/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/99169/smartermail-xsstraversalshell.txt");

  script_description(desc);
  script_summary("Check for the version of SmarterMail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_smartermail_detect.nasl");
  script_require_keys("SmartMail/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Get SmarterMail Version from KB
smVer = get_kb_item("SmartMail/Ver");
if(!isnull(smVer))
{
  ## Check for SmarterMail versions 7.4 and prior
  if(version_in_range(version:smVer, test_version:"7.0", test_version2:"7.4")) {
    security_warning(0);
  }
}
