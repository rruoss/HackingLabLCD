###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cmailserver_activex_mult_bof_vuln.nasl 3898 2009-08-19 12:45:380Z aug 
#
# CMailServer ActiveX Control Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_solution = "No solution or patch is available as of 19th August, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For further updates refer, http://www.youngzsoft.net/cmailserver/

  Workaround:
  Set the Killbit for the vulnerable CLSID
  http://support.microsoft.com/kb/240797";

tag_impact = "This issue can be exploited by sending a specially crafted POST request
  to mvmail.asp with an overly long 'indexOfMail' parameter to execute
  arbitrary code on the affected system.";
tag_affected = "CMailServer version 5.4.6 and prior.";
tag_insight = "A boundary error occurs in CMailServer POP3 Class ActiveX control
  (CMailCOM.dll) while handling arguments passed to the 'MoveToFolder()'
  method.";
tag_summary = "This host is installed with CMailServer ActiveX Control and is
  prone to Multiple Buffer Overflow vulnerabilities.";

if(description)
{
  script_id(900918);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-6922");
  script_bugtraq_id(30098);
  script_name("CMailServer ActiveX Control Multiple Buffer Overflow Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/30940");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6012");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/43594");

  script_description(desc);
  script_summary("Check for the Version of Cmail Server ActiveX");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("SMTP problems");
  script_dependencies("secpod_reg_enum.nasl", "secpod_cmailserver_detect.nasl");
  script_require_keys("SMB/WindowsVersion", "CMailServer/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

cmailVer = get_kb_item("CMailServer/Ver");
if(isnull(cmailVer)){
  exit(0);
}

if(version_is_less_equal(version:cmailVer, test_version:"5.4.6"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"+
                      "\Uninstall\CMailServer_is1", item:"InstallLocation");
  if(isnull(dllPath)){
    exit(0);
  }
  share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:dllPath +
                                                          "\CMailCOM.dll");
  dllVer = GetVer(share:share, file:file);
  # check if CMailCOM.dll version is 1.0.0.1 or prior
  if(version_is_less_equal(version:dllVer, test_version:"1.0.0.1"))
  {
    # Check if the Killbits are set
    if((is_killbit_set(clsid:"{6971D9B8-B53E-4C25-A414-76199768A592}") == 0) ||
       (is_killbit_set(clsid:"{0609792F-AB56-4CB6-8909-19CDF72CB2A0}") == 0)){
      security_hole(cmailPort);
    }
  }
}
