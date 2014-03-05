###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quiksoft_easymail_obj_actvx_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# QuikSoft EasyMail Objects ActiveX Control BOF Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Attackers may exploit this issue by executing arbitrary code in the context
  of a Web page and can cause buffer overflow.
  Impact Level: Application";
tag_affected = "QuikSoft EasyMail MailStore with emmailstore.dll version 6.5.0.3 on Windows";
tag_insight = "Flaw exists in CreateStore method in emmailstore.dll file, which fails to
  perform adequate boundary checks on user-supplied data.";
tag_solution = "No solution or patch is available as of 13th March 2009, Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.quiksoft.com/";
tag_summary = "This host is installed with QuikSoft EasyMail Objects ActiveX
  Control and is prone to buffer overflow vulnerability.";

if(description)
{
  script_id(800535);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-13 14:39:10 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-6447");
  script_bugtraq_id(32722);
  script_name("QuikSoft EasyMail Objects ActiveX Control BOF Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7402");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/240797");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/47207");

  script_description(desc);
  script_summary("Check for the emmailstore.dll version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Quiksoft\EasyMail Objects")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  emoName = registry_get_sz(key:key + item, item:"DisplayName");
  if("EasyMail Objects" >< emoName)
  {
    dllPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(dllPath != NULL)
    {
      dllPath = dllPath + "emmailstore.dll";
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

      dllVer = GetVer(file:file, share:share);
      if(version_is_less_equal(version:dllVer, test_version:"6.5.0.3")){
        security_hole(0);
      }
    }
    exit(0);
  }
}