###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_findtext_dos_vuln_aug09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Internet Explorer 'findText()' Unicode Parsing DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to cause the application
  to crash.
  Impact Level: Application";
tag_affected = "Microsoft, Internet Explorer version 7.x/8.x";
tag_insight = "The flaw is due to error in mshtml.dll file and it can causes while
  calling the JavaScript findText method with a crafted Unicode string in the
  first argument, and only one additional argument, as demonstrated by a second
  argument of -1.";
tag_solution = "No solution or patch is available as of 05th August, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/windows/products/default.aspx";
tag_summary = "This host has Internet Explorer installed and is prone to Denial
  of Service vulnerability.";

if(description)
{
  script_id(800861);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-07 07:29:21 +0200 (Fri, 07 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2655");
  script_bugtraq_id(35799);
  script_name("Microsoft Internet Explorer 'findText()' Unicode Parsing DoS Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9253");

  script_description(desc);
  script_summary("Check for the Version of Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
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

# Check for XP SP3
SP = get_kb_item("SMB/WinXP/ServicePack");
if("Service Pack 3" >< SP)
{
  # Get for Internet Explorer Version
  ieVer = get_kb_item("MS/IE/Version");
  # Check for IE 7/8
  if(ieVer =~ "^[7|8]\..*")
  {
    dllPath = registry_get_sz(item:"Install Path",
                              key:"SOFTWARE\Microsoft\COM3\Setup");
    dllPath += "\mshtml.dll";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

    # Get for mshtml.dll Version
    mshtmlVer = GetVer(file:file, share:share);
    if(isnull(mshtmlVer))
      exit(0);

    # Check for DLL version 7.0 <= 7.0.6000.16890 or 8.0 <= 8.0.6001.18812
    if(version_in_range(version:mshtmlVer, test_version:"7.0",
                                          test_version2:"7.0.6000.16890")||
       version_in_range(version:mshtmlVer, test_version:"8.0",
                                          test_version2:"8.0.6001.18812")){
      security_warning(0);
    }
  }
}
