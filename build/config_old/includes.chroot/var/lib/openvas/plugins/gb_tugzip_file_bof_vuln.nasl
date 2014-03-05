###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tugzip_file_bof_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# TUGzip zip File Buffer Overflow Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation allows attackers to execute arbitrary code by
  tricking a user into opening a specially crafted archive or can even
  crash an affected application.
  Impact Level: Application/System";
tag_affected = "TUGzip Version 3.5.0.0 and prior on Windows (Any).";
tag_insight = "The flaw exists due to boundary error while processing an archive containing
  an overly long file or directory name.";
tag_solution = "No solution or patch is available as of 31st October, 2008. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.tugzip.com/";
tag_summary = "This host is installed with TUGzip, which is prone to Buffer
  Overflow Vulnerability.";

if(description)
{
  script_id(800122);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-31 15:07:51 +0100 (Fri, 31 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-4779");
  script_bugtraq_id(31913);
  script_name("TUGzip zip File Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32411");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6831");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/46120");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2918");

  script_description(desc);
  script_summary("Check for the Version of TUGzip");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

# Get Application Path
appPath = registry_get_sz(item:"Inno Setup: App Path",
          key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TUGZip_is1");
if(!appPath){
  exit(0);
}

exePath = appPath + "\TUGZip.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

# Get TUGZip Version
tugZipVer = GetVer(file:file, share:share);
if(!tugZipVer){
  exit(0);
}

if(version_is_less_equal(version:tugZipVer, test_version:"3.5.0.0")){
  security_hole(0);
}
