###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_alftp_insecure_exec_file_load_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# ALFTP Insecure Executable File Loading Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "ALFTP version prior to 5.31";

tag_insight = "The flaw is due to the application loading executables (readme.exe)
  in an insecure manner. This can be exploited to run an arbitrary program by
  tricking a user into opening a file located on a remote WebDAV or SMB share.";
tag_solution = "Upgrade to the ALFTP version 5.31 or later,
  For updates refer to http://www.altools.jp/download/ALFTP.aspx";
tag_summary = "This host is installed with ALFTP and is prone to insecure
  executable file loading vulnerability.";

if(description)
{
  script_id(903012);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0315");
  script_bugtraq_id(51984);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("ALFTP Insecure Executable File Loading Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-28 10:36:31 +0530 (Wed, 28 Mar 2012)");

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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48027/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51984");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN85695061/index.html");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN85695061/995223/index.html");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000011.html");

  script_description(desc);
  script_summary("Check for the version of ALFTP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

## Variable Initialization
key = "";
alftpVer = "";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm the application
key = "SOFTWARE\ESTsoft\ALFTP";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get the version
alftpVer = registry_get_sz(key:key, item:"Version");
if(alftpVer)
{
  ## Check ALFTP version < 5.31
  if(version_is_less(version:alftpVer, test_version:"5.31")){
    security_hole(0);
  }
}
