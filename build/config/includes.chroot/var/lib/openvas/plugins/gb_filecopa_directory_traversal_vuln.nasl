###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_filecopa_directory_traversal_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# FileCopa FTP Server Directory Traversal Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to read or overwrite arbitrary
  files via unknown vectors.
  Impact Level: System/Application";
tag_affected = "FileCopa FTP Server version before 5.03 on Windows.";
tag_insight = "An input validation error exists within the FTP service, which can be
  exploited to download or upload arbitrary files outside the FTP root
  via directory traversal attack.";
tag_solution = "Upgrade to FileCopa FTP Server version 5.03 or later.
  http://www.filecopa-ftpserver.com/";
tag_summary = "This host is running FileCopa FTP Server and is prone to
  directory traversal vulnerability.";

if(description)
{
  script_id(800179);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2112");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:N");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("FileCopa FTP Server Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/64823");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39843");

  script_description(desc);
  script_summary("Check the version of FileCopa FTP Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("FTP");
  script_dependencies("gb_filecopa_ftp_server_detect.nasl");
  script_require_keys("FileCOPA-FTP-Server/Ver");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

## Get FTP Port
filecopaPort = get_kb_item("Services/ftp");
if(!filecopaPort){
  exit(0);
}

## Get Version from KB
filecopaVer = get_kb_item("FileCOPA-FTP-Server/Ver");
if(!filecopaVer){
  exit(0);
}

## Check for FileCopa FTP Server versions < 5.03
if(version_is_less(version:filecopaVer, test_version:"5.03")){
  security_hole(filecopaPort);
}
