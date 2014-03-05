###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_filecopa_ftp_server_noop_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# FileCopa FTP Server 'NOOP' Command DoS Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to cause a Denial of Service.
  Impact Level: Application";
tag_affected = "FileCopa FTP Server version 5.01 and prior on Windows.";
tag_insight = "The flaw is due to an error in the handling of 'NOOP' FTP commands.
  This can be exploited to hang an affected server via an overly large number
  of specially crafted NOOP commands.";
tag_solution = "Upgrade to FileCopa FTP Server version 5.02
  http://www.filecopa-ftpserver.com/download.html";
tag_summary = "This host is running FileCopa FTP Server and is prone to Denial of
  Service vulnerability.";

if(description)
{
  script_id(801125);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3662");
  script_bugtraq_id(36397);
  script_name("FileCopa FTP Server 'NOOP' Command DoS Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36773");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/36397.txt");

  script_description(desc);
  script_summary("Check the version of FileCopa FTP Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

filecopaPort = get_kb_item("Services/ftp");
if(!filecopaPort){
  exit(0);
}

filecopaVer = get_kb_item("FileCOPA-FTP-Server/Ver");
if(!filecopaVer){
  exit(0);
}

# Check for FileCopa FTP Server versions < 5.02
if(version_is_less(version:filecopaVer, test_version:"5.02")){
  security_warning(filecopaPort);
}
