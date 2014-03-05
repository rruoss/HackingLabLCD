###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xm_easyftp_dir_create_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# XM Easy Personal FTP Server File/Folder Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_impact = "Successful exploitation will let the authenticated user create recursive
  directories and crash the FTP Server.";
tag_affected = "Dxmsoft XM Easy Personal FTP Server version 5.8.0 and prior.";
tag_insight = "This flaw is due to improper validation check while creating recursive
  directories by an authenticated user inside the root folder of the FTP
  server.";
tag_solution = "No solution or patch is available as of 02nd December, 2009. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.dxm2008.com";
tag_summary = "This host is running XM Easy Personal FTP Server and is prone
  to Denial of Service Vulnerability.";

if(description)
{
  script_id(800726);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(37112);
  script_cve_id("CVE-2009-4108");
  script_name("XM Easy Personal FTP Server File/Folder Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37473");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54400");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/508049/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of XM Easy Personal FTP Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "gb_xm_easy_personal_ftp_detect.nasl");
  script_require_keys("XM-Easy-Personal-FTP/Ver");
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

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

xmFTPVer = get_kb_item("XM-Easy-Personal-FTP/Ver");
if(xmFTPVer != NULL)
{
  # Grep for version 5.8.0 and prior
  if(version_is_less_equal(version:xmFTPVer, test_version:"5.8.0")){
    security_warning(port);
  }
}
