##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_golden_ftp_server_dir_trav_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Golden FTP Server 'DELE' Command Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
################################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow the remote authenticated user to access
  arbitrary folders and delete arbitrary files from the FTP directories.";
tag_affected = "Golden FTP Server Pro version 4.30 and prior.
  Golden FTP Server Free version 4.30 and prior.";
tag_insight = "The flaw is due to an input validation error in 'DELE' command. It is
  possible to escape the FTP root and delete arbitrary files on the system via
  directory traversal (../../) attack methods.";
tag_solution = "No solution or patch is available as of 04th December 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.goldenftpserver.com/download.html";
tag_summary = "This host is running Golden FTP Server and is prone to Directory
  Traversal vulnerability.";

if(description)
{
  script_id(801073);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-05 12:49:16 +0100 (Sat, 05 Dec 2009)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4194");
  script_name("Golden FTP Server 'DELE' Command Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37527");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54497");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10258");

  script_description(desc);
  script_summary("Check for the version of Golden FTP Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_golden_ftp_server_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("Golden/FTP/Pro/Ver","Golden/FTP/Free/Ver");
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

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

if(gftpVer = get_kb_item("Golden/FTP/Pro/Ver"))
{
  # Golden FTP server Pro v4.30 = v4.50
  if(version_is_less_equal(version:gftpVer, test_version:"4.50")){
    security_hole(port);
  }
}

else if(gfftpVer = get_kb_item("Golden/FTP/Free/Ver"))
{
  # Golden FTP server Free v4.30 = v4.50
  if(version_is_less_equal(version:gfftpVer, test_version:"4.50")){
    security_hole(port);
  }
}
