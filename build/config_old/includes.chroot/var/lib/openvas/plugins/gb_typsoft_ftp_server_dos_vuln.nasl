##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typsoft_ftp_server_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# TYPSoft FTP Server 'APPE' and 'DELE' Commands DOS Vulnerability
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
tag_impact = "Successful exploitation will let the user crash the application to cause
  denial of service.";
tag_affected = "TYPSoft FTP Server version 1.10 and prior.";
tag_insight = "The flaw is due to an error when handling the 'APPE' and 'DELE' commands. These can
  be exploited through sending multiple login request in same socket.";
tag_solution = "No solution or patch is available as of 01st December 2009. Information
  regarding this issue will be updated once the solution details are available.
  http://www.softpedia.com/get/Internet/Servers/FTP-Servers/TYPSoft-FTP-Server.shtml";
tag_summary = "This host is running TYPSoft FTP Server and is prone to Denial of
  Service Vulnerability.";

if(description)
{
  script_id(801058);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(37114);
  script_cve_id("CVE-2009-4105");
  script_name("TYPSoft FTP Server 'APPE' and 'DELE' Commands DOS Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54407");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Nov/1023234.html");

  script_description(desc);
  script_summary("Check for the version of TYPSoft FTP Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_typsoft_ftp_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("TYPSoft/FTP/Ver");
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


port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

tsftpVer = get_kb_item("TYPSoft/FTP/Ver");
if(tsftpVer != NULL)
{
  if(version_is_less_equal(version:tsftpVer, test_version:"1.10")){
   security_warning(port);
  }
}

