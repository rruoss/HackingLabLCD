###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ftpshell_server_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# FTPShell Server Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will let the attacker craft a malicious license
  registry key file and can cause arbitrary code execution by tricking user
  to install the crafted malicious license registry file and may cause
  denial-of-service to the application.";
tag_affected = "FTPShell Server version 4.3.0 or prior on Windows.";
tag_insight = "This flaw is due to a boundary error in the FTPShell server application
  when processing certain Windows registry keys.";
tag_solution = "No solution or patch is available as of 05th February, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.ftpshell.com/server/index.htm";
tag_summary = "This host is running FTPshell Server and is prone to Buffer
  Overflow Vulnerability.";

if(description)
{
  script_id(800226);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0349");
  script_bugtraq_id(33403);
  script_name("FTPShell Server Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33597");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7852");

  script_description(desc);
  script_summary("Check for the version of FTPShell Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl", "gb_ftpshell_server_detect.nasl");
  script_require_keys("FTPShell/Version");
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

include("version_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

ftpShellVer = get_kb_item("FTPShell/Version");
if(!ftpShellVer){
  exit(0);
}

#Check for FTPShell Server version 4.3.0 or prior.
if(version_is_less_equal(version:ftpShellVer, test_version:"4.3.0")){
  security_hole(ftpPort);
}
