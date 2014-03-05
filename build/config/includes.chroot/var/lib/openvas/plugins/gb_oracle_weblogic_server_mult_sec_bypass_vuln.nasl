##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_weblogic_server_mult_sec_bypass_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Oracle WebLogic Server Multiple Security Bypass Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code under
  the context of the application.
  Impact Level: Application";
tag_affected = "Oracle WebLogic Server version 12c (12.1.1)";
tag_insight = "- Soap interface exposes the 'deleteFile' function which could allow to
    delete arbitrary files with administrative privileges on the target
    server through a directory traversal vulnerability.
  - A web service called 'FlashTunnelService' which can be reached without
    prior authentication and processes incoming SOAP requests.";
tag_solution = "No solution or patch is available as of 28th, August 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www.oracle.com/technetwork/middleware/ias/downloads/wls-main-097127.html";
tag_summary = "This host is running Oracle WebLogic Server and is prone to
  multiple security bypass vulnerabilities";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802446";
CPE = "cpe:/a:bea:weblogic_server";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_bugtraq_id(54870, 54839);
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-28 1:34:53 +0530 (Tue, 28 Aug 2012)");
  script_name("Oracle WebLogic Server Multiple Security Bypass Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Aug/50");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20319/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20318/");
  script_xref(name : "URL" , value : "http://retrogod.altervista.org/9sg_ora2.htm");

  script_description(desc);
  script_summary("Check the version of Oracle WebLogic Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("oracle_webLogic_server_detect.nasl");
  script_require_keys("OracleWebLogicServer/installed");
  script_require_ports("Services/www", 7001);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

vers = "";
port  = "";

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(!get_port_state(port)){
  exit(0);
}

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

if(version_is_equal(version:vers, test_version:"12.1.1")){
  security_hole(port:port);
}
