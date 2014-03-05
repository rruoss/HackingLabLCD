###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_appln_server_unspecified_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Oracle Application Server Unspecified Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "An unspecified impact and attack vectors.
  Impact Level: Application";
tag_affected = "Oracle application server version 1.3.1.27";
tag_insight = "The flaw is due to unspecified error in the oracle jinitiator
  component.";
tag_solution = "Apply patches from below link,
  http://www.oracle.com/technetwork/topics/security/cpujan2008-086860.html";
tag_summary = "This host is running Oracle application server and is prone to
  unspecified vulnerability.";

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

if(description)
{
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28518");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1019218");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/alerts-086861.html");
  script_id(802531);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2008-0346");
  script_bugtraq_id(27229);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-07 13:09:22 +0530 (Wed, 07 Dec 2011)");
  script_name("Oracle Application Server Unspecified Vulnerability");
  script_description(desc);
  script_summary("Check for the version of Oracle Application Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl");
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
include("version_func.inc");

## Get the port
appPort = "7777";
if(!get_port_state(appPort)){
  exit(0);
}

## Get the banner
banner = get_http_banner(port:appPort);

## Confirm the server
if(!banner && "Oracle-Application-Server" >!< banner){
 exit(0);
}

## Grep for version
appVer = eregmatch(pattern:"Oracle-Application-Server-[0-9a-zA-Z]+?/([0-9.]+)",
                                             string:banner);
if(appVer[1] == NULL){
  exit(0);
}

## Check the affected versions
if(version_is_less(version:appVer[1], test_version:"1.3.1.26"))
{
  security_hole(data:desc, port:appPort);
  exit(0);
}

if(report_paranoia < 2){
  exit(0);
}

report=  string("\n\n\n ***** \n" +
                " NOTE : Ignore this warning, if above mentioned patch" +
                " is already applied.\n" +
                " ***** \n");

if(version_is_equal(version:appVer[1], test_version:"1.3.1.27")){
  security_hole(data:string(desc, report), port:appPort);
}
