###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_app_serv_xst_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Sun Java System Application Server Cross Site Tracing Vulnerability
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "No solution or patch is available,
  The workaround provided in the 'Workaround' section is the final resolution
  to this issue.

  Workaround:
  Apply the workaround as it is final resolution to this issue,
  http://sunsolve.sun.com/search/document.do?assetkey=1-66-200942-1

  *****
  NOTE : Ignore this warning, if above workaround has been applied.
  *****";

tag_impact = "Successful exploitation lets the attackers to to get sensitive information,
  such as cookies or authentication data, contained in the HTTP headers.
  Impact Level: Application";
tag_affected = "Sun Java System Application Server Standard Edition 7 and later updates
  Sun Java System Application Server Standard Edition 7 2004Q2 and later updates";
tag_insight = "An error exists while processing HTTP TRACE method and returns contents of
  clients HTTP requests in the entity-body of the TRACE response. An attacker
  can use this behavior to access sensitive information, such as cookies or
  authentication data, contained in the HTTP headers of the request.";
tag_summary = "This host has Sun Java System Application Server running which is
  prone to Cross Site Tracing vulnerability.";

if(description)
{
  script_id(800162);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-0386");
  script_name("Sun Java System Application Server Cross Site Tracing Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/867593");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-200942-1");

  script_description(desc);
  script_summary("Check for the version of Sun Java Application Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_sun_java_app_serv_detect.nasl");
  script_require_keys("Sun/Java/AppServer/Ver");
  script_require_ports("Services/www", 80, 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get Sun Java Application Server version from KB
appservVer = get_kb_item("Sun/Java/AppServer/Ver");
if(appservVer =~ "^7" )
{
  ## Check for Sun Java Application Server version 7.0 and 7 2004Q2
  if(appservVer =~ "7.0|7 2004Q2"){
    security_warning(port);
  }
}
