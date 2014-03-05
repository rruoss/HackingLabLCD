##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_webserver_code_exec_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# nginx Arbitrary Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execution arbitrary
  code.
  Impact Level: Application";

tag_summary = "This host is running nginx and is prone to arbitrary code execution
  vulnerability.";
tag_solution = "Upgrade to nginx 0.7.66 or 0.7.38 or later,
  For updates refer to http://nginx.org";
tag_insight = "The null bytes are allowed in URIs by default (their presence is indicated
  via a variable named zero_in_uri defined in ngx_http_request.h). Individual
  modules have the ability to opt-out of handling URIs with null bytes.";
tag_affected = "nginx versions 0.5.x, 0.6.x, 0.7.x to 0.7.65 and 0.8.x to 0.8.37";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803194";
CPE = "cpe:/a:nginx:nginx";

if(description)
{
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-22 15:03:39 +0530 (Mon, 22 Apr 2013)");
  script_name("nginx Arbitrary Code Execution Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24967/");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/multiple/nginx-06x-arbitrary-code-execution-nullbyte-injection");
  script_description(desc);
  script_summary("Check vulnerable version of nginx");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("nginx_detect.nasl", "os_fingerprint.nasl");
  script_mandatory_keys("nginx/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

port = "";
vers = "";

## exit if its not Windows
if(host_runs("Windows") != "yes"){
  exit(0);
}

## Get the application port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  port = 80;
}

## check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get the application version
if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## check the vulnerable versions
if("unknown" >!< vers &&
   version_is_less_equal(version:vers, test_version:"0.7.65") ||
   version_in_range(version:vers, test_version:"0.8", test_version2:"0.8.37"))
{
  security_hole(port);
  exit(0);
}
