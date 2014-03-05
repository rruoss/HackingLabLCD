###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_mult_vuln_jul09.nasl 15 2013-10-27 12:49:54Z jan $
#
# WordPress Multiple Vulnerabilities - July09
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
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to view the content of plugins
  configuration pages, inject malicious scripting code, or gain knowledge of
  sensitive username information.
  Impact Level: Application";
tag_affected = "WordPress version prior to 2.8.1 on all running platform.";
tag_insight = "- Error in 'wp-settings.php' which may disclose the sensitive information via
    a direct request.
  - username of a post's author is placed in an HTML comment, which allows
    remote attackers to obtain sensitive information by reading the HTML source.
  - Error occur when user attampt for failed login or password request depending
    on whether the user account exists, and it can be exploited by enumerate
    valid usernames.
  - wp-admin/admin.php does not require administrative authentication
    to access the configuration of a plugin, which allows attackers to specify a
    configuration file in the page parameter via collapsing-archives/options.txt,
    related-ways-to-take-action/options.php, wp-security-scan/securityscan.php,
    akismet/readme.txt and wp-ids/ids-admin.php.";
tag_solution = "Update to Version 2.8.1
  http://wordpress.org/download/";
tag_summary = "The host is running WordPress and is prone to Multiple Vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800657";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2432", "CVE-2009-2431", "CVE-2009-2336",
                "CVE-2009-2335", "CVE-2009-2334");
  script_bugtraq_id(35581, 35584);
  script_name("WordPress Multiple Vulnerabilities - July09");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1833");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Jul/1022528.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/504795/100/0/threaded");

  script_description(desc);
  script_summary("Check for the Version of WordPress");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
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
include("host_details.inc");


wpmuPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!wpmuPort){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:wpmuPort))exit(0);

sndReq = http_get(item:string(dir, "/wp-settings.php"), port:wpmuPort);
rcvRes = http_send_recv(port:wpmuPort, data:sndReq);
if("ABSPATHwp-include" >< rcvRes && "include_path" >< rcvRes)
{
  security_warning(port:wpmuPort);
  exit(0);
}

exit(0);