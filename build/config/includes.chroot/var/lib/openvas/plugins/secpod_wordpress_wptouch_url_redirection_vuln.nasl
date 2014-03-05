###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_wptouch_url_redirection_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# WordPress WPtouch URL redirection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to redirect to his choice of
  malicious site via the trusted vulnerable url.
  Impact Level: Application";
tag_affected = "WordPress WPtouch Plugin Version 1.9.27 and 1.9.28";
tag_insight = "The flaw is due to improper validation of user supplied input data via
  'wptouch_redirect' parameter.";
tag_solution = "No solution or patch is available as of 20th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/wptouch/";
tag_summary = "This host is installed with WordPress Wptouch Plugin and is prone to URL
  redirection Vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902384";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("WordPress WPtouch URL redirection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17423/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102451/wptouch-redirect.txt");

  script_description(desc);
  script_summary("Check for WordPress WPtouch URL redirection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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

##
## The script code starts here
##

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check host supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct the request
sndReq = http_get(item:string(dir, "/?wptouch_view=normal&wptouch_redirect=",
                       dir, "/readme.html"), port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

## Check the response to confirm vulnerability
if(egrep(pattern:"^HTTP/.* 302 Found", string:rcvRes) &&
   egrep(pattern:'^Location:.*/readme.html', string:rcvRes)){
  security_warning(port);
}
