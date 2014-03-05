###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ssl_cookie_secure_flag_info_disc_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Missing Secure Attribute SSL Cookie Information Disclosure Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_affected = "Server with SSL.

  Workaround:
  Set the 'secure' attribute for any cookies that are sent over an SSL connection.";

tag_insight = "The flaw is due to SSL cookie is not using 'secure' attribute, which
  allows cookie to be passed to the server by the client over non-secure
  channels (http) and allows attacker to conduct session hijacking attacks.
  remote systems.

  Impact Level: Application";

tag_summary = "The host is running a server with SSL and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_id(902661);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-01 17:10:53 +0530 (Thu, 01 Mar 2012)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_name("Missing Secure Attribute SSL Cookie Information Disclosure Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected;

  script_xref(name : "URL" , value : "http://www.ietf.org/rfc/rfc2965.txt");
  script_xref(name : "URL" , value : "https://www.owasp.org/index.php/Testing_for_cookies_attributes_(OWASP-SM-002)");

  script_description(desc);
  script_copyright("Copyright (C) 2012 SecPod");
  script_summary("Check if secure flag is set for an SSL Cookie");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("openvas-https.inc");

## Variable Initialization
sslPort = 0;
host = "";
sslReq = "";
sslRes = "";
sslCookie = "";

## Get all http ports
sslPort = get_http_port(default:443);
if(!get_port_state(sslPort)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Construct basic GET request
sslReq = string("GET / HTTP/1.1\r\n",
                "Host: ", host, "\r\n\r\n");

sslRes = https_req_get(port:sslPort, request:sslReq);
if(sslRes && "Set-Cookie:" >< sslRes)
{
  sslCookie = egrep(string:sslRes, pattern:"Set-Cookie:.*");

  if(sslCookie &&  !(sslCookie =~ "[S|s]ecure;?[^a-zA-Z0-9_-]+")){
    security_hole(sslPort);
  }
}
