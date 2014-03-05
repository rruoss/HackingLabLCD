###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_xchange_server_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Open-Xchange Server Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML or
  web script in a user's browser session in context of an affected site,
  compromise the application and access or modify data in the database.
  Impact Level: Application";

tag_affected = "Open-Xchange Server versions prior to 6.20.7-rev14, 6.22.0-rev13
  and 6.22.1-rev14.";
tag_insight = "- Input passed via arbitrary GET parameters to /servlet/TestServlet is not
    properly sanitized before being returned to the user.
  - Input related to the 'Source' field when creating subscriptions is not
    properly sanitized before being used. This can be exploited to perform
    arbitrary HTTP GET requests to remote and local servers.
  - The OXUpdater component does not properly validate the SSL certificate of
    an update server. This can be exploited to spoof update packages via a
    MitM (Man-in-the-Middle) attack.
  - The application creates the /opt/open-exchange/etc directory with insecure
    world-readable permissions. This can be exploited to disclose certain
    sensitive information.
  - Input passed via the 'location' GET parameter to /ajax/redirect is not
    properly sanitized before being used to construct HTTP response headers.
  - Certain input related to RSS feed contents is not properly sanitized before
    being used. This can be exploited to insert arbitrary HTML and script code.";
tag_solution = "Update to versions 6.20.7-rev14, 6.22.0-rev13, or 6.22.1-rev14,
  For updates refer to http://www.open-xchange.com/home.html";
tag_summary = "This host is running Open-Xchange Server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803182);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1646", "CVE-2013-1647", "CVE-2013-1648", "CVE-2013-1650",
                "CVE-2013-1651");
  script_bugtraq_id(58465, 58473, 58475, 58469, 58470);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-18 10:14:58 +0530 (Mon, 18 Mar 2013)");
  script_name("Open-Xchange Server Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/91240");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52603");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Mar/74");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24791");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120785");

  script_description(desc);
  script_summary("Check if Open-Xchange Server is vulnerable to XSS vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
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
include("http_keepalive.inc");

## Variable Initialization
url = "";
port = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/ox6", "/Open-Xchange", cgi_dirs()))
{
  ## Request for the index.php
  sndReq = http_get(item:string(dir, "/ox.html"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## confirm the Application
  if(">Open-Xchange Server<" >< rcvRes)
  {
    ## Construct Attack Request
    url = dir + "/servlet/TestServlet?foo=<script>alert(document.cookie)</script>";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
             pattern:"<script>alert\(document.cookie\)</script>"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
