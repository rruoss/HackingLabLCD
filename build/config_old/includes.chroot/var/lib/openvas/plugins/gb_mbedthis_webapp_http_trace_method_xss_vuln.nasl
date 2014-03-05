###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mbedthis_webapp_http_trace_method_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mbedthis AppWeb HTTP TRACE Method Cross-Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to gain sensitive information
  or inject arbitrary web script or HTML. This may allow the attacker to steal
  cookie-based authentication credentials and to launch other attacks.
  Impact Level: System/Application";
tag_affected = "Mbedthis AppWeb versions prior to 2.2.2";
tag_insight = "The flaw is due to improper handling of HTTP requests using the
  'TRACE' method,  which allows attackers to inject arbitrary HTML via
  crafted HTTP TRACE request.";
tag_solution = "Disable TRACE method or upgrade to Mbedthis AppWeb 2.2.2 or later
  For updates refer to http://appwebserver.org/index.html";
tag_summary = "The host is running Mbedthis AppWeb Server and is prone to cross
  site scripting vulnerability.";

if(description)
{
  script_id(802350);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2007-3008");
  script_bugtraq_id(24456);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-02 14:47:36 +0530 (Fri, 02 Dec 2011)");
  script_name("Mbedthis AppWeb HTTP TRACE Method Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/35511");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/25636");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/867593");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/34854");
  script_xref(name : "URL" , value : "http://www.appwebserver.org/forum/viewtopic.php?t=996");

  script_description(desc);
  script_summary("Check if Mbedthis AppWeb HTTP TRACE Method is enabled");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_require_ports("Services/www", 7777);
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

## Check for the default port
if(!port = get_http_port(default:7777)){
  port = 7777;
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Get the path
req = http_get(item:"/doc/product/index.html", port:port);
res = http_send_recv(port:port, data:req);

## Confirm the application before trying exploit
if("<title>Mbedthis AppWeb" >< res || "<title>Mbedthis Appweb" >< res)
{
  ## Construct the attack (TRACE) request
  req = string("TRACE /doc/product/index.html HTTP/1.1\r\n",
               "Host: ", get_host_name(), "\r\n\r\n");
  res = http_send_recv(port:port, data:req);

  ## Confirm the exploit (supports TRACE method or not)
  if(egrep(pattern:"^HTTP/.* 200 OK", string:res) && "TRACE" >< res &&
                   "UnknownMethod 400 Bad Request" >!< res){
    security_warning(port);
  }
}
