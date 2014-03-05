###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_internal_ip_addr_disc_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft IIS IP Address/Internal Network Name Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_affected = "Microsoft Internet Information Services version 4.0, 5.0, 5.1 and 6.0

  Workaround:
  Apply workaround from below link for IIS 4.0, 5.0 and 5.1
  http://support.microsoft.com/default.aspx?scid=KB;EN-US;Q218180";

tag_impact = "Successful exploitation will allow remote attackers to gain internal IP
  address or internal network name, which could assist in further attacks
  against the target host.
  Impact Level: Application";
tag_insight = "The flaw is due to an error while processing 'GET' request. When
  MS IIS receives a GET request without a host header, the Web server will
  reveal the IP address of the server in the content-location field or the
  location field in the TCP header in the response.";
tag_solution = "Apply the hotfix for IIS 6.0 from below link
  http://support.microsoft.com/kb/834141/#top";
tag_summary = "The host is running Microsoft IIS Webserver and is prone to
  IP address disclosure vulnerability.";

if(description)
{
  script_id(902796);
  script_version("$Revision: 12 $");
  script_bugtraq_id(3159);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-23 15:45:49 +0530 (Thu, 23 Feb 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Microsoft IIS IP Address/Internal Network Name Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/834141/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/3159/info");
  script_xref(name : "URL" , value : "http://support.microsoft.com/default.aspx?scid=KB;EN-US;Q218180");
  script_xref(name : "URL" , value : "http://www.juniper.net/security/auto/vulnerabilities/vuln3159.html");

  script_description(desc);
  script_summary("Check if IIS server reveals the IP address of the host");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Variable Initialization
ver = "";
port = 0;
sndReq = "";
rcvRes = "";
dir = "";
ip = "";
pattern = "";

## Get HTTP port
port = get_http_port(default:80);
if(! port){
  port = 80;
}

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

##Get IIS Banner
ver = get_kb_item("IIS/" + port + "/Ver");
if(!ver){
  exit(0);
}

## Iterate over poosible dirs
foreach dir (make_list("/", "/scripts", "/admin", "/webdav", cgi_dirs()))
{
  ip = string("http://", get_host_name(), dir);

  sndReq = string("GET ", dir, " HTTP/1.0 \r\n\r\n");
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Pattern containing ip address
  pattern = string("Location: ", ip);

  ## Checking the respose to confirm vulnerability
  if(rcvRes && pattern >< rcvRes &&
     egrep(pattern:"^HTTP/.* 302 Object Moved", string:rcvRes))
  {
    security_warning(port);
    exit(0);
  }
}
