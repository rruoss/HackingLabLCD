# OpenVAS Vulnerability Test
# $Id: invision_pwb.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Invision Power Board XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote host is running Invision Power Board, a web-based bulletin-board
system written in PHP.

This version of Invision Power Board is vulnerable to cross-site scripting 
attacks, which may allow an attacker to steal users cookies.";

tag_solution = "Upgrade to the latest version of this software";

#  Ref: Alexander Antipov <Antipov SecurityLab ru>

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.15425";
CPE = "cpe:/a:invision_power_services:invision_power_board";

if(description) 
{ 
  script_oid(SCRIPT_OID); 
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1578");
  script_bugtraq_id(11332);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
      
  name = "Invision Power Board XSS"; 
        
  script_name(name); 

desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc); 
        
  summary = "Checks for Invision Power Board XSS";
  script_summary(summary);
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");

  family = "Web application abuses";
  script_family(family);
	
  script_dependencies("http_version.nasl", "invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("invision_power_board/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("host_details.inc");

port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if ( ! port || ! get_port_state(port) ) exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

s = string( "GET ", dir, "/index.php?s=5875d919a790a7c429c955e4d65b5d54&act=Login&CODE=00 HTTP/1.1\r\n", "Host: ", get_host_name(), "\r\n", "Referer: <script>foo</script>", "\r\n\r\n");
soc =  http_open_socket(port);
if(!soc) exit(0);

send(socket: soc, data: s);
r = http_recv(socket: soc);
http_close_socket(soc);

if (egrep(pattern:"input type=.*name=.referer.*<script>foo</script>", string:r) )
{ 
  security_warning(port);
}
