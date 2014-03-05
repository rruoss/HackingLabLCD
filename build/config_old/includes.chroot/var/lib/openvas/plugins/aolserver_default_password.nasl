# OpenVAS Vulnerability Test
# $Id: aolserver_default_password.nasl 17 2013-10-27 14:01:43Z jan $
# Description: AOLserver Default Password
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
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
tag_summary = "The remote web server is running AOL web server (AOLserver) with 
the default username and password set. An attacker may use this 
to gain control of the remote web server.";

tag_solution = "Change the default username and password on your web server.";

if(description)
{
 script_id(10753);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-1999-0508");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 name = "AOLserver Default Password";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "AOLserver Default Password";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 8000);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8000);

if(get_port_state(port))
 {
  banner = get_http_banner(port:port);
  if ( "AOLserver/" >!< banner ) exit(0);

  soc = http_open_socket(port);
  if (soc)
  {
    req = string("GET /nstelemetry.adp HTTP/1.0\r\nAuthorization: Basic bnNhZG1pbjp4\r\n\r\n");
    send(socket:soc, data:req);
    buf = http_recv(socket:soc);
    http_close_socket(soc);
    if ((ereg(string:buf, pattern:"HTTP/[0-9]\.[0-9] 200 ")) && 
        ("AOLserver Telemetry" >< buf))
    {
     security_warning(port);
    }
  }
 }
