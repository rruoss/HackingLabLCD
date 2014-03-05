# OpenVAS Vulnerability Test
# $Id: yawcam_dir_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Yawcam Directory Traversal
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote web server itself is prone to directory traversal attacks. 

Description :

The remote host is running Yawcam, yet another web cam software. 

The installed version of Yawcam is vulnerable to a directory traversal
flaw.  By exploiting this issue, an attacker may be able to gain
access to material outside of the web root.";

tag_solution = "Upgrade to Yawcam 0.2.6 or later.";

#  Ref: Donato Ferrante <fdonato at autistici.org>

if (description)
{
 script_id(18176);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-1230");
 script_bugtraq_id(13295);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Yawcam Directory Traversal");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary("Checks for directory traversal in Yawcam");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 8081);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=bugtraq&amp;m=111410564915961&amp;w=2");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8081);
if (! get_port_state(port) ) exit(0);

data = "local.html";
data = http_get(item:data, port:port);
buf = http_keepalive_send_recv(port:port, data:data, bodyonly:TRUE);
if( buf == NULL ) exit(0);

if ("<title>Yawcam</title>" >< buf)
{
  req = string("GET ..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini HTTP/1.0\r\n");
  soc = http_open_socket(port);
  if ( ! soc ) exit(0);
  send(socket:soc, data:req);
  res = http_recv_headers2(socket:soc);
  close (soc);
  if ("[boot loader]" >< res)
  {
	security_warning(port);	
  }
}
