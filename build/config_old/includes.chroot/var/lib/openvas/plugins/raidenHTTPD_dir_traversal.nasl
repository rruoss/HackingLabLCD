# OpenVAS Vulnerability Test
# $Id: raidenHTTPD_dir_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: RaidenHTTPD directory traversal
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
tag_summary = "The remote host is running a version of RaidenHTTPD which is 
vulnerable to a remote directory traversal bug.  An attacker
exploiting this bug would be able to gain access to potentially 
confidential material outside of the web root.";

tag_solution = "Upgrade to RaidenHTTPD version 1.1.31";

#  Ref: Donato Ferrante <fdonato autistici org>

if (description)
{
 script_id(16313);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(12451);
 script_xref(name:"OSVDB", value:"13575");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_tag(name:"risk_factor", value:"High");
 script_name("RaidenHTTPD directory traversal");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 script_summary("RaidenHTTPD directory traversal");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! get_port_state(port) ) exit(0);

banner = get_http_banner(port:port);
# Server: RaidenHTTPD/1.1.31 (Shareware)
if ( ! banner  || "RaidenHTTP" >!< banner ) exit(0);


res1 = http_keepalive_send_recv(data:http_get(item:"windows/system.ini", port:port), port:port);
res2 = http_keepalive_send_recv(data:http_get(item:"winnt/system.ini", port:port), port:port);

if ("[drivers]" >< tolower(res1) ||
    "[drivers]" >< tolower(res2)) {
		security_hole(port);
		exit(0);
}
