# OpenVAS Vulnerability Test
# $Id: db4web_tcp_relay.nasl 17 2013-10-27 14:01:43Z jan $
# Description: DB4Web TCP relay
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
tag_summary = "DB4Web debug page allows anybody to scan other machines.
You may be held for responsible.";

tag_solution = "Replace the debug page with a non verbose error page.";

# References:
#
# From:Stefan.Bagdohn@guardeonic.com
# To: bugtraq@securityfocus.com
# Subject: Advisory: TCP-Connection risk in DB4Web
# Date: Tue, 17 Sep 2002 14:44:17 +0200

if(description)
{
 script_id(11180);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_tag(name:"risk_factor", value:"High");

 name = "DB4Web TCP relay";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 summary = "DB4Web debug page allow bounce scan";
 script_summary(summary);
 script_category(ACT_ATTACK);
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
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

if (! get_port_state(port)) exit(0);


# testhost = "nosuchwww.example.com";
testhost = this_host_name();

r = http_get(port: port, item: string("/DB4Web/", testhost, ":23/foo"));
c = http_keepalive_send_recv(port:port, data:r);

if ((("connect() ok" >< c) || ("connect() failed:" >< c)) &&
    ("callmethodbinary_2 failed" >< c))
  security_hole(port);
