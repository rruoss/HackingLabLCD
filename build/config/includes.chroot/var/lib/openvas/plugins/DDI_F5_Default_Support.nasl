# OpenVAS Vulnerability Test
# $Id: DDI_F5_Default_Support.nasl 17 2013-10-27 14:01:43Z jan $
# Description: F5 Device Default Support Password
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2001 Digital Defense Inc.
# Copyright (C) 2001 H D Moore <hdmoore@digitaldefense.net>
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
tag_summary = "This F5 Networks system still has the default
password set for the support user account. This
account normally provides read/write access to the
web configuration utility. An attacker could take
advantage of this to reconfigure your systems and
possibly gain shell access to the system with
super-user privileges.";

tag_solution = "Remove the support account entirely or
change the password of this account to something 
that is difficult to guess.";

if(description)
{
 script_id(10820);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "F5 Device Default Support Password";
 script_cve_id("CVE-1999-0508");
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "F5 Device Default Support Password";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 Digital Defense Inc.");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 443);
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
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:443);
if (  !port ) exit(0);
soc = http_open_socket(port);
if (soc)
 {
    req = string("GET /bigipgui/bigconf.cgi?command=bigcommand&CommandType=bigpipe HTTP/1.0\r\nAuthorization: Basic c3VwcG9ydDpzdXBwb3J0\r\n\r\n");
    send(socket:soc, data:req);
    buf = http_recv(socket:soc);
    http_close_socket(soc);
    if (("/bigipgui/" >< buf) && ("System Command" >< buf))
    {
     security_warning(port);
     set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
    }
 }
