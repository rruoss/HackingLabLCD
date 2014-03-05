# OpenVAS Vulnerability Test
# $Id: webalizer.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Webalizer Cross Site Scripting Vulnerability
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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
tag_summary = "Webalizer have a cross-site scripting vulnerability,
that could allow malicious HTML tags to be injected
in the reports generated by the Webalizer.";

tag_solution = "Upgrade to Version 2.01-09 and change the directory in 'OutputDir'";

if(description)
{
 script_id(10816); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3473);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-0835");
 name = "Webalizer Cross Site Scripting Vulnerability";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "Checks for the Webalizer version";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
 family = "Gain a shell remotely";
 script_family(family);

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
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


dir[0] = "/usage/";	#Standard directory
dir[1] = "/webalizer/";	#Popular directory

port = get_http_port(default:80);


if (get_port_state(port))
{
 for (i = 0; dir[i] ; i = i + 1)
 {
  req = http_get(item:dir[i], port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if ("Generated by The Webalizer" >< buf)
   {
    if (egrep(pattern:"Generated by The Webalizer  Ver(\.|sion) ([01]\.|2\.00|2\.01( |\-0[0-6]))", string:buf))
    {
     security_hole(port:port);
    }
    exit(0);
   }
 }
}
