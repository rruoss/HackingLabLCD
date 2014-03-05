# OpenVAS Vulnerability Test
# $Id: minishare_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: MiniShare webserver buffer overflow
#
# Authors:
# Gareth Phillips - SensePost PTY ltd (www.sensepost.com)
# Changes by Tenable Network Security :
# * detect title to prevent false positives
# * fix version detection
# * added CVE and OSVDB xrefs.
#
# Copyright:
# Copyright (C) 2005 SensePost
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
tag_summary = "MiniShare 1.4.1 and prior versions are affected by a buffer overflow flaw.
A remote attacker could execute arbitrary commands by sending a specially
crafted file name in a the GET request.

Version 1.3.4 and below do not seem to be vulnerable.";

tag_solution = "Upgrade to MiniShare 1.4.2 or higher.";

if(description)
{
 script_id(18424);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2271");
 script_bugtraq_id (11620);
 script_xref(name:"OSVDB", value:"11530");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");


 name = "MiniShare webserver buffer overflow";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 summary = "MiniShare webserver buffer overflows";

 script_description(desc);
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2005 SensePost");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# Code Starts Here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
res = http_get_cache(item:"/", port:port);
if( res == NULL ) exit(0);
if ("<title>MiniShare</title>" >!< res)
  exit (0);

if (egrep (string:res, pattern:'<p class="versioninfo"><a href="http://minishare\\.sourceforge\\.net/">MiniShare 1\\.(3\\.([4-9][^0-9]|[0-9][0-9])|4\\.[0-1][^0-9])'))
  security_hole (port);
}
