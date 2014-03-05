# OpenVAS Vulnerability Test
# $Id: icecast_libshout_bof.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ICECast libshout remote buffer overflow
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
tag_summary = "The remote server runs a version of ICECast, an open source 
streaming audio server, which is older than version 1.3.9.

Icecast and the libshout library are affected by a remote buffer overflow because they do
not properly check bounds of data send from clients. 

As a result of this vulnerability, it is possible for a remote attacker to
cause a stack overflow and then execute arbitrary code with the privilege of the server.

*** OpenVAS reports this vulnerability using only
*** information that was gathered.";

tag_solution = "Upgrade to a newer version.";

#  Ref: Matt Messier <mmessier@prilnari.com> and John Viega <viega@list.org>

if(description)
{
 script_id(15398);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4735);
 script_cve_id("CVE-2001-1229");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "ICECast libshout remote buffer overflow";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
 
 summary = "Check icecast version";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
		
 family = "Buffer overflow";
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
if(!port) exit(0);

banner = tolower(get_http_banner(port:port));
if ( ! banner ) exit(0);
if("icecast/" >< banner &&
   egrep(pattern:"icecast/1\.(0\.[0-4][^0-9]|1\.|3\.[0-8][^0-9])", string:banner))
      security_hole(port);