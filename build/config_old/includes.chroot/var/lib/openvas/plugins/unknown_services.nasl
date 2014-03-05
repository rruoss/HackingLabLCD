# OpenVAS Vulnerability Test
# $Id: unknown_services.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Unknown services banners
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
tag_summary = "This plugin prints the banners from unknown service so that
the OpenVAS team can take them into account.";

if(description)
{
 script_id(11154);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "Unknown services banners";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;



 script_description(desc);
 
 summary = "Displays the unknown services banners";
 script_summary(summary);
 
 script_category(ACT_END); 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");

 script_family("Service detection");
 script_dependencies("find_service_nmap.nasl");
 script_require_ports("Services/unknown");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
include("misc_func.inc");
include("dump.inc");

port = get_kb_item("Services/unknown");
if (! port) exit(0);
if (! get_port_state(port)) exit(0);
if (port == 139) exit(0);	# Avoid silly messages
if (! service_is_unknown(port: port)) exit(0);

banner = get_unknown_banner(port: port, dontfetch: 1);

if (!banner) exit(0);

h = hexdump(ddata: banner);
if( strlen(banner) >= 3 )
{
m = string("An unknown server is running on this port.\n",
  "If you know what it is, please send this banner to the OpenVAS team:\n",
  h);
security_note(port: port, data: m);
}

