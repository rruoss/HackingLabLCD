# OpenVAS Vulnerability Test
# $Id: firewall_detect.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Firewall Enabled
#
# Authors:
# Tenable Network Security, Inc. based on work by Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2007 Tenable Network Security / Michel Arboi
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
tag_summary = "The remote host is behind a firewall

Description :

Based on the responses obtained by the TCP scanner, it was possible to
determine that the remote host seems to be protected by a 
firewall.";

tag_solution = "None";

if(description)
{
 script_id(80059);;
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name( "Firewall Enabled");

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary( "Determines if the remote host is behind a firewall");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2007 Tenable Network Security / Michel Arboi");
 script_family( "Firewalls");
 #
 # This plugin only works if openvas_tcp_scanner has run
 #
 script_require_keys("Host/scanners/openvas_tcp_scanner");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);
if ( ! get_kb_item("Host/scanners/openvas_tcp_scanner") ) exit(0);

open = int(get_kb_item("TCPScanner/OpenPortsNb"));
closed = int(get_kb_item("TCPScanner/ClosedPortsNb"));
filtered = int(get_kb_item("TCPScanner/FilteredPortsNb"));

total = open + closed + filtered;

if (total == 0) exit(0);
if (filtered == 0 ) exit(0);
if ( get_kb_item("TCPScanner/RSTRateLimit") ) exit(0);

if ( filtered > ( closed * 4 ) )
{
	security_note(0);
	set_kb_item(name:"Host/firewalled", value:TRUE);
}
