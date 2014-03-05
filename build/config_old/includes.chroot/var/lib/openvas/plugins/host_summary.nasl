###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Host Summary
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This NVT summarizes technical information about the scanned host
collected during the scan.";

if(description)
{
  script_id(810003);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:49:09 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Host Summary");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Host Summary");
  script_category(ACT_END);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secspace_traceroute.nasl", "secpod_open_tcp_ports.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

report = "traceroute:";
route = get_kb_item("traceroute/route");
if (route)
{
  report += route;
}
report += '\n';

report += "TCP ports:";
ports = get_kb_item("Ports/open/tcp");
if (ports)
{
  report += ports;
}
report += '\n';

report += "UDP ports:";
ports = get_kb_item("Ports/open/udp");
if (ports)
{
  report += ports;
}
report += '\n';

log_message (proto: "HOST-T", data: report);
