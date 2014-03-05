# OpenVAS Vulnerability Test
# $Id: afs_version.nasl 17 2013-10-27 14:01:43Z jan $
# Description: AFS client version
#
# Authors:
# Lionel Cons <lionel.cons@cern.ch>, CERN
#
# Copyright:
# Copyright (C) 2004 CERN
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
tag_summary = "This detects the AFS client version by connecting
to the AFS callback port and processing the buffer received.
The client version gives potential attackers additional information about the
system they are attacking. Versions and types should be omitted
where possible.";

tag_solution = "None.";

if (description)
{
  script_id(10441);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  name = "AFS client version";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);

  summary = "AFS client version";
  script_summary(summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 CERN");

  family = "General";
  script_family(family);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

#
# script
#
port = 7001;
if(!(get_udp_port_state(port)))exit(0);
sock = open_sock_udp(port);
if (sock) {
  data = raw_string(0x00, 0x00, 0x03, 0xe7, 0x00, 0x00, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x00, 0x0d, 0x05, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  send(socket:sock, data:data);
  max = 80;
  info = recv(socket:sock, length:max);
  if (strlen(info) > 28) {
    data = "AFS version: ";
    for (i = 28; i < max; i = i + 1) {
      if (info[i] == raw_string(0x00)) {
        i = max;
      } else {
        data = data + info[i];
      }
    }
    security_note(port:port, protocol:"udp", data:data);
  }
  close(sock);
}
