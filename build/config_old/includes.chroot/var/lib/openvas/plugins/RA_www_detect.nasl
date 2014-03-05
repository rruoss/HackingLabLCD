# OpenVAS Vulnerability Test
# $Id: RA_www_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: RemotelyAnywhere WWW detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Broken link deleted
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
tag_summary = "The RemotelyAnywhere WWW server is running on this system.
According to NAVCIRT attackers love this management tool.

If you installed it, ignore this warning. If not, your machine is 
compromised by an attacker.";

if(description)
{
  script_id(10920);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
 
  script_name("RemotelyAnywhere WWW detection");
 
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
 
  summary = "Detect RemotelyAnywhere www server";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  family = "Malware";
  script_family(family);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 2000, 2001);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:2000);
ports = add_port_in_list(list:ports, port:2001);


foreach port (ports)
{
 banner = get_http_banner(port:port);

 if (! banner) exit(0);

 if (egrep(pattern:"^Server: *RemotelyAnywhere", string:banner))
 {
  security_note(port);
 }
}
# TBD: check default account administrator / remotelyanywhere
