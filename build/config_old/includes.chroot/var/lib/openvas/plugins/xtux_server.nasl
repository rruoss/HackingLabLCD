# OpenVAS Vulnerability Test
# $Id: xtux_server.nasl 17 2013-10-27 14:01:43Z jan $
# Description: xtux server detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
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
tag_summary = "The xtux server might be running on this port. If somebody connects to
it and sends it garbage data, it may loop and overload your CPU.";

tag_solution = "disable it, or at least firewall it";

# xtux server will start looping and eat CPU if it receives bad input.
# Writing a nice plugin is useless, as xtux is killed by find_service!
#
# See Bugtraq :
# From:"b0iler _" <b0iler@hotmail.com>
# Subject: xtux server DoS.
# Date: Sat, 09 Mar 2002 15:53:32 -0700

if(description)
{
  script_id(11016);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(4260);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2002-0431");
 
  script_name("xtux server detection");
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
 
  summary = "Detect xtux server";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
	family = "Useless services";
	script_family(family);
	script_require_ports(8390);
	script_dependencies("find_service.nasl"); 
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
	exit(0);
}

include("misc_func.inc");

port = 8390;
kb = known_service(port:port);
if(kb && kb != "xtux")exit(0);

if(get_port_state(port))
{
	soc = open_sock_tcp(port);
	if(soc)
	{
		security_warning(port);
		close(soc);
	}
}

