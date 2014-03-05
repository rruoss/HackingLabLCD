# OpenVAS Vulnerability Test
# $Id: psybnc_check.nasl 17 2013-10-27 14:01:43Z jan $
# Description: psyBNC Server Detection
#
# Authors:
# Scott Shebby
#
# Copyright:
# Copyright (C) 2004 Scott Shebby
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
tag_summary = "The remote host appears to be running psyBNC on this port.

psyBNC is an 'easy-to-use, multi-user, permanent IRC-Bouncer with many features. Some 
of its features include symmetric ciphering of talk and connections (Blowfish and IDEA),
the possibility of linking multiple bouncers to an internal network including a shared 
partyline, vhost- and relay support to connected bouncers and an extensive online help 
system.'

The presence of this service indicates a high possibility that your server has been 
compromised by a remote attacker.  The only sure fix is to reinstall from scratch.";

tag_solution = "Make sure the presence of this service is intended";

if(description)
{
  script_id(14687);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");

  name = "psyBNC Server Detection";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
  summary = "Check for the presence of psyBNC.";
  script_summary(summary);
  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2004 Scott Shebby");

  family = "General";
  script_family(family);
  script_dependencies("find_service2.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.psybnc.info/about.html");
  script_xref(name : "URL" , value : "http://www.psychoid.net/start.html");
  exit(0);
}

# The detection is in find_service2.nasl
port = get_kb_item("Services/psyBNC");
if ( port ) security_hole(port:port, data:banner);
