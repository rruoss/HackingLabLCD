# OpenVAS Vulnerability Test
# $Id: ez_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: eZ/eZphotoshare Denial of Service
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on Michel Arboi work
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
tag_summary = "The remote host runs eZ/eZphotoshare, a service for sharing and exchanging 
digital photos.

This version is vulnerable to a denial of service attack.

An attacker could prevent the remote service from accepting requests 
from users by establishing quickly multiple connections from the same host.";

tag_solution = "Upgrade to the latest version of this software.";

# Ref: Dr_insane

if(description)
{
  script_id(14682);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(11129);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name:"OSVDB", value:"9728");
  script_name("eZ/eZphotoshare Denial of Service");
 
 desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);

  script_summary("Checks for denial of service in eZ/eZphotoshare");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_require_ports(10101);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


if ( safe_checks() ) exit(0);

port = 10101;

if(get_port_state(port))
{ 
  soc = open_sock_tcp(port);
  if (! soc) exit(0);
  
  s[0] = soc;

  #80 connections should be enough, we just add few one :)
  for (i = 1; i < 90; i = i+1)
  {
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_warning(port);
      for (j = 0; j < i; j=j+1) close(s[j]);
    }
    s[i] = soc;
  }
  for (j = 0; j < i; j=j+1) close(s[j]);
}
exit(0);
