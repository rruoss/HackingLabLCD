###############################################################################
# OpenVAS Vulnerability Test
# $Id: nsd_35029.nasl 15 2013-10-27 12:49:54Z jan $
#
# NSD 'packet.c' Off-By-One Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "NSD is prone to an off-by-one buffer-overflow vulnerability
   because the server fails to perform adequate boundary checks on
   user-supplied data.

   Successfully exploiting this issue will allow attackers to
   execute arbitrary code within the context of the affected server.
   Failed exploit attempts will result in a denial-of-service
   condition.

   Versions prior to NSD 3.2.2 are vulnerable.";

tag_solution = "The vendor has released fixes. Please see http://www.nlnetlabs.nl/projects/nsd/
   for more information.";

if(description)
{
  script_id(100209);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-24 11:22:37 +0200 (Sun, 24 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(35029);
  script_name("NSD 'packet.c' Off-By-One Buffer Overflow Vulnerability");
  desc = "

  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
  script_summary("Check for the Version of NSD");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("nsd_version.nasl");
  script_require_keys("nsd/version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

udpPort = 53;
if(!get_udp_port_state(udpPort)){
  exit(0);
}

bindVer = get_kb_item("nsd/version");
if(!bindVer){
  exit(0);
}

  if(version_is_less(version:bindVer, test_version:"3.2.2") ) {
    security_warning(port:udpPort, proto:"udp");
  }
