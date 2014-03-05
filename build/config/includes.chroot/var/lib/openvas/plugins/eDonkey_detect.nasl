# OpenVAS Vulnerability Test
# $Id: eDonkey_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: eDonkey/eMule detection
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
tag_summary = "eDonkey might be running on this port. This peer to peer 
software is used to share files.
1. This may be illegal.
2. You may have access to confidential files
3. It may eat too much bandwidth

* Note: This script only checks if ports 4661-4663 are open
*       and are unknown services.";

tag_solution = "disable it";

# This script only checks if ports 4661-4663 are open. 
# The protocol is not documented, AFAIK. It was probably 'reverse engineered'
# for mldonkey (do you read OCAML?)
# I sniffed a eDonkey connection, but could not reproduce it. 
# There were some information on http://hitech.dk/donkeyprotocol.html
# but I could not use it.

if(description)
{
  script_id(11022);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
 
  script_name("eDonkey/eMule detection");
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
 
  summary = "Detect eDonkey";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  family = "Peer-To-Peer File Sharing";
  script_family(family);
  script_dependencies("find_service.nasl");
  script_require_ports(4661, 4662, 4663);
 script_require_keys("Settings/ThoroughTests");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("misc_func.inc");
include('global_settings.inc');


if ( !thorough_tests ) exit(0);

for (port = 4661; port <= 4663; port = port + 1)
{
 if(get_port_state(port))
 {
 	kb = known_service(port:port);
	if(!kb || kb == "edonkey")
	{
	 soc = open_sock_tcp(port);
	 if(soc)
	 {
		# display(string("Open port = ", port, "\n"));
		security_warning(port);
		close(soc);
	 } 
	}
 }
}

# Looking for the mlDonkey web or telnet interface is useless:
# it only answers on localhost

exit(0);

