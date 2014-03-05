# OpenVAS Vulnerability Test
# $Id: lotus_slashdot_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Lotus /./ database lock
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_summary = "It might be possible to lock out some Lotus Domino databases by 
requesting them through the web interface with a special request
like /./name.nsf 
This attack is only efficient on databases that are not used by
the server.

*** Note that no real attack was performed, 
*** so this might be a false alert";

tag_solution = "upgrade your Lotus Domino server";

# Date:  Fri, 7 Dec 2001 14:23:10 +0100
# From: "Sebastien EXT-MICHAUD" <Sebastien.EXT-MICHAUD@atofina.com>
# Subject: Lotus Domino Web server vulnerability
# To: bugtraq@securityfocus.com

if (description)
{
  script_id(11718);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3656);
  script_cve_id("CVE-2001-0954");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  name = "Lotus /./ database lock";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
 
  summary = "Locks out Lotus database with /./ request";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  family = "Denial of Service";
  script_family(family);

  script_dependencies("find_service.nasl", "http_login.nasl", "httpver.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/domino");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);

}

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);


b = get_http_banner(port: port);
if(egrep(pattern: "^Server: Lotus-Domino/(Release-)?(5\.0\.[0-8][^0-9])", string:b))
  security_warning(port);
