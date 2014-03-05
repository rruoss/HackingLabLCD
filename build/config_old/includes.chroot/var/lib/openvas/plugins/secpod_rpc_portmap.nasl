###############################################################################
# OpenVAS Vulnerability Test
# $Id:secpod_rpc_portmap.nasl 	1024 2009-02-12 17:02:29Z Feb $
#
# RPC Port mapper
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
################################################################################

include("revisions-lib.inc");
tag_summary = "The script will detect the The RPC portmapper running on the
  port and sets the KB.";

if(description)
{
  script_id(900602);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("RPC portmapper");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Gets the port of the remote rpc portmapper");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("RPC");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("misc_func.inc");

RPC_PROG = 100000;
flag = 1;
ports = make_list(111, 121, 530, 593);
foreach p (ports)
{
  if(!get_udp_port_state(p)){
    port = 0;
  }
  else {
    port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP, portmap:p);
  }
  if(port && flag)
  {
    set_kb_item(name:"rpc/portmap", value:p);
    flag=0;
  }
}
