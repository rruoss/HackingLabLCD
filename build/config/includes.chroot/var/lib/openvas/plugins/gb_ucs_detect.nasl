###############################################################################
# OpenVAS Vulnerability Test
#
# Univention Corporate Server (UCS) Detection
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This script attempts to determine if the target is a Univention
  Corporate Server (UCS).";

if(description)
{
  script_id(103979);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-01 14:27:02 +0200 (Mon, 01 Aug 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Univention Corporate Server Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_family("Service detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_summary("Detect Univention Corporate Server");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("host_details.inc");

wwwPort = get_http_port(default:80);
if(!get_port_state(wwwPort)){
  exit(0);
}

banner = get_http_banner(port:wwwPort);
if("Univention" >!< banner){
  exit(0);
}
else
{
  register_host_detail(name:"OS", value:"cpe:/o:univention:ucs",
                       nvt:"1.3.6.1.4.1.25623.1.0.103979",
                       desc:"Univention Corporate Server Detection");
  security_note(data:"The target seems to be running a Univention Corporate Server (UCS).");
}
