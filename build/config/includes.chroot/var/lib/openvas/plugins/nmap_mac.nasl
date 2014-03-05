###############################################################################
# OpenVAS Vulnerability Test
# $Id: nmap_mac.nasl 12 2013-10-27 11:15:33Z jan $
#
# Nmap MAC Scan.
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
tag_summary = "This script attempts to gather the MAC address of the target.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.103585";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-1 15:52:11 +0100 (Thu, 11 Oct 2012)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Nmap MAC Scan");
  script_description("
  Summary:
  " + tag_summary);

  script_summary("Gathers MAC address from remote host");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("toolcheck.nasl", "ping_host.nasl");
  script_family("General");
  script_mandatory_keys("Tools/Present/nmap");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include ("toolcheck.inc");
include("host_details.inc");

SCRIPT_DESC = "Nmap MAC Scan";

exit_if_not_found (toolname: "nmap");

if(!islocalnet())exit(0);

function IP_IS_IPV6(ip) {

  if(":" >< ip) {
    return TRUE;
  }

  return FALSE;

}

argv[x++] = 'nmap';
argv[x++] = '-sP';

ip = get_host_ip();

if(IP_IS_IPV6(ip:ip)) {
    argv[x++] = "-6";
}

argv[x++] = ip;

res = pread(cmd: "nmap", argv: argv);
if(isnull(res) || 'MAC' >!< res)exit(0);

mac = eregmatch(pattern:"MAC Address: ([0-9a-fA-F:]{17})", string:res);

if(!isnull(mac[1])) {
  register_host_detail(name:"MAC", value:mac[1], nvt:SCRIPT_OID, desc:SCRIPT_DESC);
  exit(0);
}

exit(0);


