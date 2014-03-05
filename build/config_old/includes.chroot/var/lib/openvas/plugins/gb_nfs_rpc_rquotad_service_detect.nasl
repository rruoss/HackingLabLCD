###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nfs_rpc_rquotad_service_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# Nfs-utils rpc.rquotad Service Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "No solution or patch is available as of 11th August, 2011. Information
  regarding this issue will be updated once the solution details are available.

  Workaround:
  Modify /etc/inetd.conf to disable the rpc.rquotad service.";

tag_impact = "Successful exploitation could allow attackers to execute to gain information
  about NFS services including user/system quotas.
  Impact Level: System";
tag_insight = "The flaw is due to error in the 'rpc.rquotad' service. If this service
  is running then disable it as it may become a security threat.";
tag_summary = "This script detects the running 'rpc.rquotad' service on the host.";

if(description)
{
  script_id(802137);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_cve_id("CVE-1999-0625");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_name("Nfs-utils rpc.rquotad Service Detection");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/9726");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/265");
  script_xref(name : "URL" , value : "http://www.exploitsearch.net/index.php?q=CVE-1999-0625");
  script_xref(name : "URL" , value : "http://www.iss.net/security_center/reference/vuln/rquotad.htm");

  script_description(desc);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Checks the presence of a RPC service 'rpc.rquotad'");
  script_category(ACT_GATHER_INFO);
  script_family("RPC");
  script_dependencies("secpod_rpc_portmap.nasl");
  script_require_keys("rpc/portmap");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}

include("misc_func.inc");

RPC_PROG = 100011;

## Get the rpc port, running rpc.rquotad service
port = get_rpc_port(program: RPC_PROG, protocol: IPPROTO_UDP);
if(port)
{
  log_message(port);
  exit(0);
}

port = get_rpc_port(program: RPC_PROG, protocol: IPPROTO_TCP);
if(port){
  log_message(port);
}
