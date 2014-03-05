##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_openview_nnm_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# HP OpenView Network Node Manager Version Detection
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_summary = "This script detects the installed version of HP OpenView Network
  Node Manager and sets the result in KB.";

if(description)
{
  script_id(900242);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("HP OpenView Network Node Manager Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of HP OpenView Network Node Manager");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900242";
SCRIPT_DESC = "HP OpenView Network Node Manager Version Detection";

## Check NNM Port status
nnmPort = 7510;
if(!get_port_state(nnmPort)){
  exit(0);
}

## Send and Recieve response
nnmReq = http_get(item:"/topology/home", port:nnmPort);
nnmRes = http_keepalive_send_recv(port:nnmPort, data:nnmReq);

## Confirm NNM Application
if("Network Node Manager Home Base" >< nnmRes &&
    egrep(pattern:"Copyright \(c\).* Hewlett-Packard", string:nnmRes) &&
    ereg(pattern:"^HTTP/.* 200 OK", string:nnmRes))
{
  ## Extract Version from the response and set the KB
  nnmVer = eregmatch(pattern:">NNM Release ([0-9a-zA-Z\.]+)<", string:nnmRes);

  if(nnmVer != NULL)
  {
    set_kb_item(name:"www/"+ nnmPort + "/HP/OVNNM/Ver", value:nnmVer[1]);
    security_note(port:nnmPort, data:"HP OpenView Network Node Manager " +
                       "version " + nnmVer[1] + " was detected on the host");
  
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:nnmVer[1], exp:"^([0-9.]+)", base:"cpe:/a:hp:openview_network_node_manager:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
