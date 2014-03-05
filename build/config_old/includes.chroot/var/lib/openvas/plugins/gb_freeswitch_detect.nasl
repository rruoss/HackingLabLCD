###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freeswitch_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# FreeSWITCH Version Detection
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804024";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 18 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-07 18:21:20 +0530 (Mon, 07 Oct 2013)");
  script_tag(name:"detection", value:"remote probe");
  script_name("FreeSWITCH Version Detection");

  tag_summary =
"Detection of installed version of FreeSWITCH.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Detection of Installed version of FreeSWITCH");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/5060");
  script_require_ports("Services/udp/sip");
  exit(0);
}


include("sip.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
banner = "";
switchPort = "";
switchVer = "";

## Get the SIP port
switchPort = get_kb_item("Services/udp/sip");
if (!switchPort) switchPort = 5060;

## Check Port state
if(!get_udp_port_state(switchPort)) exit(0);

## Get the banner and confirm the application
banner = get_sip_banner(port: switchPort);
if ("FreeSWITCH" >!< banner) exit(0);

switchVer = eregmatch(pattern: "FreeSWITCH-.*/([0-9.]+)", string: banner);

if(switchVer)
{
  set_kb_item(name: "FreeSWITCH/Version", value: switchVer[1]);
  set_kb_item(name: "FreeSWITCH/installed",value: TRUE);

  ## Build CPE
  cpe = build_cpe(value: switchVer[1], exp: "^([0-9.]+)", base: "cpe:/a:freeswitch:freeswitch:");
  if(isnull(cpe))
    cpe = 'cpe:/a:freeswitch:freeswitch';

  register_product(cpe: cpe, location: switchPort + '/udp', nvt: SCRIPT_OID, port: switchPort);

  log_message(data: build_detection_report(app:"FreeSWITCH", version: switchVer[1],
                                               install: switchPort + '/udp', cpe: cpe,
                                               concluded: switchVer[0]), port: switchPort);
}
