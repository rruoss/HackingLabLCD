###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ironport_csma_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Cisco IronPort Content Security Management Appliance Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803753";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 18 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-03 18:58:59 +0530 (Tue, 03 Sep 2013)");
  script_tag(name:"detection", value:"remote probe");
  script_name("Cisco IronPort Content Security Management Appliance Detection");

  tag_summary =
"The script sends a connection request to the server and attempts to
extract the version number from the reply.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Checks for the presence of Cisco IronPort Security Management Appliance");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 443);
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("openvas-https.inc");

## Variable initialization
csmaPort = "";
csmahost = "";
csmaReq = "";
csmaRes = "";
csmaVersion = "";

## Get HTTP Port
csmaPort = get_http_port(default:443);
if(!csmaPort){
  csmaPort = 443;
}

## Check the port status
if(!get_port_state(csmaPort)){
  exit(0);
}

## Get Host Name
csmahost = get_host_name();
if(!csmahost){
  exit(0);
}

## Get the banner
csmaReq = string("GET /login HTTP/1.1\r\n",
             "Host: ", csmahost, "\r\n",
             "Cookie: sid=", rand(),"\r\n\r\n");
csmaRes = https_req_get(port:csmaPort, request:csmaReq);

## Confirm the application
if("<title>Cisco IronPort" >!< csmaRes && "SecurityManagementApp" >!< csmaRes){
  exit(0);
}

csmaVersion = eregmatch(string: csmaRes, pattern: "v(([0-9.]+)-?[0-9]+)");
if(csmaVersion[1])
{
  csmaVersion = ereg_replace(pattern:"-", string:csmaVersion[1], replace:".");
  set_kb_item(name:"Cisco_IronPort/CSMA/installed",value:TRUE);

  ## Set the version
  set_kb_item(name: string("www/", csmaPort, "/Cisco_IronPort/CSMA"),
             value:csmaVersion);

  ## build CPE
  cpe = build_cpe(value:csmaVersion, exp:"^([0-9.]+)",
                  base:"cpe:/h:cisco:content_security_management_appliance:");
  if(isnull(cpe))
    cpe = 'cpe:/h:cisco:content_security_management_appliance';

  ## Register the product
  register_product(cpe:cpe, location:'/https', nvt:SCRIPT_OID, port:csmaPort);

  log_message(data: build_detection_report(app:"Cisco Content Security Management Appliance",
                                           version:csmaVersion,
                                           install:'/https',
                                           cpe:cpe,
                                           concluded: csmaVersion),
                                           port:csmaPort);
}
