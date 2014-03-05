##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_pcanywhere_access_server_detect.nasl 12 2013-10-27 11:15:33Z jan $
#
# Symantec pcAnywhere Access Server Remote Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of Symantec pcAnywhere Access Server.

  The script sends a connection request to the server and attempts to
  extract the response.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802883";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-09 11:16:49 +0530 (Mon, 09 Jul 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"remote probe");
  script_name("Symantec pcAnywhere Access Server Remote Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Check for the presence of Symantec pcAnywhere Access Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/unknown", 5631);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("misc_func.inc");
include("host_details.inc");

pcAnyport = "";
resp = "";
cpe = NULL;

pcAnyport = get_kb_item("Services/unknown");
if(!pcAnyport){
  pcAnyport = 5631;
}

if(!get_port_state(pcAnyport)) {
  exit(0);
}

##  Open tcp socket
soc = open_sock_tcp(pcAnyport);
if(!soc){
  exit(0);
}

## Send initial request
initial = raw_string(0x00, 0x00, 0x00, 0x00);
send(socket:soc, data: initial);
pcanydata = recv(socket:soc, length:1024);

close(soc);
sleep(3);

if(!pcanydata){
  exit(0);
}

if("The Symantec pcAnywhere Access Server does not support" >< pcanydata ||
   "Please press <Enter>..." >< pcanydata ||
   "1b593200010342000001001" >< hexstr(pcanydata))
{
  set_kb_item(name:"Symantec/pcAnywhere-server/Installed", value:TRUE);

  ## build cpe and store it as host_detail
  cpe = 'cpe:/a:symantec:pcanywhere';

  register_service(port: pcAnyport, ipproto:"tcp", proto:"pcanywheredata");
  register_product(cpe:cpe, location: pcAnyport + '/tcp', nvt:SCRIPT_OID, port: pcAnyport);
  log_message(data: build_detection_report(app:"Symantec pcAnywhere Access Server",
                    version: "Unknown", install: pcAnyport + '/tcp', cpe:cpe,
                    concluded: "Unknown"), port: pcAnyport);
  exit(0);
}
