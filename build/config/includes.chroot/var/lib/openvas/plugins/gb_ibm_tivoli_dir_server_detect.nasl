###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tivoli_dir_server_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Tivoli Directory Server Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By : Sooraj KS <kssooraj@secpod.com> on 2011-04-27
# Updated to detect latest versions.
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This script finds the running IBM Tivoli Directory Server version
  and saves the result in KB.";

if(description)
{
  script_id(801812);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("IBM Tivoli Directory Server Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of IBM Tivoli Directory Server in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ldap", 389);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801812";
SCRIPT_DESC = "IBM Tivoli Directory Server Version Detection";

## LDAP Port
port = get_kb_item("Services/ldap");
if(!port) {
  port = 4389;
}

if(!get_port_state(port)){
  exit(0);
}

## LDAP searchMessage Request Payload
req = raw_string(0x30, 0x84, 0x00, 0x00, 0x00, 0x2d, 0x02, 0x01,
                 0x0e, 0x63, 0x84, 0x00, 0x00, 0x00, 0x24, 0x04,
                 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02,
                 0x01, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x00,
                 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
                 0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x84, 0x00,
                 0x00, 0x00, 0x00);

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc) {
  exit(0);
}

## Sending Request
send(socket:soc, data:req);
result = recv(socket:soc, length:2000);
close(soc);

## Confirm the IBM Tivoli Directory Server
if("International Business Machines" >< result && "ibmdirectoryversion1" >< result)
{
  ## Extract Version From Response
  index = stridx(result, "ibmdirectoryversion1");
  if (index == -1){
    exit(0);
  }

  version = substr(result, index+22, index+36);
  len = strlen(version);
  for(i = 0; i < len; i++)
  {
    if(version[i] =~ '[0-9.]'){
      tdsVer = tdsVer + version[i];
    }
  }

  if(tdsVer)
  {
    ## Set IBM Tivoli Directory Server Version in KB
    set_kb_item(name:"IBM/TDS/Ver",value:tdsVer);
    security_note(port:port, data:"Tivoli Directory Server version " + tdsVer +
                       " was detected on the host");
      
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tdsVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:tivoli_directory_server:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
