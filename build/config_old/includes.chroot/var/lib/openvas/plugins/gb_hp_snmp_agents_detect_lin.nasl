###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_snmp_agents_detect_lin.nasl 12 2013-10-27 11:15:33Z jan $
#
# HP SNMP Agents Version Detection (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
###############################################################################

include("revisions-lib.inc");
tag_summary = "Detection of installed version of HP SNMP Agents.

The script logs in via ssh, searches for HP SNMP Agents from the list of
installed rpm packages and gets the version";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802769";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-08 12:53:44 +0530 (Tue, 08 May 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"rpm version check");
  script_name("HP SNMP Agents Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of HP SNMP Agents on Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_require_keys("ssh/login/rpms");
  script_mandatory_keys("login/SSH/success");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
sock = 0;
result = "";
version = "";
cpe = NULL;
buffer_rpm = NULL;

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock)
{
  if (defined_func("error_message"))
    error_message(port:port, data:"Failed to open ssh port.");
  exit(-1);
}

## Confirm Linux, as SSH can be instslled on Windows as well
result = ssh_cmd(socket:sock, cmd:"uname");
if("Linux" >!< result){
  exit(0);
}

## Trying to get version from rpm
buffer_rpm = get_kb_item("ssh/login/rpms");
if(buffer_rpm != NULL && buffer_rpm =~ "hp-snmp-agents")
{
  ## Grep for the version
  version = eregmatch(pattern:"hp-snmp-agents.?([0-9.]+)", string:buffer_rpm);
  if(version[1])
  {
    path ="/opt/hp/hp-snmp-agents/";

    ## Set the KB item
    set_kb_item(name:"HP/SNMP/Agents", value:version[1]);
    cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:hp:snmp_agents_for_linux:");
    if(!isnull(cpe))
      register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);

    log_message(data: build_detection_report(app:"HP SNMP Agents",
                                         version:version[1],
                                         install:path,
                                         cpe:cpe,
                                         concluded: version[1]));
  }
}
