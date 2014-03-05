###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssh_junos_get_version.nasl 18 2013-10-27 14:14:13Z jan $
#
# Get Junos Software Version
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
#
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.96200";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 18 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Wed Jul 13 11:48:37 2011 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Junos Software Version");

  tag_summary = "This script performs SNMP based detection of Junos Software Version.";

   desc = "
   Summary:
   " + tag_summary;

  script_description(desc);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_summary("Get Junos Software Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "ssh_authorization.nasl","gb_junos_snmp_version.nasl");
  script_exclude_keys("Junos/Version"); # already detected by gb_junos_snmp_version.nasl
  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if(get_kb_item("Junos/Version"))exit(0); # already detected by gb_junos_snmp_version.nasl

soc = ssh_login_or_reuse_connection();
if(!soc)exit(0);

sysversion = ssh_cmd_exec(cmd:"show version");
build = ssh_cmd_exec(cmd:"show snmp mib walk system");

if (!sysversion) exit(0);
if (!build) exit(0);

val = split(sysversion, sep:'\n', keep:0);
for(i=0; i<max_index(val); i++){
  if (val[i] =~ "JUNOS Base OS boot.*") systemversion = val[i];
}
if (!systemversion) exit (0);

systemversion=eregmatch(pattern:"(JUNOS Base OS boot \[)(.*)(\])", string:systemversion);

build=eregmatch(pattern:"Build date: ([^ ]+)", string:build);

set_kb_item(name: "Junos/Version", value:systemversion[2]);
set_kb_item(name: "Junos/Build", value:build[1]);

model = eregmatch(pattern:"^Model: ([^$]+$)", string:model_line);
if(!isnull(model[1]))
  set_kb_item(name: "Junos/model", value:model[1]);

register_host_detail(name:"OS", value:"cpe:/o:juniper:junos:" + systemversion[2], nvt:"1.3.6.1.4.1.25623.1.0.96200", desc:"Get Junos Software Version");
register_host_detail(name:"OS", value:"JunOS", nvt:"1.3.6.1.4.1.25623.1.0.96200", desc:"Get Junos Software Version");

report = "Your Junos Version is: " + systemversion[2] + ", Build: " + build[1];
log_message(port:0, data:report);
exit(0);
