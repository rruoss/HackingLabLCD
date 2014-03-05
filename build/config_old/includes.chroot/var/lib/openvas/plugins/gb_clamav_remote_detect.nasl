###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_remote_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# ClamAV Version Detection Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "This host is running ClamAV Anti Virus.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(100651);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-05-25 13:42:13 +0200 (Tue, 25 May 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("ClamAV Version Detection Detection");
 
 script_description(desc);
 script_summary("Checks for the presence of ClamAV");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/clamd", 3310);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.clamav.net");
 exit(0);
}

include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100651";
SCRIPT_DESC = "ClamAV Version Detection Detection";

port = get_kb_item("Services/clamd");
if(!port) port = 3310;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = string("VERSION\r\n");
send(socket:soc, data:req);

buf = recv(socket:soc, length:256);

if(buf == NULL || "clamav" >!< tolower(buf))exit(0);
version = eregmatch(pattern:"clamav ([0-9.]+)", string:tolower(buf));

if(isnull(version[1]))exit(0);

set_kb_item(name:"ClamAV/remote/Ver", value: version[1]);
register_host_detail(name:"App", value:string("cpe:/a:clamav:clamav:",version[1]), nvt:SCRIPT_OID, desc:SCRIPT_DESC);

info = string("net\n\nClamAV Version (");
info += string(version[1]);
info += string(") was detected on the remote host.\n");

desc = ereg_replace(
        string:desc,
        pattern:"net$",
        replace:info
    );

if(report_verbosity > 0) {
  security_note(port:port,data:desc);
  exit(0);
}

exit(0);



