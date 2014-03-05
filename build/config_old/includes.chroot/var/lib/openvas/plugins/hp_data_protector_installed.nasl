# OpenVAS Vulnerability Test
# $Id: hp_data_protector_installed.nasl 41 2013-11-04 19:00:12Z jan $
# Description: HP Data Protector Detection
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
# Updated by : Antu Sanadi <santu@secpod.com> on 2011-01-24
# Updated check to detect the recent versions also
#
# updated by : Antu Sanadi <santu@secpod.com> on 2012-02-10
# Updated according CR#57
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "Detection of HP OpenView Data protector, is a data
management solution that automates.

The script sends a connection request to the HP OpenView Data protector
and attempts to extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.19601";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"remote probe");
  script_name("HP Data Protector Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Checks for Data Protector");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2005 Josh Zlatin-Amishav");
  script_require_ports(5555);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");

port = 5555;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if (!soc) {
  if (defined_func("error_message"))
    error_message(port:port,
      data:"Failed to open socket for port although port was reported open.");
  exit(-1);
}

versionpat = 'Data Protector ([^:]+)';
buildpat   = 'internal build ([^,]+)';

# Data Protector can take some time to return its header
response = recv(socket:soc, length:4096, timeout:20);
close(soc);

if("HP OpenView Storage Data Protector" >< response ||
   "HP Data Protector" >< response)
{
  versionmatches = egrep(pattern:versionpat, string:response);
  if (versionmatches)
  {
    foreach versionmatch (split(versionmatches))
    {
      versions = eregmatch(pattern:versionpat, string:versionmatch);
    }
  }

  buildmatches = egrep(pattern:buildpat, string:response);
  if (buildmatches)
  {
    foreach buildmatch (split(buildmatches))
    {
      builds = eregmatch(pattern:buildpat, string:buildmatch);
    }
  }

  if ((versions[1] == "") && (builds[1] == ""))
  {
    versions[1] = "unknown";
    builds[1]   = "unknown";
  }

  # In case the service wasn't identified before
  register_service (port:port, proto:"hp_openview_dataprotector");
  set_kb_item (name:"Hp/data_protector/installed", value: TRUE);

  set_kb_item (name:"Services/data_protector/version", value:versions[1]);
  set_kb_item (name:"Services/data_protector/build", value:builds[1]);

  desc += string("\n\nPlugin output :\n\nHP OpenView Data Protector version: ",
                 versions[1], " build: ", builds[1], " is installed.");

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:versions[1], exp:"^([a-zA-z]\.)([0-9.]+)",
                  base:"cpe:/a:hp:openview_storage_data_protector:");
  if(!isnull(cpe))
    register_product(cpe:cpe, location:string(port, "/tcp"), nvt:SCRIPT_OID);
  else
   cpe = "Failed";

  result_txt = 'Detected HP OpenView Storage Data Protector: ' + versions[1] + ' ' + builds[1];
  result_txt += '\nCPE: '+ cpe;
  result_txt += '\n\nConcluded from remote probe dump:\n';
  result_txt += response;
  result_txt += '\n';

  log_message(port:port, data:result_txt);
}
