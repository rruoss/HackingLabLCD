###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ossim_web_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# AlienVault OSSIM Detection
#
# Authors:
# Michael Meyer
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-10-22
# According to CR57 and new style script_tags.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100543";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-03-19 11:14:17 +0100 (Fri, 19 Mar 2010)");
  script_tag(name:"detection", value:"remote probe");
  script_name("AlienVault OSSIM Detection");

  tag_summary =
"Detection of installed version of AlienVault OSSIM (Open Source Security
Information Management)

This script sends HTTP GET request and try to get the version from the
response, and sets the result in KB.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.alienvault.com");
  script_summary("Checks for the presence of AlienVault OSSIM");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

## Variable Initialization
url = "";
buf = "";
req = "";
port = "";
vers = "";
install = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

## Check Port state
if(!can_host_php(port:port))exit(0);

dirs = make_list("/ossim",cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/session/login.php");

  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly: TRUE);

  if( buf == NULL )continue;

  if(egrep(pattern: "<title> AlienVault.*Open Source (SIM|SIEM)", string: buf, icase: FALSE) ||
     egrep(pattern: "<title> OSSIM Framework Login", string: buf, icase: FALSE))
  {
    if(strlen(dir)>0) {
       install=dir;
    } else {
       install=string("/");
    }

    vers = string("unknown");

    ## Set KB
    set_kb_item(name: string("www/", port, "/ossim"), value: string(vers," under ",install));
    set_kb_item(name:"OSSIM/installed",value:TRUE);

    cpe = 'cpe:/a:alienvault:open_source_security_information_management';

    ## Register Product
    register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app: "AlienVault OSSIM",
                                             version: vers,
                                             install: install,
                                             port: port,
                                             cpe: cpe,
                                             concluded: vers));
  }
}
