###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_detect.nasl 42 2013-11-04 19:41:32Z jan $
#
# PHP Version Detection
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800109";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 42 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-10-07 16:11:33 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"detection", value:"remote probe");
  script_name("PHP Version Detection");
  tag_summary =
"Detection of installed version of PHP.

This script sends HTTP GET request and try to get the version from the
responce, and sets the result in KB.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Identify version of PHP remotely");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");
include("global_settings.inc");

phpPort = get_http_port(default:80);
if(!get_port_state(phpPort)){
  exit(0);
}

banner = get_http_banner(port:phpPort);
if("PHP" >!< banner){
  exit(0);
}

# PHP can be installed as a stand-alone package, local checks
# have to be separately written.

phpInfo = egrep(pattern:"Server.*PHP.*", string:banner);
if(!phpInfo){
  phpInfo = egrep(pattern:"X.Powered.By.*PHP.*", string:banner);
}

phpVer = ereg_replace(pattern:".*PHP/([.0-9]*).*", string:phpInfo, replace:"\1");
if(phpVer)
{
  set_kb_item(name:"www/" + phpPort + "/PHP", value:phpVer);
  set_kb_item(name:"php/installed", value:TRUE);

  # run depending nvts only if report_paranoia is > 1 to avoid false positives against backports
  if (report_paranoia > 1 ) {
    set_kb_item(name:'php/paranoia', value:TRUE);
  }

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:phpVer, exp:"^([0-9.]+)", base:"cpe:/a:php:php:");
  if(isnull(cpe))
     cpe = 'cpe:/a:php:php';

  register_product(cpe:cpe, location:'tcp/' + phpPort, nvt:SCRIPT_OID, port:phpPort);

  log_message(data: build_detection_report(app:"PHP",
                                           version:phpVer,
                                           install:'tcp/' + phpPort,
                                           cpe:cpe,
                                           concluded: phpInfo),
                                           port:phpPort);
}
