###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_quick_arcade_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP Quick Arcade (PHPQA) Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script finds the running PHP Quick Arcade version and saves
  the result in KB.";

if(description)
{
  script_id(801363);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-21 15:32:44 +0200 (Mon, 21 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("PHP Quick Arcade (PHPQA) Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of PHP Quick Arcade in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801363";
SCRIPT_DESC = "PHP Quick Arcade (PHPQA) Version Detection";

phpqaPort = get_http_port(default:80);
if(!phpqaPort){
  exit(0);
}

foreach path (make_list("/", "/phpqa", "/phpqa/phpqa", cgi_dirs()))
{
  ## Send and receive response
  sndReq = http_get(item:string(path, "/index.php"), port:phpqaPort);
  rcvRes = http_send_recv(port:phpqaPort, data:sndReq);

  ## Confirm the application
  if(">PHP-Quick-Arcade<" >< rcvRes)
  {
    ## Grep for the version
    phpqaVer = eregmatch(pattern:"a> ([0-9.]+)", string:rcvRes);
    if(phpqaVer[1] != NULL)
    {
      ## Set the KB value
      tmp_version = phpqaVer[1] + " under " + path;
      set_kb_item(port:phpqaPort, name:"www/" + phpqaPort + "/PHP-Quick-Arcade", value:tmp_version);
      security_note(port:phpqaPort, data:"PHP Quick Arcade version " + phpqaVer[1] +
                   " running at location " + path + " was detected on the host");
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:jcink:php-quick-arcade:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
