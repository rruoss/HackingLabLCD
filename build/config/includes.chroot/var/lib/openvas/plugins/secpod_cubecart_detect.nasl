##############################################################################
# OpenVAS Vulnerability Test
# $Id:secpod_cubecart_detect.nasl 1093   2009-03-24 20:05:29Z Mar $
#
# Detection of cubecart Version
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_summary = "Detection of CubeCart.

The script sends a connection request to the server and attempts to extract the
version number from the reply.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.900614";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-04-07 09:44:25 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_name("Detecting the cubecart version");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Checks for the presence of CubeCart");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");


# Variable Initialization
port = 0;
url = "";
dir = "";
cpe = "";
version = "";
cubecartVer = "";
tmp_version = "";

port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("", "/cart", "/store", "/shop", "/cubecart",  cgi_dirs()))
{
  url = dir + "/index.php";

  ## Confirm the application before trying exploit
  if(http_vuln_check(port: port, url: url, check_header: TRUE,
     pattern: "Powered by CubeCart", extra_check: ">CubeCart<"))
  {
    set_kb_item(name:"cubecart/installed",value:TRUE);

    cubecartVer = egrep(pattern:"CubeCart</a> [0-9.]+", string:rcvRes);
    version = eregmatch(pattern:"> ([0-9.]+)", string:cubecartVer);
    if(version[1]!= NULL){
      tmp_version = version[1] + " under " + dir;
    }
    else
    {
      tmp_version = "unknown under " + dir;
      version[1] = "unknown";
    }

    tmp_version = version[1] + " under " + dir;
    set_kb_item(name:"www/" + port + "/cubecart", value:tmp_version);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:cubecart:cubecart:");
    if(isnull(cpe))
      cpe = 'cpe:/a:cubecart:cubecart';

    register_product(cpe:cpe, location:dir, nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"CubeCart", version: version[1],
                                         install:dir,
                                         cpe:cpe,
                                         concluded:version[1]),
                                         port: port);
  }
}
