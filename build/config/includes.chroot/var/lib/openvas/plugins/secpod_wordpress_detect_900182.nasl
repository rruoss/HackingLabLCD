###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_detect_900182.nasl 42 2013-11-04 19:41:32Z jan $
#
# WordPress Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
#
# Modified to Detect Versions, When it is Under Root folder
#  - By Sharath S <sharaths@secpod.com> On 2009-08-18
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-09-04
# According to CR57 and new style script_tags.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900182";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 42 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_tag(name:"detection", value:"remote probe");
  script_name("WordPress Version Detection");

  tag_summary =
"Detection of installed version of WordPress/WordPress-Mu

This script sends HTTP GET request and try to get the version from the
responce, and sets the result in KB.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Set version of WordPress/WordPress-Mu in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
flag = "";
wpPort = "";
wpName = "";
wpmuName = "";

## Function to Register Product and Build report
function build_report(app, ver, cpe, insloc, port)
{
  register_product(cpe:cpe, location:insloc, nvt:SCRIPT_OID, port:port);

  log_message(data: build_detection_report(app: app,
                                           version: ver,
                                           install: insloc,
                                           port: port,
                                           cpe: cpe,
                                           concluded: ver));
}

## Get http port
wpPort = get_kb_item("Services/www");
if(!wpPort){
  wpPort = 80;
}

## Check the port status
if(!get_port_state(wpPort)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:wpPort)){
  exit(0);
}

foreach dir (make_list("", "/blog", "/wordpress", "/wordpress-mu", cgi_dirs()))
{
  foreach file (make_list("/", "/index.php"))
  {
    url = dir + file;
    req = http_get(item:url, port:wpPort);
    rcvRes = http_send_recv(port:wpPort, data:req, bodyonly:FALSE);

    if(rcvRes && "WordPress" >< rcvRes && rcvRes =~ "HTTP/1.. 200")
    {
      if("WordPress Mu" >< rcvRes)
      {
        wpmuVer = eregmatch(pattern:"WordPress ([0-9]\.[0-9.]+)", string:rcvRes);

        if(!wpmuVer[1]){
          wpmuVer[1] = "unknown";
        }
        tmp_version = wpmuVer[1] + " under " + dir;

        ## Set the KB
        set_kb_item(name:"www/" + wpPort + "/WordPress-Mu", value:tmp_version);
        set_kb_item(name:"wordpress/installed",value:TRUE);

        ## Build CPE
        mu_cpe = build_cpe(value:wpmuVer[1], exp:"^([0-9.]+)", base:"cpe:/a:wordpress:wordpress_mu:");
        if(!mu_cpe)
          mu_cpe = 'cpe:/a:wordpress:wordpress_mu';

        ## Register Product and Build Report
        build_report(app: "WordPress-Mu", ver: wpmuVer[1], cpe: mu_cpe, insloc: dir, port: wpPort);
      }

      if("WordPress Mu" >!< rcvRes)
      {
        flag = 1;

        wpVer = eregmatch(pattern:"WordPress ([0-9]\.[0-9.]+)", string:rcvRes);
        if(!wpVer[1]){
          wpVer[1] = "unknown";
        }
        tmp_version = wpVer[1] + " under " + dir;

        ## Set the KB
        set_kb_item(name:"www/" + wpPort + "/WordPress", value:tmp_version);
        set_kb_item(name:"wordpress/installed",value:TRUE);

        ## Build CPE
        cpe = build_cpe(value:wpVer[1], exp:"^([0-9.]+)", base:"cpe:/a:wordpress:wordpress:");
        if(!cpe)
          cpe = 'cpe:/a:wordpress:wordpress';

        ## Register Product and Build Report
        build_report(app: "WordPress", ver: wpVer[1], cpe: cpe, insloc: dir, port: wpPort);
      }
    }
  }
}

if (!flag)
{
  foreach dir (make_list("", "/blog", "/wordpress", cgi_dirs()))
  {
    url = dir + '/wp-login.php';
    req = http_get(item:url, port:wpPort);
    rcvRes = http_send_recv(port:wpPort, data:req, bodyonly:FALSE);
    if(rcvRes && "WordPress" >< rcvRes && rcvRes =~ "HTTP/1.. 200")
    {
      wpVer = "unknown";
      tmp_version = wpVer + " under " + dir;

      ## Set the KB
      set_kb_item(name:"www/" + wpPort + "/WordPress", value:tmp_version);
      set_kb_item(name:"wordpress/installed",value:TRUE);

      cpe = 'cpe:/a:wordpress:wordpress';

      ## Register Product and Build Report
      build_report(app: "WordPress", ver: wpVer, cpe: cpe, insloc: dir, port: wpPort);
    }
  }
}
