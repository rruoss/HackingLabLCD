###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symphony_cms_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Symphony CMS Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_summary = "This script finds the running Symphony CMS version and saves
  the result in KB.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801219";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Symphony CMS Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Symphony CMS in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Get http Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/", "/symphony/", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"symphony/"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if("<h1>Symphony</h1>" >< res)
  {
    ## Get log file
    req = http_get(item:string(dir,"manifest/logs/main"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    vers = 'unknown';
    ## Get Version from log file
    ver = eregmatch(pattern:"[v|V]ersion: ([0-9.]+)", string:res);
    if(!isnull(ver[1])) {
      vers = ver[1];
    }  
    ## Set Symphony CMS version in KB
    tmp_version = vers + " under " + dir;
    set_kb_item(name:"www/" + port + "/symphony", value:tmp_version);
    set_kb_item(name:"symphony/installed", value:TRUE); 

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:symphony-cms:symphony_cms:");
    if(isnull(cpe))
      cpe = 'cpe:/a:symphony-cms:symphony_cms';

    register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);
    log_message(data: build_detection_report(app:"Symphony CMS", version:vers, install:dir, cpe:cpe, concluded: ver[0]),
                port:port);

  }
}
