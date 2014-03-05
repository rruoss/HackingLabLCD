###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_fusion_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Detection of php_fusion Version
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2011-04-22
#   - Modified KB item to hold the directory name
#
#Updated By: Rachana Shetty <srachana@secpod.com>
#    - Updated according to CR 57
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
tag_summary = "Detection of php-fusion.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900612";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-04-07 09:44:25 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"remote probe");
  script_name("Detection of php_fusion Version");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Detects the version of php-fusion and sets the kb value");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
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

## Variable initialization
port = "";
dir = "";
sndReq = "";
rcvRes = "";

## start script
port = get_http_port(default:80);
if(!port){
   exit(0);
}

## check the port status
if(!get_port_state(port)){
  exit(0);
}

## set th kb and CPE
function _SetCpe(version, tmp_version, dir)
{
  ## set the kb
  set_kb_item(name: string("www/", port, "/php-fusion"), value: tmp_version);
  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:php-fusion:php-fusion:");

  if(isnull(cpe))
    cpe = "cpe:/a:php-fusion:php-fusion";

  ## set the CPE
  register_product(cpe:cpe, location:dir, nvt:SCRIPT_OID, port:port);
  log_message(data: build_detection_report(app:"PHP-Fusion", version:version,
                                           install:dir,
                                           cpe:cpe,
                                           concluded:version),
                                           port:port);
}

## Iterate over the possible directories
foreach dir (make_list("", "/php-fusion", "/phpfusion", cgi_dirs()))
{
  flag = 0; tmp_version= ""; version= "";

   ## Iterate over the  possible subdirectories
   foreach subdir (make_list("/files", "/php-files"))
   {
     ## Request for the news.php
     sndReq = http_get(item:string(dir + subdir, "/news.php"), port:port);
     rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

     ## confirm the PHP-Fusion installation
     if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes) &&
        ("PHP-Fusion Powered" >< rcvRes))
     {
       set_kb_item(name:"php-fusion/installed", value:TRUE);
       flag = 1;

       ## Match the version from response
       matchline = egrep(pattern:"></a> v[0-9.]+", string:rcvRes);
       matchVersion = eregmatch(pattern:"> v([0-9.]+)", string:matchline);
       if(matchVersion[1]!= NULL)
       {
         version = matchVersion[1];
         tmp_version = matchVersion[1] + " under " + dir;
       }
       if(version) {
         _SetCpe(version, tmp_version, dir);
       }
     }
   }

   ## If PHP-Fusion is installed and not get the version from news.php
   ## check for the version in readme-en.html
   if(!version)
   {
     sndReq = http_get(item:string(dir, "/readme-en.html"), port:port);
     rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

     ## Confirm its PHP-Fusion Readme only
     if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes) &&
        ("PHP-Fusion Readme" >< rcvRes))
     {
       ## Match the version
       matchline = egrep(pattern:"Version:</[a-z]+> [0-9.]+", string:rcvRes);
       matchVersion = eregmatch(pattern:"> ([0-9.]+)", string:matchline);

       if(matchVersion[1]!= NULL)
       {
         version = matchVersion[1];
         tmp_version = matchVersion[1] + " under " + dir;
       }

       ## set the cpe and version
       if(version){
        _SetCpe(version, tmp_version, dir);
       }
    }
  }

  ## If PHP-Fusion is installed and not able get the version from any
  ## of the file set the version as "unknown" and CPE
  if(!version && flag)
  {
    version = "Unknown";
    tmp_version = version + " under " + dir;
    _SetCpe(version, tmp_version, dir);
  }
}
