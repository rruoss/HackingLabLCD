###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_geoserver_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# GeoServer Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Verendra GG <verendragg@secpod.com> on 2010-04-28
# Updated the detection logic
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
###############################################################################

include("revisions-lib.inc");
tag_summary = "This script detects the installed version of GeoServer
  and sets the result in KB.";

if(description)
{
  script_id(900945);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("GeoServer Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the KB for the version of GeoServer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900945";
SCRIPT_DESC = "GeoServer Version Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
geoPort = get_http_port(default:8080);
if(!geoPort){
  geoPort = 8080;
}

if(!get_port_state(geoPort)){
  exit(0);
}

foreach dir (make_list("/", "/geoserver", cgi_dirs()))
{
  path = string(dir, "/welcome.do");
  sndReq = http_get(item:path, port:geoPort);
  rcvRes = http_send_recv(port:geoPort, data:sndReq);

  ## Logic for version lesser then 2.0
  if(("My GeoServer" >< rcvRes) && ("Welcome to GeoServer" >< rcvRes))
  {
    ## Matches 1.7.0 or 1.7.0-RC1 or 1.7.0-beta1
    geoVer = eregmatch(pattern:"Welcome to GeoServer ([0-9.]+(-[a-zA-Z0-9]+)?)"
                      , string:rcvRes);
    if(geoVer[1])
    {
      ## to remove "." at the end
      geoVer = ereg_replace(pattern:"([0-9]\.[0-9]\.[0-9])\.", string:geoVer[1],
                            replace:"\1");
      ## Replacing "-" with "." ex 1.7.0-RC1 and 1.7.0-beta1
      geoVer = ereg_replace(pattern:string("-"), replace:string("."),
                            string:geoVer);
      tmp_version = geoVer + " under " + dir;
      set_kb_item(name:"www/" + geoPort + "/GeoServer",
                  value:tmp_version);
      security_note(data:"GeoServer version " + geoVer + " running at location "
                                          + dir +  " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:geoserver:geoserver:");

    }
  }

  ## Logic for version 2.0
  else
  {
    path = string(dir, "/web/?wicket:bookmarkablePage=:org.geoserver.web."+
                                                        "AboutGeoServerPage");
    sndReq = http_get(item:path, port:geoPort);
    rcvRes = http_send_recv(port:geoPort, data:sndReq);
    if((">About GeoServer<" >< rcvRes))
    {
      ## Matches 2.0.1 or 2.0.1-RC1 or 2.0.1-beta1
      geoVer = eregmatch(pattern:">GeoServer ([0-9]\.[0-9]\.[0-9]"+
                                 "(-[a-zA-Z0-9]+)?)<", string:rcvRes);
      if(geoVer[1])
      {
        ## to remove "." at the end
        geoVer = ereg_replace(pattern:"([0-9]\.[0-9]\.[0-9])\.", string:geoVer[1],
                              replace:"\1");
        ## Replacing "-" with "." ex 1.7.0-RC1 and 1.7.0-beta1
        geoVer = ereg_replace(pattern:string("-"), replace:string("."),
                              string:geoVer);
        tmp_version = geoVer + " under " + dir;
        set_kb_item(name:"www/" + geoPort + "/GeoServer",
                    value:tmp_version);
        security_note(data:"GeoServer version " + geoVer + 
                 " running at location " + dir +  " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:geoserver:geoserver:");

      }
    }
  }
}
