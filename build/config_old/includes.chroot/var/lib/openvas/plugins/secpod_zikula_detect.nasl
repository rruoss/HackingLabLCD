##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_zikula_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Detection of zikula or Post-Nuke Version
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-05-12
#  - Modified the script to detect the recent versions
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
tag_summary = "This script finds the version of the PostNuke installed
  on remote system and sets the equivelent value in the KB.";

if(description)
{
  script_id(900620);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-06-02 12:54:52 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Detecting the zikula or PostNuke version");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detects the version of zikula or PostNuke and sets the kb value");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}



# The PostNuke product is stopped and again started same  product with the name zikula.
# This script first searches the version of postnuke installed , if it not founds then
# it serches for the zikula installed.

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900620";
SCRIPT_DESC = "Detecting the zikula or PostNuke version";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/postnuke", "/PostNuke", "/zikula", cgi_dirs()))
{
  req = http_get(item:string(dir, "/index.php"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if(r == NULL){
    exit(0);
  }
  # searching for postnuke version in different possible files
  if('PostNuke' >< r && egrep(pattern:"<meta name=.generator. content"+
                     "=.PostNuke", string:r, icase:1))
  {
     version_str = egrep(pattern:"<meta name=.generator. content="+
                     ".PostNuke", string:r, icase:1);
     version_str = chomp(version_str);
     version = ereg_replace(pattern:".*content=.PostNuke ([0-9].*) .*",
                          string:version_str, replace:"\1");
     if(version == version_str)
     {
       req = http_get(item:string(dir, "/docs/manual.txt"), port:port);
       r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
       if(r == NULL){
             exit(0);
        }

       if('PostNuke' >< r && egrep(pattern:".*PostNuke:.The (Phoenix|"+
                                          "Platinum) Release.*$", string:r))
       {
         version_str = egrep(pattern:".*PostNuke:.The (Phoenix|"+
                        "Platinum) Release.*$", string:r);
         version_str = chomp(version_str);
         version = ereg_replace(pattern:".*PostNuke:.The (Phoenix|"+
                         "Platinum) Release.*\(([0-9].*)\)",
                                        string:version_str, replace:"\2");
         # if postnuke is installed sets the kb values and exits
          if(version){

           tmp_version = version + " under " + dir;
           set_kb_item(name:"www/"+ port + "/postnuke", value:tmpVers);
           security_note(data:"Zikula/PostNuke version " + version +
                              " running at location " + dir +
                              " was detected on the host");

           ## build cpe and store it as host detail
           register_cpe(tmpVers:tmp_version,tmpExpr:"^([0-9.]+)",tmpBase:"cpe:/a:postnuke:postnuke:");

             exit(0);
         }
        }
      }
    }

   # searching for postnuke version in different possible files
   if("postnuke" >< dir || "PostNuke" >< dir )
   {
    sndReq = http_get(item:string(dir, "/themes/SeaBreeze/style/style.css"), port:port);
    rcvRes =http_send_recv(port:port, data:sndReq);
    if(rcvRes == NULL){
       exit(0);
     }
    if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
    {
      postNuke= egrep(pattern:"PN [0-9.]+", string:rcvRes);
      version = eregmatch(pattern:"([0-9.]+)", string:postNuke);
      if(version[0]!= NULL){

        tmp_version = version[0] + " under " + dir;
        set_kb_item(name:"www/"+ port + "/postnuke", value:tmp_version);
        security_note(data:"Zikula/PostNuke version " + version[0] +
                           " running at location " + dir +
                           " was detected on the host");

        ## build cpe and store it as host detail
        register_cpe(tmpVers:tmp_version,tmpExpr:"^([0-9.]+)",tmpBase:"cpe:/a:postnuke:postnuke:");

        exit(0);
      }
     }
    }

   # searching for the zikula version in zikula directory
   sndReq = http_get(item:string(dir, "/docs/distribution/tour_page1.htm"), port:port);
   rcvRes =http_send_recv(port:port, data:sndReq);
   if(!isnull(rcvRes))
   {
     if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes) && "congratulations and welcome to Zikula" >< rcvRes)
     {
       zikula= egrep(pattern:"welcome to Zikula [0-9.]+", string:rcvRes);
       version = eregmatch(pattern:"([0-9.]+)", string:zikula);
       if(version[0]!= NULL)
       {
         set_kb_item(name:"www/"+ port + "/zikula", value:version[0] + " under " + dir);
         security_note(data:"Zikula/PostNuke version " + version[0] +
                            " running at location " + dir +
                            " was detected on the host");
         exit(0);
       }
     }
   }

   sndReq = http_get(item:string(dir, "/docs/CHANGELOG"), port:port);
   rcvRes =http_send_recv(port:port, data:sndReq);

   if(!isnull(rcvRes) && "ZIKULA" >< rcvRes)
   {
     zikula= egrep(pattern:"ZIKULA [0-9.]+", string:rcvRes);
     version = eregmatch(pattern:"([0-9.]+)", string:zikula);
     if(version[0]!= NULL)
     {
       set_kb_item(name:"www/"+ port + "/zikula", value:version[0] + " under " + dir);
       security_note(data:"Zikula/PostNuke version " + version[0] +
                          " running at location " + dir +
                          " was detected on the host");
       exit(0);
     }
   }
}
