###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mediawiki_detect.nasl 42 2013-11-04 19:41:32Z jan $
#
# MediaWiki Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated By : Sooraj KS <kssooraj@secpod.com> on 2010-04-27
#   -Modified the regex for detecting beta versions.
#
# Updated By : Antu Sanadi<santu@secpod.com> on 2011-03-o3
#  - Modified the application confirmation logic
#
# Updated By : Madhuri D<dmadhuri@secpod.com> on 2011-05-31
#  - Updated the KB item to save directory path
#
# Updated By : Madhuri D<dmadhuri@secpod.com> on 2012-07-09
#   Updated according to CR 57 and used build_detection_report
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-10-01
# According to new style script_tags.
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900420";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 42 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-12-29 13:55:43 +0100 (Mon, 29 Dec 2008)");
  script_tag(name:"detection", value:"remote probe");
  script_name("MediaWiki Version Detection");

  tag_summary =
"Detection of installed version of MediaWiki

This script sends HTTP GET request and try to get the version from the
responce, and sets the result in KB.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Checks for the presence of MediaWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## start script
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

foreach dir (make_list("/wiki", "/mediawiki", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php/Special:Version"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);
  if(rcvRes == NULL){
    exit(0);
  }

  if(("Powered by" >< rcvRes || "powered by" >< rcvRes) && "MediaWiki" >< rcvRes)
  {
    wikiVer = eregmatch(pattern:"MediaWiki ([0-9.]+)(.?([a-zA-Z0-9]+))?", string:rcvRes);

    if(wikiVer[1] != NULL)
    {
      if(wikiVer[3] != NULL)
      {
        tmp_version = wikiVer[1]+ "." +wikiVer[2] + " under " + dir;
        set_kb_item(name:"MediaWiki/Version", value:tmp_version);
        set_kb_item(name:"mediawiki/installed",value:TRUE);
      }
      else
      {
        tmp_version = wikiVer[1] + " under " + dir;
        set_kb_item(name:"MediaWiki/Version", value:tmp_version);
        set_kb_item(name:"mediawiki/installed",value:TRUE);
      }

      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:mediawiki:mediawiki:");
      if(isnull(cpe))
        cpe = 'cpe:/a:mediawiki:mediawiki';

      register_product(cpe:cpe, location:dir, nvt:SCRIPT_OID, port:port);

      log_message(data: build_detection_report(app:"MediaWiki", version:tmp_version,
                                               install:dir, cpe:cpe, concluded: tmp_version),
                                               port:port);

    }
  }
}
