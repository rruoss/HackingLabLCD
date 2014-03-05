###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pmwiki_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# PmWiki Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-28
#  - To detect the latest versions
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
tag_summary = "The script detects the version of PmWiki on remote host
  and sets the KB.";

if(description)
{
  script_id(801209);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("PmWiki Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of PmWiki in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
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

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801209";
SCRIPT_DESC = "PmWiki Version Detection";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/", "/pmwiki", "/wiki", cgi_dirs()))
{
  ## Send and Recieve the response
  sndReq = http_get(item:string(dir, "/pmwiki.php?n=PmWiki.ReleaseNotes"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if("PmWiki / Release Notes </title>" >< rcvRes)
  {
    ## Get PmWiki Version
    wikiVer = eregmatch(pattern:">Version ([0-9.]+)", string:rcvRes);
    if(wikiVer[1]!= NULL)
    {
      ## Set the version of PmWiki in KB
      tmp_version = wikiVer[1] + " under " + dir;
      set_kb_item(name:"www/" + port + "/PmWiki", value: tmp_version);
      security_note(data:"PmWiki version " + wikiVer[1] +
                 " running at location " + dir +  " was detected on the host");
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:pmwiki:pmwiki:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
