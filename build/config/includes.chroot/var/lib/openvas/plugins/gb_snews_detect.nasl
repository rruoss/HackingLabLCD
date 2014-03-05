###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snews_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# sNews Version Detection
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
tag_summary = "The script detects the version of sNews on remote host
  and sets the KB.";

if(description)
{
  script_id(801242);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-04 08:26:41 +0200 (Wed, 04 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("sNews Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Check for sNews version");
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

## Get http port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/sNews", "/snews", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## Confirm the application and Get version
  ver = eregmatch(pattern:'<title>sNews ([0-9.]+)</title>', string:rcvRes);
  if(ver[1] == NULL)
  {
    ## Get Version from readme file
    sndReq = http_get(item:string(dir, "/readme.txt"), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);
    ver = eregmatch(pattern:'sNews v([0-9.]+)', string:rcvRes);
  }

  if(ver[1])
  {
    ## Set the KB value
    set_kb_item(name:"www/" + port + "/snews", value:ver[1] +" under "+ dir);
    security_note(data:"sNews Version " + ver[1] + " running at location "
                             + dir +  " was detected on the host", port:port);
  }
}
