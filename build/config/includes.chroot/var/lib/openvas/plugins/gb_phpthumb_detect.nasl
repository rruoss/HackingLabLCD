###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpthumb_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# phpThumb Version Detection
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
tag_summary = "This script finds the running phpThumb version and saves
  the result in KB.";

if(description)
{
  script_id(801232);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("phpThumb Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of phpThumb in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

foreach dir (make_list("/demo/demo", "/phpThumb/demo", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/phpThumb.demo.demo.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application and Get version
  if('>phpThumb()<' >< res)
  {
    ver = eregmatch(pattern:'current version: v([0-9.]+)', string:res);
    if(ver[1])
    {
      ## Set phpThumb Version in KB
      set_kb_item(name:"www/" + port + "/phpThumb", value:ver[1] +
                       " under " + dir);
      security_note(data:"phpThumb version " + ver[1] +
                         " running at location " + dir +
                         " was detected on the host", port:port);
    }
  }
}
