###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_gollem_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# Horde Gollem Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "The script detects the version of Horde Gollem on remote host
  and sets the KB.";

if(description)
{
  script_id(801869);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Horde Gollem Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Check for Horde Gollem version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801869";
SCRIPT_DESC = "Horde Gollem Version Detection";

## Get http port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/horde/gollem", "/gollem", cgi_dirs()))
{
  ## Send and Recieve the response
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## Confirm the application
  if(">File Manager Login<" >< rcvRes)
  {
    ## Send and Recieve the response
    sndReq = http_get(item:string(dir, "/test.php"), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

    ## Get the version
    ver = eregmatch(pattern:">Gollem: H. \(([0-9.]+)\)<", string:rcvRes);

    if(ver[1] == NULL)
    {
      ## Get Version from CHANGES file
      sndReq = http_get(item:string(dir, "/docs/CHANGES"), port:port);
      rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);
      ver = eregmatch(pattern:"v([0-9.]+)", string:rcvRes);
    }

    if(ver[1])
    {
      ## Set the KB value
      tmp_version = ver[1] + " under " + dir;
      set_kb_item(name:"www/" + port + "/gollem", value:tmp_version);
      security_note(data:"Horde Gollem version " + ver[1] + " running at location "
                         + dir +" was detected on the host", port:port);
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:horde:gollem:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
