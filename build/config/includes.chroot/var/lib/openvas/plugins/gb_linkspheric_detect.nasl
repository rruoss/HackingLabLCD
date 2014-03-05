###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linkspheric_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# linkSpheric Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script detects the installed version of linkSpheric and
  sets the result in KB.";

if(description)
{
  script_id(801112);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("linkSpheric Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of linkSpheric in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801112";
SCRIPT_DESC = "linkSpheric Version Detection";

spheric_port = get_http_port(default:80);
if(!spheric_port){
  spheric_port = 80;
}

if(!get_port_state(spheric_port)){
  exit(0);
}

foreach dir (make_list("/linkSpheric", "/Spheric", "/", cgi_dirs()))
{
  sndReq = http_get(item:dir + "/admin/index.php", port:spheric_port);
  rcvRes = http_send_recv(port:spheric_port, data:sndReq);

  if("linkSpheric" >< rcvRes )
  {
    version = eregmatch(pattern:"linkSpheric version ([0-9.]+( Beta [0-9.])?)",
                        string:rcvRes, icase:1);
    if(isnull(version))
    {
      sndReq = http_get(item:dir + "/CHANGELOG", port:spheric_port);
      rcvRes = http_send_recv(port:spheric_port, data:sndReq);
      version = egrep(pattern:"version [0-9.]+[a-z0-9 ]+(release)",
                      string:rcvRes, icase:1);
      version = eregmatch(pattern:"version ([0-9.]+( Beta [0-9])?)",
                          string:version, icase:1);
    }
    spheric_ver[1] = ereg_replace(pattern:" ", replace:".", string:version[1]);

    if(!isnull(spheric_ver[1]))
    {
      tmp_version = spheric_ver[1] + " under " + dir;
      set_kb_item(name:"www/" + spheric_port + "/linkSpheric",
                  value:tmp_version);
      security_note(data:"linkSpheric version " + spheric_ver[1] +
                   " running at location " + dir + " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:dataspheric:linkspheric:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
