###################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ortro_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Ortro Version Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
################################################################################

include("revisions-lib.inc");
tag_summary = "This script detects the installed Ortro version and sets
  the result in KB.";

if(description)
{
  script_id(800980);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Ortro Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Ortro");
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
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800980";
SCRIPT_DESC = "Ortro Version Detection";

ortroPort = get_http_port(default:80);
if(!ortroPort){
  exit(0);
}

foreach dir (make_list("/", "/ortro", "/ortro/www", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:ortroPort);
  rcvRes = http_keepalive_send_recv(port:ortroPort, data:sndReq, bodyonly:1);
  if("Ortro" >< rcvRes)
  {
    ortroVer = eregmatch(pattern:"v(([0-9.]+).([a-zA-Z0-9]+)?)", string:rcvRes);
    if(ortroVer[1] != NULL)
    {
      ortroVer[1] = ereg_replace(pattern:"-| ", replace:".", string:ortroVer[1]);
      tmp_version = ortroVer[1] + " under " + dir;
      set_kb_item(name:"www/"+ ortroPort + "/Ortro", value:tmp_version);
      security_note(data:"Ortro version " + ortroVer[1] + " running at location "
                        + dir + " was detected on the host");
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:ortro:ortro:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}

