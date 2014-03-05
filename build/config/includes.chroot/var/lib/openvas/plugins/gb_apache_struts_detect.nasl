###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Apache Struts Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-09-09
# - Modified the script to detect the recent versions
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
tag_summary = "The script detects the version of Apache Struts and sets the
  result in KB.";

if(description)
{
  script_id(800276);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Apache Struts Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Apache Struts");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800276";
SCRIPT_DESC = "Apache Struts Version Detection";

asPort = get_http_port(default:8080);
if(!asPort){
  asPort = 8080;
}

foreach dir (make_list("/", "/struts", cgi_dirs()))
{
  sndReq = string("GET " + dir + "/docs/index.html \r\n",
                  "Host: ", get_host_name(), "\r\n\r\n");
  rcvRes = http_keepalive_send_recv(port:asPort, data:sndReq);

  if("Struts" >< rcvRes)
  {
    core = string("GET ", dir + "/docs/WW/cwiki.apache.org/WW/home.html \r\n",
                  "Host: ", get_host_name(), "\r\n\r\n");
    buf = http_send_recv(port:asPort, data:core);

    if("Getting Started" >< buf && "Home" >< buf && "Distributions" >< buf){
      strutsVer = eregmatch(pattern:"Release Notes ([0-9]\.[0-9.]+)", string:buf);
    }

    if(strutsVer[1] == NULL)
    {
      guide = string("GET ", dir + "/docs/WW/cwiki.apache.org/WW/guides.html \r\n",
                     "Host: ", get_host_name(), "\r\n\r\n");
      buf = http_send_recv(port:asPort, data:guide);

      if("Migration Guide" >< buf && "Core Developers Guide" >< buf && "Release Notes" >< buf){
        strutsVer = eregmatch(pattern:"Release Notes ([0-9]\.[0-9.]+)", string:buf);
      }
    }

    if(isnull(strutsVer[1]))
    {
       ## searching for Struts version in different possible files
       sndReq = http_get(item:string(dir, "/src/src/site/xdoc/index.xml"), port:asPort);
       rcvRes =http_send_recv(port:asPort, data:sndReq);

        if("Apache Struts" >< rcvRes){
          strutsVer = eregmatch(pattern:">version ([0-9.]+)", string:rcvRes);
       }
    }

    if(strutsVer[1] != NULL)
    {
      tmp_version = strutsVer[1] + " under " + dir;
      set_kb_item(name:"www/" + asPort + "/Apache/Struts", value:tmp_version);
      security_note(data:"Apache Struts version " + strutsVer[1] + " running" +
                         " at location " + dir +  " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:apache:struts:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
