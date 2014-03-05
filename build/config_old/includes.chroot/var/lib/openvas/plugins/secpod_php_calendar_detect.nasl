###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_calendar_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# PHP Calendar Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_summary = "This script detects the installed version of PHP Calendar
  and sets the result in KB.";

if(description)
{
  script_id(901089);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-12-31 08:44:14 +0100 (Thu, 31 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("PHP Calendar Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets the KB for the version of PHP Calendar");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901089";
SCRIPT_DESC = "PHP Calendar Version Detection";

calPort = get_http_port(default:80);
if(!calPort){
  exit(0);
}

foreach dir (make_list("/", "/php-calendar", "/calendar", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:calPort);
  rcvRes = http_send_recv(port:calPort, data:sndReq);
  if(("200 OK" >< rcvRes) && ("PHP-Calendar" >< rcvRes))
  {
    foreach path (make_list("/NEWS", "/docs/NEWS"))
    {
      sndReq = http_get(item:string(dir, path), port:calPort);
      rcvRes = http_keepalive_send_recv(port:calPort, data:sndReq, bodyonly:TRUE);
      if(("404 Not Found" >!< rcvRes) && ("calendar" >< rcvRes))
      {
        calVer = eregmatch(pattern:"(([0-9.]+).?([a-zA-Z0-9]+)?)", string:rcvRes);
        if(!isnull(calVer[1]))
        {
           Ver = ereg_replace(pattern:"-", replace:".", string:calVer[1]);
           tmp_version = Ver + " under " + dir;
           set_kb_item(name:"www/" + calPort + "/PHP-Calendar", value:tmp_version);
           security_note(data:"PHP Calendar version " + Ver  + " running " +
                              "at location " + dir +  " was detected on the "+
                              "host");

           ## build cpe and store it as host_detail
           cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:php-calendar:php-calendar:");
           if(!isnull(cpe))
              register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

        }
      }
    }
  }
}
