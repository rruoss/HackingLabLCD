##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_frontaccounting_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# FrontAccounting Version Detection
#
# Authors:
# Maneesh KB <kmaneesh@secpod.com>
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
tag_summary = "This script detects the installed version of FrontAccounting and
  sets the result in KB.";

if (description)
{
  script_id(900256);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("FrontAccounting Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of FrontAccounting");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900256";
SCRIPT_DESC = "FrontAccounting Detection";

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

foreach dir (make_list("/frontaccount", "/account", "/", cgi_dirs()))
{
  req = http_get(item:string(dir, "/index.php"), port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:TRUE);

  if("FrontAccounting" >!< buf)
  {
    req = string("GET ", dir, "/index.php", "\r\n",
                 "Host: ", get_host_name(), "\r\n\r\n");
    buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
  }

  if("FrontAccounting" >< buf) {

    # Grep version
    version = eregmatch(pattern:"(FrontAccounting |Version )([0-9.]+) ?([a-zA-Z]+ ?[0-9]+?)?",
                        string:buf, icase:TRUE);

    if(!isnull(version[2]))
    {
      if(version[3])
      {
        version[3] = ereg_replace(string: version[3], pattern:" ", replace:"");
        version = version[2] + "." + version[3];
      }
      else{
        version = version[2];
      }
      if(version)
      {
        tmp_version = string(version," under ",dir);
        set_kb_item(name:string("www/", port, "/FrontAccounting"),
                    value:tmp_version);
        security_note(data:"FrontAccounting version " + version +
                  " running at location " + dir +  " was detected on the host");
  
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:frontaccounting:frontaccounting:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

        exit(0);
      }
    }
  }
}  
