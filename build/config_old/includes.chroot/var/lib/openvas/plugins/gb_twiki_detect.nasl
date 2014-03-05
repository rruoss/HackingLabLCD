###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twiki_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# TWiki Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2011-10-04
#  - Updated to detect latest versions by adding egrep pattern match.
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2012-03-21
#  - Updated to set KB if Twiki is installed
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
tag_summary = "This script detects the installed version of TWiki and
  sets the result in KB.";

if(description)
{
  script_id(800399);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("TWiki Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Version of TWiki in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800399";
SCRIPT_DESC = "TWiki Version Detection";

## Variables Initialization
twikiPort  = 0;
dir  = "";
sndReq = "";
rcvRes = "";
dump   = "";
twikiVer = "";
cpe = "";
tmp_version = "";
ver  = NULL;


##TWiki Port
twikiPort = get_http_port(default:80);
if(!get_port_state(twikiPort)){
  exit(0);
}

foreach dir (make_list("/", "/twiki", "/wiki", cgi_dirs()))
{
  sndReq = http_get(item:dir + "/bin/view/TWiki/WebHome", port:twikiPort);
  rcvRes = http_send_recv(port:twikiPort, data:sndReq);

  if("owered by TWiki" >!< rcvRes){
    sndReq = http_get(item:dir + "/do/view/TWiki/WebHome", port:twikiPort);
    rcvRes = http_send_recv(port:twikiPort, data:sndReq);
  }

  if(rcvRes && (egrep(pattern:"[p|P]owered by TWiki", string:rcvRes)))
  {
    if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }

    twikiVer = eregmatch(pattern:"TWiki-([0-9.]+),", string:rcvRes);
    dump = twikiVer;

    if(twikiVer[1] != NULL)
    {
      tmp_version = twikiVer[1] + " under " + dir;
      twikiVer = twikiVer[1];
    }
    else
    {
      tmp_version = "unknown under " + dir;
      twikiVer = "unknown";
    }

    ##Set the KB
    set_kb_item(name:"www/" + twikiPort + "/TWiki", value:tmp_version);
    set_kb_item(name:"twiki/installed",value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:twiki:twiki:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    log_message(data:'Detected TWiki version: ' + twikiVer +
    '\nLocation: ' + dir +
    '\nCPE: '+ cpe +
    '\n\nConcluded from version identification result:\n' + dump[max_index(dump)-1]);
  }
}
