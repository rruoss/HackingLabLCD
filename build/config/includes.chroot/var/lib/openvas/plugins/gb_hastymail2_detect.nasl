###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hastymail2_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# Hastymail2 Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_summary = "The script detects the version of Hastymail2 on remote host
  and sets the KB.";

if(description)
{
  script_id(801575);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Hastymail2 Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Hastymail2 in KB");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801575";
SCRIPT_DESC = "Hastymail2 Version Detection";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/", "/Hastymail2", "/hastymail2", "/hastymail","/hm2", cgi_dirs()))
{
  ## Send and Recieve the response
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if(" Login | Hastymail2<" >< rcvRes && "Hastymail Development Group" >< rcvRes)
  { 

    ## Check for upgrading.txt file for version
    sndReq = http_get(item:string(dir, "/UPGRADING"), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    ## Match the version
    hm2Ver = eregmatch(pattern:"to (([a-zA-z]+)?([0-9.]+)( (RC[0-9]))?)", string:rcvRes);

    if(hm2Ver[1]!= NULL && (hm2Ver[2]!= NULL)){
      vers = hm2Ver[1];
    }

    else if(hm2Ver[3]!= NULL && (hm2Ver[2] == NULL)){
      vers = hm2Ver[3];
    }

    if("RC" >< hm2Ver[5])vers = vers + ' ' + hm2Ver[5];

    if(vers)
    {
      tmp_version = vers + " under " + dir;
      ## Set the version of Hastymail2 in KB
      set_kb_item(name:"www/" + port + "/Hastymail2", value: tmp_version);
      security_note(data:"Hastymail2 version " + vers +
                 " running at location " + dir +  " was detected on the host");

      register_host_detail(name:"App", value:"cpe:/a:hastymail:hastymail2:"+vers, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
