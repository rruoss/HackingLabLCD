###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_websvn_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# WebSVN script version detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_summary = "The script detects the version of WebSVN and sets the result in KB.";

if(description)
{
  script_id(900440);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("WebSVN version detection");
  desc = "

  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Set the KB for the Version of WebSVN");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900440";
SCRIPT_DESC = "WebSVN version detection";

websvnPort = get_kb_item("Services/www");
if(!websvnPort){
  exit(0);
}

foreach dir (make_list("/", "/websvn", "/svn", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:websvnPort);
  rcvRes = http_keepalive_send_recv(port:websvnPort, data:sndReq);
  if("WebSVN" >< rcvRes)
  {
    svnVer = eregmatch(pattern:"WebSVN ([0-9]\.[0-9.]+)", string:rcvRes);
    if(svnVer[1] != NULL)
    {
      set_kb_item(name:"www/" + websvnPort + "/WebSVN", value:svnVer[1]);
      security_note(data:"WebSVN version " + svnVer[1] + " running at " +
                         "location " + dir +  " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:svnVer[1], exp:"^([0-9.]+)", base:"cpe:/a:tigris:websvn:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}