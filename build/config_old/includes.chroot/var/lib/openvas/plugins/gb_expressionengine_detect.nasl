###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_expressionengine_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# ExpressionEngine CMS Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_summary = "The script detects the version of ExpressionEngine CMS and sets
  the result in KB.";

if(description)
{
  script_id(800262);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("ExpressionEngine CMS Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the KB for the Version of ExpressionEngine CMS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 8080);
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800262";
SCRIPT_DESC = "ExpressionEngine CMS Version Detection";

httpPort = get_kb_item("Services/www");
if(!httpPort){
  exit(0);
}

# Possible directory checks for ExpressionEngine Installed Location
foreach dir (make_list("/", "/system", "/cms/system", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:httpPort);
  rcvRes = http_keepalive_send_recv(port:httpPort, data:sndReq);
  if("ExpressionEngine" >< rcvRes)
  {
    cmsVer = eregmatch(pattern:"ExpressionEngine Core ([0-9]\.[0-9.]+)", string:rcvRes);
    if(cmsVer[1] == NULL){
      cmsVer = eregmatch(pattern:"v ([0-9]\.[0-9.]+)", string:rcvRes);
    }
    if(cmsVer[1] != NULL)
    {
      set_kb_item(name:"www/" + httpPort + "/ExpEngine", value:cmsVer[1]);
      security_note(data:"Expression Engine version " + cmsVer[1] + " running" + 
                         " at location " + dir +  " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:cmsVer[1], exp:"^([0-9.]+)", base:"cpe:/a:expressionengine:expressionengine:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}
