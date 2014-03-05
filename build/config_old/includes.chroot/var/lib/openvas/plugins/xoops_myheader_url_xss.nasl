# OpenVAS Vulnerability Test
# $Id: xoops_myheader_url_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Xoops myheader.php URL Cross Site Scripting Vulnerability
#
# Authors:
# Noam Rathaus
# Updated: 05/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The weblinks module of XOOPS contains a file named 'myheader.php'
  in /modules/mylinks/ directory. The code of the module insufficently
  filters out user provided data. The URL parameter used by 'myheader.php'
  can be used to insert malicious HTML and/or JavaScript in to the web
  page.";

tag_solution = "Upgrade to the latest version of XOOPS.";

# From: Chintan Trivedi [chesschintan@hotmail.com]
# Subject: XSS vulnerability in XOOPS 2.0.5.1
# Date: Sunday 21/12/2003 16:45

if(description)
{
  script_id(11962);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9269);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  name = "Xoops myheader.php URL Cross Site Scripting Vulnerability";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);

  summary = "Detect Xoops myheader.php URL XSS";
  script_summary(summary);

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");

  family = "General";
  script_family(family);
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");

xoopsPort = get_http_port(default:80);
if(!xoopsPort){
  exit(0);
}

expRes = raw_string(0x22);

foreach path (make_list("/", "/xoops/htdocs", "/xoops/htdocs/install", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/index.php"), port:xoopsPort);
  rcvRes = http_send_recv(port:xoopsPort, data:sndReq);
  if("XOOPS" >< rcvRes)
  {
    sndReq = http_get(item:string(path, "/modules/mylinks/myheader.php?url=" +
                                        "javascript:foo"), port:xoopsPort);
    rcvRes = http_send_recv(port:xoopsPort, data:sndReq);
    if(rcvRes != NULL )
    {
      expRes = string("href=", expRes, "javascript:foo", expRes);
      if(expRes >< rcvRes )
      {
        security_warning(xoopsport);
        exit(0);
      }
    }
  }
}
