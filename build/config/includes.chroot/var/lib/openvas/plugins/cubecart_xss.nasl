# OpenVAS Vulnerability Test
# $Id: cubecart_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Multiple CubeCart XSS vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at ramat dot cc>
# Updated: 04/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
tag_summary = "Description :
  The remote version of CubeCart contains several cross-site scripting
  vulnerabilities to due to its failure to properly sanitize user-supplied
  input of certain variables to the 'index.php' and 'cart.php' scripts.";

tag_solution = "Upgrade to CubeCart version 3.0.4 or later.";

if(description)
{
  script_id(19945);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3152");
  script_bugtraq_id(14962);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Multiple CubeCart XSS vulnerabilities");
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
  script_summary("Checks for XSS in index.php");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("secpod_cubecart_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://lostmon.blogspot.com/2005/09/cubecart-303-multiple-variable-cross.html");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)){
  exit(0);
}

version = get_kb_item(string("www/", port, "/cubecart"));
if(!version){
  exit(0);
}

if(!safe_checks())
{
  foreach dir (make_list("/cubecart/upload","/upload", cgi_dirs()))
  {
    xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
    exss = urlencode(str:xss);
    req = http_get(item:string(dir, "/index.php?",'searchStr=">', exss,
         "&act=viewCat&Submit=Go"),port:port);
    res = http_send_recv(port:port, data:req);
    if(xss >< res)
    {
      security_note(port);
      exit(0);
    }
  }
}

if(version_is_less_equal(version:version, test_version:"3.0.3")){
  security_warning(port);
}