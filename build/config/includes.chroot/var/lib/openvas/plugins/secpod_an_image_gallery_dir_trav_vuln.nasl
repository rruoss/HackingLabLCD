###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_an_image_gallery_dir_trav_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# An Image Gallery Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to gain information about
  directory and file locations.
  Impact Level: System/Application.";
tag_affected = "An Image Gallery version 1.0 and prior.";
tag_insight = "Input passed to the 'path' parameter in 'navigation.php' is not properly
  verified before being used to generate and display folder contents.";
tag_solution = "No solution or patch is available as of 30th September, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://plohni.com/wb/content/php/Free_scripts.php";
tag_summary = "This host is running An Image Gallery and is prone to Directory
  Traversal vulnerability.";

if(description)
{
  script_id(901037);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3366");
  script_name("An Image Gallery Directory Traversal Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36680");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9636");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53148");

  script_description(desc);
  script_summary("Check for the version of An Image Gallery");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

anPort = get_http_port(default:80);
if(!anPort){
  anPort = 80;
}

if(!get_port_state(anPort)){
  exit(0);
}

if(safe_checks()){
  exit(0);
}

foreach dir (make_list("/", "/image_gallery", "/gallery", "/album", cgi_dirs()))
{
  sndReq = http_get(item:string(dir + "/main.php"), port:anPort);
  rcvRes = http_send_recv(port:anPort, data:sndReq);

  if("An image gallery" >< rcvRes)
  {
    request = http_get(item:dir + "/navigation.php?path=../../../../../../../",
                       port:anPort);
    response = http_send_recv(port:anPort, data:request);

    if(("WINDOWS" >< response) || ("root" >< response))
    {
      security_warning(anPort);
      exit(0);
    }
  }
}