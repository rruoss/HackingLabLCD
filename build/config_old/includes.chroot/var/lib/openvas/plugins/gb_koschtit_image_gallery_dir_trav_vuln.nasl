###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_koschtit_image_gallery_dir_trav_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# KoschtIT Image Gallery Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary commands to
  retrieve local system related files and gain sensitive information.
  Impact Level: Application";
tag_affected = "KoschtIT Image Gallery version 1.82 and prior";
tag_insight = "Improper validation check while processing user supplied input in the file
  parameter for the files 'ki_makepic.php' and 'ki_nojsdisplayimage.php' under
  ki_base directory.";
tag_solution = "Upgrade to KoschtIT Image Gallery version 2.0 Beta 1
  http://koschtit.tabere.net/en";
tag_summary = "This host is running KoschtIT Image Gallery and is prone to multiple
  Directory Traversal vulnerabilities.";

if(description)
{
  script_id(800803);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-22 08:49:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1510");
  script_bugtraq_id(34335);
  script_name("KoschtIT Image Gallery Multiple Directory Traversal Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8334");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/378734.php");
  script_xref(name : "URL" , value : "http://koschtit.tabere.net/forum/showthread.php?tid=6");

  script_description(desc);
  script_summary("Check for the version of KoschtIT Image Gallery");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

koschITPort = get_http_port(default:80);
if(!koschITPort){
  koschITPort = 80;
}

if(!get_port_state(koschITPort)){
  exit(0);
}

foreach dir (make_list("/kos2", "/koschtit", "/koschtit2", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir + "/changelog.txt"), port:koschITPort);
  rcvRes = http_send_recv(port:koschITPort, data:sndReq);

  if("KoschtIT Image Gallery" >< rcvRes)
  {
    # Match for KoschtIT Image Gallery Version
    ver = eregmatch(pattern:"Gallery ([0-9.]+)(beta)?([0-9]+)?", string:rcvRes);
    if(ver[1] != NULL)
    {
      if(ver[1] != NULL && ver[3] != NULL){
        version = ver[1] + "." + ver[3]; # ver[3] points to beta version.
      }
      else
        version = ver[1];
    }

    if(version != NULL)
    {
      if(version_is_less_equal(version:version, test_version:"1.82"))
      {
        security_hole(koschITPort);
        exit(0);
      }
    }
  }
}
