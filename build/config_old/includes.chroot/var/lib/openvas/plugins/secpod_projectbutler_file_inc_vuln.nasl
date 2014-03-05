###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_projectbutler_file_inc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# ProjectButler PHP Remote File Inclusion Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By : Antu Sanadi <santu@secpod.com> on 2010-03-25
#  - Updated check for login.php to confirm the product installation.
#  - Modified the substring check for exploit.
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
tag_impact = "Attacker can exploit this issue to execute remote PHP code by passing the
  mailicious URL into the 'offset' parameter.
  Impact Level: Application";
tag_affected = "ProjectButler version 1.5.0 and prior.";
tag_insight = "The input passed into the 'pda_projects.php' script is not sufficiently
  sanitized before being returned to the user.";
tag_solution = "No solution or patch is available as of 28th Agusut, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://projectbutler.sourceforge.net/";
tag_summary = "This host is installed with ProjectButler and is prone to PHP
  Remote File Inclusion vulnerability.";

if(description)
{
  script_id(900928);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-28 14:39:11 +0200 (Fri, 28 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2791");
  script_bugtraq_id(35919);
  script_name("ProjectButler PHP Remote File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9331");
  script_xref(name : "URL" , value : "http://heapoverflow.com/f0rums/sitemap/t-17452.html");

  script_description(desc);
  script_summary("Check through attack string on ProjectButler");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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

pbPort = get_http_port(default:80);
if(!pbPort){
  pbPort = 80;
}

if(!get_port_state(pbPort)){
  exit(0);
}

if(safe_checks()){
 exit(0);
}

foreach dir (make_list("/", "/ProjectButler", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/login.php"), port:pbPort);
  rcvRes = http_send_recv(port:pbPort, data:sndReq);
  if(">ProjectButler<" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, "/pda/pda_projects.php?offset=ATTACK-STRING"),
                                  port:pbPort);
    rcvRes = http_send_recv(port:pbPort, data:sndReq);
    if(("ATTACK-STRING ">< rcvRes) && ("200 OK" >< rcvRes))
    {
      security_hole(pbPort);
      exit(0);
    }
  }
}
