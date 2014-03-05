###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fuzzylime_cms_local_file_inc_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# fuzzylime cms code/track.php Local File Inclusion Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will cause inclusion and execution of arbitrary
  files from local resources via directory traversal attacks.
  Impact Level: Application";
tag_affected = "fuzzylime cms version 3.03 and prior.";
tag_insight = "The flaw is caused due improper handling of input passed to p parameter
  in code/track.php file when the url, title and excerpt form parameters
  are set to non-null values.";
tag_solution = "No solution or patch is available as of 12th December, 2008. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://cms.fuzzylime.co.uk/st/front/index/";
tag_summary = "The host is running fuzzylime CMS and is prone to Local File
  Inclusion vulnerability.";

if(description)
{
  script_id(800314);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-15 15:44:51 +0100 (Mon, 15 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-5291");
  script_bugtraq_id(32475);
  script_name("fuzzylime cms code/track.php Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32865");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7231");

  script_description(desc);
  script_summary("Check for the Version of fuzzylime cms");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach path (make_list("/fuzzylime/_cms303", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/docs/readme.txt"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);
  if(rcvRes == NULL){
    exit(0);
  }

  if("fuzzylime (cms)" >< rcvRes)
  {
    cmsVer = eregmatch(pattern:"v([0-9.]+)", string:rcvRes);
    if(cmsVer[1] != NULL)
    {
      # Grep version 3.03 and prior
      if(version_is_less_equal(version:cmsVer[1], test_version:"3.03")){
        security_hole(port);
      }
    }
    exit(0);
  }
}
