###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotclear_file_upload_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Dotclear Arbitrary File Upload Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation allows remote authenticated users to upload and
  execute arbitrary PHP code.
  Impact Level: Application";
tag_affected = "Dotclear versions prior to 2.2.3";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed
  via the 'updateFile()' function in inc/core/class.dc.media.php, which
  allows attackers to execute arbitrary PHP code by uploading a PHP file.";
tag_solution = "Upgrade to Dotclear version 2.2.3 or later,
  For updates refer to http://dotclear.org/download";
tag_summary = "This host is running Dotclear and is prone to arbitrary file upload
  vulnerability.";

if(description)
{
  script_id(802207);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-17 11:16:31 +0200 (Fri, 17 Jun 2011)");
  script_cve_id("CVE-2011-1584");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Dotclear Arbitrary File Upload Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44049");
  script_xref(name : "URL" , value : "http://dev.dotclear.org/2.0/changeset/2:3427");
  script_xref(name : "URL" , value : "http://dotclear.org/blog/post/2011/04/01/Dotclear-2.2.3");

  script_description(desc);
  script_summary("Check for the version of Dotclear");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/dotclear", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if(egrep(pattern:"Powered by.*>Dotclear<", string:res))
  {
    ## Get Version from CHANGELOG
    req = http_get(item:string(dir, "/CHANGELOG"), port:port);
    res = http_send_recv(port:port, data:req);
    ver = eregmatch(pattern:"Dotclear ([0-9.]+)", string:res);
    if(ver[1] == NULL) {
      exit(0);
    }

    ## Check for Dotclear versions prior to 2.2.3
    if(version_is_less(version:ver[1], test_version:"2.2.3"))
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
