##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nakid_cms_rfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Nakid CMS 'core[system_path]' Parameter Remote File Inclusion Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to include malicious PHP
  scripts and execute arbitrary commands with the privileges of the web server.
  Impact Level: Application.";
tag_affected = "Nakid CMS version 0.5.2 and 0.5.1";

tag_insight = "The flaw is caused by an input validation error in the '/modules/catalog/upload_photo.php'
  script when processing the 'core[system_path]' parameter.";
tag_solution = "No solution or patch is available as of 23rd June 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.nakid.org/";
tag_summary = "This host is running Nakid CMS and is prone to remote file inclusion
  vulnerability.";

if(description)
{
  script_id(902082);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-2358");
  script_bugtraq_id(40882);
  script_name("Nakid CMS 'core[system_path]' Parameter Remote File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40174");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59453");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/13889/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1498");

  script_description(desc);
  script_summary("Check Nakid CMS is vulnerable to RFI");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_nakid_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");

## Get HTTP Port
ncPort = get_http_port(default:80);
if(!ncPort){
  exit(0);
}

## Get version from KB
ncVer = get_kb_item("www/" + ncPort + "/Nakid/CMS/Ver");
if(!ncVer){
 exit(0);
}

ncVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ncVer);
if(!isnull(ncVer[2]))
{
  # Try expliot and check response
  sndReq = http_get(item:string(ncVer[2], "/modules/catalog/upload_photo.php?" +
                                  "core[system_path]=OpenVAS_RFI.php"), port:ncPort);
  rcvRes = http_send_recv(port:ncPort, data:sndReq);
  if("OpenVAS_RFI.php" >< rcvRes && "failed to open stream" >< rcvRes){
    security_hole(ncPort);
  }
}
