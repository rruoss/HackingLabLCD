###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f3site_mult_lfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# F3Site 'GLOBALS[nlang]' Parameter Multiple Local File Include Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow remote attackers to obtain sensitive
  information or execute arbitrary code on the vulnerable Web Server.
  Impact Level: Application.";
tag_affected = "F3Site 2009 and prior.";
tag_insight = "The flaw is due to error in 'mod/poll.php' and 'mod/new.php' which
  are not properly sanitising user supplied input data via 'GLOBALS[nlang]'
  parameter.";
tag_solution = "Upgrade to F3Site 2010 or later,
  For updates refer to http://dhost.info/compmaster/index.php";
tag_summary = "The host is running F3Site and is prone to multiple local file include
  Vulnerabilities.";

if(description)
{
  script_id(800415);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4435");
  script_bugtraq_id(37408);
  script_name("F3Site 'GLOBALS[nlang]' Parameter Multiple Local File Include Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54908");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10536");

  script_description(desc);
  script_summary("Check for the version of F3Site");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
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

f3sPort = get_http_port(default:80);
if(!f3sPort){
  exit(0);
}

foreach path (make_list("/", "/F3Site/SYSTEM", "/F3Site", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/index.php"), port:f3sPort);
  rcvRes = http_send_recv(port:f3sPort, data:sndReq);
  if("F3Site" >< rcvRes)
  {
    f3sVer = eregmatch(pattern:"F3Site ([0-9.]+)",string:rcvRes);
    if(f3sVer[1] != NULL)
    {
      if(version_is_less_equal(version:f3sVer[1], test_version:"2009")){
        security_hole(f3sPort);
      }
    }
  }
}

