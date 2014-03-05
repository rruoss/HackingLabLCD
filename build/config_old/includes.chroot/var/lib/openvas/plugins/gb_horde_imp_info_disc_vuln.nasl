###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_imp_info_disc_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Horde IMP Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation allows remote attackers to determine the network location
  of the webmail user by logging DNS requests.
  Impact Level: Application.";
tag_affected = "Horde IMP version 4.3.6 and prior.";
tag_insight = "The flaw exists when DNS prefetching of domain names contained in links within
  e-mail messages.";
tag_solution = "No solution or patch is available as of 03rd, February 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.horde.org/download/";
tag_summary = "This host is running Horde IMP and is prone to Information Disclosure
  vulnerability";

if(description)
{
  script_id(800288);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-0463");
  script_name("Horde IMP Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://bugs.horde.org/ticket/8836");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2010-0463");
  script_xref(name : "URL" , value : "https://secure.grepular.com/DNS_Prefetch_Exposure_on_Thunderbird_and_Webmail");

  script_description(desc);
  script_summary("Check for the version of Horde IMP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("horde_detect.nasl");
  script_family("General");
  script_require_ports("Services/www", 80);
  script_require_keys("horde/installed");
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

hordePort = get_http_port(default:80);
if(!hordePort){
  exit(0);
}

hordeVer = get_kb_item("www/" + hordePort + "/horde");
if(!hordeVer){
  exit(0);
}

foreach dir (make_list("/horde/imp", "/Horde/IMP", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/test.php"), port:hordePort );
  rcvRes = http_keepalive_send_recv(port:hordePort, data:sndReq);

  if("imp" >< rcvRes || "IMP" >< rcvRes)
  {
    impVer = eregmatch(pattern:"IMP: H3 .([0-9.]+)" , string:rcvRes);
    if(impVer[1] != NULL)
    {
      if(version_is_less_equal(version:impVer[1], test_version:"4.3.6"))
      {
        security_warning(hordePort);
        exit(0);
      }
    }
  }
}
