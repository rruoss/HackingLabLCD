###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_awstats_xss_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# AWStats awstats.pl XSS Vulnerability - Dec08
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful attack could lead to execution of arbitrary HTML and
  script code in the context of an affected site.
  Impact Level: Application

  NOTE: This issue exists because of an incomplete fix for CVE-2008-3714.";

tag_solution = "Update to higher Version or Apply patches from,
  http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=495432#21

  *****
  NOTE : Ignore this warning, if above mentioned patch is applied already.
  *****";

tag_affected = "AWStats 6.8 and earlier.";
tag_insight = "The flaw is due to query_string parameter in awstats.pl which is not
  properly sanitized before being returned to the user.";
tag_summary = "The host is running AWStats, which is prone to XSS Vulnerability.";

if(description)
{
  script_id(800151);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-09 13:27:23 +0100 (Tue, 09 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5080");
  script_name("AWStats awstats.pl XSS Vulnerability - Dec08");
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

  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=474396");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=495432");

  script_description(desc);
  script_summary("Check for the Version of AWStats");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "impact" , value : tag_impact);
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

foreach dir (make_list("/awstats/wwwroot/cgi-bin", cgi_dirs()))
{
  sndReq = http_get(item: dir + "/awstats.pl", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);

  if(rcvRes == NULL){
    exit(0);
  }

  if("Advanced Web Statistics" >< rcvRes)
  {
    awVer = eregmatch(pattern:"AWStats ([0-9.]+)", string:rcvRes);
    if(awVer[1] != NULL && version_is_less_equal(version:awVer[1],
                                                 test_version:"6.8")){
     security_warning(port);
    }
    exit(0);
  }
}
