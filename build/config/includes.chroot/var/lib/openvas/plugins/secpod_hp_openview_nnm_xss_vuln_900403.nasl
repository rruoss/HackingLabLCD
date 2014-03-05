##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_openview_nnm_xss_vuln_900403.nasl 16 2013-10-27 13:09:52Z jan $
# Description: HP OpenView Network Node Manager XSS Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to execute arbitrary codes.
  Impact Level: Application";
tag_solution = "Apply patches or upgrade to the latest version.
  http://welcome.hp.com/country/us/en/support.html

  ******
  NOTE: Windows platform is not affected.
  ******";

tag_affected = "HP OpenView Network Node Manager versions 7.01, 7.51 and 7.53 on HP-UX, Linux,
  and Solaris.";
tag_insight = "The flaws are due to errors in HP OpenView NNM 'Network Node Manager'
  program.";
tag_summary = "This host is running HP OpenView Network Node Manager, which is prone to 
  Cross Site Scripting vulnerability.";


if(description)
{
  script_id(900403);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_bugtraq_id(26838,27237);
  script_cve_id("CVE-2007-5000","CVE-2007-6388");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_name("HP OpenView Network Node Manager XSS Vulnerability");
  script_summary("Check for version of HP OpenView Network Node Manager");
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
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://secunia.com/Advisories/32800");
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2007-5000");
  exit(0);
}


include("http_func.inc");

port = 7510;
if(get_port_state(port))
{
  request = http_get(item:"/topology/home", port:port);
  response = http_send_recv(port:port, data:request);

  if("hp OpenView Network Node Manager" >< response &&
     egrep(pattern:"Copyright \(c\).* Hewlett-Packard", string:response) &&
     ereg(pattern:"^HTTP/.* 200 OK", string:response))
  {
    if(egrep(pattern:"NNM Release B\.07\.(01|51|53)", string:response)){
      security_warning(port);
    }
  }
}
