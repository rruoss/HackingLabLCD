###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_asp_dotnet_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft ASP.NET Cross-Site Scripting Vulnerability
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
tag_impact = "Successful exploitation could allow attackers to conduct cross-site scripting
  attacks against the form control via vectors related to an attribute.";
tag_affected = "Microsoft ASP.NET version 2.0 and prior.";
tag_insight = "The flaw is due to error in the handling of 'HtmlContainerControl', which
  does not prevent setting the 'InnerHtml' property on a control that inherits
  from HtmlContainerControl when processing the vectors related to an attribute.";
tag_solution = "No solution or patch is available as of 04th Jun, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/downloads/details.aspx?displaylang=en";
tag_summary = "The host is running Microsoft ASP .NET and is prone to Cross-Site
  Scripting Vulnerability.";

if(description)
{
  script_id(801342);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-2084");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Microsoft ASP.NET Cross-Site Scripting vulnerability");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/394300.php");
  script_xref(name : "URL" , value : "https://launchpad.net/bugs/cve/2010-2084");
  script_xref(name : "URL" , value : "http://www.communities.hp.com/securitysoftware/blogs/spilabs/archive/2010/03/30/configuration-is-half-the-battle-asp-net-and-cross-site-scripting.aspx");

  script_description(desc);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_summary("Check the version of Microsoft ASP .NET");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("remote-detect-MSdotNET-version.nasl");
  script_require_ports("Services/www");
  script_require_keys("dotNET/install", "aspNET/installed", "aspNET/version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Get the version from KB
dotNet = get_kb_item("dotNET/install");
if(!dotNet){
  exit(0);
}

apsdotNet = get_kb_item("aspNET/installed");
if(!aspdotNet){
  exit(0);
}

aspdotnetVer = get_kb_item("aspNET/version");
if(!dotNet){
  exit(0);
}

## Check for Microsoft ASP.NET version less than or equal 2.0
if(version_is_less_equal(version:aspdotnetVer, test_version:"2.0")){
   security_warning(0);
}
