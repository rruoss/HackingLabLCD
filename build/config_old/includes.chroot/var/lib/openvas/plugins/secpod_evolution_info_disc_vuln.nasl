###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_evolution_info_disc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Evolution Mail Client Information Disclosure Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the local attacker gain sensitive information
  about the victim's mail folders and can view their contents.

  Impact level: Application";

tag_affected = "Evolution Mail Client version 2.26.1 and prior.";
tag_insight = "The flaw is due to Mailer component in Evolution, uses world readable
  permissions for the .evolution directory and some other certain directories
  under .evolution which causes disclosure of sensitive information of the
  user's mail directories and their contents.";
tag_solution = "Upgrade to Evolution Mail Client version 2.30.1 or later
  For further updates refer, http://projects.gnome.org/evolution";
tag_summary = "This host is installed with Evolution for Linux and is prone to
  Information Disclosure Vulnerability.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.900709";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-19 08:03:45 +0200 (Tue, 19 May 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1631");
  script_bugtraq_id(34921);
  script_name("Evolution Mail Client Information Disclosure Vulnerability");
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
  script_summary("Check for the version of Evolution");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_evolution_data_server_detect.nasl");
  script_require_keys("Evolution/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  script_xref(name : "URL" , value : "http://bugzilla.gnome.org/show_bug.cgi?id=581604");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=498648");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=526409");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

# Grep for Evolution Mail Client version 2.26.1 and prior
ver = get_app_version(cpe:"cpe:/a:gnome:evolution", nvt:SCRIPT_OID);
if(version_is_less_equal(version:ver, test_version:"2.26.1")){
  security_warning(0);
}
