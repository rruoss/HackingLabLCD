#############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mdaemon_script_insertion_vuln_900405.nasl 16 2013-10-27 13:09:52Z jan $
# Description: MDaemon Server WordClient Script Insertion Vulnerability
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
tag_impact = "Attacker can execute malicious arbitrary codes in the email body.
  Impact Level: Application.";
tag_affected = "MDaemon Server version prior to 10.0.2.";
tag_insight = "This vulnerability is due to input validation error in 'HTML tags' in
  emails are not properly filtered before displaying. This can be exploited when
  the malicious email is viewed.";
tag_solution = "Upgrade to the latest version 10.0.2.
  http://www.altn.com/Downloads/FreeEvaluation";
tag_summary = "This host is installed with MDaemon and is prone to script insertion
  vulnerability.";

if(description)
{
  script_id(900405);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-6967");
 script_bugtraq_id(32355);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_name("MDaemon Server WordClient Script Insertion Vulnerability");
  script_summary("Check for vulnerable version of MDaemon");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32142");
  script_xref(name : "URL" , value : "http://files.altn.com/MDaemon/Release/RelNotes_en.txt");

  script_description(desc);
  script_dependencies("find_service.nasl");
  script_require_ports("Services/smtp", 25);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port){
  port = 25;
}

if(get_port_state(port))
{
  response = get_smtp_banner(port);
  if("MDaemon" >< response)
  {
    #Grep for WorldClient version 10.0.1 or prior
    if(egrep(pattern:"MDaemon .* [0-9]\..*|10\.0\.[01]" , string:response)){
      security_warning(port);
    }
  }
}
