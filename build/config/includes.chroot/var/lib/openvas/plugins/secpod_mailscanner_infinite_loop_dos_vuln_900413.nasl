##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mailscanner_infinite_loop_dos_vuln_900413.nasl 16 2013-10-27 13:09:52Z jan $
# Description: MailScanner Infinite Loop Denial of Service Vulnerability
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in a
  crafted message and it can lead to system crash through high CPU resources.
  Impact Level: Application";
tag_affected = "MailScanner version prior to 4.73.3-1 on all Linux platforms.";
tag_insight = "This error is due to an issue in 'Clean' Function in message.pm.";
tag_solution = "Upgrade to the latest MailScanner version 4.73.3-1
  http://www.mailscanner.info/downloads.html";
tag_summary = "This host is installed with MailScanner and is prone to Denial of
  Service vulnerability.";

if(description)
{
  script_id(900413);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-10 08:20:26 +0100 (Wed, 10 Dec 2008)");
  script_bugtraq_id(32514);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("MailScanner Infinite Loop Denial of Service Vulnerability");
  script_summary("Check for vulnerable version of MailScanner");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/50268");
  script_xref(name : "URL" , value : "http://secunia.com/Advisories/32915");

  script_description(desc);
  script_dependencies("gather-package-list.nasl");
  script_require_keys("ssh/login/uname");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");

if("Linux" >!< get_kb_item("ssh/login/uname")){
  exit(0);
}

sock = ssh_login_or_reuse_connection();
if(sock)
{
  ver = ssh_cmd(socket:sock, cmd:"MailScanner -v", timeout:120);
  ssh_close_connection();
  if("MailScanner" >< ver){
    # Grep for MailScanner version prior to 4.73.3
    pattern = "MailScanner version ([0-3](\..*)|4(\.[0-6]?[0-9](\..*)?|\.7" +
              "[0-2](\..*)?|\.73\.[0-3]))($|[^.0-9])";
    if(egrep(pattern:pattern, string:ver)){
      security_warning(0);
    }
  }
}
