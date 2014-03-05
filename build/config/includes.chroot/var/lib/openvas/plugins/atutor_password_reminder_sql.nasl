# OpenVAS Vulnerability Test
# $Id: atutor_password_reminder_sql.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ATutor password reminder SQL injection
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote host contains a PHP script vulnerable to a SQL injection 
vulnerability.

Description : 

The remote host is running ATutor, an open source web-based Learning
Content Management System (LCMS) designed with accessibility and
adaptability in mind. 

The remote version of this software contains an input validation flaw in
the 'password_reminder.php' script.  This vulnerability occurs only when
'magic_quotes_gpc' is set to off in the 'php.ini' configuration file.  A
malicious user can exploit this flaw to manipulate SQL queries and steal
any user's password.";

tag_solution = "Upgrade to ATutor 1.5.1 pl1 or later";

if (description) {
  script_id(19765);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2005-2954");
  script_bugtraq_id(14831);

  name = "ATutor password reminder SQL injection";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
 
  summary = "Checks for SQL injection in password_reminder.php";
  script_summary(summary);
 
  script_category(ACT_ATTACK);
  script_family("Web application abuses");

  script_copyright("(C) 2005 Josh Zlatin-Amishav");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://retrogod.altervista.org/atutor151.html");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
      
postdata = string(
  "form_password_reminder=true&",
  "form_email=%27", SCRIPT_NAME, "&",
  "submit=Submit"
);

foreach dir ( cgi_dirs() )
{
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/password_reminder.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (
    "ATutor" >< res &&
    '<input type="hidden" name="form_password_reminder"' >< res
  ) {
    req = string(
      "POST ", dir, "/password_reminder.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    if ( "mysql_fetch_assoc(): supplied argument is not a valid MySQL result resource" >< res) {
      security_hole(port);
      exit(0);
    }
  }
}

