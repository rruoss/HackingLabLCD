# OpenVAS Vulnerability Test
# $Id: nikto.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Nikto (NASL wrapper)
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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
tag_summary = "This plugin uses nikto(1) to find weak CGI scripts
and other known issues regarding web server security.
See the preferences section for configuration options.";

if(description)
{
 script_id(14260);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 name = "Nikto (NASL wrapper)";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Assess web server security with Nikto";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 family = "Web application abuses";
 script_family(family);

 script_dependencies("find_service.nasl", "httpver.nasl", "logins.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);

 script_add_preference(name:"Force scan even without 404s",
                       type:"checkbox", value:"no");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

nikto = "";

if (  find_in_path("nikto.pl")  )
{
	nikto = "nikto.pl";
}
else if (  find_in_path("nikto")  )
{
	nikto = "nikto";	
}
else
{
    text = 'Nikto could not be found in your system path.\n';
    text += 'OpenVAS was unable to execute Nikto and to perform the scan you
requested.\nPlease make sure that Nikto is installed and that nikto.pl or nikto is
available in the PATH variable defined for your environment.';
    log_message(port: port, data: text);
    exit(0);
}

user = get_kb_item("http/login");
pass = get_kb_item("http/password");
ids = get_kb_item("/Settings/Whisker/NIDS");

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0);

# Nikto will generate many false positives if the web server is broken
no404 = get_kb_item("www/no404/" + port);
if ( no404 )
{
  text = 'The target server did not return 404 on requests for non-existent pages.\n';
  p = script_get_preference("Force scan even without 404s");
  if ("no" >< p)
  {
    text += 'This scan has not been executed since Nikto is prone to reporting many false positives in this case.\n';
    text += 'If you wish to force this scan, you can enable it in the Nikto preferences in your client.\n';
    security_note(port: port, data: text);
    exit(0);
  }
  else
  {
    text += 'You have requested to force this scan. Please be aware that Nikto is very likely to report false\n';
    text += 'positives under these circumstances. You need to check whether the issues reported by Nikto are\n';
    text += 'real threats or were caused by otherwise correct configuration on the target server.\n';
    security_note(port: port, data: text);
  }
}

i = 0;
argv[i++] = nikto;

httpver = get_kb_item("http/"+port);
if (httpver == "11")
{
  argv[i++] = "-vhost";
  argv[i++] = get_host_name();
}

# disable interactive mode
# see http://attrition.org/pipermail/nikto-discuss/2010-September/000319.html
argv[i++] = "-ask";
argv[i++] = "no";
argv[i++] = "-h"; argv[i++] = get_host_ip();
argv[i++] = "-p"; argv[i++] = port;

encaps = get_port_transport(port);
if (encaps > 1) argv[i++] = "-ssl";

if (idx && idx != "X")
{
  argv[i++] = "-evasion";
  argv[i++] = ids[0];
}

if (user)
{
  if (pass)
    s = strcat(user, ':', pass);
  else
    s = user;
  argv[i++] = "-id";
  argv[i++] = s;
}

r = pread(cmd: nikto, argv: argv, cd: 1);
if (! r) exit(0);	# error

report = 'Here is the Nikto report:\n';
foreach l (split(r))
{
  l = ereg_replace(string: l, pattern: '^[ \t]+', replace: '');
  if (l[0] == '+' || l[0] == '-' || ! match(pattern: "ERROR*", string: l))
    report += l;
}

security_note(port: port, data: report);
