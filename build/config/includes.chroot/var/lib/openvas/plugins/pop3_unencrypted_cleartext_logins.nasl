# OpenVAS Vulnerability Test
# $Id: pop3_unencrypted_cleartext_logins.nasl 17 2013-10-27 14:01:43Z jan $
# Description: POP3 Unencrypted Cleartext Logins
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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
tag_summary = "The remote host is running a POP3 daemon that allows cleartext logins over
unencrypted connections.  An attacker can uncover user names and
passwords by sniffing traffic to the POP3 daemon if a less secure
authentication mechanism (eg, USER command, AUTH PLAIN, AUTH LOGIN) is
used.";

tag_solution = "Contact your vendor for a fix or encrypt traffic with SSL /
TLS using stunnel.";

if (description) {
  script_id(15855);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");

  script_xref(name:"OSVDB", value:"3119");

  name = "POP3 Unencrypted Cleartext Logins";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);

  summary = "Checks if POP3 daemon allows unencrypted cleartext logins";
  script_summary(summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "General";
  script_family(family);

  script_dependencies("find_service.nasl", "global_settings.nasl", "logins.nasl");
  script_require_ports("Services/pop3", 110);
  script_exclude_keys("pop3/false_pop3");
  script_require_keys("pop3/login", "pop3/password");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.ietf.org/rfc/rfc2222.txt");
  script_xref(name : "URL" , value : "http://www.ietf.org/rfc/rfc2595.txt");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# nb: non US ASCII characters in user and password must be 
#     represented in UTF-8.
user = get_kb_item("pop3/login");
pass = get_kb_item("pop3/password");
if (!user || !pass) {
  if (log_verbosity > 1) display("pop3/login and/or pop3/password are empty; ", SCRIPT_NAME, " skipped!\n");
  exit(1);
}

if (get_kb_item("pop3/false_pop3")) exit(0);
port = get_kb_item("Services/pop3");
if (!port) port = 110;
debug_print("checking if POP3 daemon on port ", port, " allows unencrypted cleartext logins.");
if (!get_port_state(port)) exit(0);
# nb: skip it if traffic is encrypted.
encaps = get_kb_item("Transports/TCP/" + port);
if (encaps > 1) exit(0);

# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);

# Read banner.
s = recv_line(socket:soc, length:1024);
if (!strlen(s)) {
  close(soc);
  exit(0);
}
s = chomp(s);
debug_print("S: '", s, "'.");

# Try to determine server's capabilities.
c = "CAPA";
debug_print("C: '", c, "'.");
send(socket:soc, data:string(c, "\r\n"));
caps = "";
s = recv_line(socket:soc, length:1024);
s = chomp(s);
debug_print("S: '", s, "'.");
if (s =~ "^\+OK ") {
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    debug_print("S: '", s, "'.");
    if (s =~ "^\.$") break;
    caps = string(caps, s, "\n");
  }
}

# Try to determine if problem exists from server's capabilities; 
# otherwise, try to actually log in.
done = 0;
if (egrep(string:caps, pattern:"(SASL (PLAIN|LOGIN)|USER)", icase:TRUE)) {
  security_note(port);
  done = 1;
}
if (!done) {
  # nb: there's no way to distinguish between a bad username / password
  #     combination and disabled unencrypted logins. This makes it 
  #     important to configure the scan with valid POP3 username /
  #     password info.

  # - try the PLAIN SASL mechanism.
  c = "AUTH PLAIN";
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);
  s = chomp(s);
  debug_print("S: '", s, "'.");
  if (s =~ "^\+") {
    c = base64(str:raw_string(0, user, 0, pass));
    debug_print("C: '", c, "'.");
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      debug_print("S: '", s, "'.");
      m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }
  }
  # nb: the obsolete LOGIN SASL mechanism is also dangerous. Since the
  #     PLAIN mechanism is required to be supported, though, I won't
  #     bother to check for the LOGIN mechanism.

  # If that didn't work, try USER command.
  if (isnull(resp)) {
    c = string("USER ", user);
    debug_print("C: '", c, "'.");
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      debug_print("S: '", s, "'.");
      m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }

    if (resp && resp =~ "OK") {
      c = string("PASS ", pass);
      debug_print("C: '", c, "'.");
      send(socket:soc, data:string(c, "\r\n"));
      while (s = recv_line(socket:soc, length:1024)) {
        s = chomp(s);
        debug_print("S: '", s, "'.");
        m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
        if (!isnull(m)) {
          resp = m[1];
          break;
        }
        resp = "";
      }
    }
  }

  # If successful, unencrypted logins are possible.
  if (resp && resp =~ "OK") security_note(port);
}

# Logout.
c = "QUIT";
debug_print("C: '", c, "'.");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  debug_print("S: '", s, "'.");
  m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);
