/*
 * Created on Jul 26, 2005
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package ch.but.repository;

import ch.but.props.PropsLdap;
import ch.but.log.Util;


import java.util.Enumeration;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.servlet.http.HttpServletRequest;

/**
 * @author hobo
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class UserInfoBean {

          //private static final String LDAPERROR_ALREADY_EXISTS = "LDAP: error code 68";
          //private static final int LDAP_OK = 1;
          //private static final int LDAP_USER_ALREADY_EXISTS = 2;
          //private static final int LDAP_ERROR = 0;

          private static final PropsLdap _propsLdap = new PropsLdap();

          //private String _username;


          @SuppressWarnings({"unchecked"})
		public static boolean checkPassword(HttpServletRequest request, String username, String password) {

            Hashtable env = new Hashtable();
            env.put(Context.INITIAL_CONTEXT_FACTORY, _propsLdap.getFactory());
            env.put(Context.PROVIDER_URL, _propsLdap.getUrl());
            env.put(Context.SECURITY_AUTHENTICATION, _propsLdap.getAuthType());
            env.put(Context.SECURITY_PRINCIPAL, "cn=" + username + "," + _propsLdap.getPrincipal());
            env.put(Context.SECURITY_CREDENTIALS, password);
            env.put("com.sun.jndi.ldap.connect.timeout", _propsLdap.getTimeout());

            Enumeration e = env.keys();

            while (e.hasMoreElements()) {
              Object obj = e.nextElement();
              Util.log(request.getHeader("unique_id") + "\t'" + "checkPassword\t" + (String) obj + "' = '" + env.get(obj) + "'");
              //Util.log("'" + (String) obj + "' = '" + env.get(obj) + "'");
            }

            // Create the initial context
            try {
              DirContext ctx = new InitialDirContext(env);
              ctx.close();
              return true;
            }
            catch (NamingException ne) {
              if (ne.getExplanation() != null)
            	Util.log(request.getHeader("unique_id") + "\t" + ne.getExplanation(), ne);
                //Util.log(ne.getExplanation(), ne);
              else
                ne.printStackTrace();
              return false;
            }
          }

}
