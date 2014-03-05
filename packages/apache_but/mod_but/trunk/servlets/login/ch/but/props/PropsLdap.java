/*
 * Created on Jul 26, 2005
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package ch.but.props;

/**
 * @author hobo
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class PropsLdap extends Props {
	  
	private String prefix = "ldap.";
	  
	  
	public PropsLdap() {
		super();
		}
	  
	  public String getFactory() {
	    return _props.getProperty(prefix + "factory").trim();
	  }
	  public String getUrl() {
	    return _props.getProperty(prefix + "url").trim();
	  }
	  public String getAuthType() {
	    return _props.getProperty(prefix + "authType").trim();
	  }
	  public String getPrincipal() {
	    return _props.getProperty(prefix + "principal").trim();
	  }
	  public String getTimeout() {
	    return _props.getProperty(prefix + "timeout").trim();
	  }
	  public String getUsername() {
	    return _props.getProperty(prefix + "username").trim();
	  }
	  public String getPassword() {
	    return _props.getProperty(prefix + "password").trim();
	  }
	  

}
