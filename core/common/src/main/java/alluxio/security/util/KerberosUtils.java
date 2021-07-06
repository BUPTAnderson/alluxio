/*
 * The Alluxio Open Foundation licenses this work under the Apache License, version 2.0
 * (the "License"). You may not use this work except in compliance with the License, which is
 * available at www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied, as more fully set forth in the License.
 *
 * See the NOTICE file distributed with this work for information regarding copyright ownership.
 */

package alluxio.security.util;

import alluxio.conf.AlluxioConfiguration;
import alluxio.conf.PropertyKey;
import alluxio.util.CommonUtils;
import alluxio.util.network.NetworkAddressUtils;
import com.google.common.base.Preconditions;
import com.google.common.net.HostAndPort;
import org.apache.zookeeper.server.auth.KerberosName;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * this class is Kerberos Util class.
 */
public final class KerberosUtils {
  static final String JAVA_VENDOR_NAME =
      System.getProperty("java.vendor");
  static final boolean IBM_JAVA = JAVA_VENDOR_NAME.contains("IBM");
  public static final String GSSAPI_MECHANISM_NAME = "GSSAPI";
  public static final String GSSAPI_MECHANISM_ID = "1.2.840.113554.1.2.2";
  public static final String HOSTNAME_PATTERN = "_HOST";

  private static final Logger LOG = LoggerFactory.getLogger(KerberosUtils.class);

  public static final Map<String, String> SASL_PROPERTIES =
      Collections.unmodifiableMap(new HashMap<>());

  /**
   * get the kerberos login module name of current machine.
   * @return kerberos login module name
   */
  public static String getKrb5LoginModuleName() {
    return IBM_JAVA ? "com.ibm.security.auth.module.Krb5LoginModule"
        : "com.sun.security.auth.module.Krb5LoginModule";
  }

  /**
   * get realm.
   * @return the name of realm
   * @throws ClassNotFoundException
   * @throws NoSuchMethodException
   * @throws IllegalArgumentException
   * @throws IllegalAccessException
   * @throws InvocationTargetException
   */
  public static String getDefaultRealm() throws ClassNotFoundException, NoSuchMethodException,
      IllegalArgumentException, IllegalAccessException, InvocationTargetException {
    Class<?> classRef;
    if (System.getProperty("java.vendor").contains("IBM")) {
      classRef = Class.forName("com.ibm.security.krb5.internal.Config");
    } else {
      classRef = Class.forName("sun.security.krb5.Config");
    }
    Method getInstanceMethod = classRef.getMethod("getInstance", new Class[0]);
    Object kerbConf = getInstanceMethod.invoke(classRef, new Object[0]);
    Method getDefaultRealmMethod = classRef.getDeclaredMethod("getDefaultRealm", new Class[0]);
    return (String) getDefaultRealmMethod.invoke(kerbConf, new Object[0]);
  }

  /**
   * @param conf current conf
   * @param processType process type
   * @return the name of kerberos service name
   */
//  public static String getKerberosServiceName(AlluxioConfiguration conf,
//      CommonUtils.ProcessType processType) {
//    switch (processType) {
//      case MASTER:
//      case WORKER:
//        return getServiceName(conf);
//      case JOB_MASTER:
//      case JOB_WORKER:
//        return getJobServiceName(conf);
//      case CLIENT:
//      case PROXY:
//      default:
//        throw new RuntimeException(processType.name() + " not support.");
//    }
//  }

  /**
   * @param conf current conf
   * @param remoteServiceType service type
   * @return kerberos service name
   */
//  public static String getKerberosServiceName(AlluxioConfiguration conf,
//      ServiceType remoteServiceType) {
//    if (remoteServiceType == ServiceType.JOB_MASTER_CLIENT_SERVICE
//        || remoteServiceType == remoteServiceType.JOB_MASTER_WORKER_SERVICE) {
//      return getJobServiceName(conf);
//    } else {
//      return getServiceName(conf);
//    }
//  }

  /**
   * @param conf current conf
   * @return service name
   */
  public static String getServiceName(AlluxioConfiguration conf) {
    if (!conf.isSet(PropertyKey.SECURITY_KERBEROS_SERVER_PRINCIPAL)) {
      throw new RuntimeException(PropertyKey.SECURITY_KERBEROS_SERVER_PRINCIPAL
          .toString() + " must be set.");
    }
    String principal = conf.get(PropertyKey.SECURITY_KERBEROS_SERVER_PRINCIPAL);
    try {
      KerberosName kerberosName = new KerberosName(principal);
      return kerberosName.getServiceName();
    } catch (IllegalArgumentException e) {
      throw new RuntimeException("Illegal Kerberos principal "
          + PropertyKey.SECURITY_KERBEROS_SERVER_PRINCIPAL.toString() + ": " + principal);
    }
  }

  /**
   * @param conf current conf
   * @return job service name
   */
//  public static String getJobServiceName(AlluxioConfiguration conf) {
//    if (!conf.isSet(PropertyKey.SECURITY_KERBEROS_JOB_SERVER_PRINCIPAL)) {
//      throw new RuntimeException(PropertyKey.SECURITY_KERBEROS_JOB_SERVER_PRINCIPAL
//              .toString() + " must be set.");
//    }
//    String principal = conf.get(PropertyKey.SECURITY_KERBEROS_JOB_SERVER_PRINCIPAL);
//    try {
//      KerberosName kerberosName = new KerberosName(principal);
//      return kerberosName.getServiceName();
//    } catch (IllegalArgumentException e) {
//      throw new RuntimeException("Illegal Kerberos principal "
//          + PropertyKey.SECURITY_KERBEROS_JOB_SERVER_PRINCIPAL.toString() + ": " + principal);
//    }
//  }

  /**
   * @param conf current conf
   * @return unified instance name
   */
//  public static String maybeGetKerberosUnifiedInstanceName(AlluxioConfiguration conf) {
//    if (!conf.isSet(PropertyKey.SECURITY_KERBEROS_UNIFIED_INSTANCE_NAME)) {
//      return null;
//    }
//    String unifedInstance = conf.get(PropertyKey.SECURITY_KERBEROS_UNIFIED_INSTANCE_NAME);
//    if (unifedInstance.isEmpty()) {
//      return null;
//    }
//    return unifedInstance;
//  }

  /**
   * @return {@link GSSCredential} from JGSS
   * @throws GSSException
   */
//  public static GSSCredential getCredentialFromJGSS() throws GSSException {
//    GSSManager gssManager = GSSManager.getInstance();
//    Oid krb5Mechanism = new Oid(GSSAPI_MECHANISM_ID);
//    if (CommonUtils.isAlluxioServer()) {
//      return gssManager.createCredential(null, 0, krb5Mechanism, 2);
//    }
//    return gssManager.createCredential(null, 0, krb5Mechanism, 1);
//  }

  /**
   * @return kerberos principal from JGSS
   * @throws GSSException
   */
  private static String getKerberosPrincipalFromJGSS() throws GSSException {
    GSSManager gssManager = GSSManager.getInstance();
    Oid krb5Mechanism = new Oid(GSSAPI_MECHANISM_ID);
    GSSCredential cred = gssManager.createCredential(null, 0, krb5Mechanism, 1);
    String retval = cred.getName().toString();
    cred.dispose();
    return retval;
  }

  /**
   * @param subject a kerberos subject
   * @return {@link KerberosName} extract from subject
   * @throws LoginException
   */
  public static KerberosName extractKerberosNameFromSubject(Subject subject)
      throws LoginException {
    if (Boolean.getBoolean("sun.security.jgss.native")) {
      try {
        String principal = getKerberosPrincipalFromJGSS();
        Preconditions.checkNotNull(principal);
        return new KerberosName(principal);
      } catch (GSSException e) {
        throw new LoginException("Failed to get the Kerberos principal from JGSS." + e);
      }
    }

    Set<KerberosPrincipal> krb5Principals = subject.getPrincipals(KerberosPrincipal.class);
    if (!krb5Principals.isEmpty()) {
      return new KerberosName((krb5Principals.iterator().next()).toString());
    }
    throw new LoginException("Failed to get the Kerberos principal from the login subject.");
  }

  /**
   * @param subject specified subject
   * @return login subject
   */
//  public static Subject getLoginSubject(Subject subject) {
//    Set<User> users = subject.getPrincipals(User.class);
//    if (users.isEmpty()) {
//      return subject;
//    }
//    User user = users.iterator().next();
//    Subject loginSubject = user.getLoginSubject();
//    if (loginSubject == null) {
//      return subject;
//    }
//    return loginSubject;
//  }

  /**
   * @param subject specified subject
   * @return login subject
   */
  public static KerberosTicket extractOriginalTGTFromSubject(Subject subject) {
    if (subject == null) {
      return null;
    }
    Set<KerberosTicket> tickets = subject.getPrivateCredentials(KerberosTicket.class);
    for (KerberosTicket ticket : tickets) {
      KerberosPrincipal serverPrincipal = ticket.getServer();
      if (serverPrincipal != null) {
        if (serverPrincipal.getName().equals("krbtgt/" + serverPrincipal
            .getRealm() + "@" + serverPrincipal.getRealm())) {
          return ticket;
        }
      }
    }
    return null;
  }

  /**
   * @param subject specified subject
   * @param addr address of token
   * @return token
   */
//  public static Token<DelegationTokenIdentifier> getDelegationToken(Subject subject, String addr) {
//    LOG.debug("getting alluxio delegation tokens for subject: {}", subject);
//    if (subject == null) {
//      return null;
//    }
//    synchronized (subject) {
//      Set<Credentials> allCredentials = subject.getPrivateCredentials(Credentials.class);
//      if (allCredentials.isEmpty()) {
//        LOG.debug("no Alluxio credentials found.");
//        return null;
//      }
//      Credentials credentials = allCredentials.iterator().next();
//      Token<DelegationTokenIdentifier> token = credentials.getToken(addr);
//      LOG.debug("got alluxio delegation token: {}", token);
//      return token;
//    }
//  }

  /**
   * @param address address
   * @param conf specified conf
   * @return token service name
   */
  public static String getTokenServiceName(InetSocketAddress address, AlluxioConfiguration conf) {
    return HostAndPort.fromParts(address.getHostString(), address.getPort()).toString();
  }

  /**
   * @param address specified address
   * @return resolved address
   */
  public static InetSocketAddress getResolvedAddress(InetSocketAddress address) {
    if (address.isUnresolved()) {
      return new InetSocketAddress(address.getHostName(), address.getPort());
    }
    return address;
  }

  /**
   * @param principalConfig principal conf
   * @param conf alluxio conf
   * @param processType process type
   * @return server principal
   */
  public static String getServerPrincipal(String principalConfig, AlluxioConfiguration conf,
                                          CommonUtils.ProcessType processType) {
    if (principalConfig == null || principalConfig.isEmpty()) {
      return principalConfig;
    }
    InetSocketAddress inetSocketAddress = null;
    switch (processType) {
      case MASTER:
        inetSocketAddress = NetworkAddressUtils.getConnectAddress(
            NetworkAddressUtils.ServiceType.MASTER_RPC, conf);
        break;
      case WORKER:
        inetSocketAddress = NetworkAddressUtils.getConnectAddress(
            NetworkAddressUtils.ServiceType.WORKER_RPC, conf);
        break;
      case JOB_MASTER:
        inetSocketAddress = NetworkAddressUtils.getConnectAddress(
            NetworkAddressUtils.ServiceType.JOB_MASTER_RPC, conf);
        break;
      case JOB_WORKER:
        inetSocketAddress = NetworkAddressUtils.getConnectAddress(
            NetworkAddressUtils.ServiceType.JOB_WORKER_RPC, conf);
        break;
      default:
        LOG.warn("current process is not a server process."
            + "principalConfig:{} will not be resolved.", principalConfig);
        return principalConfig;
    }

    String hostname = inetSocketAddress.getHostName();
    LOG.info("resolve server hostname={}", hostname);

    String[] components = getComponents(principalConfig);
    if (components == null || components.length != 3
        || !components[1].equals(HOSTNAME_PATTERN)) {
      return principalConfig;
    } else {
      try {
        return replacePattern(components, hostname);
      } catch (IOException e) {
        LOG.error("resolve server principalConfig error, cause:{}", e.getMessage());
        return principalConfig;
      }
    }
  }

  /**
   * @param principalConfig represent a principal
   * @return string array of principal
   */
  private static String[] getComponents(String principalConfig) {
    if (principalConfig == null) {
      return null;
    }
    return principalConfig.split("[/@]");
  }

  /**
   * @param components of a principal
   * @param hostname hostname
   * @return replaced principal
   * @throws IOException
   */
  private static String replacePattern(String[] components, String hostname)
      throws IOException {
    String fqdn = hostname;
    if (fqdn == null || fqdn.isEmpty() || fqdn.equals("0.0.0.0")) {
      fqdn = InetAddress.getLocalHost().getCanonicalHostName();
    }
    return components[0] + "/" + fqdn.toLowerCase(Locale.ENGLISH) + "@" + components[2];
  }
}
