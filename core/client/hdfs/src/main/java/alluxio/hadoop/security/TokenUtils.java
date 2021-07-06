package alluxio.hadoop.security;

import alluxio.conf.AlluxioConfiguration;
import alluxio.conf.PropertyKey;
import alluxio.util.ConfigurationUtils;
import com.google.common.base.Preconditions;
import net.jcip.annotations.ThreadSafe;
import org.apache.hadoop.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

/**
 * alluxio token utils.
 */
@ThreadSafe
public class TokenUtils {
  private static final Logger LOG = LoggerFactory.getLogger(TokenUtils.class);

  public static String buildTokenService(URI uri, AlluxioConfiguration conf) {
    if (ConfigurationUtils.isHaMode(conf)) {
      return uri.toString();
    }
    if (uri.getAuthority() == null) {
      Preconditions.checkArgument(conf.isSet(PropertyKey.MASTER_HOSTNAME),
          String.format("%s should be set for single master token service, for uri: %s", PropertyKey.MASTER_HOSTNAME.getName(), uri));
      uri = URI.create(uri.getScheme() + "://" + conf.get(PropertyKey.MASTER_HOSTNAME) + ":" + conf.get(PropertyKey.MASTER_RPC_PORT));
    }
    return SecurityUtil.buildTokenService(uri).toString();
  }
}
