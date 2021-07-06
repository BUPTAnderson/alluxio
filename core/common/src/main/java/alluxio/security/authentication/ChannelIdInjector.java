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

package alluxio.security.authentication;

import alluxio.grpc.SaslMessage;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.ForwardingClientCallListener;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;

import javax.annotation.concurrent.ThreadSafe;
import java.util.UUID;

/**
 * Client side interceptor that is used to augment outgoing metadata with the unique id for the
 * channel that the RPC is being called on.
 */
@ThreadSafe
public final class ChannelIdInjector implements ClientInterceptor {

  /** Metadata key for the channel Id. */
  public static final Metadata.Key<UUID> S_CLIENT_ID_KEY =
      Metadata.Key.of("channel-id", new Metadata.AsciiMarshaller<UUID>() {
        @Override
        public String toAsciiString(UUID value) {
          return value.toString();
        }

        @Override
        public UUID parseAsciiString(String serialized) {
          return UUID.fromString(serialized);
        }
      });

  /** Metadata key for the channel Id. */
  public static final Metadata.Key<SaslMessage> S_CLIENT_SASL_KEY =
      Metadata.Key.of("sasl-key-bin", new Metadata.BinaryMarshaller<SaslMessage>() {
        @Override
        public byte[] toBytes(SaslMessage value) {
          return value.toByteArray();
        }

        @Override
        public SaslMessage parseBytes(byte[] serialized) {
          try {
            return SaslMessage.parseFrom(serialized);
          } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
            return null;
          }
        }
      });

  // TODO(ggezer) Consider more lightweight Id type.
  private final UUID mChannelId;

  /**
   * Creates the injector that augments the outgoing metadata with given Id.
   *
   * @param channelId channel id
   */
  public ChannelIdInjector(UUID channelId) {
    mChannelId = channelId;
  }

  @Override
  public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method,
      CallOptions callOptions, Channel next) {
    return new ForwardingClientCall.SimpleForwardingClientCall<ReqT, RespT>(
        next.newCall(method, callOptions)) {
      @Override
      public void start(Listener<RespT> responseListener, Metadata headers) {
        // Put channel Id to headers.
        headers.put(S_CLIENT_ID_KEY, mChannelId);
        super.start(new ForwardingClientCallListener.SimpleForwardingClientCallListener<RespT>(
            responseListener) {
          @Override
          public void onHeaders(Metadata headers) {
            super.onHeaders(headers);
          }
        }, headers);
      }
    };
  }
}
