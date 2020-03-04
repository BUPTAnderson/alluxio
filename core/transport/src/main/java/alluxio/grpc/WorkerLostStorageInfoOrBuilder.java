// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: grpc/block_master.proto

package alluxio.grpc;

public interface WorkerLostStorageInfoOrBuilder extends
    // @@protoc_insertion_point(interface_extends:alluxio.grpc.block.WorkerLostStorageInfo)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>optional .alluxio.grpc.WorkerNetAddress address = 1;</code>
   * @return Whether the address field is set.
   */
  boolean hasAddress();
  /**
   * <code>optional .alluxio.grpc.WorkerNetAddress address = 1;</code>
   * @return The address.
   */
  alluxio.grpc.WorkerNetAddress getAddress();
  /**
   * <code>optional .alluxio.grpc.WorkerNetAddress address = 1;</code>
   */
  alluxio.grpc.WorkerNetAddressOrBuilder getAddressOrBuilder();

  /**
   * <pre>
   ** a map from tier alias to the lost storage paths 
   * </pre>
   *
   * <code>map&lt;string, .alluxio.grpc.block.StorageList&gt; lostStorage = 2;</code>
   */
  int getLostStorageCount();
  /**
   * <pre>
   ** a map from tier alias to the lost storage paths 
   * </pre>
   *
   * <code>map&lt;string, .alluxio.grpc.block.StorageList&gt; lostStorage = 2;</code>
   */
  boolean containsLostStorage(
      java.lang.String key);
  /**
   * Use {@link #getLostStorageMap()} instead.
   */
  @java.lang.Deprecated
  java.util.Map<java.lang.String, alluxio.grpc.StorageList>
  getLostStorage();
  /**
   * <pre>
   ** a map from tier alias to the lost storage paths 
   * </pre>
   *
   * <code>map&lt;string, .alluxio.grpc.block.StorageList&gt; lostStorage = 2;</code>
   */
  java.util.Map<java.lang.String, alluxio.grpc.StorageList>
  getLostStorageMap();
  /**
   * <pre>
   ** a map from tier alias to the lost storage paths 
   * </pre>
   *
   * <code>map&lt;string, .alluxio.grpc.block.StorageList&gt; lostStorage = 2;</code>
   */

  alluxio.grpc.StorageList getLostStorageOrDefault(
      java.lang.String key,
      alluxio.grpc.StorageList defaultValue);
  /**
   * <pre>
   ** a map from tier alias to the lost storage paths 
   * </pre>
   *
   * <code>map&lt;string, .alluxio.grpc.block.StorageList&gt; lostStorage = 2;</code>
   */

  alluxio.grpc.StorageList getLostStorageOrThrow(
      java.lang.String key);
}