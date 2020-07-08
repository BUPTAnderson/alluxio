// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: grpc/meta_master.proto

package alluxio.grpc;

public interface MasterInfoOrBuilder extends
    // @@protoc_insertion_point(interface_extends:alluxio.grpc.meta.MasterInfo)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>optional string leaderMasterAddress = 1;</code>
   * @return Whether the leaderMasterAddress field is set.
   */
  boolean hasLeaderMasterAddress();
  /**
   * <code>optional string leaderMasterAddress = 1;</code>
   * @return The leaderMasterAddress.
   */
  java.lang.String getLeaderMasterAddress();
  /**
   * <code>optional string leaderMasterAddress = 1;</code>
   * @return The bytes for leaderMasterAddress.
   */
  com.google.protobuf.ByteString
      getLeaderMasterAddressBytes();

  /**
   * <code>repeated .alluxio.grpc.NetAddress masterAddresses = 2;</code>
   */
  java.util.List<alluxio.grpc.NetAddress> 
      getMasterAddressesList();
  /**
   * <code>repeated .alluxio.grpc.NetAddress masterAddresses = 2;</code>
   */
  alluxio.grpc.NetAddress getMasterAddresses(int index);
  /**
   * <code>repeated .alluxio.grpc.NetAddress masterAddresses = 2;</code>
   */
  int getMasterAddressesCount();
  /**
   * <code>repeated .alluxio.grpc.NetAddress masterAddresses = 2;</code>
   */
  java.util.List<? extends alluxio.grpc.NetAddressOrBuilder> 
      getMasterAddressesOrBuilderList();
  /**
   * <code>repeated .alluxio.grpc.NetAddress masterAddresses = 2;</code>
   */
  alluxio.grpc.NetAddressOrBuilder getMasterAddressesOrBuilder(
      int index);

  /**
   * <code>optional int32 rpcPort = 3;</code>
   * @return Whether the rpcPort field is set.
   */
  boolean hasRpcPort();
  /**
   * <code>optional int32 rpcPort = 3;</code>
   * @return The rpcPort.
   */
  int getRpcPort();

  /**
   * <code>optional bool safeMode = 4;</code>
   * @return Whether the safeMode field is set.
   */
  boolean hasSafeMode();
  /**
   * <code>optional bool safeMode = 4;</code>
   * @return The safeMode.
   */
  boolean getSafeMode();

  /**
   * <code>optional int64 startTimeMs = 5;</code>
   * @return Whether the startTimeMs field is set.
   */
  boolean hasStartTimeMs();
  /**
   * <code>optional int64 startTimeMs = 5;</code>
   * @return The startTimeMs.
   */
  long getStartTimeMs();

  /**
   * <code>optional int64 upTimeMs = 6;</code>
   * @return Whether the upTimeMs field is set.
   */
  boolean hasUpTimeMs();
  /**
   * <code>optional int64 upTimeMs = 6;</code>
   * @return The upTimeMs.
   */
  long getUpTimeMs();

  /**
   * <code>optional string version = 7;</code>
   * @return Whether the version field is set.
   */
  boolean hasVersion();
  /**
   * <code>optional string version = 7;</code>
   * @return The version.
   */
  java.lang.String getVersion();
  /**
   * <code>optional string version = 7;</code>
   * @return The bytes for version.
   */
  com.google.protobuf.ByteString
      getVersionBytes();

  /**
   * <code>optional int32 webPort = 8;</code>
   * @return Whether the webPort field is set.
   */
  boolean hasWebPort();
  /**
   * <code>optional int32 webPort = 8;</code>
   * @return The webPort.
   */
  int getWebPort();

  /**
   * <code>repeated .alluxio.grpc.NetAddress workerAddresses = 9;</code>
   */
  java.util.List<alluxio.grpc.NetAddress> 
      getWorkerAddressesList();
  /**
   * <code>repeated .alluxio.grpc.NetAddress workerAddresses = 9;</code>
   */
  alluxio.grpc.NetAddress getWorkerAddresses(int index);
  /**
   * <code>repeated .alluxio.grpc.NetAddress workerAddresses = 9;</code>
   */
  int getWorkerAddressesCount();
  /**
   * <code>repeated .alluxio.grpc.NetAddress workerAddresses = 9;</code>
   */
  java.util.List<? extends alluxio.grpc.NetAddressOrBuilder> 
      getWorkerAddressesOrBuilderList();
  /**
   * <code>repeated .alluxio.grpc.NetAddress workerAddresses = 9;</code>
   */
  alluxio.grpc.NetAddressOrBuilder getWorkerAddressesOrBuilder(
      int index);

  /**
   * <pre>
   * Empty means zookeeper is not enabled
   * </pre>
   *
   * <code>repeated string zookeeperAddresses = 10;</code>
   * @return A list containing the zookeeperAddresses.
   */
  java.util.List<java.lang.String>
      getZookeeperAddressesList();
  /**
   * <pre>
   * Empty means zookeeper is not enabled
   * </pre>
   *
   * <code>repeated string zookeeperAddresses = 10;</code>
   * @return The count of zookeeperAddresses.
   */
  int getZookeeperAddressesCount();
  /**
   * <pre>
   * Empty means zookeeper is not enabled
   * </pre>
   *
   * <code>repeated string zookeeperAddresses = 10;</code>
   * @param index The index of the element to return.
   * @return The zookeeperAddresses at the given index.
   */
  java.lang.String getZookeeperAddresses(int index);
  /**
   * <pre>
   * Empty means zookeeper is not enabled
   * </pre>
   *
   * <code>repeated string zookeeperAddresses = 10;</code>
   * @param index The index of the value to return.
   * @return The bytes of the zookeeperAddresses at the given index.
   */
  com.google.protobuf.ByteString
      getZookeeperAddressesBytes(int index);
}