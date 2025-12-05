import { IEnvironmentAware } from "../environment-aware";
import * as constructs from "constructs";
/**
 * Indicates that this resource can be referenced as a Cluster.
 *
 * @stability experimental
 */
export interface IClusterRef extends constructs.IConstruct, IEnvironmentAware {
    /**
     * A reference to a Cluster resource.
     */
    readonly clusterRef: ClusterReference;
}
/**
 * A reference to a Cluster resource.
 *
 * @struct
 * @stability external
 */
export interface ClusterReference {
    /**
     * The Id of the Cluster resource.
     */
    readonly clusterId: string;
    /**
     * The ARN of the Cluster resource.
     */
    readonly clusterArn: string;
}
/**
 * Indicates that this resource can be referenced as a ParameterGroup.
 *
 * @stability experimental
 */
export interface IParameterGroupRef extends constructs.IConstruct, IEnvironmentAware {
    /**
     * A reference to a ParameterGroup resource.
     */
    readonly parameterGroupRef: ParameterGroupReference;
}
/**
 * A reference to a ParameterGroup resource.
 *
 * @struct
 * @stability external
 */
export interface ParameterGroupReference {
    /**
     * The Id of the ParameterGroup resource.
     */
    readonly parameterGroupId: string;
}
/**
 * Indicates that this resource can be referenced as a SubnetGroup.
 *
 * @stability experimental
 */
export interface ISubnetGroupRef extends constructs.IConstruct, IEnvironmentAware {
    /**
     * A reference to a SubnetGroup resource.
     */
    readonly subnetGroupRef: SubnetGroupReference;
}
/**
 * A reference to a SubnetGroup resource.
 *
 * @struct
 * @stability external
 */
export interface SubnetGroupReference {
    /**
     * The Id of the SubnetGroup resource.
     */
    readonly subnetGroupId: string;
}
