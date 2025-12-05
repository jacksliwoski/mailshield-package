import { IEnvironmentAware } from "../environment-aware";
import * as constructs from "constructs";
/**
 * Indicates that this resource can be referenced as a VirtualCluster.
 *
 * @stability experimental
 */
export interface IVirtualClusterRef extends constructs.IConstruct, IEnvironmentAware {
    /**
     * A reference to a VirtualCluster resource.
     */
    readonly virtualClusterRef: VirtualClusterReference;
}
/**
 * A reference to a VirtualCluster resource.
 *
 * @struct
 * @stability external
 */
export interface VirtualClusterReference {
    /**
     * The Id of the VirtualCluster resource.
     */
    readonly virtualClusterId: string;
    /**
     * The ARN of the VirtualCluster resource.
     */
    readonly virtualClusterArn: string;
}
