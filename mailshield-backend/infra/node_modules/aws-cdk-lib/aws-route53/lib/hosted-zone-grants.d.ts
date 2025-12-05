import { GrantDelegationOptions, INamedHostedZoneRef } from './hosted-zone-ref';
import { IGrantable } from '../../aws-iam';
import { Grant } from '../../aws-iam/lib/grant';
/**
 * Collection of grant methods for a INamedHostedZoneRef
 */
export declare class HostedZoneGrants {
    private readonly hostedZone;
    /**
     * Creates grants for INamedHostedZoneRef
     *
     */
    static fromHostedZone(hostedZone: INamedHostedZoneRef): HostedZoneGrants;
    private constructor();
    /**
     * Grant permissions to add delegation records to this zone
     */
    delegation(grantee: IGrantable, delegationOptions?: GrantDelegationOptions): Grant;
}
