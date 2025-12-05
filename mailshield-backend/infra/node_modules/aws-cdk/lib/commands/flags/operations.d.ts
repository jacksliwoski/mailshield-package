import type { FeatureFlag, Toolkit } from '@aws-cdk/toolkit-lib';
import type { FlagOperationsParams } from './types';
import type { IoHelper } from '../../api-private';
export declare class FlagOperations {
    private readonly flags;
    private readonly toolkit;
    private readonly ioHelper;
    private app;
    private baseContextValues;
    private allStacks;
    private queue;
    private baselineTempDir?;
    constructor(flags: FeatureFlag[], toolkit: Toolkit, ioHelper: IoHelper);
    /** Main entry point that routes to either flag setting or display operations */
    execute(params: FlagOperationsParams): Promise<void>;
    /** Sets a single specific flag with validation and user confirmation */
    setFlag(params: FlagOperationsParams): Promise<void>;
    /** Sets multiple flags (all or unconfigured) with validation and user confirmation */
    setMultipleFlags(params: FlagOperationsParams): Promise<void>;
    /** Determines which flags should be set based on the provided parameters */
    private getFlagsToSet;
    /** Sets flags that don't cause template changes */
    setSafeFlags(params: FlagOperationsParams): Promise<void>;
    /** Initializes the safety check by reading context and synthesizing baseline templates */
    private initializeSafetyCheck;
    /** Cleans up temporary directories created during safety checks */
    private cleanupSafetyCheck;
    /** Tests multiple flags together and isolates unsafe ones using binary search */
    private batchTestFlags;
    /** Tests if a set of context values causes template changes by synthesizing and diffing */
    private testBatch;
    /** Uses binary search to isolate which flags are safe to set without template changes */
    private isolateUnsafeFlags;
    /** Prototypes flag changes by synthesizing templates and showing diffs to the user */
    private prototypeChanges;
    /** Displays a summary of flag changes showing old and new values */
    private displayFlagChanges;
    /** Builds the update object with new flag values based on parameters and current context */
    private buildUpdateObject;
    /** Prompts user for confirmation and applies changes if accepted */
    private handleUserResponse;
    /** Removes temporary directories created during flag operations */
    private cleanupTempDirectories;
    /** Actually modifies the cdk.json file with the new flag values */
    private modifyValues;
    /** Displays flags in a table format, either specific flags or filtered by criteria */
    displayFlags(params: FlagOperationsParams): Promise<void>;
    /** Displays detailed information for specific flags matching the given names */
    private displaySpecificFlags;
    /** Returns sort order for flags */
    private getFlagSortOrder;
    /** Displays flags in a formatted table grouped by module and sorted */
    displayFlagTable(flags: FeatureFlag[]): Promise<void>;
    /** Checks if a flag has a boolean recommended value */
    isBooleanFlag(flag: FeatureFlag): boolean;
    /** Checks if the user's current value matches the recommended value */
    private isUserValueEqualToRecommended;
    /** Shows helpful usage examples and available command options */
    displayHelpMessage(): Promise<void>;
}
