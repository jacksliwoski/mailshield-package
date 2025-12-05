"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FlagOperations = void 0;
const os = require("os");
const path = require("path");
const cloudformation_diff_1 = require("@aws-cdk/cloudformation-diff");
const toolkit_lib_1 = require("@aws-cdk/toolkit-lib");
const chalk = require("chalk");
const fs = require("fs-extra");
const p_queue_1 = require("p-queue");
const api_1 = require("../../api");
class FlagOperations {
    constructor(flags, toolkit, ioHelper) {
        this.flags = flags;
        this.toolkit = toolkit;
        this.ioHelper = ioHelper;
        this.app = '';
        this.baseContextValues = {};
        this.allStacks = [];
        this.queue = new p_queue_1.default({ concurrency: 4 });
    }
    /** Main entry point that routes to either flag setting or display operations */
    async execute(params) {
        if (params.set) {
            if (params.FLAGNAME && params.value) {
                await this.setFlag(params);
            }
            else {
                await this.setMultipleFlags(params);
            }
        }
        else {
            await this.displayFlags(params);
        }
    }
    /** Sets a single specific flag with validation and user confirmation */
    async setFlag(params) {
        const flagName = params.FLAGNAME[0];
        const flag = this.flags.find(f => f.name === flagName);
        if (!flag) {
            await this.ioHelper.defaults.error('Flag not found.');
            return;
        }
        if (!this.isBooleanFlag(flag)) {
            await this.ioHelper.defaults.error(`Flag '${flagName}' is not a boolean flag. Only boolean flags are currently supported.`);
            return;
        }
        const prototypeSuccess = await this.prototypeChanges([flagName], params);
        if (prototypeSuccess) {
            await this.handleUserResponse([flagName], params);
        }
    }
    /** Sets multiple flags (all or unconfigured) with validation and user confirmation */
    async setMultipleFlags(params) {
        if (params.default && !this.flags.some(f => f.unconfiguredBehavesLike)) {
            await this.ioHelper.defaults.error('The --default options are not compatible with the AWS CDK library used by your application. Please upgrade to 2.212.0 or above.');
            return;
        }
        const flagsToSet = this.getFlagsToSet(params);
        const prototypeSuccess = await this.prototypeChanges(flagsToSet, params);
        if (prototypeSuccess) {
            await this.handleUserResponse(flagsToSet, params);
        }
    }
    /** Determines which flags should be set based on the provided parameters */
    getFlagsToSet(params) {
        if (params.all && params.default) {
            return this.flags
                .filter(flag => this.isBooleanFlag(flag))
                .map(flag => flag.name);
        }
        else if (params.all) {
            return this.flags
                .filter(flag => flag.userValue === undefined || !this.isUserValueEqualToRecommended(flag))
                .filter(flag => this.isBooleanFlag(flag))
                .map(flag => flag.name);
        }
        else {
            return this.flags
                .filter(flag => flag.userValue === undefined)
                .filter(flag => this.isBooleanFlag(flag))
                .map(flag => flag.name);
        }
    }
    /** Sets flags that don't cause template changes */
    async setSafeFlags(params) {
        const cdkJson = await JSON.parse(await fs.readFile(path.join(process.cwd(), 'cdk.json'), 'utf-8'));
        this.app = params.app || cdkJson.app;
        const isUsingTsNode = this.app.includes('ts-node');
        if (isUsingTsNode && !this.app.includes('-T') && !this.app.includes('--transpileOnly')) {
            await this.ioHelper.defaults.info('Repeated synths with ts-node will type-check the application on every synth. Add --transpileOnly to cdk.json\'s "app" command to make this operation faster.');
        }
        const unconfiguredFlags = this.flags.filter(flag => flag.userValue === undefined && this.isBooleanFlag(flag));
        if (unconfiguredFlags.length === 0) {
            await this.ioHelper.defaults.info('All feature flags are configured.');
            return;
        }
        await this.initializeSafetyCheck();
        const safeFlags = await this.batchTestFlags(unconfiguredFlags);
        await this.cleanupSafetyCheck();
        if (safeFlags.length > 0) {
            await this.ioHelper.defaults.info('Flags that can be set without template changes:');
            for (const flag of safeFlags) {
                await this.ioHelper.defaults.info(`- ${flag.name} -> ${flag.recommendedValue}`);
            }
            await this.handleUserResponse(safeFlags.map(flag => flag.name), { ...params, recommended: true });
        }
        else {
            await this.ioHelper.defaults.info('No more flags can be set without causing template changes.');
        }
    }
    /** Initializes the safety check by reading context and synthesizing baseline templates */
    async initializeSafetyCheck() {
        const baseContext = new toolkit_lib_1.CdkAppMultiContext(process.cwd());
        this.baseContextValues = await baseContext.read();
        this.baselineTempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cdk-baseline-'));
        const baseSource = await this.toolkit.fromCdkApp(this.app, {
            contextStore: baseContext,
            outdir: this.baselineTempDir,
        });
        const baseCx = await this.toolkit.synth(baseSource);
        const baseAssembly = baseCx.cloudAssembly;
        this.allStacks = baseAssembly.stacksRecursively;
        this.queue = new p_queue_1.default({ concurrency: 4 });
    }
    /** Cleans up temporary directories created during safety checks */
    async cleanupSafetyCheck() {
        if (this.baselineTempDir) {
            await fs.remove(this.baselineTempDir);
            this.baselineTempDir = undefined;
        }
    }
    /** Tests multiple flags together and isolates unsafe ones using binary search */
    async batchTestFlags(flags) {
        if (flags.length === 0)
            return [];
        const allFlagsContext = { ...this.baseContextValues };
        flags.forEach(flag => {
            allFlagsContext[flag.name] = flag.recommendedValue;
        });
        const allSafe = await this.testBatch(allFlagsContext);
        if (allSafe)
            return flags;
        return this.isolateUnsafeFlags(flags);
    }
    /** Tests if a set of context values causes template changes by synthesizing and diffing */
    async testBatch(contextValues) {
        const testContext = new toolkit_lib_1.MemoryContext(contextValues);
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cdk-test-'));
        const testSource = await this.toolkit.fromCdkApp(this.app, {
            contextStore: testContext,
            outdir: tempDir,
        });
        const testCx = await this.toolkit.synth(testSource);
        try {
            for (const stack of this.allStacks) {
                const templatePath = stack.templateFullPath;
                const diff = await this.toolkit.diff(testCx, {
                    method: toolkit_lib_1.DiffMethod.LocalFile(templatePath),
                    stacks: {
                        strategy: api_1.StackSelectionStrategy.PATTERN_MUST_MATCH_SINGLE,
                        patterns: [stack.hierarchicalId],
                    },
                });
                for (const stackDiff of Object.values(diff)) {
                    if (stackDiff.differenceCount > 0) {
                        return false;
                    }
                }
            }
            return true;
        }
        finally {
            await fs.remove(tempDir);
        }
    }
    /** Uses binary search to isolate which flags are safe to set without template changes */
    async isolateUnsafeFlags(flags) {
        const safeFlags = [];
        const processBatch = async (batch, contextValues) => {
            if (batch.length === 1) {
                const isSafe = await this.testBatch({ ...contextValues, [batch[0].name]: batch[0].recommendedValue });
                if (isSafe)
                    safeFlags.push(batch[0]);
                return;
            }
            const batchContext = { ...contextValues };
            batch.forEach(flag => {
                batchContext[flag.name] = flag.recommendedValue;
            });
            const isSafeBatch = await this.testBatch(batchContext);
            if (isSafeBatch) {
                safeFlags.push(...batch);
                return;
            }
            const mid = Math.floor(batch.length / 2);
            const left = batch.slice(0, mid);
            const right = batch.slice(mid);
            void this.queue.add(() => processBatch(left, contextValues));
            void this.queue.add(() => processBatch(right, contextValues));
        };
        void this.queue.add(() => processBatch(flags, this.baseContextValues));
        await this.queue.onIdle();
        return safeFlags;
    }
    /** Prototypes flag changes by synthesizing templates and showing diffs to the user */
    async prototypeChanges(flagNames, params) {
        const baseContext = new toolkit_lib_1.CdkAppMultiContext(process.cwd());
        const baseContextValues = await baseContext.read();
        const memoryContext = new toolkit_lib_1.MemoryContext(baseContextValues);
        const cdkJson = await JSON.parse(await fs.readFile(path.join(process.cwd(), 'cdk.json'), 'utf-8'));
        const app = cdkJson.app;
        const source = await this.toolkit.fromCdkApp(app, {
            contextStore: baseContext,
            outdir: fs.mkdtempSync(path.join(os.tmpdir(), 'cdk-original-')),
        });
        const updateObj = await this.buildUpdateObject(flagNames, params, baseContextValues);
        if (!updateObj)
            return false;
        await memoryContext.update(updateObj);
        const cx = await this.toolkit.synth(source);
        const assembly = cx.cloudAssembly;
        const modifiedSource = await this.toolkit.fromCdkApp(app, {
            contextStore: memoryContext,
            outdir: fs.mkdtempSync(path.join(os.tmpdir(), 'cdk-temp-')),
        });
        const modifiedCx = await this.toolkit.synth(modifiedSource);
        const allStacks = assembly.stacksRecursively;
        for (const stack of allStacks) {
            const templatePath = stack.templateFullPath;
            await this.toolkit.diff(modifiedCx, {
                method: toolkit_lib_1.DiffMethod.LocalFile(templatePath),
                stacks: {
                    strategy: api_1.StackSelectionStrategy.PATTERN_MUST_MATCH_SINGLE,
                    patterns: [stack.hierarchicalId],
                },
            });
        }
        await this.displayFlagChanges(updateObj, baseContextValues);
        return true;
    }
    /** Displays a summary of flag changes showing old and new values */
    async displayFlagChanges(updateObj, baseContextValues) {
        await this.ioHelper.defaults.info('\nFlag changes:');
        for (const [flagName, newValue] of Object.entries(updateObj)) {
            const currentValue = baseContextValues[flagName];
            const currentDisplay = currentValue === undefined ? '<unset>' : String(currentValue);
            await this.ioHelper.defaults.info(`  ${flagName}: ${currentDisplay} → ${newValue}`);
        }
    }
    /** Builds the update object with new flag values based on parameters and current context */
    async buildUpdateObject(flagNames, params, baseContextValues) {
        const updateObj = {};
        if (flagNames.length === 1 && params.value !== undefined) {
            const flagName = flagNames[0];
            const boolValue = params.value === 'true';
            if (baseContextValues[flagName] === boolValue) {
                await this.ioHelper.defaults.info('Flag is already set to the specified value. No changes needed.');
                return null;
            }
            updateObj[flagName] = boolValue;
        }
        else {
            for (const flagName of flagNames) {
                const flag = this.flags.find(f => f.name === flagName);
                if (!flag) {
                    await this.ioHelper.defaults.error(`Flag ${flagName} not found.`);
                    return null;
                }
                const newValue = params.recommended
                    ? flag.recommendedValue
                    : String(flag.unconfiguredBehavesLike?.v2) === 'true';
                updateObj[flagName] = newValue;
            }
        }
        return updateObj;
    }
    /** Prompts user for confirmation and applies changes if accepted */
    async handleUserResponse(flagNames, params) {
        const userAccepted = await this.ioHelper.requestResponse({
            time: new Date(),
            level: 'info',
            code: 'CDK_TOOLKIT_I9300',
            message: 'Do you want to accept these changes?',
            data: {
                flagNames,
                responseDescription: 'Enter "y" to apply changes or "n" to cancel',
            },
            defaultResponse: false,
        });
        if (userAccepted) {
            await this.modifyValues(flagNames, params);
            await this.ioHelper.defaults.info('Flag value(s) updated successfully.');
        }
        else {
            await this.ioHelper.defaults.info('Operation cancelled');
        }
        await this.cleanupTempDirectories();
    }
    /** Removes temporary directories created during flag operations */
    async cleanupTempDirectories() {
        const originalDir = path.join(process.cwd(), 'original');
        const tempDir = path.join(process.cwd(), 'temp');
        await fs.remove(originalDir);
        await fs.remove(tempDir);
    }
    /** Actually modifies the cdk.json file with the new flag values */
    async modifyValues(flagNames, params) {
        const cdkJsonPath = path.join(process.cwd(), 'cdk.json');
        const cdkJsonContent = await fs.readFile(cdkJsonPath, 'utf-8');
        const cdkJson = JSON.parse(cdkJsonContent);
        if (flagNames.length === 1 && !params.safe) {
            const boolValue = params.value === 'true';
            cdkJson.context[String(flagNames[0])] = boolValue;
            await this.ioHelper.defaults.info(`Setting flag '${flagNames}' to: ${boolValue}`);
        }
        else {
            for (const flagName of flagNames) {
                const flag = this.flags.find(f => f.name === flagName);
                const newValue = params.recommended || params.safe
                    ? flag.recommendedValue
                    : String(flag.unconfiguredBehavesLike?.v2) === 'true';
                cdkJson.context[flagName] = newValue;
            }
        }
        await fs.writeFile(cdkJsonPath, JSON.stringify(cdkJson, null, 2), 'utf-8');
    }
    /** Displays flags in a table format, either specific flags or filtered by criteria */
    async displayFlags(params) {
        const { FLAGNAME, all } = params;
        if (FLAGNAME && FLAGNAME.length > 0) {
            await this.displaySpecificFlags(FLAGNAME);
            return;
        }
        const flagsToDisplay = all ? this.flags : this.flags.filter(flag => flag.userValue === undefined || !this.isUserValueEqualToRecommended(flag));
        await this.displayFlagTable(flagsToDisplay);
        // Add helpful message after empty table when not using --all
        if (!all && flagsToDisplay.length === 0) {
            await this.ioHelper.defaults.info('');
            await this.ioHelper.defaults.info('✅ All feature flags are already set to their recommended values.');
            await this.ioHelper.defaults.info('Use \'cdk flags --all --unstable=flags\' to see all flags and their current values.');
        }
    }
    /** Displays detailed information for specific flags matching the given names */
    async displaySpecificFlags(flagNames) {
        const matchingFlags = this.flags.filter(f => flagNames.some(searchTerm => f.name.toLowerCase().includes(searchTerm.toLowerCase())));
        if (matchingFlags.length === 0) {
            await this.ioHelper.defaults.error(`Flag matching "${flagNames.join(', ')}" not found.`);
            return;
        }
        if (matchingFlags.length === 1) {
            const flag = matchingFlags[0];
            await this.ioHelper.defaults.info(`Flag name: ${flag.name}`);
            await this.ioHelper.defaults.info(`Description: ${flag.explanation}`);
            await this.ioHelper.defaults.info(`Recommended value: ${flag.recommendedValue}`);
            await this.ioHelper.defaults.info(`User value: ${flag.userValue}`);
            return;
        }
        await this.ioHelper.defaults.info(`Found ${matchingFlags.length} flags matching "${flagNames.join(', ')}":`);
        await this.displayFlagTable(matchingFlags);
    }
    /** Returns sort order for flags */
    getFlagSortOrder(flag) {
        if (flag.userValue === undefined)
            return 3;
        if (this.isUserValueEqualToRecommended(flag))
            return 1;
        return 2;
    }
    /** Displays flags in a formatted table grouped by module and sorted */
    async displayFlagTable(flags) {
        const sortedFlags = [...flags].sort((a, b) => {
            const orderA = this.getFlagSortOrder(a);
            const orderB = this.getFlagSortOrder(b);
            if (orderA !== orderB)
                return orderA - orderB;
            if (a.module !== b.module)
                return a.module.localeCompare(b.module);
            return a.name.localeCompare(b.name);
        });
        const rows = [['Feature Flag Name', 'Recommended Value', 'User Value']];
        let currentModule = '';
        sortedFlags.forEach((flag) => {
            if (flag.module !== currentModule) {
                rows.push([chalk.bold(`Module: ${flag.module}`), '', '']);
                currentModule = flag.module;
            }
            rows.push([
                `  ${flag.name}`,
                String(flag.recommendedValue),
                flag.userValue === undefined ? '<unset>' : String(flag.userValue),
            ]);
        });
        const formattedTable = (0, cloudformation_diff_1.formatTable)(rows, undefined, true);
        await this.ioHelper.defaults.info(formattedTable);
    }
    /** Checks if a flag has a boolean recommended value */
    isBooleanFlag(flag) {
        const recommended = flag.recommendedValue;
        return typeof recommended === 'boolean' ||
            recommended === 'true' ||
            recommended === 'false';
    }
    /** Checks if the user's current value matches the recommended value */
    isUserValueEqualToRecommended(flag) {
        return String(flag.userValue) === String(flag.recommendedValue);
    }
    /** Shows helpful usage examples and available command options */
    async displayHelpMessage() {
        await this.ioHelper.defaults.info('\n' + chalk.bold('Available options:'));
        await this.ioHelper.defaults.info('  cdk flags --interactive     # Interactive menu to manage flags');
        await this.ioHelper.defaults.info('  cdk flags --all             # Show all flags (including configured ones)');
        await this.ioHelper.defaults.info('  cdk flags --set --all --recommended    # Set all flags to recommended values');
        await this.ioHelper.defaults.info('  cdk flags --set --all --default       # Set all flags to default values');
        await this.ioHelper.defaults.info('  cdk flags --set --unconfigured --recommended  # Set unconfigured flags to recommended');
        await this.ioHelper.defaults.info('  cdk flags --set <flag-name> --value <true|false>  # Set specific flag');
        await this.ioHelper.defaults.info('  cdk flags --safe            # Safely set flags that don\'t change templates');
    }
}
exports.FlagOperations = FlagOperations;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib3BlcmF0aW9ucy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIm9wZXJhdGlvbnMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEseUJBQXlCO0FBQ3pCLDZCQUE2QjtBQUM3QixzRUFBMkQ7QUFHM0Qsc0RBQXFGO0FBQ3JGLCtCQUErQjtBQUMvQiwrQkFBK0I7QUFDL0IscUNBQTZCO0FBRTdCLG1DQUFtRDtBQUduRCxNQUFhLGNBQWM7SUFPekIsWUFDbUIsS0FBb0IsRUFDcEIsT0FBZ0IsRUFDaEIsUUFBa0I7UUFGbEIsVUFBSyxHQUFMLEtBQUssQ0FBZTtRQUNwQixZQUFPLEdBQVAsT0FBTyxDQUFTO1FBQ2hCLGFBQVEsR0FBUixRQUFRLENBQVU7UUFFbkMsSUFBSSxDQUFDLEdBQUcsR0FBRyxFQUFFLENBQUM7UUFDZCxJQUFJLENBQUMsaUJBQWlCLEdBQUcsRUFBRSxDQUFDO1FBQzVCLElBQUksQ0FBQyxTQUFTLEdBQUcsRUFBRSxDQUFDO1FBQ3BCLElBQUksQ0FBQyxLQUFLLEdBQUcsSUFBSSxpQkFBTSxDQUFDLEVBQUUsV0FBVyxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUM7SUFDOUMsQ0FBQztJQUVELGdGQUFnRjtJQUNoRixLQUFLLENBQUMsT0FBTyxDQUFDLE1BQTRCO1FBQ3hDLElBQUksTUFBTSxDQUFDLEdBQUcsRUFBRSxDQUFDO1lBQ2YsSUFBSSxNQUFNLENBQUMsUUFBUSxJQUFJLE1BQU0sQ0FBQyxLQUFLLEVBQUUsQ0FBQztnQkFDcEMsTUFBTSxJQUFJLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDO1lBQzdCLENBQUM7aUJBQU0sQ0FBQztnQkFDTixNQUFNLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxNQUFNLENBQUMsQ0FBQztZQUN0QyxDQUFDO1FBQ0gsQ0FBQzthQUFNLENBQUM7WUFDTixNQUFNLElBQUksQ0FBQyxZQUFZLENBQUMsTUFBTSxDQUFDLENBQUM7UUFDbEMsQ0FBQztJQUNILENBQUM7SUFFRCx3RUFB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Q0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLHlGQUF5RixDQUFDLENBQUM7UUFDN0gsTUFBTSxJQUFJLENBQUMsUUFBUSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMseUVBQXlFLENBQUMsQ0FBQztRQUM3RyxNQUFNLElBQUksQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQywrRUFBK0UsQ0FBQyxDQUFDO0lBQ3JILENBQUM7Q0FDRjtBQXpkRCx3Q0F5ZEMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgKiBhcyBvcyBmcm9tICdvcyc7XG5pbXBvcnQgKiBhcyBwYXRoIGZyb20gJ3BhdGgnO1xuaW1wb3J0IHsgZm9ybWF0VGFibGUgfSBmcm9tICdAYXdzLWNkay9jbG91ZGZvcm1hdGlvbi1kaWZmJztcbmltcG9ydCB0eXBlIHsgQ2xvdWRGb3JtYXRpb25TdGFja0FydGlmYWN0IH0gZnJvbSAnQGF3cy1jZGsvY3gtYXBpJztcbmltcG9ydCB0eXBlIHsgRmVhdHVyZUZsYWcsIFRvb2xraXQgfSBmcm9tICdAYXdzLWNkay90b29sa2l0LWxpYic7XG5pbXBvcnQgeyBDZGtBcHBNdWx0aUNvbnRleHQsIE1lbW9yeUNvbnRleHQsIERpZmZNZXRob2QgfSBmcm9tICdAYXdzLWNkay90b29sa2l0LWxpYic7XG5pbXBvcnQgKiBhcyBjaGFsayBmcm9tICdjaGFsayc7XG5pbXBvcnQgKiBhcyBmcyBmcm9tICdmcy1leHRyYSc7XG5pbXBvcnQgUFF1ZXVlIGZyb20gJ3AtcXVldWUnO1xuaW1wb3J0IHR5cGUgeyBGbGFnT3BlcmF0aW9uc1BhcmFtcyB9IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IHsgU3RhY2tTZWxlY3Rpb25TdHJhdGVneSB9IGZyb20gJy4uLy4uL2FwaSc7XG5pbXBvcnQgdHlwZSB7IElvSGVscGVyIH0gZnJvbSAnLi4vLi4vYXBpLXByaXZhdGUnO1xuXG5leHBvcnQgY2xhc3MgRmxhZ09wZXJhdGlvbnMge1xuICBwcml2YXRlIGFwcDogc3RyaW5nO1xuICBwcml2YXRlIGJhc2VDb250ZXh0VmFsdWVzOiBSZWNvcmQ8c3RyaW5nLCBhbnk+O1xuICBwcml2YXRlIGFsbFN0YWNrczogQ2xvdWRGb3JtYXRpb25TdGFja0FydGlmYWN0W107XG4gIHByaXZhdGUgcXVldWU6IFBRdWV1ZTtcbiAgcHJpdmF0ZSBiYXNlbGluZVRlbXBEaXI/OiBzdHJpbmc7XG5cbiAgY29uc3RydWN0b3IoXG4gICAgcHJpdmF0ZSByZWFkb25seSBmbGFnczogRmVhdHVyZUZsYWdbXSxcbiAgICBwcml2YXRlIHJlYWRvbmx5IHRvb2xraXQ6IFRvb2xraXQsXG4gICAgcHJpdmF0ZSByZWFkb25seSBpb0hlbHBlcjogSW9IZWxwZXIsXG4gICkge1xuICAgIHRoaXMuYXBwID0gJyc7XG4gICAgdGhpcy5iYXNlQ29udGV4dFZhbHVlcyA9IHt9O1xuICAgIHRoaXMuYWxsU3RhY2tzID0gW107XG4gICAgdGhpcy5xdWV1ZSA9IG5ldyBQUXVldWUoeyBjb25jdXJyZW5jeTogNCB9KTtcbiAgfVxuXG4gIC8qKiBNYWluIGVudHJ5IHBvaW50IHRoYXQgcm91dGVzIHRvIGVpdGhlciBmbGFnIHNldHRpbmcgb3IgZGlzcGxheSBvcGVyYXRpb25zICovXG4gIGFzeW5jIGV4ZWN1dGUocGFyYW1zOiBGbGFnT3BlcmF0aW9uc1BhcmFtcyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGlmIChwYXJhbXMuc2V0KSB7XG4gICAgICBpZiAocGFyYW1zLkZMQUdOQU1FICYmIHBhcmFtcy52YWx1ZSkge1xuICAgICAgICBhd2FpdCB0aGlzLnNldEZsYWcocGFyYW1zKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGF3YWl0IHRoaXMuc2V0TXVsdGlwbGVGbGFncyhwYXJhbXMpO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBhd2FpdCB0aGlzLmRpc3BsYXlGbGFncyhwYXJhbXMpO1xuICAgIH1cbiAgfVxuXG4gIC8qKiBTZXRzIGEgc2luZ2xlIHNwZWNpZmljIGZsYWcgd2l0aCB2YWxpZGF0aW9uIGFuZCB1c2VyIGNvbmZpcm1hdGlvbiAqL1xuICBhc3luYyBzZXRGbGFnKHBhcmFtczogRmxhZ09wZXJhdGlvbnNQYXJhbXMpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBmbGFnTmFtZSA9IHBhcmFtcy5GTEFHTkFNRSFbMF07XG4gICAgY29uc3QgZmxhZyA9IHRoaXMuZmxhZ3MuZmluZChmID0+IGYubmFtZSA9PT0gZmxhZ05hbWUpO1xuXG4gICAgaWYgKCFmbGFnKSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSGVscGVyLmRlZmF1bHRzLmVycm9yKCdGbGFnIG5vdCBmb3VuZC4nKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBpZiAoIXRoaXMuaXNCb29sZWFuRmxhZyhmbGFnKSkge1xuICAgICAgYXdhaXQgdGhpcy5pb0hlbHBlci5kZWZhdWx0cy5lcnJvcihgRmxhZyAnJHtmbGFnTmFtZX0nIGlzIG5vdCBhIGJvb2xlYW4gZmxhZy4gT25seSBib29sZWFuIGZsYWdzIGFyZSBjdXJyZW50bHkgc3VwcG9ydGVkLmApO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IHByb3RvdHlwZVN1Y2Nlc3MgPSBhd2FpdCB0aGlzLnByb3RvdHlwZUNoYW5nZXMoW2ZsYWdOYW1lXSwgcGFyYW1zKTtcbiAgICBpZiAocHJvdG90eXBlU3VjY2Vzcykge1xuICAgICAgYXdhaXQgdGhpcy5oYW5kbGVVc2VyUmVzcG9uc2UoW2ZsYWdOYW1lXSwgcGFyYW1zKTtcbiAgICB9XG4gIH1cblxuICAvKiogU2V0cyBtdWx0aXBsZSBmbGFncyAoYWxsIG9yIHVuY29uZmlndXJlZCkgd2l0aCB2YWxpZGF0aW9uIGFuZCB1c2VyIGNvbmZpcm1hdGlvbiAqL1xuICBhc3luYyBzZXRNdWx0aXBsZUZsYWdzKHBhcmFtczogRmxhZ09wZXJhdGlvbnNQYXJhbXMpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBpZiAocGFyYW1zLmRlZmF1bHQgJiYgIXRoaXMuZmxhZ3Muc29tZShmID0+IGYudW5jb25maWd1cmVkQmVoYXZlc0xpa2UpKSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSGVscGVyLmRlZmF1bHRzLmVycm9yKCdUaGUgLS1kZWZhdWx0IG9wdGlvbnMgYXJlIG5vdCBjb21wYXRpYmxlIHdpdGggdGhlIEFXUyBDREsgbGlicmFyeSB1c2VkIGJ5IHlvdXIgYXBwbGljYXRpb24uIFBsZWFzZSB1cGdyYWRlIHRvIDIuMjEyLjAgb3IgYWJvdmUuJyk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgZmxhZ3NUb1NldCA9IHRoaXMuZ2V0RmxhZ3NUb1NldChwYXJhbXMpO1xuICAgIGNvbnN0IHByb3RvdHlwZVN1Y2Nlc3MgPSBhd2FpdCB0aGlzLnByb3RvdHlwZUNoYW5nZXMoZmxhZ3NUb1NldCwgcGFyYW1zKTtcblxuICAgIGlmIChwcm90b3R5cGVTdWNjZXNzKSB7XG4gICAgICBhd2FpdCB0aGlzLmhhbmRsZVVzZXJSZXNwb25zZShmbGFnc1RvU2V0LCBwYXJhbXMpO1xuICAgIH1cbiAgfVxuXG4gIC8qKiBEZXRlcm1pbmVzIHdoaWNoIGZsYWdzIHNob3VsZCBiZSBzZXQgYmFzZWQgb24gdGhlIHByb3ZpZGVkIHBhcmFtZXRlcnMgKi9cbiAgcHJpdmF0ZSBnZXRGbGFnc1RvU2V0KHBhcmFtczogRmxhZ09wZXJhdGlvbnNQYXJhbXMpOiBzdHJpbmdbXSB7XG4gICAgaWYgKHBhcmFtcy5hbGwgJiYgcGFyYW1zLmRlZmF1bHQpIHtcbiAgICAgIHJldHVybiB0aGlzLmZsYWdzXG4gICAgICAgIC5maWx0ZXIoZmxhZyA9PiB0aGlzLmlzQm9vbGVhbkZsYWcoZmxhZykpXG4gICAgICAgIC5tYXAoZmxhZyA9PiBmbGFnLm5hbWUpO1xuICAgIH0gZWxzZSBpZiAocGFyYW1zLmFsbCkge1xuICAgICAgcmV0dXJuIHRoaXMuZmxhZ3NcbiAgICAgICAgLmZpbHRlcihmbGFnID0+IGZsYWcudXNlclZhbHVlID09PSB1bmRlZmluZWQgfHwgIXRoaXMuaXNVc2VyVmFsdWVFcXVhbFRvUmVjb21tZW5kZWQoZmxhZykpXG4gICAgICAgIC5maWx0ZXIoZmxhZyA9PiB0aGlzLmlzQm9vbGVhbkZsYWcoZmxhZykpXG4gICAgICAgIC5tYXAoZmxhZyA9PiBmbGFnLm5hbWUpO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gdGhpcy5mbGFnc1xuICAgICAgICAuZmlsdGVyKGZsYWcgPT4gZmxhZy51c2VyVmFsdWUgPT09IHVuZGVmaW5lZClcbiAgICAgICAgLmZpbHRlcihmbGFnID0+IHRoaXMuaXNCb29sZWFuRmxhZyhmbGFnKSlcbiAgICAgICAgLm1hcChmbGFnID0+IGZsYWcubmFtZSk7XG4gICAgfVxuICB9XG5cbiAgLyoqIFNldHMgZmxhZ3MgdGhhdCBkb24ndCBjYXVzZSB0ZW1wbGF0ZSBjaGFuZ2VzICovXG4gIGFzeW5jIHNldFNhZmVGbGFncyhwYXJhbXM6IEZsYWdPcGVyYXRpb25zUGFyYW1zKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgY2RrSnNvbiA9IGF3YWl0IEpTT04ucGFyc2UoYXdhaXQgZnMucmVhZEZpbGUocGF0aC5qb2luKHByb2Nlc3MuY3dkKCksICdjZGsuanNvbicpLCAndXRmLTgnKSk7XG4gICAgdGhpcy5hcHAgPSBwYXJhbXMuYXBwIHx8IGNka0pzb24uYXBwO1xuXG4gICAgY29uc3QgaXNVc2luZ1RzTm9kZSA9IHRoaXMuYXBwLmluY2x1ZGVzKCd0cy1ub2RlJyk7XG4gICAgaWYgKGlzVXNpbmdUc05vZGUgJiYgIXRoaXMuYXBwLmluY2x1ZGVzKCctVCcpICYmICF0aGlzLmFwcC5pbmNsdWRlcygnLS10cmFuc3BpbGVPbmx5JykpIHtcbiAgICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuaW5mbygnUmVwZWF0ZWQgc3ludGhzIHdpdGggdHMtbm9kZSB3aWxsIHR5cGUtY2hlY2sgdGhlIGFwcGxpY2F0aW9uIG9uIGV2ZXJ5IHN5bnRoLiBBZGQgLS10cmFuc3BpbGVPbmx5IHRvIGNkay5qc29uXFwncyBcImFwcFwiIGNvbW1hbmQgdG8gbWFrZSB0aGlzIG9wZXJhdGlvbiBmYXN0ZXIuJyk7XG4gICAgfVxuXG4gICAgY29uc3QgdW5jb25maWd1cmVkRmxhZ3MgPSB0aGlzLmZsYWdzLmZpbHRlcihmbGFnID0+XG4gICAgICBmbGFnLnVzZXJWYWx1ZSA9PT0gdW5kZWZpbmVkICYmIHRoaXMuaXNCb29sZWFuRmxhZyhmbGFnKSk7XG5cbiAgICBpZiAodW5jb25maWd1cmVkRmxhZ3MubGVuZ3RoID09PSAwKSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSGVscGVyLmRlZmF1bHRzLmluZm8oJ0FsbCBmZWF0dXJlIGZsYWdzIGFyZSBjb25maWd1cmVkLicpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGF3YWl0IHRoaXMuaW5pdGlhbGl6ZVNhZmV0eUNoZWNrKCk7XG4gICAgY29uc3Qgc2FmZUZsYWdzID0gYXdhaXQgdGhpcy5iYXRjaFRlc3RGbGFncyh1bmNvbmZpZ3VyZWRGbGFncyk7XG4gICAgYXdhaXQgdGhpcy5jbGVhbnVwU2FmZXR5Q2hlY2soKTtcblxuICAgIGlmIChzYWZlRmxhZ3MubGVuZ3RoID4gMCkge1xuICAgICAgYXdhaXQgdGhpcy5pb0hlbHBlci5kZWZhdWx0cy5pbmZvKCdGbGFncyB0aGF0IGNhbiBiZSBzZXQgd2l0aG91dCB0ZW1wbGF0ZSBjaGFuZ2VzOicpO1xuICAgICAgZm9yIChjb25zdCBmbGFnIG9mIHNhZmVGbGFncykge1xuICAgICAgICBhd2FpdCB0aGlzLmlvSGVscGVyLmRlZmF1bHRzLmluZm8oYC0gJHtmbGFnLm5hbWV9IC0+ICR7ZmxhZy5yZWNvbW1lbmRlZFZhbHVlfWApO1xuICAgICAgfVxuICAgICAgYXdhaXQgdGhpcy5oYW5kbGVVc2VyUmVzcG9uc2Uoc2FmZUZsYWdzLm1hcChmbGFnID0+IGZsYWcubmFtZSksIHsgLi4ucGFyYW1zLCByZWNvbW1lbmRlZDogdHJ1ZSB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgYXdhaXQgdGhpcy5pb0hlbHBlci5kZWZhdWx0cy5pbmZvKCdObyBtb3JlIGZsYWdzIGNhbiBiZSBzZXQgd2l0aG91dCBjYXVzaW5nIHRlbXBsYXRlIGNoYW5nZXMuJyk7XG4gICAgfVxuICB9XG5cbiAgLyoqIEluaXRpYWxpemVzIHRoZSBzYWZldHkgY2hlY2sgYnkgcmVhZGluZyBjb250ZXh0IGFuZCBzeW50aGVzaXppbmcgYmFzZWxpbmUgdGVtcGxhdGVzICovXG4gIHByaXZhdGUgYXN5bmMgaW5pdGlhbGl6ZVNhZmV0eUNoZWNrKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGJhc2VDb250ZXh0ID0gbmV3IENka0FwcE11bHRpQ29udGV4dChwcm9jZXNzLmN3ZCgpKTtcbiAgICB0aGlzLmJhc2VDb250ZXh0VmFsdWVzID0gYXdhaXQgYmFzZUNvbnRleHQucmVhZCgpO1xuXG4gICAgdGhpcy5iYXNlbGluZVRlbXBEaXIgPSBmcy5ta2R0ZW1wU3luYyhwYXRoLmpvaW4ob3MudG1wZGlyKCksICdjZGstYmFzZWxpbmUtJykpO1xuICAgIGNvbnN0IGJhc2VTb3VyY2UgPSBhd2FpdCB0aGlzLnRvb2xraXQuZnJvbUNka0FwcCh0aGlzLmFwcCwge1xuICAgICAgY29udGV4dFN0b3JlOiBiYXNlQ29udGV4dCxcbiAgICAgIG91dGRpcjogdGhpcy5iYXNlbGluZVRlbXBEaXIsXG4gICAgfSk7XG5cbiAgICBjb25zdCBiYXNlQ3ggPSBhd2FpdCB0aGlzLnRvb2xraXQuc3ludGgoYmFzZVNvdXJjZSk7XG4gICAgY29uc3QgYmFzZUFzc2VtYmx5ID0gYmFzZUN4LmNsb3VkQXNzZW1ibHk7XG4gICAgdGhpcy5hbGxTdGFja3MgPSBiYXNlQXNzZW1ibHkuc3RhY2tzUmVjdXJzaXZlbHk7XG4gICAgdGhpcy5xdWV1ZSA9IG5ldyBQUXVldWUoeyBjb25jdXJyZW5jeTogNCB9KTtcbiAgfVxuXG4gIC8qKiBDbGVhbnMgdXAgdGVtcG9yYXJ5IGRpcmVjdG9yaWVzIGNyZWF0ZWQgZHVyaW5nIHNhZmV0eSBjaGVja3MgKi9cbiAgcHJpdmF0ZSBhc3luYyBjbGVhbnVwU2FmZXR5Q2hlY2soKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgaWYgKHRoaXMuYmFzZWxpbmVUZW1wRGlyKSB7XG4gICAgICBhd2FpdCBmcy5yZW1vdmUodGhpcy5iYXNlbGluZVRlbXBEaXIpO1xuICAgICAgdGhpcy5iYXNlbGluZVRlbXBEaXIgPSB1bmRlZmluZWQ7XG4gICAgfVxuICB9XG5cbiAgLyoqIFRlc3RzIG11bHRpcGxlIGZsYWdzIHRvZ2V0aGVyIGFuZCBpc29sYXRlcyB1bnNhZmUgb25lcyB1c2luZyBiaW5hcnkgc2VhcmNoICovXG4gIHByaXZhdGUgYXN5bmMgYmF0Y2hUZXN0RmxhZ3MoZmxhZ3M6IEZlYXR1cmVGbGFnW10pOiBQcm9taXNlPEZlYXR1cmVGbGFnW10+IHtcbiAgICBpZiAoZmxhZ3MubGVuZ3RoID09PSAwKSByZXR1cm4gW107XG5cbiAgICBjb25zdCBhbGxGbGFnc0NvbnRleHQgPSB7IC4uLnRoaXMuYmFzZUNvbnRleHRWYWx1ZXMgfTtcbiAgICBmbGFncy5mb3JFYWNoKGZsYWcgPT4ge1xuICAgICAgYWxsRmxhZ3NDb250ZXh0W2ZsYWcubmFtZV0gPSBmbGFnLnJlY29tbWVuZGVkVmFsdWU7XG4gICAgfSk7XG5cbiAgICBjb25zdCBhbGxTYWZlID0gYXdhaXQgdGhpcy50ZXN0QmF0Y2goYWxsRmxhZ3NDb250ZXh0KTtcbiAgICBpZiAoYWxsU2FmZSkgcmV0dXJuIGZsYWdzO1xuXG4gICAgcmV0dXJuIHRoaXMuaXNvbGF0ZVVuc2FmZUZsYWdzKGZsYWdzKTtcbiAgfVxuXG4gIC8qKiBUZXN0cyBpZiBhIHNldCBvZiBjb250ZXh0IHZhbHVlcyBjYXVzZXMgdGVtcGxhdGUgY2hhbmdlcyBieSBzeW50aGVzaXppbmcgYW5kIGRpZmZpbmcgKi9cbiAgcHJpdmF0ZSBhc3luYyB0ZXN0QmF0Y2goY29udGV4dFZhbHVlczogUmVjb3JkPHN0cmluZywgYW55Pik6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIGNvbnN0IHRlc3RDb250ZXh0ID0gbmV3IE1lbW9yeUNvbnRleHQoY29udGV4dFZhbHVlcyk7XG4gICAgY29uc3QgdGVtcERpciA9IGZzLm1rZHRlbXBTeW5jKHBhdGguam9pbihvcy50bXBkaXIoKSwgJ2Nkay10ZXN0LScpKTtcbiAgICBjb25zdCB0ZXN0U291cmNlID0gYXdhaXQgdGhpcy50b29sa2l0LmZyb21DZGtBcHAodGhpcy5hcHAsIHtcbiAgICAgIGNvbnRleHRTdG9yZTogdGVzdENvbnRleHQsXG4gICAgICBvdXRkaXI6IHRlbXBEaXIsXG4gICAgfSk7XG5cbiAgICBjb25zdCB0ZXN0Q3ggPSBhd2FpdCB0aGlzLnRvb2xraXQuc3ludGgodGVzdFNvdXJjZSk7XG5cbiAgICB0cnkge1xuICAgICAgZm9yIChjb25zdCBzdGFjayBvZiB0aGlzLmFsbFN0YWNrcykge1xuICAgICAgICBjb25zdCB0ZW1wbGF0ZVBhdGggPSBzdGFjay50ZW1wbGF0ZUZ1bGxQYXRoO1xuICAgICAgICBjb25zdCBkaWZmID0gYXdhaXQgdGhpcy50b29sa2l0LmRpZmYodGVzdEN4LCB7XG4gICAgICAgICAgbWV0aG9kOiBEaWZmTWV0aG9kLkxvY2FsRmlsZSh0ZW1wbGF0ZVBhdGgpLFxuICAgICAgICAgIHN0YWNrczoge1xuICAgICAgICAgICAgc3RyYXRlZ3k6IFN0YWNrU2VsZWN0aW9uU3RyYXRlZ3kuUEFUVEVSTl9NVVNUX01BVENIX1NJTkdMRSxcbiAgICAgICAgICAgIHBhdHRlcm5zOiBbc3RhY2suaGllcmFyY2hpY2FsSWRdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0pO1xuXG4gICAgICAgIGZvciAoY29uc3Qgc3RhY2tEaWZmIG9mIE9iamVjdC52YWx1ZXMoZGlmZikpIHtcbiAgICAgICAgICBpZiAoc3RhY2tEaWZmLmRpZmZlcmVuY2VDb3VudCA+IDApIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH0gZmluYWxseSB7XG4gICAgICBhd2FpdCBmcy5yZW1vdmUodGVtcERpcik7XG4gICAgfVxuICB9XG5cbiAgLyoqIFVzZXMgYmluYXJ5IHNlYXJjaCB0byBpc29sYXRlIHdoaWNoIGZsYWdzIGFyZSBzYWZlIHRvIHNldCB3aXRob3V0IHRlbXBsYXRlIGNoYW5nZXMgKi9cbiAgcHJpdmF0ZSBhc3luYyBpc29sYXRlVW5zYWZlRmxhZ3MoZmxhZ3M6IEZlYXR1cmVGbGFnW10pOiBQcm9taXNlPEZlYXR1cmVGbGFnW10+IHtcbiAgICBjb25zdCBzYWZlRmxhZ3M6IEZlYXR1cmVGbGFnW10gPSBbXTtcblxuICAgIGNvbnN0IHByb2Nlc3NCYXRjaCA9IGFzeW5jIChiYXRjaDogRmVhdHVyZUZsYWdbXSwgY29udGV4dFZhbHVlczogUmVjb3JkPHN0cmluZywgYW55Pik6IFByb21pc2U8dm9pZD4gPT4ge1xuICAgICAgaWYgKGJhdGNoLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICBjb25zdCBpc1NhZmUgPSBhd2FpdCB0aGlzLnRlc3RCYXRjaChcbiAgICAgICAgICB7IC4uLmNvbnRleHRWYWx1ZXMsIFtiYXRjaFswXS5uYW1lXTogYmF0Y2hbMF0ucmVjb21tZW5kZWRWYWx1ZSB9LFxuICAgICAgICApO1xuICAgICAgICBpZiAoaXNTYWZlKSBzYWZlRmxhZ3MucHVzaChiYXRjaFswXSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgY29uc3QgYmF0Y2hDb250ZXh0ID0geyAuLi5jb250ZXh0VmFsdWVzIH07XG4gICAgICBiYXRjaC5mb3JFYWNoKGZsYWcgPT4ge1xuICAgICAgICBiYXRjaENvbnRleHRbZmxhZy5uYW1lXSA9IGZsYWcucmVjb21tZW5kZWRWYWx1ZTtcbiAgICAgIH0pO1xuXG4gICAgICBjb25zdCBpc1NhZmVCYXRjaCA9IGF3YWl0IHRoaXMudGVzdEJhdGNoKGJhdGNoQ29udGV4dCk7XG4gICAgICBpZiAoaXNTYWZlQmF0Y2gpIHtcbiAgICAgICAgc2FmZUZsYWdzLnB1c2goLi4uYmF0Y2gpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IG1pZCA9IE1hdGguZmxvb3IoYmF0Y2gubGVuZ3RoIC8gMik7XG4gICAgICBjb25zdCBsZWZ0ID0gYmF0Y2guc2xpY2UoMCwgbWlkKTtcbiAgICAgIGNvbnN0IHJpZ2h0ID0gYmF0Y2guc2xpY2UobWlkKTtcblxuICAgICAgdm9pZCB0aGlzLnF1ZXVlLmFkZCgoKSA9PiBwcm9jZXNzQmF0Y2gobGVmdCwgY29udGV4dFZhbHVlcykpO1xuICAgICAgdm9pZCB0aGlzLnF1ZXVlLmFkZCgoKSA9PiBwcm9jZXNzQmF0Y2gocmlnaHQsIGNvbnRleHRWYWx1ZXMpKTtcbiAgICB9O1xuXG4gICAgdm9pZCB0aGlzLnF1ZXVlLmFkZCgoKSA9PiBwcm9jZXNzQmF0Y2goZmxhZ3MsIHRoaXMuYmFzZUNvbnRleHRWYWx1ZXMpKTtcbiAgICBhd2FpdCB0aGlzLnF1ZXVlLm9uSWRsZSgpO1xuICAgIHJldHVybiBzYWZlRmxhZ3M7XG4gIH1cblxuICAvKiogUHJvdG90eXBlcyBmbGFnIGNoYW5nZXMgYnkgc3ludGhlc2l6aW5nIHRlbXBsYXRlcyBhbmQgc2hvd2luZyBkaWZmcyB0byB0aGUgdXNlciAqL1xuICBwcml2YXRlIGFzeW5jIHByb3RvdHlwZUNoYW5nZXMoZmxhZ05hbWVzOiBzdHJpbmdbXSwgcGFyYW1zOiBGbGFnT3BlcmF0aW9uc1BhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIGNvbnN0IGJhc2VDb250ZXh0ID0gbmV3IENka0FwcE11bHRpQ29udGV4dChwcm9jZXNzLmN3ZCgpKTtcbiAgICBjb25zdCBiYXNlQ29udGV4dFZhbHVlcyA9IGF3YWl0IGJhc2VDb250ZXh0LnJlYWQoKTtcbiAgICBjb25zdCBtZW1vcnlDb250ZXh0ID0gbmV3IE1lbW9yeUNvbnRleHQoYmFzZUNvbnRleHRWYWx1ZXMpO1xuXG4gICAgY29uc3QgY2RrSnNvbiA9IGF3YWl0IEpTT04ucGFyc2UoYXdhaXQgZnMucmVhZEZpbGUocGF0aC5qb2luKHByb2Nlc3MuY3dkKCksICdjZGsuanNvbicpLCAndXRmLTgnKSk7XG4gICAgY29uc3QgYXBwID0gY2RrSnNvbi5hcHA7XG5cbiAgICBjb25zdCBzb3VyY2UgPSBhd2FpdCB0aGlzLnRvb2xraXQuZnJvbUNka0FwcChhcHAsIHtcbiAgICAgIGNvbnRleHRTdG9yZTogYmFzZUNvbnRleHQsXG4gICAgICBvdXRkaXI6IGZzLm1rZHRlbXBTeW5jKHBhdGguam9pbihvcy50bXBkaXIoKSwgJ2Nkay1vcmlnaW5hbC0nKSksXG4gICAgfSk7XG5cbiAgICBjb25zdCB1cGRhdGVPYmogPSBhd2FpdCB0aGlzLmJ1aWxkVXBkYXRlT2JqZWN0KGZsYWdOYW1lcywgcGFyYW1zLCBiYXNlQ29udGV4dFZhbHVlcyk7XG4gICAgaWYgKCF1cGRhdGVPYmopIHJldHVybiBmYWxzZTtcblxuICAgIGF3YWl0IG1lbW9yeUNvbnRleHQudXBkYXRlKHVwZGF0ZU9iaik7XG4gICAgY29uc3QgY3ggPSBhd2FpdCB0aGlzLnRvb2xraXQuc3ludGgoc291cmNlKTtcbiAgICBjb25zdCBhc3NlbWJseSA9IGN4LmNsb3VkQXNzZW1ibHk7XG5cbiAgICBjb25zdCBtb2RpZmllZFNvdXJjZSA9IGF3YWl0IHRoaXMudG9vbGtpdC5mcm9tQ2RrQXBwKGFwcCwge1xuICAgICAgY29udGV4dFN0b3JlOiBtZW1vcnlDb250ZXh0LFxuICAgICAgb3V0ZGlyOiBmcy5ta2R0ZW1wU3luYyhwYXRoLmpvaW4ob3MudG1wZGlyKCksICdjZGstdGVtcC0nKSksXG4gICAgfSk7XG5cbiAgICBjb25zdCBtb2RpZmllZEN4ID0gYXdhaXQgdGhpcy50b29sa2l0LnN5bnRoKG1vZGlmaWVkU291cmNlKTtcbiAgICBjb25zdCBhbGxTdGFja3MgPSBhc3NlbWJseS5zdGFja3NSZWN1cnNpdmVseTtcblxuICAgIGZvciAoY29uc3Qgc3RhY2sgb2YgYWxsU3RhY2tzKSB7XG4gICAgICBjb25zdCB0ZW1wbGF0ZVBhdGggPSBzdGFjay50ZW1wbGF0ZUZ1bGxQYXRoO1xuICAgICAgYXdhaXQgdGhpcy50b29sa2l0LmRpZmYobW9kaWZpZWRDeCwge1xuICAgICAgICBtZXRob2Q6IERpZmZNZXRob2QuTG9jYWxGaWxlKHRlbXBsYXRlUGF0aCksXG4gICAgICAgIHN0YWNrczoge1xuICAgICAgICAgIHN0cmF0ZWd5OiBTdGFja1NlbGVjdGlvblN0cmF0ZWd5LlBBVFRFUk5fTVVTVF9NQVRDSF9TSU5HTEUsXG4gICAgICAgICAgcGF0dGVybnM6IFtzdGFjay5oaWVyYXJjaGljYWxJZF0sXG4gICAgICAgIH0sXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBhd2FpdCB0aGlzLmRpc3BsYXlGbGFnQ2hhbmdlcyh1cGRhdGVPYmosIGJhc2VDb250ZXh0VmFsdWVzKTtcbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuXG4gIC8qKiBEaXNwbGF5cyBhIHN1bW1hcnkgb2YgZmxhZyBjaGFuZ2VzIHNob3dpbmcgb2xkIGFuZCBuZXcgdmFsdWVzICovXG4gIHByaXZhdGUgYXN5bmMgZGlzcGxheUZsYWdDaGFuZ2VzKHVwZGF0ZU9iajogUmVjb3JkPHN0cmluZywgYm9vbGVhbj4sIGJhc2VDb250ZXh0VmFsdWVzOiBSZWNvcmQ8c3RyaW5nLCBhbnk+KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5pb0hlbHBlci5kZWZhdWx0cy5pbmZvKCdcXG5GbGFnIGNoYW5nZXM6Jyk7XG4gICAgZm9yIChjb25zdCBbZmxhZ05hbWUsIG5ld1ZhbHVlXSBvZiBPYmplY3QuZW50cmllcyh1cGRhdGVPYmopKSB7XG4gICAgICBjb25zdCBjdXJyZW50VmFsdWUgPSBiYXNlQ29udGV4dFZhbHVlc1tmbGFnTmFtZV07XG4gICAgICBjb25zdCBjdXJyZW50RGlzcGxheSA9IGN1cnJlbnRWYWx1ZSA9PT0gdW5kZWZpbmVkID8gJzx1bnNldD4nIDogU3RyaW5nKGN1cnJlbnRWYWx1ZSk7XG4gICAgICBhd2FpdCB0aGlzLmlvSGVscGVyLmRlZmF1bHRzLmluZm8oYCAgJHtmbGFnTmFtZX06ICR7Y3VycmVudERpc3BsYXl9IOKGkiAke25ld1ZhbHVlfWApO1xuICAgIH1cbiAgfVxuXG4gIC8qKiBCdWlsZHMgdGhlIHVwZGF0ZSBvYmplY3Qgd2l0aCBuZXcgZmxhZyB2YWx1ZXMgYmFzZWQgb24gcGFyYW1ldGVycyBhbmQgY3VycmVudCBjb250ZXh0ICovXG4gIHByaXZhdGUgYXN5bmMgYnVpbGRVcGRhdGVPYmplY3QoZmxhZ05hbWVzOiBzdHJpbmdbXSwgcGFyYW1zOiBGbGFnT3BlcmF0aW9uc1BhcmFtcywgYmFzZUNvbnRleHRWYWx1ZXM6IFJlY29yZDxzdHJpbmcsIGFueT4pXG4gICAgOiBQcm9taXNlPFJlY29yZDxzdHJpbmcsIGJvb2xlYW4+IHwgbnVsbD4ge1xuICAgIGNvbnN0IHVwZGF0ZU9iajogUmVjb3JkPHN0cmluZywgYm9vbGVhbj4gPSB7fTtcblxuICAgIGlmIChmbGFnTmFtZXMubGVuZ3RoID09PSAxICYmIHBhcmFtcy52YWx1ZSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICBjb25zdCBmbGFnTmFtZSA9IGZsYWdOYW1lc1swXTtcbiAgICAgIGNvbnN0IGJvb2xWYWx1ZSA9IHBhcmFtcy52YWx1ZSA9PT0gJ3RydWUnO1xuICAgICAgaWYgKGJhc2VDb250ZXh0VmFsdWVzW2ZsYWdOYW1lXSA9PT0gYm9vbFZhbHVlKSB7XG4gICAgICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuaW5mbygnRmxhZyBpcyBhbHJlYWR5IHNldCB0byB0aGUgc3BlY2lmaWVkIHZhbHVlLiBObyBjaGFuZ2VzIG5lZWRlZC4nKTtcbiAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICB9XG4gICAgICB1cGRhdGVPYmpbZmxhZ05hbWVdID0gYm9vbFZhbHVlO1xuICAgIH0gZWxzZSB7XG4gICAgICBmb3IgKGNvbnN0IGZsYWdOYW1lIG9mIGZsYWdOYW1lcykge1xuICAgICAgICBjb25zdCBmbGFnID0gdGhpcy5mbGFncy5maW5kKGYgPT4gZi5uYW1lID09PSBmbGFnTmFtZSk7XG4gICAgICAgIGlmICghZmxhZykge1xuICAgICAgICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuZXJyb3IoYEZsYWcgJHtmbGFnTmFtZX0gbm90IGZvdW5kLmApO1xuICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IG5ld1ZhbHVlID0gcGFyYW1zLnJlY29tbWVuZGVkXG4gICAgICAgICAgPyBmbGFnLnJlY29tbWVuZGVkVmFsdWUgYXMgYm9vbGVhblxuICAgICAgICAgIDogU3RyaW5nKGZsYWcudW5jb25maWd1cmVkQmVoYXZlc0xpa2U/LnYyKSA9PT0gJ3RydWUnO1xuICAgICAgICB1cGRhdGVPYmpbZmxhZ05hbWVdID0gbmV3VmFsdWU7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiB1cGRhdGVPYmo7XG4gIH1cblxuICAvKiogUHJvbXB0cyB1c2VyIGZvciBjb25maXJtYXRpb24gYW5kIGFwcGxpZXMgY2hhbmdlcyBpZiBhY2NlcHRlZCAqL1xuICBwcml2YXRlIGFzeW5jIGhhbmRsZVVzZXJSZXNwb25zZShmbGFnTmFtZXM6IHN0cmluZ1tdLCBwYXJhbXM6IEZsYWdPcGVyYXRpb25zUGFyYW1zKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgdXNlckFjY2VwdGVkID0gYXdhaXQgdGhpcy5pb0hlbHBlci5yZXF1ZXN0UmVzcG9uc2Uoe1xuICAgICAgdGltZTogbmV3IERhdGUoKSxcbiAgICAgIGxldmVsOiAnaW5mbycsXG4gICAgICBjb2RlOiAnQ0RLX1RPT0xLSVRfSTkzMDAnLFxuICAgICAgbWVzc2FnZTogJ0RvIHlvdSB3YW50IHRvIGFjY2VwdCB0aGVzZSBjaGFuZ2VzPycsXG4gICAgICBkYXRhOiB7XG4gICAgICAgIGZsYWdOYW1lcyxcbiAgICAgICAgcmVzcG9uc2VEZXNjcmlwdGlvbjogJ0VudGVyIFwieVwiIHRvIGFwcGx5IGNoYW5nZXMgb3IgXCJuXCIgdG8gY2FuY2VsJyxcbiAgICAgIH0sXG4gICAgICBkZWZhdWx0UmVzcG9uc2U6IGZhbHNlLFxuICAgIH0pO1xuXG4gICAgaWYgKHVzZXJBY2NlcHRlZCkge1xuICAgICAgYXdhaXQgdGhpcy5tb2RpZnlWYWx1ZXMoZmxhZ05hbWVzLCBwYXJhbXMpO1xuICAgICAgYXdhaXQgdGhpcy5pb0hlbHBlci5kZWZhdWx0cy5pbmZvKCdGbGFnIHZhbHVlKHMpIHVwZGF0ZWQgc3VjY2Vzc2Z1bGx5LicpO1xuICAgIH0gZWxzZSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSGVscGVyLmRlZmF1bHRzLmluZm8oJ09wZXJhdGlvbiBjYW5jZWxsZWQnKTtcbiAgICB9XG5cbiAgICBhd2FpdCB0aGlzLmNsZWFudXBUZW1wRGlyZWN0b3JpZXMoKTtcbiAgfVxuXG4gIC8qKiBSZW1vdmVzIHRlbXBvcmFyeSBkaXJlY3RvcmllcyBjcmVhdGVkIGR1cmluZyBmbGFnIG9wZXJhdGlvbnMgKi9cbiAgcHJpdmF0ZSBhc3luYyBjbGVhbnVwVGVtcERpcmVjdG9yaWVzKCk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IG9yaWdpbmFsRGlyID0gcGF0aC5qb2luKHByb2Nlc3MuY3dkKCksICdvcmlnaW5hbCcpO1xuICAgIGNvbnN0IHRlbXBEaXIgPSBwYXRoLmpvaW4ocHJvY2Vzcy5jd2QoKSwgJ3RlbXAnKTtcbiAgICBhd2FpdCBmcy5yZW1vdmUob3JpZ2luYWxEaXIpO1xuICAgIGF3YWl0IGZzLnJlbW92ZSh0ZW1wRGlyKTtcbiAgfVxuXG4gIC8qKiBBY3R1YWxseSBtb2RpZmllcyB0aGUgY2RrLmpzb24gZmlsZSB3aXRoIHRoZSBuZXcgZmxhZyB2YWx1ZXMgKi9cbiAgcHJpdmF0ZSBhc3luYyBtb2RpZnlWYWx1ZXMoZmxhZ05hbWVzOiBzdHJpbmdbXSwgcGFyYW1zOiBGbGFnT3BlcmF0aW9uc1BhcmFtcyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IGNka0pzb25QYXRoID0gcGF0aC5qb2luKHByb2Nlc3MuY3dkKCksICdjZGsuanNvbicpO1xuICAgIGNvbnN0IGNka0pzb25Db250ZW50ID0gYXdhaXQgZnMucmVhZEZpbGUoY2RrSnNvblBhdGgsICd1dGYtOCcpO1xuICAgIGNvbnN0IGNka0pzb24gPSBKU09OLnBhcnNlKGNka0pzb25Db250ZW50KTtcblxuICAgIGlmIChmbGFnTmFtZXMubGVuZ3RoID09PSAxICYmICFwYXJhbXMuc2FmZSkge1xuICAgICAgY29uc3QgYm9vbFZhbHVlID0gcGFyYW1zLnZhbHVlID09PSAndHJ1ZSc7XG4gICAgICBjZGtKc29uLmNvbnRleHRbU3RyaW5nKGZsYWdOYW1lc1swXSldID0gYm9vbFZhbHVlO1xuICAgICAgYXdhaXQgdGhpcy5pb0hlbHBlci5kZWZhdWx0cy5pbmZvKGBTZXR0aW5nIGZsYWcgJyR7ZmxhZ05hbWVzfScgdG86ICR7Ym9vbFZhbHVlfWApO1xuICAgIH0gZWxzZSB7XG4gICAgICBmb3IgKGNvbnN0IGZsYWdOYW1lIG9mIGZsYWdOYW1lcykge1xuICAgICAgICBjb25zdCBmbGFnID0gdGhpcy5mbGFncy5maW5kKGYgPT4gZi5uYW1lID09PSBmbGFnTmFtZSk7XG4gICAgICAgIGNvbnN0IG5ld1ZhbHVlID0gcGFyYW1zLnJlY29tbWVuZGVkIHx8IHBhcmFtcy5zYWZlXG4gICAgICAgICAgPyBmbGFnIS5yZWNvbW1lbmRlZFZhbHVlIGFzIGJvb2xlYW5cbiAgICAgICAgICA6IFN0cmluZyhmbGFnIS51bmNvbmZpZ3VyZWRCZWhhdmVzTGlrZT8udjIpID09PSAndHJ1ZSc7XG4gICAgICAgIGNka0pzb24uY29udGV4dFtmbGFnTmFtZV0gPSBuZXdWYWx1ZTtcbiAgICAgIH1cbiAgICB9XG4gICAgYXdhaXQgZnMud3JpdGVGaWxlKGNka0pzb25QYXRoLCBKU09OLnN0cmluZ2lmeShjZGtKc29uLCBudWxsLCAyKSwgJ3V0Zi04Jyk7XG4gIH1cblxuICAvKiogRGlzcGxheXMgZmxhZ3MgaW4gYSB0YWJsZSBmb3JtYXQsIGVpdGhlciBzcGVjaWZpYyBmbGFncyBvciBmaWx0ZXJlZCBieSBjcml0ZXJpYSAqL1xuICBhc3luYyBkaXNwbGF5RmxhZ3MocGFyYW1zOiBGbGFnT3BlcmF0aW9uc1BhcmFtcyk6IFByb21pc2U8dm9pZD4ge1xuICAgIGNvbnN0IHsgRkxBR05BTUUsIGFsbCB9ID0gcGFyYW1zO1xuXG4gICAgaWYgKEZMQUdOQU1FICYmIEZMQUdOQU1FLmxlbmd0aCA+IDApIHtcbiAgICAgIGF3YWl0IHRoaXMuZGlzcGxheVNwZWNpZmljRmxhZ3MoRkxBR05BTUUpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IGZsYWdzVG9EaXNwbGF5ID0gYWxsID8gdGhpcy5mbGFncyA6IHRoaXMuZmxhZ3MuZmlsdGVyKGZsYWcgPT5cbiAgICAgIGZsYWcudXNlclZhbHVlID09PSB1bmRlZmluZWQgfHwgIXRoaXMuaXNVc2VyVmFsdWVFcXVhbFRvUmVjb21tZW5kZWQoZmxhZykpO1xuXG4gICAgYXdhaXQgdGhpcy5kaXNwbGF5RmxhZ1RhYmxlKGZsYWdzVG9EaXNwbGF5KTtcblxuICAgIC8vIEFkZCBoZWxwZnVsIG1lc3NhZ2UgYWZ0ZXIgZW1wdHkgdGFibGUgd2hlbiBub3QgdXNpbmcgLS1hbGxcbiAgICBpZiAoIWFsbCAmJiBmbGFnc1RvRGlzcGxheS5sZW5ndGggPT09IDApIHtcbiAgICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuaW5mbygnJyk7XG4gICAgICBhd2FpdCB0aGlzLmlvSGVscGVyLmRlZmF1bHRzLmluZm8oJ+KchSBBbGwgZmVhdHVyZSBmbGFncyBhcmUgYWxyZWFkeSBzZXQgdG8gdGhlaXIgcmVjb21tZW5kZWQgdmFsdWVzLicpO1xuICAgICAgYXdhaXQgdGhpcy5pb0hlbHBlci5kZWZhdWx0cy5pbmZvKCdVc2UgXFwnY2RrIGZsYWdzIC0tYWxsIC0tdW5zdGFibGU9ZmxhZ3NcXCcgdG8gc2VlIGFsbCBmbGFncyBhbmQgdGhlaXIgY3VycmVudCB2YWx1ZXMuJyk7XG4gICAgfVxuICB9XG5cbiAgLyoqIERpc3BsYXlzIGRldGFpbGVkIGluZm9ybWF0aW9uIGZvciBzcGVjaWZpYyBmbGFncyBtYXRjaGluZyB0aGUgZ2l2ZW4gbmFtZXMgKi9cbiAgcHJpdmF0ZSBhc3luYyBkaXNwbGF5U3BlY2lmaWNGbGFncyhmbGFnTmFtZXM6IHN0cmluZ1tdKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgbWF0Y2hpbmdGbGFncyA9IHRoaXMuZmxhZ3MuZmlsdGVyKGYgPT5cbiAgICAgIGZsYWdOYW1lcy5zb21lKHNlYXJjaFRlcm0gPT4gZi5uYW1lLnRvTG93ZXJDYXNlKCkuaW5jbHVkZXMoc2VhcmNoVGVybS50b0xvd2VyQ2FzZSgpKSkpO1xuXG4gICAgaWYgKG1hdGNoaW5nRmxhZ3MubGVuZ3RoID09PSAwKSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSGVscGVyLmRlZmF1bHRzLmVycm9yKGBGbGFnIG1hdGNoaW5nIFwiJHtmbGFnTmFtZXMuam9pbignLCAnKX1cIiBub3QgZm91bmQuYCk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgaWYgKG1hdGNoaW5nRmxhZ3MubGVuZ3RoID09PSAxKSB7XG4gICAgICBjb25zdCBmbGFnID0gbWF0Y2hpbmdGbGFnc1swXTtcbiAgICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuaW5mbyhgRmxhZyBuYW1lOiAke2ZsYWcubmFtZX1gKTtcbiAgICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuaW5mbyhgRGVzY3JpcHRpb246ICR7ZmxhZy5leHBsYW5hdGlvbn1gKTtcbiAgICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuaW5mbyhgUmVjb21tZW5kZWQgdmFsdWU6ICR7ZmxhZy5yZWNvbW1lbmRlZFZhbHVlfWApO1xuICAgICAgYXdhaXQgdGhpcy5pb0hlbHBlci5kZWZhdWx0cy5pbmZvKGBVc2VyIHZhbHVlOiAke2ZsYWcudXNlclZhbHVlfWApO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuaW5mbyhgRm91bmQgJHttYXRjaGluZ0ZsYWdzLmxlbmd0aH0gZmxhZ3MgbWF0Y2hpbmcgXCIke2ZsYWdOYW1lcy5qb2luKCcsICcpfVwiOmApO1xuICAgIGF3YWl0IHRoaXMuZGlzcGxheUZsYWdUYWJsZShtYXRjaGluZ0ZsYWdzKTtcbiAgfVxuXG4gIC8qKiBSZXR1cm5zIHNvcnQgb3JkZXIgZm9yIGZsYWdzICovXG4gIHByaXZhdGUgZ2V0RmxhZ1NvcnRPcmRlcihmbGFnOiBGZWF0dXJlRmxhZyk6IG51bWJlciB7XG4gICAgaWYgKGZsYWcudXNlclZhbHVlID09PSB1bmRlZmluZWQpIHJldHVybiAzO1xuICAgIGlmICh0aGlzLmlzVXNlclZhbHVlRXF1YWxUb1JlY29tbWVuZGVkKGZsYWcpKSByZXR1cm4gMTtcbiAgICByZXR1cm4gMjtcbiAgfVxuXG4gIC8qKiBEaXNwbGF5cyBmbGFncyBpbiBhIGZvcm1hdHRlZCB0YWJsZSBncm91cGVkIGJ5IG1vZHVsZSBhbmQgc29ydGVkICovXG4gIGFzeW5jIGRpc3BsYXlGbGFnVGFibGUoZmxhZ3M6IEZlYXR1cmVGbGFnW10pOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBzb3J0ZWRGbGFncyA9IFsuLi5mbGFnc10uc29ydCgoYSwgYikgPT4ge1xuICAgICAgY29uc3Qgb3JkZXJBID0gdGhpcy5nZXRGbGFnU29ydE9yZGVyKGEpO1xuICAgICAgY29uc3Qgb3JkZXJCID0gdGhpcy5nZXRGbGFnU29ydE9yZGVyKGIpO1xuXG4gICAgICBpZiAob3JkZXJBICE9PSBvcmRlckIpIHJldHVybiBvcmRlckEgLSBvcmRlckI7XG4gICAgICBpZiAoYS5tb2R1bGUgIT09IGIubW9kdWxlKSByZXR1cm4gYS5tb2R1bGUubG9jYWxlQ29tcGFyZShiLm1vZHVsZSk7XG4gICAgICByZXR1cm4gYS5uYW1lLmxvY2FsZUNvbXBhcmUoYi5uYW1lKTtcbiAgICB9KTtcblxuICAgIGNvbnN0IHJvd3M6IHN0cmluZ1tdW10gPSBbWydGZWF0dXJlIEZsYWcgTmFtZScsICdSZWNvbW1lbmRlZCBWYWx1ZScsICdVc2VyIFZhbHVlJ11dO1xuICAgIGxldCBjdXJyZW50TW9kdWxlID0gJyc7XG5cbiAgICBzb3J0ZWRGbGFncy5mb3JFYWNoKChmbGFnKSA9PiB7XG4gICAgICBpZiAoZmxhZy5tb2R1bGUgIT09IGN1cnJlbnRNb2R1bGUpIHtcbiAgICAgICAgcm93cy5wdXNoKFtjaGFsay5ib2xkKGBNb2R1bGU6ICR7ZmxhZy5tb2R1bGV9YCksICcnLCAnJ10pO1xuICAgICAgICBjdXJyZW50TW9kdWxlID0gZmxhZy5tb2R1bGU7XG4gICAgICB9XG4gICAgICByb3dzLnB1c2goW1xuICAgICAgICBgICAke2ZsYWcubmFtZX1gLFxuICAgICAgICBTdHJpbmcoZmxhZy5yZWNvbW1lbmRlZFZhbHVlKSxcbiAgICAgICAgZmxhZy51c2VyVmFsdWUgPT09IHVuZGVmaW5lZCA/ICc8dW5zZXQ+JyA6IFN0cmluZyhmbGFnLnVzZXJWYWx1ZSksXG4gICAgICBdKTtcbiAgICB9KTtcblxuICAgIGNvbnN0IGZvcm1hdHRlZFRhYmxlID0gZm9ybWF0VGFibGUocm93cywgdW5kZWZpbmVkLCB0cnVlKTtcbiAgICBhd2FpdCB0aGlzLmlvSGVscGVyLmRlZmF1bHRzLmluZm8oZm9ybWF0dGVkVGFibGUpO1xuICB9XG5cbiAgLyoqIENoZWNrcyBpZiBhIGZsYWcgaGFzIGEgYm9vbGVhbiByZWNvbW1lbmRlZCB2YWx1ZSAqL1xuICBpc0Jvb2xlYW5GbGFnKGZsYWc6IEZlYXR1cmVGbGFnKTogYm9vbGVhbiB7XG4gICAgY29uc3QgcmVjb21tZW5kZWQgPSBmbGFnLnJlY29tbWVuZGVkVmFsdWU7XG4gICAgcmV0dXJuIHR5cGVvZiByZWNvbW1lbmRlZCA9PT0gJ2Jvb2xlYW4nIHx8XG4gICAgICByZWNvbW1lbmRlZCA9PT0gJ3RydWUnIHx8XG4gICAgICByZWNvbW1lbmRlZCA9PT0gJ2ZhbHNlJztcbiAgfVxuXG4gIC8qKiBDaGVja3MgaWYgdGhlIHVzZXIncyBjdXJyZW50IHZhbHVlIG1hdGNoZXMgdGhlIHJlY29tbWVuZGVkIHZhbHVlICovXG4gIHByaXZhdGUgaXNVc2VyVmFsdWVFcXVhbFRvUmVjb21tZW5kZWQoZmxhZzogRmVhdHVyZUZsYWcpOiBib29sZWFuIHtcbiAgICByZXR1cm4gU3RyaW5nKGZsYWcudXNlclZhbHVlKSA9PT0gU3RyaW5nKGZsYWcucmVjb21tZW5kZWRWYWx1ZSk7XG4gIH1cblxuICAvKiogU2hvd3MgaGVscGZ1bCB1c2FnZSBleGFtcGxlcyBhbmQgYXZhaWxhYmxlIGNvbW1hbmQgb3B0aW9ucyAqL1xuICBhc3luYyBkaXNwbGF5SGVscE1lc3NhZ2UoKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5pb0hlbHBlci5kZWZhdWx0cy5pbmZvKCdcXG4nICsgY2hhbGsuYm9sZCgnQXZhaWxhYmxlIG9wdGlvbnM6JykpO1xuICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuaW5mbygnICBjZGsgZmxhZ3MgLS1pbnRlcmFjdGl2ZSAgICAgIyBJbnRlcmFjdGl2ZSBtZW51IHRvIG1hbmFnZSBmbGFncycpO1xuICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuaW5mbygnICBjZGsgZmxhZ3MgLS1hbGwgICAgICAgICAgICAgIyBTaG93IGFsbCBmbGFncyAoaW5jbHVkaW5nIGNvbmZpZ3VyZWQgb25lcyknKTtcbiAgICBhd2FpdCB0aGlzLmlvSGVscGVyLmRlZmF1bHRzLmluZm8oJyAgY2RrIGZsYWdzIC0tc2V0IC0tYWxsIC0tcmVjb21tZW5kZWQgICAgIyBTZXQgYWxsIGZsYWdzIHRvIHJlY29tbWVuZGVkIHZhbHVlcycpO1xuICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuaW5mbygnICBjZGsgZmxhZ3MgLS1zZXQgLS1hbGwgLS1kZWZhdWx0ICAgICAgICMgU2V0IGFsbCBmbGFncyB0byBkZWZhdWx0IHZhbHVlcycpO1xuICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuaW5mbygnICBjZGsgZmxhZ3MgLS1zZXQgLS11bmNvbmZpZ3VyZWQgLS1yZWNvbW1lbmRlZCAgIyBTZXQgdW5jb25maWd1cmVkIGZsYWdzIHRvIHJlY29tbWVuZGVkJyk7XG4gICAgYXdhaXQgdGhpcy5pb0hlbHBlci5kZWZhdWx0cy5pbmZvKCcgIGNkayBmbGFncyAtLXNldCA8ZmxhZy1uYW1lPiAtLXZhbHVlIDx0cnVlfGZhbHNlPiAgIyBTZXQgc3BlY2lmaWMgZmxhZycpO1xuICAgIGF3YWl0IHRoaXMuaW9IZWxwZXIuZGVmYXVsdHMuaW5mbygnICBjZGsgZmxhZ3MgLS1zYWZlICAgICAgICAgICAgIyBTYWZlbHkgc2V0IGZsYWdzIHRoYXQgZG9uXFwndCBjaGFuZ2UgdGVtcGxhdGVzJyk7XG4gIH1cbn1cbiJdfQ==