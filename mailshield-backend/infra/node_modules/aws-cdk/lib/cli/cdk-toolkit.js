"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CdkToolkit = exports.AssetBuildTime = void 0;
exports.displayFlagsMessage = displayFlagsMessage;
const path = require("path");
const util_1 = require("util");
const cloud_assembly_schema_1 = require("@aws-cdk/cloud-assembly-schema");
const cxapi = require("@aws-cdk/cx-api");
const toolkit_lib_1 = require("@aws-cdk/toolkit-lib");
const chalk = require("chalk");
const chokidar = require("chokidar");
const fs = require("fs-extra");
const uuid = require("uuid");
const io_host_1 = require("./io-host");
const user_configuration_1 = require("./user-configuration");
const api_private_1 = require("../../lib/api-private");
const api_1 = require("../api");
const bootstrap_1 = require("../api/bootstrap");
const cloud_assembly_1 = require("../api/cloud-assembly");
const refactor_1 = require("../api/refactor");
const deploy_1 = require("../commands/deploy");
const list_stacks_1 = require("../commands/list-stacks");
const migrate_1 = require("../commands/migrate");
const cxapp_1 = require("../cxapp");
const obsolete_flags_1 = require("../obsolete-flags");
const util_2 = require("../util");
const collect_telemetry_1 = require("./telemetry/collect-telemetry");
const error_1 = require("./telemetry/error");
const messages_1 = require("./telemetry/messages");
// Must use a require() otherwise esbuild complains about calling a namespace
// eslint-disable-next-line @typescript-eslint/no-require-imports,@typescript-eslint/consistent-type-imports
const pLimit = require('p-limit');
/**
 * When to build assets
 */
var AssetBuildTime;
(function (AssetBuildTime) {
    /**
     * Build all assets before deploying the first stack
     *
     * This is intended for expensive Docker image builds; so that if the Docker image build
     * fails, no stacks are unnecessarily deployed (with the attendant wait time).
     */
    AssetBuildTime["ALL_BEFORE_DEPLOY"] = "all-before-deploy";
    /**
     * Build assets just-in-time, before publishing
     */
    AssetBuildTime["JUST_IN_TIME"] = "just-in-time";
})(AssetBuildTime || (exports.AssetBuildTime = AssetBuildTime = {}));
/**
 * Custom implementation of the public Toolkit to integrate with the legacy CdkToolkit
 *
 * This overwrites how an sdkProvider is acquired
 * in favor of the one provided directly to CdkToolkit.
 */
class InternalToolkit extends toolkit_lib_1.Toolkit {
    constructor(sdkProvider, options) {
        super(options);
        this._sdkProvider = sdkProvider;
    }
    /**
     * Access to the AWS SDK
     * @internal
     */
    async sdkProvider(_action) {
        return this._sdkProvider;
    }
}
/**
 * Toolkit logic
 *
 * The toolkit runs the `cloudExecutable` to obtain a cloud assembly and
 * deploys applies them to `cloudFormation`.
 */
class CdkToolkit {
    constructor(props) {
        this.props = props;
        this.ioHost = props.ioHost ?? io_host_1.CliIoHost.instance();
        this.toolkitStackName = props.toolkitStackName ?? api_1.DEFAULT_TOOLKIT_STACK_NAME;
        this.toolkit = new InternalToolkit(props.sdkProvider, {
            assemblyFailureAt: this.validateMetadataFailAt(),
            color: true,
            emojis: true,
            ioHost: this.ioHost,
            toolkitStackName: this.toolkitStackName,
            unstableFeatures: ['refactor', 'flags'],
        });
    }
    async metadata(stackName, json) {
        const stacks = await this.selectSingleStackByName(stackName);
        await printSerializedObject(this.ioHost.asIoHelper(), stacks.firstStack.manifest.metadata ?? {}, json);
    }
    async acknowledge(noticeId) {
        const acks = new Set(this.props.configuration.context.get('acknowledged-issue-numbers') ?? []);
        acks.add(Number(noticeId));
        this.props.configuration.context.set('acknowledged-issue-numbers', Array.from(acks));
        await this.props.configuration.saveContext();
    }
    async cliTelemetryStatus(versionReporting = true) {
        // recreate the version-reporting property in args rather than bring the entire args object over
        const args = { ['version-reporting']: versionReporting };
        const canCollect = (0, collect_telemetry_1.canCollectTelemetry)(args, this.props.configuration.context);
        if (canCollect) {
            await this.ioHost.asIoHelper().defaults.info('CLI Telemetry is enabled. See https://docs.aws.amazon.com/cdk/v2/guide/cli-telemetry.html for ways to disable.');
        }
        else {
            await this.ioHost.asIoHelper().defaults.info('CLI Telemetry is disabled. See https://docs.aws.amazon.com/cdk/v2/guide/cli-telemetry.html for ways to enable.');
        }
    }
    async cliTelemetry(enable) {
        this.props.configuration.context.set('cli-telemetry', enable);
        await this.props.configuration.saveContext();
        await this.ioHost.asIoHelper().defaults.info(`Telemetry ${enable ? 'enabled' : 'disabled'}`);
    }
    async diff(options) {
        const stacks = await this.selectStacksForDiff(options.stackNames, options.exclusively);
        const strict = !!options.strict;
        const contextLines = options.contextLines || 3;
        const quiet = options.quiet || false;
        let diffs = 0;
        const parameterMap = buildParameterMap(options.parameters);
        if (options.templatePath !== undefined) {
            // Compare single stack against fixed template
            if (stacks.stackCount !== 1) {
                throw new toolkit_lib_1.ToolkitError('Can only select one stack when comparing to fixed template. Use --exclusively to avoid selecting multiple stacks.');
            }
            if (!(await fs.pathExists(options.templatePath))) {
                throw new toolkit_lib_1.ToolkitError(`There is no file at ${options.templatePath}`);
            }
            if (options.importExistingResources) {
                throw new toolkit_lib_1.ToolkitError('Can only use --import-existing-resources flag when comparing against deployed stacks.');
            }
            const template = (0, util_2.deserializeStructure)(await fs.readFile(options.templatePath, { encoding: 'UTF-8' }));
            const formatter = new api_1.DiffFormatter({
                templateInfo: {
                    oldTemplate: template,
                    newTemplate: stacks.firstStack,
                },
            });
            if (options.securityOnly) {
                const securityDiff = formatter.formatSecurityDiff();
                // Warn, count, and display the diff only if the reported changes are broadening permissions
                if (securityDiff.permissionChangeType === toolkit_lib_1.PermissionChangeType.BROADENING) {
                    await this.ioHost.asIoHelper().defaults.warn('This deployment will make potentially sensitive changes according to your current security approval level.\nPlease confirm you intend to make the following modifications:\n');
                    await this.ioHost.asIoHelper().defaults.info(securityDiff.formattedDiff);
                    diffs += 1;
                }
            }
            else {
                const diff = formatter.formatStackDiff({
                    strict,
                    contextLines,
                    quiet,
                });
                diffs = diff.numStacksWithChanges;
                await this.ioHost.asIoHelper().defaults.info(diff.formattedDiff);
            }
        }
        else {
            const allMappings = options.includeMoves
                ? await (0, refactor_1.mappingsByEnvironment)(stacks.stackArtifacts, this.props.sdkProvider, true)
                : [];
            // Compare N stacks against deployed templates
            for (const stack of stacks.stackArtifacts) {
                const templateWithNestedStacks = await this.props.deployments.readCurrentTemplateWithNestedStacks(stack, options.compareAgainstProcessedTemplate);
                const currentTemplate = templateWithNestedStacks.deployedRootTemplate;
                const nestedStacks = templateWithNestedStacks.nestedStacks;
                const migrator = new api_1.ResourceMigrator({
                    deployments: this.props.deployments,
                    ioHelper: (0, api_private_1.asIoHelper)(this.ioHost, 'diff'),
                });
                const resourcesToImport = await migrator.tryGetResources(await this.props.deployments.resolveEnvironment(stack));
                if (resourcesToImport) {
                    (0, api_1.removeNonImportResources)(stack);
                }
                let changeSet = undefined;
                if (options.changeSet) {
                    let stackExists = false;
                    try {
                        stackExists = await this.props.deployments.stackExists({
                            stack,
                            deployName: stack.stackName,
                            tryLookupRole: true,
                        });
                    }
                    catch (e) {
                        await this.ioHost.asIoHelper().defaults.debug((0, util_2.formatErrorMessage)(e));
                        if (!quiet) {
                            await this.ioHost.asIoHelper().defaults.info(`Checking if the stack ${stack.stackName} exists before creating the changeset has failed, will base the diff on template differences (run again with -v to see the reason)\n`);
                        }
                        stackExists = false;
                    }
                    if (stackExists) {
                        changeSet = await api_private_1.cfnApi.createDiffChangeSet((0, api_private_1.asIoHelper)(this.ioHost, 'diff'), {
                            stack,
                            uuid: uuid.v4(),
                            deployments: this.props.deployments,
                            willExecute: false,
                            sdkProvider: this.props.sdkProvider,
                            parameters: Object.assign({}, parameterMap['*'], parameterMap[stack.stackName]),
                            resourcesToImport,
                            importExistingResources: options.importExistingResources,
                        });
                    }
                    else {
                        await this.ioHost.asIoHelper().defaults.debug(`the stack '${stack.stackName}' has not been deployed to CloudFormation or describeStacks call failed, skipping changeset creation.`);
                    }
                }
                const mappings = allMappings.find(m => m.environment.region === stack.environment.region && m.environment.account === stack.environment.account)?.mappings ?? {};
                const formatter = new api_1.DiffFormatter({
                    templateInfo: {
                        oldTemplate: currentTemplate,
                        newTemplate: stack,
                        changeSet,
                        isImport: !!resourcesToImport,
                        nestedStacks,
                        mappings,
                    },
                });
                if (options.securityOnly) {
                    const securityDiff = formatter.formatSecurityDiff();
                    // Warn, count, and display the diff only if the reported changes are broadening permissions
                    if (securityDiff.permissionChangeType === toolkit_lib_1.PermissionChangeType.BROADENING) {
                        await this.ioHost.asIoHelper().defaults.warn('This deployment will make potentially sensitive changes according to your current security approval level.\nPlease confirm you intend to make the following modifications:\n');
                        await this.ioHost.asIoHelper().defaults.info(securityDiff.formattedDiff);
                        diffs += 1;
                    }
                }
                else {
                    const diff = formatter.formatStackDiff({
                        strict,
                        contextLines,
                        quiet,
                    });
                    await this.ioHost.asIoHelper().defaults.info(diff.formattedDiff);
                    diffs += diff.numStacksWithChanges;
                }
            }
        }
        await this.ioHost.asIoHelper().defaults.info((0, util_1.format)('\n✨  Number of stacks with differences: %s\n', diffs));
        return diffs && options.fail ? 1 : 0;
    }
    async deploy(options) {
        if (options.watch) {
            return this.watch(options);
        }
        // set progress from options, this includes user and app config
        if (options.progress) {
            this.ioHost.stackProgress = options.progress;
        }
        const startSynthTime = new Date().getTime();
        const stackCollection = await this.selectStacksForDeploy(options.selector, options.exclusively, options.cacheCloudAssembly, options.ignoreNoStacks);
        const elapsedSynthTime = new Date().getTime() - startSynthTime;
        await this.ioHost.asIoHelper().defaults.info(`\n✨  Synthesis time: ${(0, util_2.formatTime)(elapsedSynthTime)}s\n`);
        if (stackCollection.stackCount === 0) {
            await this.ioHost.asIoHelper().defaults.error('This app contains no stacks');
            return;
        }
        const migrator = new api_1.ResourceMigrator({
            deployments: this.props.deployments,
            ioHelper: (0, api_private_1.asIoHelper)(this.ioHost, 'deploy'),
        });
        await migrator.tryMigrateResources(stackCollection, {
            toolkitStackName: this.toolkitStackName,
            ...options,
        });
        const requireApproval = options.requireApproval ?? cloud_assembly_schema_1.RequireApproval.BROADENING;
        const parameterMap = buildParameterMap(options.parameters);
        if (options.deploymentMethod?.method === 'hotswap') {
            await this.ioHost.asIoHelper().defaults.warn('⚠️ The --hotswap and --hotswap-fallback flags deliberately introduce CloudFormation drift to speed up deployments');
            await this.ioHost.asIoHelper().defaults.warn('⚠️ They should only be used for development - never use them for your production Stacks!\n');
        }
        const stacks = stackCollection.stackArtifacts;
        const stackOutputs = {};
        const outputsFile = options.outputsFile;
        const buildAsset = async (assetNode) => {
            await this.props.deployments.buildSingleAsset(assetNode.assetManifestArtifact, assetNode.assetManifest, assetNode.asset, {
                stack: assetNode.parentStack,
                roleArn: options.roleArn,
                stackName: assetNode.parentStack.stackName,
            });
        };
        const publishAsset = async (assetNode) => {
            await this.props.deployments.publishSingleAsset(assetNode.assetManifest, assetNode.asset, {
                stack: assetNode.parentStack,
                roleArn: options.roleArn,
                stackName: assetNode.parentStack.stackName,
                forcePublish: options.force,
            });
        };
        const deployStack = async (stackNode) => {
            const stack = stackNode.stack;
            if (stackCollection.stackCount !== 1) {
                await this.ioHost.asIoHelper().defaults.info(chalk.bold(stack.displayName));
            }
            if (!stack.environment) {
                // eslint-disable-next-line @stylistic/max-len
                throw new toolkit_lib_1.ToolkitError(`Stack ${stack.displayName} does not define an environment, and AWS credentials could not be obtained from standard locations or no region was configured.`);
            }
            if (Object.keys(stack.template.Resources || {}).length === 0) {
                // The generated stack has no resources
                if (!(await this.props.deployments.stackExists({ stack }))) {
                    await this.ioHost.asIoHelper().defaults.warn('%s: stack has no resources, skipping deployment.', chalk.bold(stack.displayName));
                }
                else {
                    await this.ioHost.asIoHelper().defaults.warn('%s: stack has no resources, deleting existing stack.', chalk.bold(stack.displayName));
                    await this.destroy({
                        selector: { patterns: [stack.hierarchicalId] },
                        exclusively: true,
                        force: true,
                        roleArn: options.roleArn,
                        fromDeploy: true,
                    });
                }
                return;
            }
            if (requireApproval !== cloud_assembly_schema_1.RequireApproval.NEVER) {
                const currentTemplate = await this.props.deployments.readCurrentTemplate(stack);
                const formatter = new api_1.DiffFormatter({
                    templateInfo: {
                        oldTemplate: currentTemplate,
                        newTemplate: stack,
                    },
                });
                const securityDiff = formatter.formatSecurityDiff();
                if (requiresApproval(requireApproval, securityDiff.permissionChangeType)) {
                    const motivation = '"--require-approval" is enabled and stack includes security-sensitive updates';
                    await this.ioHost.asIoHelper().defaults.info(securityDiff.formattedDiff);
                    await askUserConfirmation(this.ioHost, api_private_1.IO.CDK_TOOLKIT_I5060.req(`${motivation}: 'Do you wish to deploy these changes'`, {
                        motivation,
                        concurrency,
                        permissionChangeType: securityDiff.permissionChangeType,
                        templateDiffs: formatter.diffs,
                    }));
                }
            }
            // Following are the same semantics we apply with respect to Notification ARNs (dictated by the SDK)
            //
            //  - undefined  =>  cdk ignores it, as if it wasn't supported (allows external management).
            //  - []:        =>  cdk manages it, and the user wants to wipe it out.
            //  - ['arn-1']  =>  cdk manages it, and the user wants to set it to ['arn-1'].
            const notificationArns = (!!options.notificationArns || !!stack.notificationArns)
                ? (options.notificationArns ?? []).concat(stack.notificationArns ?? [])
                : undefined;
            for (const notificationArn of notificationArns ?? []) {
                if (!(0, util_2.validateSnsTopicArn)(notificationArn)) {
                    throw new toolkit_lib_1.ToolkitError(`Notification arn ${notificationArn} is not a valid arn for an SNS topic`);
                }
            }
            const stackIndex = stacks.indexOf(stack) + 1;
            await this.ioHost.asIoHelper().defaults.info(`${chalk.bold(stack.displayName)}: deploying... [${stackIndex}/${stackCollection.stackCount}]`);
            const startDeployTime = new Date().getTime();
            let tags = options.tags;
            if (!tags || tags.length === 0) {
                tags = (0, api_private_1.tagsForStack)(stack);
            }
            // There is already a startDeployTime constant, but that does not work with telemetry.
            // We should integrate the two in the future
            const deploySpan = await this.ioHost.asIoHelper().span(messages_1.CLI_PRIVATE_SPAN.DEPLOY).begin({});
            let error;
            let elapsedDeployTime = 0;
            try {
                let deployResult;
                let rollback = options.rollback;
                let iteration = 0;
                while (!deployResult) {
                    if (++iteration > 2) {
                        throw new toolkit_lib_1.ToolkitError('This loop should have stabilized in 2 iterations, but didn\'t. If you are seeing this error, please report it at https://github.com/aws/aws-cdk/issues/new/choose');
                    }
                    const r = await this.props.deployments.deployStack({
                        stack,
                        deployName: stack.stackName,
                        roleArn: options.roleArn,
                        toolkitStackName: options.toolkitStackName,
                        reuseAssets: options.reuseAssets,
                        notificationArns,
                        tags,
                        execute: options.execute,
                        changeSetName: options.changeSetName,
                        deploymentMethod: options.deploymentMethod,
                        forceDeployment: options.force,
                        parameters: Object.assign({}, parameterMap['*'], parameterMap[stack.stackName]),
                        usePreviousParameters: options.usePreviousParameters,
                        rollback,
                        extraUserAgent: options.extraUserAgent,
                        assetParallelism: options.assetParallelism,
                        ignoreNoStacks: options.ignoreNoStacks,
                    });
                    switch (r.type) {
                        case 'did-deploy-stack':
                            deployResult = r;
                            break;
                        case 'failpaused-need-rollback-first': {
                            const motivation = r.reason === 'replacement'
                                ? `Stack is in a paused fail state (${r.status}) and change includes a replacement which cannot be deployed with "--no-rollback"`
                                : `Stack is in a paused fail state (${r.status}) and command line arguments do not include "--no-rollback"`;
                            if (options.force) {
                                await this.ioHost.asIoHelper().defaults.warn(`${motivation}. Rolling back first (--force).`);
                            }
                            else {
                                await askUserConfirmation(this.ioHost, api_private_1.IO.CDK_TOOLKIT_I5050.req(`${motivation}. Roll back first and then proceed with deployment`, {
                                    motivation,
                                    concurrency,
                                }));
                            }
                            // Perform a rollback
                            await this.rollback({
                                selector: { patterns: [stack.hierarchicalId] },
                                toolkitStackName: options.toolkitStackName,
                                force: options.force,
                            });
                            // Go around through the 'while' loop again but switch rollback to true.
                            rollback = true;
                            break;
                        }
                        case 'replacement-requires-rollback': {
                            const motivation = 'Change includes a replacement which cannot be deployed with "--no-rollback"';
                            if (options.force) {
                                await this.ioHost.asIoHelper().defaults.warn(`${motivation}. Proceeding with regular deployment (--force).`);
                            }
                            else {
                                await askUserConfirmation(this.ioHost, api_private_1.IO.CDK_TOOLKIT_I5050.req(`${motivation}. Perform a regular deployment`, {
                                    concurrency,
                                    motivation,
                                }));
                            }
                            // Go around through the 'while' loop again but switch rollback to true.
                            rollback = true;
                            break;
                        }
                        default:
                            throw new toolkit_lib_1.ToolkitError(`Unexpected result type from deployStack: ${JSON.stringify(r)}. If you are seeing this error, please report it at https://github.com/aws/aws-cdk/issues/new/choose`);
                    }
                }
                const message = deployResult.noOp
                    ? ' ✅  %s (no changes)'
                    : ' ✅  %s';
                await this.ioHost.asIoHelper().defaults.info(chalk.green('\n' + message), stack.displayName);
                elapsedDeployTime = new Date().getTime() - startDeployTime;
                await this.ioHost.asIoHelper().defaults.info(`\n✨  Deployment time: ${(0, util_2.formatTime)(elapsedDeployTime)}s\n`);
                if (Object.keys(deployResult.outputs).length > 0) {
                    await this.ioHost.asIoHelper().defaults.info('Outputs:');
                    stackOutputs[stack.stackName] = deployResult.outputs;
                }
                for (const name of Object.keys(deployResult.outputs).sort()) {
                    const value = deployResult.outputs[name];
                    await this.ioHost.asIoHelper().defaults.info(`${chalk.cyan(stack.id)}.${chalk.cyan(name)} = ${chalk.underline(chalk.cyan(value))}`);
                }
                await this.ioHost.asIoHelper().defaults.info('Stack ARN:');
                await this.ioHost.asIoHelper().defaults.result(deployResult.stackArn);
            }
            catch (e) {
                // It has to be exactly this string because an integration test tests for
                // "bold(stackname) failed: ResourceNotReady: <error>"
                const wrappedError = new toolkit_lib_1.ToolkitError([`❌  ${chalk.bold(stack.stackName)} failed:`, ...(e.name ? [`${e.name}:`] : []), (0, util_2.formatErrorMessage)(e)].join(' '));
                error = {
                    name: (0, error_1.cdkCliErrorName)(wrappedError.name),
                };
                throw wrappedError;
            }
            finally {
                await deploySpan.end({ error });
                if (options.cloudWatchLogMonitor) {
                    const foundLogGroupsResult = await (0, api_1.findCloudWatchLogGroups)(this.props.sdkProvider, (0, api_private_1.asIoHelper)(this.ioHost, 'deploy'), stack);
                    options.cloudWatchLogMonitor.addLogGroups(foundLogGroupsResult.env, foundLogGroupsResult.sdk, foundLogGroupsResult.logGroupNames);
                }
                // If an outputs file has been specified, create the file path and write stack outputs to it once.
                // Outputs are written after all stacks have been deployed. If a stack deployment fails,
                // all of the outputs from successfully deployed stacks before the failure will still be written.
                if (outputsFile) {
                    fs.ensureFileSync(outputsFile);
                    await fs.writeJson(outputsFile, stackOutputs, {
                        spaces: 2,
                        encoding: 'utf8',
                    });
                }
            }
            await this.ioHost.asIoHelper().defaults.info(`\n✨  Total time: ${(0, util_2.formatTime)(elapsedSynthTime + elapsedDeployTime)}s\n`);
        };
        const assetBuildTime = options.assetBuildTime ?? AssetBuildTime.ALL_BEFORE_DEPLOY;
        const prebuildAssets = assetBuildTime === AssetBuildTime.ALL_BEFORE_DEPLOY;
        const concurrency = options.concurrency || 1;
        if (concurrency > 1) {
            // always force "events" progress output when we have concurrency
            this.ioHost.stackProgress = deploy_1.StackActivityProgress.EVENTS;
            // ...but only warn if the user explicitly requested "bar" progress
            if (options.progress && options.progress != deploy_1.StackActivityProgress.EVENTS) {
                await this.ioHost.asIoHelper().defaults.warn('⚠️ The --concurrency flag only supports --progress "events". Switching to "events".');
            }
        }
        const stacksAndTheirAssetManifests = stacks.flatMap((stack) => [
            stack,
            ...stack.dependencies.filter(x => cxapi.AssetManifestArtifact.isAssetManifestArtifact(x)),
        ]);
        const workGraph = new api_1.WorkGraphBuilder((0, api_private_1.asIoHelper)(this.ioHost, 'deploy'), prebuildAssets).build(stacksAndTheirAssetManifests);
        // Unless we are running with '--force', skip already published assets
        if (!options.force) {
            await this.removePublishedAssets(workGraph, options);
        }
        const graphConcurrency = {
            'stack': concurrency,
            'asset-build': 1, // This will be CPU-bound/memory bound, mostly matters for Docker builds
            'asset-publish': (options.assetParallelism ?? true) ? 8 : 1, // This will be I/O-bound, 8 in parallel seems reasonable
        };
        await workGraph.doParallel(graphConcurrency, {
            deployStack,
            buildAsset,
            publishAsset,
        });
    }
    /**
     * Detect infrastructure drift for the given stack(s)
     */
    async drift(options) {
        const driftResults = await this.toolkit.drift(this.props.cloudExecutable, {
            stacks: {
                patterns: options.selector.patterns,
                strategy: options.selector.patterns.length > 0 ? api_1.StackSelectionStrategy.PATTERN_MATCH : api_1.StackSelectionStrategy.ALL_STACKS,
            },
        });
        const totalDrifts = Object.values(driftResults).reduce((total, current) => total + (current.numResourcesWithDrift ?? 0), 0);
        return totalDrifts > 0 && options.fail ? 1 : 0;
    }
    /**
     * Roll back the given stack or stacks.
     */
    async rollback(options) {
        const startSynthTime = new Date().getTime();
        const stackCollection = await this.selectStacksForDeploy(options.selector, true);
        const elapsedSynthTime = new Date().getTime() - startSynthTime;
        await this.ioHost.asIoHelper().defaults.info(`\n✨  Synthesis time: ${(0, util_2.formatTime)(elapsedSynthTime)}s\n`);
        if (stackCollection.stackCount === 0) {
            await this.ioHost.asIoHelper().defaults.error('No stacks selected');
            return;
        }
        let anyRollbackable = false;
        for (const stack of stackCollection.stackArtifacts) {
            await this.ioHost.asIoHelper().defaults.info('Rolling back %s', chalk.bold(stack.displayName));
            const startRollbackTime = new Date().getTime();
            try {
                const result = await this.props.deployments.rollbackStack({
                    stack,
                    roleArn: options.roleArn,
                    toolkitStackName: options.toolkitStackName,
                    orphanFailedResources: options.force,
                    validateBootstrapStackVersion: options.validateBootstrapStackVersion,
                    orphanLogicalIds: options.orphanLogicalIds,
                });
                if (!result.notInRollbackableState) {
                    anyRollbackable = true;
                }
                const elapsedRollbackTime = new Date().getTime() - startRollbackTime;
                await this.ioHost.asIoHelper().defaults.info(`\n✨  Rollback time: ${(0, util_2.formatTime)(elapsedRollbackTime).toString()}s\n`);
            }
            catch (e) {
                await this.ioHost.asIoHelper().defaults.error('\n ❌  %s failed: %s', chalk.bold(stack.displayName), (0, util_2.formatErrorMessage)(e));
                throw new toolkit_lib_1.ToolkitError('Rollback failed (use --force to orphan failing resources)');
            }
        }
        if (!anyRollbackable) {
            throw new toolkit_lib_1.ToolkitError('No stacks were in a state that could be rolled back');
        }
    }
    async watch(options) {
        const rootDir = path.dirname(path.resolve(user_configuration_1.PROJECT_CONFIG));
        const ioHelper = (0, api_private_1.asIoHelper)(this.ioHost, 'watch');
        await this.ioHost.asIoHelper().defaults.debug("root directory used for 'watch' is: %s", rootDir);
        const watchSettings = this.props.configuration.settings.get(['watch']);
        if (!watchSettings) {
            throw new toolkit_lib_1.ToolkitError("Cannot use the 'watch' command without specifying at least one directory to monitor. " +
                'Make sure to add a "watch" key to your cdk.json');
        }
        // For the "include" subkey under the "watch" key, the behavior is:
        // 1. No "watch" setting? We error out.
        // 2. "watch" setting without an "include" key? We default to observing "./**".
        // 3. "watch" setting with an empty "include" key? We default to observing "./**".
        // 4. Non-empty "include" key? Just use the "include" key.
        const watchIncludes = this.patternsArrayForWatch(watchSettings.include, {
            rootDir,
            returnRootDirIfEmpty: true,
        });
        await this.ioHost.asIoHelper().defaults.debug("'include' patterns for 'watch': %s", watchIncludes);
        // For the "exclude" subkey under the "watch" key,
        // the behavior is to add some default excludes in addition to the ones specified by the user:
        // 1. The CDK output directory.
        // 2. Any file whose name starts with a dot.
        // 3. Any directory's content whose name starts with a dot.
        // 4. Any node_modules and its content (even if it's not a JS/TS project, you might be using a local aws-cli package)
        const outputDir = this.props.configuration.settings.get(['output']);
        const watchExcludes = this.patternsArrayForWatch(watchSettings.exclude, {
            rootDir,
            returnRootDirIfEmpty: false,
        }).concat(`${outputDir}/**`, '**/.*', '**/.*/**', '**/node_modules/**');
        await this.ioHost.asIoHelper().defaults.debug("'exclude' patterns for 'watch': %s", watchExcludes);
        // Since 'cdk deploy' is a relatively slow operation for a 'watch' process,
        // introduce a concurrency latch that tracks the state.
        // This way, if file change events arrive when a 'cdk deploy' is still executing,
        // we will batch them, and trigger another 'cdk deploy' after the current one finishes,
        // making sure 'cdk deploy's  always execute one at a time.
        // Here's a diagram showing the state transitions:
        // --------------                --------    file changed     --------------    file changed     --------------  file changed
        // |            |  ready event   |      | ------------------> |            | ------------------> |            | --------------|
        // | pre-ready  | -------------> | open |                     | deploying  |                     |   queued   |               |
        // |            |                |      | <------------------ |            | <------------------ |            | <-------------|
        // --------------                --------  'cdk deploy' done  --------------  'cdk deploy' done  --------------
        let latch = 'pre-ready';
        const cloudWatchLogMonitor = options.traceLogs ? new api_1.CloudWatchLogEventMonitor({
            ioHelper,
        }) : undefined;
        const deployAndWatch = async () => {
            latch = 'deploying';
            await cloudWatchLogMonitor?.deactivate();
            await this.invokeDeployFromWatch(options, cloudWatchLogMonitor);
            // If latch is still 'deploying' after the 'await', that's fine,
            // but if it's 'queued', that means we need to deploy again
            while (latch === 'queued') {
                // TypeScript doesn't realize latch can change between 'awaits',
                // and thinks the above 'while' condition is always 'false' without the cast
                latch = 'deploying';
                await this.ioHost.asIoHelper().defaults.info("Detected file changes during deployment. Invoking 'cdk deploy' again");
                await this.invokeDeployFromWatch(options, cloudWatchLogMonitor);
            }
            latch = 'open';
            await cloudWatchLogMonitor?.activate();
        };
        chokidar
            .watch(watchIncludes, {
            ignored: watchExcludes,
            cwd: rootDir,
        })
            .on('ready', async () => {
            latch = 'open';
            await this.ioHost.asIoHelper().defaults.debug("'watch' received the 'ready' event. From now on, all file changes will trigger a deployment");
            await this.ioHost.asIoHelper().defaults.info("Triggering initial 'cdk deploy'");
            await deployAndWatch();
        })
            .on('all', async (event, filePath) => {
            if (latch === 'pre-ready') {
                await this.ioHost.asIoHelper().defaults.info(`'watch' is observing ${event === 'addDir' ? 'directory' : 'the file'} '%s' for changes`, filePath);
            }
            else if (latch === 'open') {
                await this.ioHost.asIoHelper().defaults.info("Detected change to '%s' (type: %s). Triggering 'cdk deploy'", filePath, event);
                await deployAndWatch();
            }
            else {
                // this means latch is either 'deploying' or 'queued'
                latch = 'queued';
                await this.ioHost.asIoHelper().defaults.info("Detected change to '%s' (type: %s) while 'cdk deploy' is still running. " +
                    'Will queue for another deployment after this one finishes', filePath, event);
            }
        });
    }
    async import(options) {
        const stacks = await this.selectStacksForDeploy(options.selector, true, true, false);
        // set progress from options, this includes user and app config
        if (options.progress) {
            this.ioHost.stackProgress = options.progress;
        }
        if (stacks.stackCount > 1) {
            throw new toolkit_lib_1.ToolkitError(`Stack selection is ambiguous, please choose a specific stack for import [${stacks.stackArtifacts.map((x) => x.id).join(', ')}]`);
        }
        if (!process.stdout.isTTY && !options.resourceMappingFile) {
            throw new toolkit_lib_1.ToolkitError('--resource-mapping is required when input is not a terminal');
        }
        const stack = stacks.stackArtifacts[0];
        await this.ioHost.asIoHelper().defaults.info(chalk.bold(stack.displayName));
        const resourceImporter = new api_1.ResourceImporter(stack, {
            deployments: this.props.deployments,
            ioHelper: (0, api_private_1.asIoHelper)(this.ioHost, 'import'),
        });
        const { additions, hasNonAdditions } = await resourceImporter.discoverImportableResources(options.force);
        if (additions.length === 0) {
            await this.ioHost.asIoHelper().defaults.warn('%s: no new resources compared to the currently deployed stack, skipping import.', chalk.bold(stack.displayName));
            return;
        }
        // Prepare a mapping of physical resources to CDK constructs
        const actualImport = !options.resourceMappingFile
            ? await resourceImporter.askForResourceIdentifiers(additions)
            : await resourceImporter.loadResourceIdentifiers(additions, options.resourceMappingFile);
        if (actualImport.importResources.length === 0) {
            await this.ioHost.asIoHelper().defaults.warn('No resources selected for import.');
            return;
        }
        // If "--create-resource-mapping" option was passed, write the resource mapping to the given file and exit
        if (options.recordResourceMapping) {
            const outputFile = options.recordResourceMapping;
            fs.ensureFileSync(outputFile);
            await fs.writeJson(outputFile, actualImport.resourceMap, {
                spaces: 2,
                encoding: 'utf8',
            });
            await this.ioHost.asIoHelper().defaults.info('%s: mapping file written.', outputFile);
            return;
        }
        // Import the resources according to the given mapping
        await this.ioHost.asIoHelper().defaults.info('%s: importing resources into stack...', chalk.bold(stack.displayName));
        const tags = (0, api_private_1.tagsForStack)(stack);
        await resourceImporter.importResourcesFromMap(actualImport, {
            roleArn: options.roleArn,
            tags,
            deploymentMethod: options.deploymentMethod,
            usePreviousParameters: true,
            rollback: options.rollback,
        });
        // Notify user of next steps
        await this.ioHost.asIoHelper().defaults.info(`Import operation complete. We recommend you run a ${chalk.blueBright('drift detection')} operation ` +
            'to confirm your CDK app resource definitions are up-to-date. Read more here: ' +
            chalk.underline.blueBright('https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/detect-drift-stack.html'));
        if (actualImport.importResources.length < additions.length) {
            await this.ioHost.asIoHelper().defaults.info('');
            await this.ioHost.asIoHelper().defaults.warn(`Some resources were skipped. Run another ${chalk.blueBright('cdk import')} or a ${chalk.blueBright('cdk deploy')} to bring the stack up-to-date with your CDK app definition.`);
        }
        else if (hasNonAdditions) {
            await this.ioHost.asIoHelper().defaults.info('');
            await this.ioHost.asIoHelper().defaults.warn(`Your app has pending updates or deletes excluded from this import operation. Run a ${chalk.blueBright('cdk deploy')} to bring the stack up-to-date with your CDK app definition.`);
        }
    }
    async destroy(options) {
        const ioHelper = this.ioHost.asIoHelper();
        // The stacks will have been ordered for deployment, so reverse them for deletion.
        const stacks = (await this.selectStacksForDestroy(options.selector, options.exclusively)).reversed();
        if (!options.force) {
            const motivation = 'Destroying stacks is an irreversible action';
            const question = `Are you sure you want to delete: ${chalk.blue(stacks.stackArtifacts.map((s) => s.hierarchicalId).join(', '))}`;
            try {
                await ioHelper.requestResponse(api_private_1.IO.CDK_TOOLKIT_I7010.req(question, { motivation }));
            }
            catch (err) {
                if (!toolkit_lib_1.ToolkitError.isToolkitError(err) || err.message != 'Aborted by user') {
                    throw err; // unexpected error
                }
                await ioHelper.notify(api_private_1.IO.CDK_TOOLKIT_E7010.msg(err.message));
                return;
            }
        }
        const action = options.fromDeploy ? 'deploy' : 'destroy';
        for (const [index, stack] of stacks.stackArtifacts.entries()) {
            await ioHelper.defaults.info(chalk.green('%s: destroying... [%s/%s]'), chalk.blue(stack.displayName), index + 1, stacks.stackCount);
            try {
                await this.props.deployments.destroyStack({
                    stack,
                    deployName: stack.stackName,
                    roleArn: options.roleArn,
                });
                await ioHelper.defaults.info(chalk.green(`\n ✅  %s: ${action}ed`), chalk.blue(stack.displayName));
            }
            catch (e) {
                await ioHelper.defaults.error(`\n ❌  %s: ${action} failed`, chalk.blue(stack.displayName), e);
                throw e;
            }
        }
    }
    async list(selectors, options = {}) {
        const stacks = await (0, list_stacks_1.listStacks)(this, {
            selectors: selectors,
        });
        if (options.long && options.showDeps) {
            await printSerializedObject(this.ioHost.asIoHelper(), stacks, options.json ?? false);
            return 0;
        }
        if (options.showDeps) {
            const stackDeps = stacks.map(stack => ({
                id: stack.id,
                dependencies: stack.dependencies,
            }));
            await printSerializedObject(this.ioHost.asIoHelper(), stackDeps, options.json ?? false);
            return 0;
        }
        if (options.long) {
            const long = stacks.map(stack => ({
                id: stack.id,
                name: stack.name,
                environment: stack.environment,
            }));
            await printSerializedObject(this.ioHost.asIoHelper(), long, options.json ?? false);
            return 0;
        }
        // just print stack IDs
        for (const stack of stacks) {
            await this.ioHost.asIoHelper().defaults.result(stack.id);
        }
        return 0; // exit-code
    }
    /**
     * Synthesize the given set of stacks (called when the user runs 'cdk synth')
     *
     * INPUT: Stack names can be supplied using a glob filter. If no stacks are
     * given, all stacks from the application are implicitly selected.
     *
     * OUTPUT: If more than one stack ends up being selected, an output directory
     * should be supplied, where the templates will be written.
     */
    async synth(stackNames, exclusively, quiet, autoValidate, json) {
        const stacks = await this.selectStacksForDiff(stackNames, exclusively, autoValidate);
        // if we have a single stack, print it to STDOUT
        if (stacks.stackCount === 1) {
            if (!quiet) {
                await printSerializedObject(this.ioHost.asIoHelper(), (0, util_2.obscureTemplate)(stacks.firstStack.template), json ?? false);
            }
            await displayFlagsMessage(this.ioHost.asIoHelper(), this.toolkit, this.props.cloudExecutable);
            return undefined;
        }
        // not outputting template to stdout, let's explain things to the user a little bit...
        await this.ioHost.asIoHelper().defaults.info(chalk.green(`Successfully synthesized to ${chalk.blue(path.resolve(stacks.assembly.directory))}`));
        await this.ioHost.asIoHelper().defaults.info(`Supply a stack id (${stacks.stackArtifacts.map((s) => chalk.green(s.hierarchicalId)).join(', ')}) to display its template.`);
        await displayFlagsMessage(this.ioHost.asIoHelper(), this.toolkit, this.props.cloudExecutable);
        return undefined;
    }
    /**
     * Bootstrap the CDK Toolkit stack in the accounts used by the specified stack(s).
     *
     * @param userEnvironmentSpecs - environment names that need to have toolkit support
     *             provisioned, as a glob filter. If none is provided, all stacks are implicitly selected.
     * @param options - The name, role ARN, bootstrapping parameters, etc. to be used for the CDK Toolkit stack.
     */
    async bootstrap(userEnvironmentSpecs, options) {
        const bootstrapper = new bootstrap_1.Bootstrapper(options.source, (0, api_private_1.asIoHelper)(this.ioHost, 'bootstrap'));
        // If there is an '--app' argument and an environment looks like a glob, we
        // select the environments from the app. Otherwise, use what the user said.
        const environments = await this.defineEnvironments(userEnvironmentSpecs);
        const limit = pLimit(20);
        // eslint-disable-next-line @cdklabs/promiseall-no-unbounded-parallelism
        await Promise.all(environments.map((environment) => limit(async () => {
            await this.ioHost.asIoHelper().defaults.info(chalk.green(' ⏳  Bootstrapping environment %s...'), chalk.blue(environment.name));
            try {
                const result = await bootstrapper.bootstrapEnvironment(environment, this.props.sdkProvider, options);
                const message = result.noOp
                    ? ' ✅  Environment %s bootstrapped (no changes).'
                    : ' ✅  Environment %s bootstrapped.';
                await this.ioHost.asIoHelper().defaults.info(chalk.green(message), chalk.blue(environment.name));
            }
            catch (e) {
                await this.ioHost.asIoHelper().defaults.error(' ❌  Environment %s failed bootstrapping: %s', chalk.blue(environment.name), e);
                throw e;
            }
        })));
    }
    /**
     * Garbage collects assets from a CDK app's environment
     * @param options - Options for Garbage Collection
     */
    async garbageCollect(userEnvironmentSpecs, options) {
        const environments = await this.defineEnvironments(userEnvironmentSpecs);
        for (const environment of environments) {
            await this.ioHost.asIoHelper().defaults.info(chalk.green(' ⏳  Garbage Collecting environment %s...'), chalk.blue(environment.name));
            const gc = new api_1.GarbageCollector({
                sdkProvider: this.props.sdkProvider,
                ioHelper: (0, api_private_1.asIoHelper)(this.ioHost, 'gc'),
                resolvedEnvironment: environment,
                bootstrapStackName: options.bootstrapStackName,
                rollbackBufferDays: options.rollbackBufferDays,
                createdBufferDays: options.createdBufferDays,
                action: options.action ?? 'full',
                type: options.type ?? 'all',
                confirm: options.confirm ?? true,
            });
            await gc.garbageCollect();
        }
    }
    async defineEnvironments(userEnvironmentSpecs) {
        // By default, glob for everything
        const environmentSpecs = userEnvironmentSpecs.length > 0 ? [...userEnvironmentSpecs] : ['**'];
        // Partition into globs and non-globs (this will mutate environmentSpecs).
        const globSpecs = (0, util_2.partition)(environmentSpecs, cxapp_1.looksLikeGlob);
        if (globSpecs.length > 0 && !this.props.cloudExecutable.hasApp) {
            if (userEnvironmentSpecs.length > 0) {
                // User did request this glob
                throw new toolkit_lib_1.ToolkitError(`'${globSpecs}' is not an environment name. Specify an environment name like 'aws://123456789012/us-east-1', or run in a directory with 'cdk.json' to use wildcards.`);
            }
            else {
                // User did not request anything
                throw new toolkit_lib_1.ToolkitError("Specify an environment name like 'aws://123456789012/us-east-1', or run in a directory with 'cdk.json'.");
            }
        }
        const environments = [...(0, cxapp_1.environmentsFromDescriptors)(environmentSpecs)];
        // If there is an '--app' argument, select the environments from the app.
        if (this.props.cloudExecutable.hasApp) {
            environments.push(...(await (0, cxapp_1.globEnvironmentsFromStacks)(await this.selectStacksForList([]), globSpecs, this.props.sdkProvider)));
        }
        return environments;
    }
    /**
     * Migrates a CloudFormation stack/template to a CDK app
     * @param options - Options for CDK app creation
     */
    async migrate(options) {
        await this.ioHost.asIoHelper().defaults.warn('This command is an experimental feature.');
        const language = options.language?.toLowerCase() ?? 'typescript';
        const environment = (0, migrate_1.setEnvironment)(options.account, options.region);
        let generateTemplateOutput;
        let cfn;
        let templateToDelete;
        try {
            // if neither fromPath nor fromStack is provided, generate a template using cloudformation
            const scanType = (0, migrate_1.parseSourceOptions)(options.fromPath, options.fromStack, options.stackName).source;
            if (scanType == migrate_1.TemplateSourceOptions.SCAN) {
                generateTemplateOutput = await (0, migrate_1.generateTemplate)({
                    stackName: options.stackName,
                    filters: options.filter,
                    fromScan: options.fromScan,
                    sdkProvider: this.props.sdkProvider,
                    environment: environment,
                    ioHelper: this.ioHost.asIoHelper(),
                });
                templateToDelete = generateTemplateOutput.templateId;
            }
            else if (scanType == migrate_1.TemplateSourceOptions.PATH) {
                const templateBody = (0, migrate_1.readFromPath)(options.fromPath);
                const parsedTemplate = (0, util_2.deserializeStructure)(templateBody);
                const templateId = parsedTemplate.Metadata?.AWSToolsMetrics?.IaC_Generator?.toString();
                if (templateId) {
                    // if we have a template id, we can call describe generated template to get the resource identifiers
                    // resource metadata, and template source to generate the template
                    cfn = new migrate_1.CfnTemplateGeneratorProvider(await (0, migrate_1.buildCfnClient)(this.props.sdkProvider, environment), this.ioHost.asIoHelper());
                    const generatedTemplateSummary = await cfn.describeGeneratedTemplate(templateId);
                    generateTemplateOutput = (0, migrate_1.buildGeneratedTemplateOutput)(generatedTemplateSummary, templateBody, generatedTemplateSummary.GeneratedTemplateId);
                }
                else {
                    generateTemplateOutput = {
                        migrateJson: {
                            templateBody: templateBody,
                            source: 'localfile',
                        },
                    };
                }
            }
            else if (scanType == migrate_1.TemplateSourceOptions.STACK) {
                const template = await (0, migrate_1.readFromStack)(options.stackName, this.props.sdkProvider, environment);
                if (!template) {
                    throw new toolkit_lib_1.ToolkitError(`No template found for stack-name: ${options.stackName}`);
                }
                generateTemplateOutput = {
                    migrateJson: {
                        templateBody: template,
                        source: options.stackName,
                    },
                };
            }
            else {
                // We shouldn't ever get here, but just in case.
                throw new toolkit_lib_1.ToolkitError(`Invalid source option provided: ${scanType}`);
            }
            const stack = (0, migrate_1.generateStack)(generateTemplateOutput.migrateJson.templateBody, options.stackName, language);
            await this.ioHost.asIoHelper().defaults.info(chalk.green(' ⏳  Generating CDK app for %s...'), chalk.blue(options.stackName));
            await (0, migrate_1.generateCdkApp)(this.ioHost.asIoHelper(), options.stackName, stack, language, options.outputPath, options.compress);
            if (generateTemplateOutput) {
                (0, migrate_1.writeMigrateJsonFile)(options.outputPath, options.stackName, generateTemplateOutput.migrateJson);
            }
            if ((0, migrate_1.isThereAWarning)(generateTemplateOutput)) {
                await this.ioHost.asIoHelper().defaults.warn(' ⚠️  Some resources could not be migrated completely. Please review the README.md file for more information.');
                (0, migrate_1.appendWarningsToReadme)(`${path.join(options.outputPath ?? process.cwd(), options.stackName)}/README.md`, generateTemplateOutput.resources);
            }
        }
        catch (e) {
            await this.ioHost.asIoHelper().defaults.error(' ❌  Migrate failed for `%s`: %s', options.stackName, e.message);
            throw e;
        }
        finally {
            if (templateToDelete) {
                if (!cfn) {
                    cfn = new migrate_1.CfnTemplateGeneratorProvider(await (0, migrate_1.buildCfnClient)(this.props.sdkProvider, environment), this.ioHost.asIoHelper());
                }
                if (!process.env.MIGRATE_INTEG_TEST) {
                    await cfn.deleteGeneratedTemplate(templateToDelete);
                }
            }
        }
    }
    async refactor(options) {
        if (options.revert && !options.overrideFile) {
            throw new toolkit_lib_1.ToolkitError('The --revert option can only be used with the --override-file option.');
        }
        try {
            const patterns = options.stacks?.patterns ?? [];
            await this.toolkit.refactor(this.props.cloudExecutable, {
                dryRun: options.dryRun,
                stacks: {
                    patterns: patterns,
                    strategy: patterns.length > 0 ? api_1.StackSelectionStrategy.PATTERN_MATCH : api_1.StackSelectionStrategy.ALL_STACKS,
                },
                force: options.force,
                additionalStackNames: options.additionalStackNames,
                overrides: readOverrides(options.overrideFile, options.revert),
                roleArn: options.roleArn,
            });
        }
        catch (e) {
            await this.ioHost.asIoHelper().defaults.error(e.message);
            throw e;
        }
        return 0;
        function readOverrides(filePath, revert = false) {
            if (filePath == null) {
                return [];
            }
            if (!fs.pathExistsSync(filePath)) {
                throw new toolkit_lib_1.ToolkitError(`The mapping file ${filePath} does not exist`);
            }
            const groups = (0, refactor_1.parseMappingGroups)(fs.readFileSync(filePath).toString('utf-8'));
            return revert
                ? groups.map((group) => ({
                    ...group,
                    resources: Object.fromEntries(Object.entries(group.resources ?? {}).map(([src, dst]) => [dst, src])),
                }))
                : groups;
        }
    }
    async selectStacksForList(patterns) {
        const assembly = await this.assembly();
        const stacks = await assembly.selectStacks({ patterns }, { defaultBehavior: cxapp_1.DefaultSelection.AllStacks });
        // No validation
        return stacks;
    }
    async selectStacksForDeploy(selector, exclusively, cacheCloudAssembly, ignoreNoStacks) {
        const assembly = await this.assembly(cacheCloudAssembly);
        const stacks = await assembly.selectStacks(selector, {
            extend: exclusively ? cloud_assembly_1.ExtendedStackSelection.None : cloud_assembly_1.ExtendedStackSelection.Upstream,
            defaultBehavior: cxapp_1.DefaultSelection.OnlySingle,
            ignoreNoStacks,
        });
        this.validateStacksSelected(stacks, selector.patterns);
        await this.validateStacks(stacks);
        return stacks;
    }
    async selectStacksForDiff(stackNames, exclusively, autoValidate) {
        const assembly = await this.assembly();
        const selectedForDiff = await assembly.selectStacks({ patterns: stackNames }, {
            extend: exclusively ? cloud_assembly_1.ExtendedStackSelection.None : cloud_assembly_1.ExtendedStackSelection.Upstream,
            defaultBehavior: cxapp_1.DefaultSelection.MainAssembly,
        });
        const allStacks = await this.selectStacksForList([]);
        const autoValidateStacks = autoValidate
            ? allStacks.filter((art) => art.validateOnSynth ?? false)
            : new cloud_assembly_1.StackCollection(assembly, []);
        this.validateStacksSelected(selectedForDiff.concat(autoValidateStacks), stackNames);
        await this.validateStacks(selectedForDiff.concat(autoValidateStacks));
        return selectedForDiff;
    }
    async selectStacksForDestroy(selector, exclusively) {
        const assembly = await this.assembly();
        const stacks = await assembly.selectStacks(selector, {
            extend: exclusively ? cloud_assembly_1.ExtendedStackSelection.None : cloud_assembly_1.ExtendedStackSelection.Downstream,
            defaultBehavior: cxapp_1.DefaultSelection.OnlySingle,
        });
        // No validation
        return stacks;
    }
    /**
     * Validate the stacks for errors and warnings according to the CLI's current settings
     */
    async validateStacks(stacks) {
        const failAt = this.validateMetadataFailAt();
        await stacks.validateMetadata(failAt, stackMetadataLogger(this.ioHost.asIoHelper(), this.props.verbose));
    }
    validateMetadataFailAt() {
        let failAt = 'error';
        if (this.props.ignoreErrors) {
            failAt = 'none';
        }
        if (this.props.strict) {
            failAt = 'warn';
        }
        return failAt;
    }
    /**
     * Validate that if a user specified a stack name there exists at least 1 stack selected
     */
    validateStacksSelected(stacks, stackNames) {
        if (stackNames.length != 0 && stacks.stackCount == 0) {
            throw new toolkit_lib_1.ToolkitError(`No stacks match the name(s) ${stackNames}`);
        }
    }
    /**
     * Select a single stack by its name
     */
    async selectSingleStackByName(stackName) {
        const assembly = await this.assembly();
        const stacks = await assembly.selectStacks({ patterns: [stackName] }, {
            extend: cloud_assembly_1.ExtendedStackSelection.None,
            defaultBehavior: cxapp_1.DefaultSelection.None,
        });
        // Could have been a glob so check that we evaluated to exactly one
        if (stacks.stackCount > 1) {
            throw new toolkit_lib_1.ToolkitError(`This command requires exactly one stack and we matched more than one: ${stacks.stackIds}`);
        }
        return assembly.stackById(stacks.firstStack.id);
    }
    assembly(cacheCloudAssembly) {
        return this.props.cloudExecutable.synthesize(cacheCloudAssembly);
    }
    patternsArrayForWatch(patterns, options) {
        const patternsArray = patterns !== undefined ? (Array.isArray(patterns) ? patterns : [patterns]) : [];
        return patternsArray.length > 0 ? patternsArray : options.returnRootDirIfEmpty ? [options.rootDir] : [];
    }
    async invokeDeployFromWatch(options, cloudWatchLogMonitor) {
        const deployOptions = {
            ...options,
            requireApproval: cloud_assembly_schema_1.RequireApproval.NEVER,
            // if 'watch' is called by invoking 'cdk deploy --watch',
            // we need to make sure to not call 'deploy' with 'watch' again,
            // as that would lead to a cycle
            watch: false,
            cloudWatchLogMonitor,
            cacheCloudAssembly: false,
            extraUserAgent: `cdk-watch/hotswap-${options.deploymentMethod?.method === 'hotswap' ? 'on' : 'off'}`,
            concurrency: options.concurrency,
        };
        try {
            await this.deploy(deployOptions);
        }
        catch {
            // just continue - deploy will show the error
        }
    }
    /**
     * Remove the asset publishing and building from the work graph for assets that are already in place
     */
    async removePublishedAssets(graph, options) {
        await graph.removeUnnecessaryAssets(assetNode => this.props.deployments.isSingleAssetPublished(assetNode.assetManifest, assetNode.asset, {
            stack: assetNode.parentStack,
            roleArn: options.roleArn,
            stackName: assetNode.parentStack.stackName,
        }));
    }
}
exports.CdkToolkit = CdkToolkit;
/**
 * Print a serialized object (YAML or JSON) to stdout.
 */
async function printSerializedObject(ioHelper, obj, json) {
    await ioHelper.defaults.result((0, util_2.serializeStructure)(obj, json));
}
function buildParameterMap(parameters) {
    const parameterMap = { '*': {} };
    for (const key in parameters) {
        if (parameters.hasOwnProperty(key)) {
            const [stack, parameter] = key.split(':', 2);
            if (!parameter) {
                parameterMap['*'][stack] = parameters[key];
            }
            else {
                if (!parameterMap[stack]) {
                    parameterMap[stack] = {};
                }
                parameterMap[stack][parameter] = parameters[key];
            }
        }
    }
    return parameterMap;
}
/**
 * Ask the user for a yes/no confirmation
 *
 * Automatically fail the confirmation in case we're in a situation where the confirmation
 * cannot be interactively obtained from a human at the keyboard.
 */
async function askUserConfirmation(ioHost, req) {
    await ioHost.withCorkedLogging(async () => {
        await ioHost.asIoHelper().requestResponse(req);
    });
}
/**
 * Display a warning if there are flags that are different from the recommended value
 *
 * This happens if both of the following are true:
 *
 * - The user didn't configure the value
 * - The default value for the flag (unconfiguredBehavesLike) is different from the recommended value
 */
async function displayFlagsMessage(ioHost, toolkit, cloudExecutable) {
    const flags = await toolkit.flags(cloudExecutable);
    // The "unconfiguredBehavesLike" information got added later. If none of the flags have this information,
    // we don't have enough information to reliably display this information without scaring users, so don't do anything.
    if (flags.every(flag => flag.unconfiguredBehavesLike === undefined)) {
        return;
    }
    const unconfiguredFlags = flags
        .filter(flag => !obsolete_flags_1.OBSOLETE_FLAGS.includes(flag.name))
        .filter(flag => (flag.unconfiguredBehavesLike?.v2 ?? false) !== flag.recommendedValue)
        .filter(flag => flag.userValue === undefined);
    const numUnconfigured = unconfiguredFlags.length;
    if (numUnconfigured > 0) {
        await ioHost.defaults.warn(`${numUnconfigured} feature flags are not configured. Run 'cdk flags --unstable=flags' to learn more.`);
    }
}
/**
 * Logger for processing stack metadata
 */
function stackMetadataLogger(ioHelper, verbose) {
    const makeLogger = (level) => {
        switch (level) {
            case 'error':
                return [(m) => ioHelper.defaults.error(m), 'Error'];
            case 'warn':
                return [(m) => ioHelper.defaults.warn(m), 'Warning'];
            default:
                return [(m) => ioHelper.defaults.info(m), 'Info'];
        }
    };
    return async (level, msg) => {
        const [logFn, prefix] = makeLogger(level);
        await logFn(`[${prefix} at ${msg.id}] ${msg.entry.data}`);
        if (verbose && msg.entry.trace) {
            logFn(`  ${msg.entry.trace.join('\n  ')}`);
        }
    };
}
/**
 * Determine if manual approval is required or not. Requires approval for
 * - RequireApproval.ANY_CHANGE
 * - RequireApproval.BROADENING and the changes are indeed broadening permissions
 */
function requiresApproval(requireApproval, permissionChangeType) {
    return requireApproval === cloud_assembly_schema_1.RequireApproval.ANYCHANGE ||
        requireApproval === cloud_assembly_schema_1.RequireApproval.BROADENING && permissionChangeType === toolkit_lib_1.PermissionChangeType.BROADENING;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2RrLXRvb2xraXQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJjZGstdG9vbGtpdC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUEya0VBLGtEQWtCQztBQTdsRUQsNkJBQTZCO0FBQzdCLCtCQUE4QjtBQUM5QiwwRUFBaUU7QUFDakUseUNBQXlDO0FBRXpDLHNEQUFtRjtBQUNuRiwrQkFBK0I7QUFDL0IscUNBQXFDO0FBQ3JDLCtCQUErQjtBQUMvQiw2QkFBNkI7QUFDN0IsdUNBQXNDO0FBRXRDLDZEQUFzRDtBQUV0RCx1REFBNkU7QUFFN0UsZ0NBV2dCO0FBR2hCLGdEQUFnRDtBQUNoRCwwREFBZ0Y7QUFFaEYsOENBQTRFO0FBRTVFLCtDQUEyRDtBQUMzRCx5REFBcUQ7QUFFckQsaURBZTZCO0FBRTdCLG9DQUFvSDtBQUNwSCxzREFBbUQ7QUFDbkQsa0NBUWlCO0FBQ2pCLHFFQUFvRTtBQUNwRSw2Q0FBb0Q7QUFDcEQsbURBQXdEO0FBR3hELDZFQUE2RTtBQUM3RSw0R0FBNEc7QUFDNUcsTUFBTSxNQUFNLEdBQTZCLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQztBQXlENUQ7O0dBRUc7QUFDSCxJQUFZLGNBYVg7QUFiRCxXQUFZLGNBQWM7SUFDeEI7Ozs7O09BS0c7SUFDSCx5REFBdUMsQ0FBQTtJQUV2Qzs7T0FFRztJQUNILCtDQUE2QixDQUFBO0FBQy9CLENBQUMsRUFiVyxjQUFjLDhCQUFkLGNBQWMsUUFhekI7QUFFRDs7Ozs7R0FLRztBQUNILE1BQU0sZUFBZ0IsU0FBUSxxQkFBTztJQUVuQyxZQUFtQixXQUF3QixFQUFFLE9BQTBDO1FBQ3JGLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUNmLElBQUksQ0FBQyxZQUFZLEdBQUcsV0FBVyxDQUFDO0lBQ2xDLENBQUM7SUFFRDs7O09BR0c7SUFDTyxLQUFLLENBQUMsV0FBVyxDQUFDLE9BQXNCO1FBQ2hELE9BQU8sSUFBSSxDQUFDLFlBQVksQ0FBQztJQUMzQixDQUFDO0NBQ0Y7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QUFPLENBQUMsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxDQUFDO1lBQ3ZEO2dCQUNFLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsUUFBUSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFDdEQsQ0FBQztJQUNILENBQUMsQ0FBQztJQUVGLE9BQU8sS0FBSyxFQUFFLEtBQUssRUFBRSxHQUFHLEVBQUUsRUFBRTtRQUMxQixNQUFNLENBQUMsS0FBSyxFQUFFLE1BQU0sQ0FBQyxHQUFHLFVBQVUsQ0FBQyxLQUFLLENBQUMsQ0FBQztRQUMxQyxNQUFNLEtBQUssQ0FBQyxJQUFJLE1BQU0sT0FBTyxHQUFHLENBQUMsRUFBRSxLQUFLLEdBQUcsQ0FBQyxLQUFLLENBQUMsSUFBSSxFQUFFLENBQUMsQ0FBQztRQUUxRCxJQUFJLE9BQU8sSUFBSSxHQUFHLENBQUMsS0FBSyxDQUFDLEtBQUssRUFBRSxDQUFDO1lBQy9CLEtBQUssQ0FBQyxLQUFLLEdBQUcsQ0FBQyxLQUFLLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsRUFBRSxDQUFDLENBQUM7UUFDN0MsQ0FBQztJQUNILENBQUMsQ0FBQztBQUNKLENBQUM7QUFFRDs7OztHQUlHO0FBQ0gsU0FBUyxnQkFBZ0IsQ0FBQyxlQUFnQyxFQUFFLG9CQUEwQztJQUNwRyxPQUFPLGVBQWUsS0FBSyx1Q0FBZSxDQUFDLFNBQVM7UUFDbEQsZUFBZSxLQUFLLHVDQUFlLENBQUMsVUFBVSxJQUFJLG9CQUFvQixLQUFLLGtDQUFvQixDQUFDLFVBQVUsQ0FBQztBQUMvRyxDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0ICogYXMgcGF0aCBmcm9tICdwYXRoJztcbmltcG9ydCB7IGZvcm1hdCB9IGZyb20gJ3V0aWwnO1xuaW1wb3J0IHsgUmVxdWlyZUFwcHJvdmFsIH0gZnJvbSAnQGF3cy1jZGsvY2xvdWQtYXNzZW1ibHktc2NoZW1hJztcbmltcG9ydCAqIGFzIGN4YXBpIGZyb20gJ0Bhd3MtY2RrL2N4LWFwaSc7XG5pbXBvcnQgdHlwZSB7IENvbmZpcm1hdGlvblJlcXVlc3QsIERlcGxveW1lbnRNZXRob2QsIFRvb2xraXRBY3Rpb24sIFRvb2xraXRPcHRpb25zIH0gZnJvbSAnQGF3cy1jZGsvdG9vbGtpdC1saWInO1xuaW1wb3J0IHsgUGVybWlzc2lvbkNoYW5nZVR5cGUsIFRvb2xraXQsIFRvb2xraXRFcnJvciB9IGZyb20gJ0Bhd3MtY2RrL3Rvb2xraXQtbGliJztcbmltcG9ydCAqIGFzIGNoYWxrIGZyb20gJ2NoYWxrJztcbmltcG9ydCAqIGFzIGNob2tpZGFyIGZyb20gJ2Nob2tpZGFyJztcbmltcG9ydCAqIGFzIGZzIGZyb20gJ2ZzLWV4dHJhJztcbmltcG9ydCAqIGFzIHV1aWQgZnJvbSAndXVpZCc7XG5pbXBvcnQgeyBDbGlJb0hvc3QgfSBmcm9tICcuL2lvLWhvc3QnO1xuaW1wb3J0IHR5cGUgeyBDb25maWd1cmF0aW9uIH0gZnJvbSAnLi91c2VyLWNvbmZpZ3VyYXRpb24nO1xuaW1wb3J0IHsgUFJPSkVDVF9DT05GSUcgfSBmcm9tICcuL3VzZXItY29uZmlndXJhdGlvbic7XG5pbXBvcnQgdHlwZSB7IEFjdGlvbkxlc3NSZXF1ZXN0LCBJb0hlbHBlciB9IGZyb20gJy4uLy4uL2xpYi9hcGktcHJpdmF0ZSc7XG5pbXBvcnQgeyBhc0lvSGVscGVyLCBjZm5BcGksIElPLCB0YWdzRm9yU3RhY2sgfSBmcm9tICcuLi8uLi9saWIvYXBpLXByaXZhdGUnO1xuaW1wb3J0IHR5cGUgeyBBc3NldEJ1aWxkTm9kZSwgQXNzZXRQdWJsaXNoTm9kZSwgQ29uY3VycmVuY3ksIFN0YWNrTm9kZSwgV29ya0dyYXBoIH0gZnJvbSAnLi4vYXBpJztcbmltcG9ydCB7XG4gIENsb3VkV2F0Y2hMb2dFdmVudE1vbml0b3IsXG4gIERFRkFVTFRfVE9PTEtJVF9TVEFDS19OQU1FLFxuICBEaWZmRm9ybWF0dGVyLFxuICBmaW5kQ2xvdWRXYXRjaExvZ0dyb3VwcyxcbiAgR2FyYmFnZUNvbGxlY3RvcixcbiAgcmVtb3ZlTm9uSW1wb3J0UmVzb3VyY2VzLFxuICBSZXNvdXJjZUltcG9ydGVyLFxuICBSZXNvdXJjZU1pZ3JhdG9yLFxuICBTdGFja1NlbGVjdGlvblN0cmF0ZWd5LFxuICBXb3JrR3JhcGhCdWlsZGVyLFxufSBmcm9tICcuLi9hcGknO1xuaW1wb3J0IHR5cGUgeyBTZGtQcm92aWRlciB9IGZyb20gJy4uL2FwaS9hd3MtYXV0aCc7XG5pbXBvcnQgdHlwZSB7IEJvb3RzdHJhcEVudmlyb25tZW50T3B0aW9ucyB9IGZyb20gJy4uL2FwaS9ib290c3RyYXAnO1xuaW1wb3J0IHsgQm9vdHN0cmFwcGVyIH0gZnJvbSAnLi4vYXBpL2Jvb3RzdHJhcCc7XG5pbXBvcnQgeyBFeHRlbmRlZFN0YWNrU2VsZWN0aW9uLCBTdGFja0NvbGxlY3Rpb24gfSBmcm9tICcuLi9hcGkvY2xvdWQtYXNzZW1ibHknO1xuaW1wb3J0IHR5cGUgeyBEZXBsb3ltZW50cywgU3VjY2Vzc2Z1bERlcGxveVN0YWNrUmVzdWx0IH0gZnJvbSAnLi4vYXBpL2RlcGxveW1lbnRzJztcbmltcG9ydCB7IG1hcHBpbmdzQnlFbnZpcm9ubWVudCwgcGFyc2VNYXBwaW5nR3JvdXBzIH0gZnJvbSAnLi4vYXBpL3JlZmFjdG9yJztcbmltcG9ydCB7IHR5cGUgVGFnIH0gZnJvbSAnLi4vYXBpL3RhZ3MnO1xuaW1wb3J0IHsgU3RhY2tBY3Rpdml0eVByb2dyZXNzIH0gZnJvbSAnLi4vY29tbWFuZHMvZGVwbG95JztcbmltcG9ydCB7IGxpc3RTdGFja3MgfSBmcm9tICcuLi9jb21tYW5kcy9saXN0LXN0YWNrcyc7XG5pbXBvcnQgdHlwZSB7IEZyb21TY2FuLCBHZW5lcmF0ZVRlbXBsYXRlT3V0cHV0IH0gZnJvbSAnLi4vY29tbWFuZHMvbWlncmF0ZSc7XG5pbXBvcnQge1xuICBhcHBlbmRXYXJuaW5nc1RvUmVhZG1lLFxuICBidWlsZENmbkNsaWVudCxcbiAgYnVpbGRHZW5lcmF0ZWRUZW1wbGF0ZU91dHB1dCxcbiAgQ2ZuVGVtcGxhdGVHZW5lcmF0b3JQcm92aWRlcixcbiAgZ2VuZXJhdGVDZGtBcHAsXG4gIGdlbmVyYXRlU3RhY2ssXG4gIGdlbmVyYXRlVGVtcGxhdGUsXG4gIGlzVGhlcmVBV2FybmluZyxcbiAgcGFyc2VTb3VyY2VPcHRpb25zLFxuICByZWFkRnJvbVBhdGgsXG4gIHJlYWRGcm9tU3RhY2ssXG4gIHNldEVudmlyb25tZW50LFxuICBUZW1wbGF0ZVNvdXJjZU9wdGlvbnMsXG4gIHdyaXRlTWlncmF0ZUpzb25GaWxlLFxufSBmcm9tICcuLi9jb21tYW5kcy9taWdyYXRlJztcbmltcG9ydCB0eXBlIHsgQ2xvdWRBc3NlbWJseSwgQ2xvdWRFeGVjdXRhYmxlLCBTdGFja1NlbGVjdG9yIH0gZnJvbSAnLi4vY3hhcHAnO1xuaW1wb3J0IHsgRGVmYXVsdFNlbGVjdGlvbiwgZW52aXJvbm1lbnRzRnJvbURlc2NyaXB0b3JzLCBnbG9iRW52aXJvbm1lbnRzRnJvbVN0YWNrcywgbG9va3NMaWtlR2xvYiB9IGZyb20gJy4uL2N4YXBwJztcbmltcG9ydCB7IE9CU09MRVRFX0ZMQUdTIH0gZnJvbSAnLi4vb2Jzb2xldGUtZmxhZ3MnO1xuaW1wb3J0IHtcbiAgZGVzZXJpYWxpemVTdHJ1Y3R1cmUsXG4gIGZvcm1hdEVycm9yTWVzc2FnZSxcbiAgZm9ybWF0VGltZSxcbiAgb2JzY3VyZVRlbXBsYXRlLFxuICBwYXJ0aXRpb24sXG4gIHNlcmlhbGl6ZVN0cnVjdHVyZSxcbiAgdmFsaWRhdGVTbnNUb3BpY0Fybixcbn0gZnJvbSAnLi4vdXRpbCc7XG5pbXBvcnQgeyBjYW5Db2xsZWN0VGVsZW1ldHJ5IH0gZnJvbSAnLi90ZWxlbWV0cnkvY29sbGVjdC10ZWxlbWV0cnknO1xuaW1wb3J0IHsgY2RrQ2xpRXJyb3JOYW1lIH0gZnJvbSAnLi90ZWxlbWV0cnkvZXJyb3InO1xuaW1wb3J0IHsgQ0xJX1BSSVZBVEVfU1BBTiB9IGZyb20gJy4vdGVsZW1ldHJ5L21lc3NhZ2VzJztcbmltcG9ydCB0eXBlIHsgRXJyb3JEZXRhaWxzIH0gZnJvbSAnLi90ZWxlbWV0cnkvc2NoZW1hJztcblxuLy8gTXVzdCB1c2UgYSByZXF1aXJlKCkgb3RoZXJ3aXNlIGVzYnVpbGQgY29tcGxhaW5zIGFib3V0IGNhbGxpbmcgYSBuYW1lc3BhY2Vcbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBAdHlwZXNjcmlwdC1lc2xpbnQvbm8tcmVxdWlyZS1pbXBvcnRzLEB0eXBlc2NyaXB0LWVzbGludC9jb25zaXN0ZW50LXR5cGUtaW1wb3J0c1xuY29uc3QgcExpbWl0OiB0eXBlb2YgaW1wb3J0KCdwLWxpbWl0JykgPSByZXF1aXJlKCdwLWxpbWl0Jyk7XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2RrVG9vbGtpdFByb3BzIHtcbiAgLyoqXG4gICAqIFRoZSBDbG91ZCBFeGVjdXRhYmxlXG4gICAqL1xuICBjbG91ZEV4ZWN1dGFibGU6IENsb3VkRXhlY3V0YWJsZTtcblxuICAvKipcbiAgICogVGhlIHByb3Zpc2lvbmluZyBlbmdpbmUgdXNlZCB0byBhcHBseSBjaGFuZ2VzIHRvIHRoZSBjbG91ZFxuICAgKi9cbiAgZGVwbG95bWVudHM6IERlcGxveW1lbnRzO1xuXG4gIC8qKlxuICAgKiBUaGUgQ2xpSW9Ib3N0IHRoYXQncyB1c2VkIGZvciBJL08gb3BlcmF0aW9uc1xuICAgKi9cbiAgaW9Ib3N0PzogQ2xpSW9Ib3N0O1xuXG4gIC8qKlxuICAgKiBOYW1lIG9mIHRoZSB0b29sa2l0IHN0YWNrIHRvIHVzZS9kZXBsb3lcbiAgICpcbiAgICogQGRlZmF1bHQgQ0RLVG9vbGtpdFxuICAgKi9cbiAgdG9vbGtpdFN0YWNrTmFtZT86IHN0cmluZztcblxuICAvKipcbiAgICogV2hldGhlciB0byBiZSB2ZXJib3NlXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICB2ZXJib3NlPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogRG9uJ3Qgc3RvcCBvbiBlcnJvciBtZXRhZGF0YVxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgaWdub3JlRXJyb3JzPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogVHJlYXQgd2FybmluZ3MgaW4gbWV0YWRhdGEgYXMgZXJyb3JzXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICBzdHJpY3Q/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBBcHBsaWNhdGlvbiBjb25maWd1cmF0aW9uIChzZXR0aW5ncyBhbmQgY29udGV4dClcbiAgICovXG4gIGNvbmZpZ3VyYXRpb246IENvbmZpZ3VyYXRpb247XG5cbiAgLyoqXG4gICAqIEFXUyBvYmplY3QgKHVzZWQgYnkgc3ludGhlc2l6ZXIgYW5kIGNvbnRleHRwcm92aWRlcilcbiAgICovXG4gIHNka1Byb3ZpZGVyOiBTZGtQcm92aWRlcjtcbn1cblxuLyoqXG4gKiBXaGVuIHRvIGJ1aWxkIGFzc2V0c1xuICovXG5leHBvcnQgZW51bSBBc3NldEJ1aWxkVGltZSB7XG4gIC8qKlxuICAgKiBCdWlsZCBhbGwgYXNzZXRzIGJlZm9yZSBkZXBsb3lpbmcgdGhlIGZpcnN0IHN0YWNrXG4gICAqXG4gICAqIFRoaXMgaXMgaW50ZW5kZWQgZm9yIGV4cGVuc2l2ZSBEb2NrZXIgaW1hZ2UgYnVpbGRzOyBzbyB0aGF0IGlmIHRoZSBEb2NrZXIgaW1hZ2UgYnVpbGRcbiAgICogZmFpbHMsIG5vIHN0YWNrcyBhcmUgdW5uZWNlc3NhcmlseSBkZXBsb3llZCAod2l0aCB0aGUgYXR0ZW5kYW50IHdhaXQgdGltZSkuXG4gICAqL1xuICBBTExfQkVGT1JFX0RFUExPWSA9ICdhbGwtYmVmb3JlLWRlcGxveScsXG5cbiAgLyoqXG4gICAqIEJ1aWxkIGFzc2V0cyBqdXN0LWluLXRpbWUsIGJlZm9yZSBwdWJsaXNoaW5nXG4gICAqL1xuICBKVVNUX0lOX1RJTUUgPSAnanVzdC1pbi10aW1lJyxcbn1cblxuLyoqXG4gKiBDdXN0b20gaW1wbGVtZW50YXRpb24gb2YgdGhlIHB1YmxpYyBUb29sa2l0IHRvIGludGVncmF0ZSB3aXRoIHRoZSBsZWdhY3kgQ2RrVG9vbGtpdFxuICpcbiAqIFRoaXMgb3ZlcndyaXRlcyBob3cgYW4gc2RrUHJvdmlkZXIgaXMgYWNxdWlyZWRcbiAqIGluIGZhdm9yIG9mIHRoZSBvbmUgcHJvdmlkZWQgZGlyZWN0bHkgdG8gQ2RrVG9vbGtpdC5cbiAqL1xuY2xhc3MgSW50ZXJuYWxUb29sa2l0IGV4dGVuZHMgVG9vbGtpdCB7XG4gIHByaXZhdGUgcmVhZG9ubHkgX3Nka1Byb3ZpZGVyOiBTZGtQcm92aWRlcjtcbiAgcHVibGljIGNvbnN0cnVjdG9yKHNka1Byb3ZpZGVyOiBTZGtQcm92aWRlciwgb3B0aW9uczogT21pdDxUb29sa2l0T3B0aW9ucywgJ3Nka0NvbmZpZyc+KSB7XG4gICAgc3VwZXIob3B0aW9ucyk7XG4gICAgdGhpcy5fc2RrUHJvdmlkZXIgPSBzZGtQcm92aWRlcjtcbiAgfVxuXG4gIC8qKlxuICAgKiBBY2Nlc3MgdG8gdGhlIEFXUyBTREtcbiAgICogQGludGVybmFsXG4gICAqL1xuICBwcm90ZWN0ZWQgYXN5bmMgc2RrUHJvdmlkZXIoX2FjdGlvbjogVG9vbGtpdEFjdGlvbik6IFByb21pc2U8U2RrUHJvdmlkZXI+IHtcbiAgICByZXR1cm4gdGhpcy5fc2RrUHJvdmlkZXI7XG4gIH1cbn1cblxuLyoqXG4gKiBUb29sa2l0IGxvZ2ljXG4gKlxuICogVGhlIHRvb2xraXQgcnVucyB0aGUgYGNsb3VkRXhlY3V0YWJsZWAgdG8gb2J0YWluIGEgY2xvdWQgYXNzZW1ibHkgYW5kXG4gKiBkZXBsb3lzIGFwcGxpZXMgdGhlbSB0byBgY2xvdWRGb3JtYXRpb25gLlxuICovXG5leHBvcnQgY2xhc3MgQ2RrVG9vbGtpdCB7XG4gIHByaXZhdGUgaW9Ib3N0OiBDbGlJb0hvc3Q7XG4gIHByaXZhdGUgdG9vbGtpdFN0YWNrTmFtZTogc3RyaW5nO1xuICBwcml2YXRlIHRvb2xraXQ6IEludGVybmFsVG9vbGtpdDtcblxuICBjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IHByb3BzOiBDZGtUb29sa2l0UHJvcHMpIHtcbiAgICB0aGlzLmlvSG9zdCA9IHByb3BzLmlvSG9zdCA/PyBDbGlJb0hvc3QuaW5zdGFuY2UoKTtcbiAgICB0aGlzLnRvb2xraXRTdGFja05hbWUgPSBwcm9wcy50b29sa2l0U3RhY2tOYW1lID8/IERFRkFVTFRfVE9PTEtJVF9TVEFDS19OQU1FO1xuXG4gICAgdGhpcy50b29sa2l0ID0gbmV3IEludGVybmFsVG9vbGtpdChwcm9wcy5zZGtQcm92aWRlciwge1xuICAgICAgYXNzZW1ibHlGYWlsdXJlQXQ6IHRoaXMudmFsaWRhdGVNZXRhZGF0YUZhaWxBdCgpLFxuICAgICAgY29sb3I6IHRydWUsXG4gICAgICBlbW9qaXM6IHRydWUsXG4gICAgICBpb0hvc3Q6IHRoaXMuaW9Ib3N0LFxuICAgICAgdG9vbGtpdFN0YWNrTmFtZTogdGhpcy50b29sa2l0U3RhY2tOYW1lLFxuICAgICAgdW5zdGFibGVGZWF0dXJlczogWydyZWZhY3RvcicsICdmbGFncyddLFxuICAgIH0pO1xuICB9XG5cbiAgcHVibGljIGFzeW5jIG1ldGFkYXRhKHN0YWNrTmFtZTogc3RyaW5nLCBqc29uOiBib29sZWFuKSB7XG4gICAgY29uc3Qgc3RhY2tzID0gYXdhaXQgdGhpcy5zZWxlY3RTaW5nbGVTdGFja0J5TmFtZShzdGFja05hbWUpO1xuICAgIGF3YWl0IHByaW50U2VyaWFsaXplZE9iamVjdCh0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCksIHN0YWNrcy5maXJzdFN0YWNrLm1hbmlmZXN0Lm1ldGFkYXRhID8/IHt9LCBqc29uKTtcbiAgfVxuXG4gIHB1YmxpYyBhc3luYyBhY2tub3dsZWRnZShub3RpY2VJZDogc3RyaW5nKSB7XG4gICAgY29uc3QgYWNrcyA9IG5ldyBTZXQodGhpcy5wcm9wcy5jb25maWd1cmF0aW9uLmNvbnRleHQuZ2V0KCdhY2tub3dsZWRnZWQtaXNzdWUtbnVtYmVycycpID8/IFtdKTtcbiAgICBhY2tzLmFkZChOdW1iZXIobm90aWNlSWQpKTtcbiAgICB0aGlzLnByb3BzLmNvbmZpZ3VyYXRpb24uY29udGV4dC5zZXQoJ2Fja25vd2xlZGdlZC1pc3N1ZS1udW1iZXJzJywgQXJyYXkuZnJvbShhY2tzKSk7XG4gICAgYXdhaXQgdGhpcy5wcm9wcy5jb25maWd1cmF0aW9uLnNhdmVDb250ZXh0KCk7XG4gIH1cblxuICBwdWJsaWMgYXN5bmMgY2xpVGVsZW1ldHJ5U3RhdHVzKHZlcnNpb25SZXBvcnRpbmc6IGJvb2xlYW4gPSB0cnVlKSB7XG4gICAgLy8gcmVjcmVhdGUgdGhlIHZlcnNpb24tcmVwb3J0aW5nIHByb3BlcnR5IGluIGFyZ3MgcmF0aGVyIHRoYW4gYnJpbmcgdGhlIGVudGlyZSBhcmdzIG9iamVjdCBvdmVyXG4gICAgY29uc3QgYXJncyA9IHsgWyd2ZXJzaW9uLXJlcG9ydGluZyddOiB2ZXJzaW9uUmVwb3J0aW5nIH07XG4gICAgY29uc3QgY2FuQ29sbGVjdCA9IGNhbkNvbGxlY3RUZWxlbWV0cnkoYXJncywgdGhpcy5wcm9wcy5jb25maWd1cmF0aW9uLmNvbnRleHQpO1xuICAgIGlmIChjYW5Db2xsZWN0KSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbygnQ0xJIFRlbGVtZXRyeSBpcyBlbmFibGVkLiBTZWUgaHR0cHM6Ly9kb2NzLmF3cy5hbWF6b24uY29tL2Nkay92Mi9ndWlkZS9jbGktdGVsZW1ldHJ5Lmh0bWwgZm9yIHdheXMgdG8gZGlzYWJsZS4nKTtcbiAgICB9IGVsc2Uge1xuICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLmluZm8oJ0NMSSBUZWxlbWV0cnkgaXMgZGlzYWJsZWQuIFNlZSBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vY2RrL3YyL2d1aWRlL2NsaS10ZWxlbWV0cnkuaHRtbCBmb3Igd2F5cyB0byBlbmFibGUuJyk7XG4gICAgfVxuICB9XG5cbiAgcHVibGljIGFzeW5jIGNsaVRlbGVtZXRyeShlbmFibGU6IGJvb2xlYW4pIHtcbiAgICB0aGlzLnByb3BzLmNvbmZpZ3VyYXRpb24uY29udGV4dC5zZXQoJ2NsaS10ZWxlbWV0cnknLCBlbmFibGUpO1xuICAgIGF3YWl0IHRoaXMucHJvcHMuY29uZmlndXJhdGlvbi5zYXZlQ29udGV4dCgpO1xuICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKGBUZWxlbWV0cnkgJHtlbmFibGUgPyAnZW5hYmxlZCcgOiAnZGlzYWJsZWQnfWApO1xuICB9XG5cbiAgcHVibGljIGFzeW5jIGRpZmYob3B0aW9uczogRGlmZk9wdGlvbnMpOiBQcm9taXNlPG51bWJlcj4ge1xuICAgIGNvbnN0IHN0YWNrcyA9IGF3YWl0IHRoaXMuc2VsZWN0U3RhY2tzRm9yRGlmZihvcHRpb25zLnN0YWNrTmFtZXMsIG9wdGlvbnMuZXhjbHVzaXZlbHkpO1xuXG4gICAgY29uc3Qgc3RyaWN0ID0gISFvcHRpb25zLnN0cmljdDtcbiAgICBjb25zdCBjb250ZXh0TGluZXMgPSBvcHRpb25zLmNvbnRleHRMaW5lcyB8fCAzO1xuICAgIGNvbnN0IHF1aWV0ID0gb3B0aW9ucy5xdWlldCB8fCBmYWxzZTtcblxuICAgIGxldCBkaWZmcyA9IDA7XG4gICAgY29uc3QgcGFyYW1ldGVyTWFwID0gYnVpbGRQYXJhbWV0ZXJNYXAob3B0aW9ucy5wYXJhbWV0ZXJzKTtcblxuICAgIGlmIChvcHRpb25zLnRlbXBsYXRlUGF0aCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAvLyBDb21wYXJlIHNpbmdsZSBzdGFjayBhZ2FpbnN0IGZpeGVkIHRlbXBsYXRlXG4gICAgICBpZiAoc3RhY2tzLnN0YWNrQ291bnQgIT09IDEpIHtcbiAgICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihcbiAgICAgICAgICAnQ2FuIG9ubHkgc2VsZWN0IG9uZSBzdGFjayB3aGVuIGNvbXBhcmluZyB0byBmaXhlZCB0ZW1wbGF0ZS4gVXNlIC0tZXhjbHVzaXZlbHkgdG8gYXZvaWQgc2VsZWN0aW5nIG11bHRpcGxlIHN0YWNrcy4nLFxuICAgICAgICApO1xuICAgICAgfVxuXG4gICAgICBpZiAoIShhd2FpdCBmcy5wYXRoRXhpc3RzKG9wdGlvbnMudGVtcGxhdGVQYXRoKSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihgVGhlcmUgaXMgbm8gZmlsZSBhdCAke29wdGlvbnMudGVtcGxhdGVQYXRofWApO1xuICAgICAgfVxuXG4gICAgICBpZiAob3B0aW9ucy5pbXBvcnRFeGlzdGluZ1Jlc291cmNlcykge1xuICAgICAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKFxuICAgICAgICAgICdDYW4gb25seSB1c2UgLS1pbXBvcnQtZXhpc3RpbmctcmVzb3VyY2VzIGZsYWcgd2hlbiBjb21wYXJpbmcgYWdhaW5zdCBkZXBsb3llZCBzdGFja3MuJyxcbiAgICAgICAgKTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgdGVtcGxhdGUgPSBkZXNlcmlhbGl6ZVN0cnVjdHVyZShhd2FpdCBmcy5yZWFkRmlsZShvcHRpb25zLnRlbXBsYXRlUGF0aCwgeyBlbmNvZGluZzogJ1VURi04JyB9KSk7XG4gICAgICBjb25zdCBmb3JtYXR0ZXIgPSBuZXcgRGlmZkZvcm1hdHRlcih7XG4gICAgICAgIHRlbXBsYXRlSW5mbzoge1xuICAgICAgICAgIG9sZFRlbXBsYXRlOiB0ZW1wbGF0ZSxcbiAgICAgICAgICBuZXdUZW1wbGF0ZTogc3RhY2tzLmZpcnN0U3RhY2ssXG4gICAgICAgIH0sXG4gICAgICB9KTtcblxuICAgICAgaWYgKG9wdGlvbnMuc2VjdXJpdHlPbmx5KSB7XG4gICAgICAgIGNvbnN0IHNlY3VyaXR5RGlmZiA9IGZvcm1hdHRlci5mb3JtYXRTZWN1cml0eURpZmYoKTtcbiAgICAgICAgLy8gV2FybiwgY291bnQsIGFuZCBkaXNwbGF5IHRoZSBkaWZmIG9ubHkgaWYgdGhlIHJlcG9ydGVkIGNoYW5nZXMgYXJlIGJyb2FkZW5pbmcgcGVybWlzc2lvbnNcbiAgICAgICAgaWYgKHNlY3VyaXR5RGlmZi5wZXJtaXNzaW9uQ2hhbmdlVHlwZSA9PT0gUGVybWlzc2lvbkNoYW5nZVR5cGUuQlJPQURFTklORykge1xuICAgICAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy53YXJuKCdUaGlzIGRlcGxveW1lbnQgd2lsbCBtYWtlIHBvdGVudGlhbGx5IHNlbnNpdGl2ZSBjaGFuZ2VzIGFjY29yZGluZyB0byB5b3VyIGN1cnJlbnQgc2VjdXJpdHkgYXBwcm92YWwgbGV2ZWwuXFxuUGxlYXNlIGNvbmZpcm0geW91IGludGVuZCB0byBtYWtlIHRoZSBmb2xsb3dpbmcgbW9kaWZpY2F0aW9uczpcXG4nKTtcbiAgICAgICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbyhzZWN1cml0eURpZmYuZm9ybWF0dGVkRGlmZik7XG4gICAgICAgICAgZGlmZnMgKz0gMTtcbiAgICAgICAgfVxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgY29uc3QgZGlmZiA9IGZvcm1hdHRlci5mb3JtYXRTdGFja0RpZmYoe1xuICAgICAgICAgIHN0cmljdCxcbiAgICAgICAgICBjb250ZXh0TGluZXMsXG4gICAgICAgICAgcXVpZXQsXG4gICAgICAgIH0pO1xuICAgICAgICBkaWZmcyA9IGRpZmYubnVtU3RhY2tzV2l0aENoYW5nZXM7XG4gICAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKGRpZmYuZm9ybWF0dGVkRGlmZik7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGNvbnN0IGFsbE1hcHBpbmdzID0gb3B0aW9ucy5pbmNsdWRlTW92ZXNcbiAgICAgICAgPyBhd2FpdCBtYXBwaW5nc0J5RW52aXJvbm1lbnQoc3RhY2tzLnN0YWNrQXJ0aWZhY3RzLCB0aGlzLnByb3BzLnNka1Byb3ZpZGVyLCB0cnVlKVxuICAgICAgICA6IFtdO1xuXG4gICAgICAvLyBDb21wYXJlIE4gc3RhY2tzIGFnYWluc3QgZGVwbG95ZWQgdGVtcGxhdGVzXG4gICAgICBmb3IgKGNvbnN0IHN0YWNrIG9mIHN0YWNrcy5zdGFja0FydGlmYWN0cykge1xuICAgICAgICBjb25zdCB0ZW1wbGF0ZVdpdGhOZXN0ZWRTdGFja3MgPSBhd2FpdCB0aGlzLnByb3BzLmRlcGxveW1lbnRzLnJlYWRDdXJyZW50VGVtcGxhdGVXaXRoTmVzdGVkU3RhY2tzKFxuICAgICAgICAgIHN0YWNrLFxuICAgICAgICAgIG9wdGlvbnMuY29tcGFyZUFnYWluc3RQcm9jZXNzZWRUZW1wbGF0ZSxcbiAgICAgICAgKTtcbiAgICAgICAgY29uc3QgY3VycmVudFRlbXBsYXRlID0gdGVtcGxhdGVXaXRoTmVzdGVkU3RhY2tzLmRlcGxveWVkUm9vdFRlbXBsYXRlO1xuICAgICAgICBjb25zdCBuZXN0ZWRTdGFja3MgPSB0ZW1wbGF0ZVdpdGhOZXN0ZWRTdGFja3MubmVzdGVkU3RhY2tzO1xuXG4gICAgICAgIGNvbnN0IG1pZ3JhdG9yID0gbmV3IFJlc291cmNlTWlncmF0b3Ioe1xuICAgICAgICAgIGRlcGxveW1lbnRzOiB0aGlzLnByb3BzLmRlcGxveW1lbnRzLFxuICAgICAgICAgIGlvSGVscGVyOiBhc0lvSGVscGVyKHRoaXMuaW9Ib3N0LCAnZGlmZicpLFxuICAgICAgICB9KTtcbiAgICAgICAgY29uc3QgcmVzb3VyY2VzVG9JbXBvcnQgPSBhd2FpdCBtaWdyYXRvci50cnlHZXRSZXNvdXJjZXMoYXdhaXQgdGhpcy5wcm9wcy5kZXBsb3ltZW50cy5yZXNvbHZlRW52aXJvbm1lbnQoc3RhY2spKTtcbiAgICAgICAgaWYgKHJlc291cmNlc1RvSW1wb3J0KSB7XG4gICAgICAgICAgcmVtb3ZlTm9uSW1wb3J0UmVzb3VyY2VzKHN0YWNrKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGxldCBjaGFuZ2VTZXQgPSB1bmRlZmluZWQ7XG5cbiAgICAgICAgaWYgKG9wdGlvbnMuY2hhbmdlU2V0KSB7XG4gICAgICAgICAgbGV0IHN0YWNrRXhpc3RzID0gZmFsc2U7XG4gICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHN0YWNrRXhpc3RzID0gYXdhaXQgdGhpcy5wcm9wcy5kZXBsb3ltZW50cy5zdGFja0V4aXN0cyh7XG4gICAgICAgICAgICAgIHN0YWNrLFxuICAgICAgICAgICAgICBkZXBsb3lOYW1lOiBzdGFjay5zdGFja05hbWUsXG4gICAgICAgICAgICAgIHRyeUxvb2t1cFJvbGU6IHRydWUsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9IGNhdGNoIChlOiBhbnkpIHtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5kZWJ1Zyhmb3JtYXRFcnJvck1lc3NhZ2UoZSkpO1xuICAgICAgICAgICAgaWYgKCFxdWlldCkge1xuICAgICAgICAgICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbyhcbiAgICAgICAgICAgICAgICBgQ2hlY2tpbmcgaWYgdGhlIHN0YWNrICR7c3RhY2suc3RhY2tOYW1lfSBleGlzdHMgYmVmb3JlIGNyZWF0aW5nIHRoZSBjaGFuZ2VzZXQgaGFzIGZhaWxlZCwgd2lsbCBiYXNlIHRoZSBkaWZmIG9uIHRlbXBsYXRlIGRpZmZlcmVuY2VzIChydW4gYWdhaW4gd2l0aCAtdiB0byBzZWUgdGhlIHJlYXNvbilcXG5gLFxuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgc3RhY2tFeGlzdHMgPSBmYWxzZTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAoc3RhY2tFeGlzdHMpIHtcbiAgICAgICAgICAgIGNoYW5nZVNldCA9IGF3YWl0IGNmbkFwaS5jcmVhdGVEaWZmQ2hhbmdlU2V0KGFzSW9IZWxwZXIodGhpcy5pb0hvc3QsICdkaWZmJyksIHtcbiAgICAgICAgICAgICAgc3RhY2ssXG4gICAgICAgICAgICAgIHV1aWQ6IHV1aWQudjQoKSxcbiAgICAgICAgICAgICAgZGVwbG95bWVudHM6IHRoaXMucHJvcHMuZGVwbG95bWVudHMsXG4gICAgICAgICAgICAgIHdpbGxFeGVjdXRlOiBmYWxzZSxcbiAgICAgICAgICAgICAgc2RrUHJvdmlkZXI6IHRoaXMucHJvcHMuc2RrUHJvdmlkZXIsXG4gICAgICAgICAgICAgIHBhcmFtZXRlcnM6IE9iamVjdC5hc3NpZ24oe30sIHBhcmFtZXRlck1hcFsnKiddLCBwYXJhbWV0ZXJNYXBbc3RhY2suc3RhY2tOYW1lXSksXG4gICAgICAgICAgICAgIHJlc291cmNlc1RvSW1wb3J0LFxuICAgICAgICAgICAgICBpbXBvcnRFeGlzdGluZ1Jlc291cmNlczogb3B0aW9ucy5pbXBvcnRFeGlzdGluZ1Jlc291cmNlcyxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuZGVidWcoXG4gICAgICAgICAgICAgIGB0aGUgc3RhY2sgJyR7c3RhY2suc3RhY2tOYW1lfScgaGFzIG5vdCBiZWVuIGRlcGxveWVkIHRvIENsb3VkRm9ybWF0aW9uIG9yIGRlc2NyaWJlU3RhY2tzIGNhbGwgZmFpbGVkLCBza2lwcGluZyBjaGFuZ2VzZXQgY3JlYXRpb24uYCxcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgbWFwcGluZ3MgPSBhbGxNYXBwaW5ncy5maW5kKG0gPT5cbiAgICAgICAgICBtLmVudmlyb25tZW50LnJlZ2lvbiA9PT0gc3RhY2suZW52aXJvbm1lbnQucmVnaW9uICYmIG0uZW52aXJvbm1lbnQuYWNjb3VudCA9PT0gc3RhY2suZW52aXJvbm1lbnQuYWNjb3VudCxcbiAgICAgICAgKT8ubWFwcGluZ3MgPz8ge307XG5cbiAgICAgICAgY29uc3QgZm9ybWF0dGVyID0gbmV3IERpZmZGb3JtYXR0ZXIoe1xuICAgICAgICAgIHRlbXBsYXRlSW5mbzoge1xuICAgICAgICAgICAgb2xkVGVtcGxhdGU6IGN1cnJlbnRUZW1wbGF0ZSxcbiAgICAgICAgICAgIG5ld1RlbXBsYXRlOiBzdGFjayxcbiAgICAgICAgICAgIGNoYW5nZVNldCxcbiAgICAgICAgICAgIGlzSW1wb3J0OiAhIXJlc291cmNlc1RvSW1wb3J0LFxuICAgICAgICAgICAgbmVzdGVkU3RhY2tzLFxuICAgICAgICAgICAgbWFwcGluZ3MsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSk7XG5cbiAgICAgICAgaWYgKG9wdGlvbnMuc2VjdXJpdHlPbmx5KSB7XG4gICAgICAgICAgY29uc3Qgc2VjdXJpdHlEaWZmID0gZm9ybWF0dGVyLmZvcm1hdFNlY3VyaXR5RGlmZigpO1xuICAgICAgICAgIC8vIFdhcm4sIGNvdW50LCBhbmQgZGlzcGxheSB0aGUgZGlmZiBvbmx5IGlmIHRoZSByZXBvcnRlZCBjaGFuZ2VzIGFyZSBicm9hZGVuaW5nIHBlcm1pc3Npb25zXG4gICAgICAgICAgaWYgKHNlY3VyaXR5RGlmZi5wZXJtaXNzaW9uQ2hhbmdlVHlwZSA9PT0gUGVybWlzc2lvbkNoYW5nZVR5cGUuQlJPQURFTklORykge1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLndhcm4oJ1RoaXMgZGVwbG95bWVudCB3aWxsIG1ha2UgcG90ZW50aWFsbHkgc2Vuc2l0aXZlIGNoYW5nZXMgYWNjb3JkaW5nIHRvIHlvdXIgY3VycmVudCBzZWN1cml0eSBhcHByb3ZhbCBsZXZlbC5cXG5QbGVhc2UgY29uZmlybSB5b3UgaW50ZW5kIHRvIG1ha2UgdGhlIGZvbGxvd2luZyBtb2RpZmljYXRpb25zOlxcbicpO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLmluZm8oc2VjdXJpdHlEaWZmLmZvcm1hdHRlZERpZmYpO1xuICAgICAgICAgICAgZGlmZnMgKz0gMTtcbiAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgY29uc3QgZGlmZiA9IGZvcm1hdHRlci5mb3JtYXRTdGFja0RpZmYoe1xuICAgICAgICAgICAgc3RyaWN0LFxuICAgICAgICAgICAgY29udGV4dExpbmVzLFxuICAgICAgICAgICAgcXVpZXQsXG4gICAgICAgICAgfSk7XG4gICAgICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLmluZm8oZGlmZi5mb3JtYXR0ZWREaWZmKTtcbiAgICAgICAgICBkaWZmcyArPSBkaWZmLm51bVN0YWNrc1dpdGhDaGFuZ2VzO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLmluZm8oZm9ybWF0KCdcXG7inKggIE51bWJlciBvZiBzdGFja3Mgd2l0aCBkaWZmZXJlbmNlczogJXNcXG4nLCBkaWZmcykpO1xuXG4gICAgcmV0dXJuIGRpZmZzICYmIG9wdGlvbnMuZmFpbCA/IDEgOiAwO1xuICB9XG5cbiAgcHVibGljIGFzeW5jIGRlcGxveShvcHRpb25zOiBEZXBsb3lPcHRpb25zKSB7XG4gICAgaWYgKG9wdGlvbnMud2F0Y2gpIHtcbiAgICAgIHJldHVybiB0aGlzLndhdGNoKG9wdGlvbnMpO1xuICAgIH1cblxuICAgIC8vIHNldCBwcm9ncmVzcyBmcm9tIG9wdGlvbnMsIHRoaXMgaW5jbHVkZXMgdXNlciBhbmQgYXBwIGNvbmZpZ1xuICAgIGlmIChvcHRpb25zLnByb2dyZXNzKSB7XG4gICAgICB0aGlzLmlvSG9zdC5zdGFja1Byb2dyZXNzID0gb3B0aW9ucy5wcm9ncmVzcztcbiAgICB9XG5cbiAgICBjb25zdCBzdGFydFN5bnRoVGltZSA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpO1xuICAgIGNvbnN0IHN0YWNrQ29sbGVjdGlvbiA9IGF3YWl0IHRoaXMuc2VsZWN0U3RhY2tzRm9yRGVwbG95KFxuICAgICAgb3B0aW9ucy5zZWxlY3RvcixcbiAgICAgIG9wdGlvbnMuZXhjbHVzaXZlbHksXG4gICAgICBvcHRpb25zLmNhY2hlQ2xvdWRBc3NlbWJseSxcbiAgICAgIG9wdGlvbnMuaWdub3JlTm9TdGFja3MsXG4gICAgKTtcbiAgICBjb25zdCBlbGFwc2VkU3ludGhUaW1lID0gbmV3IERhdGUoKS5nZXRUaW1lKCkgLSBzdGFydFN5bnRoVGltZTtcbiAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbyhgXFxu4pyoICBTeW50aGVzaXMgdGltZTogJHtmb3JtYXRUaW1lKGVsYXBzZWRTeW50aFRpbWUpfXNcXG5gKTtcblxuICAgIGlmIChzdGFja0NvbGxlY3Rpb24uc3RhY2tDb3VudCA9PT0gMCkge1xuICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLmVycm9yKCdUaGlzIGFwcCBjb250YWlucyBubyBzdGFja3MnKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBtaWdyYXRvciA9IG5ldyBSZXNvdXJjZU1pZ3JhdG9yKHtcbiAgICAgIGRlcGxveW1lbnRzOiB0aGlzLnByb3BzLmRlcGxveW1lbnRzLFxuICAgICAgaW9IZWxwZXI6IGFzSW9IZWxwZXIodGhpcy5pb0hvc3QsICdkZXBsb3knKSxcbiAgICB9KTtcbiAgICBhd2FpdCBtaWdyYXRvci50cnlNaWdyYXRlUmVzb3VyY2VzKHN0YWNrQ29sbGVjdGlvbiwge1xuICAgICAgdG9vbGtpdFN0YWNrTmFtZTogdGhpcy50b29sa2l0U3RhY2tOYW1lLFxuICAgICAgLi4ub3B0aW9ucyxcbiAgICB9KTtcblxuICAgIGNvbnN0IHJlcXVpcmVBcHByb3ZhbCA9IG9wdGlvbnMucmVxdWlyZUFwcHJvdmFsID8/IFJlcXVpcmVBcHByb3ZhbC5CUk9BREVOSU5HO1xuXG4gICAgY29uc3QgcGFyYW1ldGVyTWFwID0gYnVpbGRQYXJhbWV0ZXJNYXAob3B0aW9ucy5wYXJhbWV0ZXJzKTtcblxuICAgIGlmIChvcHRpb25zLmRlcGxveW1lbnRNZXRob2Q/Lm1ldGhvZCA9PT0gJ2hvdHN3YXAnKSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMud2FybihcbiAgICAgICAgJ+KaoO+4jyBUaGUgLS1ob3Rzd2FwIGFuZCAtLWhvdHN3YXAtZmFsbGJhY2sgZmxhZ3MgZGVsaWJlcmF0ZWx5IGludHJvZHVjZSBDbG91ZEZvcm1hdGlvbiBkcmlmdCB0byBzcGVlZCB1cCBkZXBsb3ltZW50cycsXG4gICAgICApO1xuICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLndhcm4oJ+KaoO+4jyBUaGV5IHNob3VsZCBvbmx5IGJlIHVzZWQgZm9yIGRldmVsb3BtZW50IC0gbmV2ZXIgdXNlIHRoZW0gZm9yIHlvdXIgcHJvZHVjdGlvbiBTdGFja3MhXFxuJyk7XG4gICAgfVxuXG4gICAgY29uc3Qgc3RhY2tzID0gc3RhY2tDb2xsZWN0aW9uLnN0YWNrQXJ0aWZhY3RzO1xuXG4gICAgY29uc3Qgc3RhY2tPdXRwdXRzOiB7IFtrZXk6IHN0cmluZ106IGFueSB9ID0ge307XG4gICAgY29uc3Qgb3V0cHV0c0ZpbGUgPSBvcHRpb25zLm91dHB1dHNGaWxlO1xuXG4gICAgY29uc3QgYnVpbGRBc3NldCA9IGFzeW5jIChhc3NldE5vZGU6IEFzc2V0QnVpbGROb2RlKSA9PiB7XG4gICAgICBhd2FpdCB0aGlzLnByb3BzLmRlcGxveW1lbnRzLmJ1aWxkU2luZ2xlQXNzZXQoXG4gICAgICAgIGFzc2V0Tm9kZS5hc3NldE1hbmlmZXN0QXJ0aWZhY3QsXG4gICAgICAgIGFzc2V0Tm9kZS5hc3NldE1hbmlmZXN0LFxuICAgICAgICBhc3NldE5vZGUuYXNzZXQsXG4gICAgICAgIHtcbiAgICAgICAgICBzdGFjazogYXNzZXROb2RlLnBhcmVudFN0YWNrLFxuICAgICAgICAgIHJvbGVBcm46IG9wdGlvbnMucm9sZUFybixcbiAgICAgICAgICBzdGFja05hbWU6IGFzc2V0Tm9kZS5wYXJlbnRTdGFjay5zdGFja05hbWUsXG4gICAgICAgIH0sXG4gICAgICApO1xuICAgIH07XG5cbiAgICBjb25zdCBwdWJsaXNoQXNzZXQgPSBhc3luYyAoYXNzZXROb2RlOiBBc3NldFB1Ymxpc2hOb2RlKSA9PiB7XG4gICAgICBhd2FpdCB0aGlzLnByb3BzLmRlcGxveW1lbnRzLnB1Ymxpc2hTaW5nbGVBc3NldChhc3NldE5vZGUuYXNzZXRNYW5pZmVzdCwgYXNzZXROb2RlLmFzc2V0LCB7XG4gICAgICAgIHN0YWNrOiBhc3NldE5vZGUucGFyZW50U3RhY2ssXG4gICAgICAgIHJvbGVBcm46IG9wdGlvbnMucm9sZUFybixcbiAgICAgICAgc3RhY2tOYW1lOiBhc3NldE5vZGUucGFyZW50U3RhY2suc3RhY2tOYW1lLFxuICAgICAgICBmb3JjZVB1Ymxpc2g6IG9wdGlvbnMuZm9yY2UsXG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgY29uc3QgZGVwbG95U3RhY2sgPSBhc3luYyAoc3RhY2tOb2RlOiBTdGFja05vZGUpID0+IHtcbiAgICAgIGNvbnN0IHN0YWNrID0gc3RhY2tOb2RlLnN0YWNrO1xuICAgICAgaWYgKHN0YWNrQ29sbGVjdGlvbi5zdGFja0NvdW50ICE9PSAxKSB7XG4gICAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKGNoYWxrLmJvbGQoc3RhY2suZGlzcGxheU5hbWUpKTtcbiAgICAgIH1cblxuICAgICAgaWYgKCFzdGFjay5lbnZpcm9ubWVudCkge1xuICAgICAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgQHN0eWxpc3RpYy9tYXgtbGVuXG4gICAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoXG4gICAgICAgICAgYFN0YWNrICR7c3RhY2suZGlzcGxheU5hbWV9IGRvZXMgbm90IGRlZmluZSBhbiBlbnZpcm9ubWVudCwgYW5kIEFXUyBjcmVkZW50aWFscyBjb3VsZCBub3QgYmUgb2J0YWluZWQgZnJvbSBzdGFuZGFyZCBsb2NhdGlvbnMgb3Igbm8gcmVnaW9uIHdhcyBjb25maWd1cmVkLmAsXG4gICAgICAgICk7XG4gICAgICB9XG5cbiAgICAgIGlmIChPYmplY3Qua2V5cyhzdGFjay50ZW1wbGF0ZS5SZXNvdXJjZXMgfHwge30pLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICAvLyBUaGUgZ2VuZXJhdGVkIHN0YWNrIGhhcyBubyByZXNvdXJjZXNcbiAgICAgICAgaWYgKCEoYXdhaXQgdGhpcy5wcm9wcy5kZXBsb3ltZW50cy5zdGFja0V4aXN0cyh7IHN0YWNrIH0pKSkge1xuICAgICAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy53YXJuKCclczogc3RhY2sgaGFzIG5vIHJlc291cmNlcywgc2tpcHBpbmcgZGVwbG95bWVudC4nLCBjaGFsay5ib2xkKHN0YWNrLmRpc3BsYXlOYW1lKSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLndhcm4oJyVzOiBzdGFjayBoYXMgbm8gcmVzb3VyY2VzLCBkZWxldGluZyBleGlzdGluZyBzdGFjay4nLCBjaGFsay5ib2xkKHN0YWNrLmRpc3BsYXlOYW1lKSk7XG4gICAgICAgICAgYXdhaXQgdGhpcy5kZXN0cm95KHtcbiAgICAgICAgICAgIHNlbGVjdG9yOiB7IHBhdHRlcm5zOiBbc3RhY2suaGllcmFyY2hpY2FsSWRdIH0sXG4gICAgICAgICAgICBleGNsdXNpdmVseTogdHJ1ZSxcbiAgICAgICAgICAgIGZvcmNlOiB0cnVlLFxuICAgICAgICAgICAgcm9sZUFybjogb3B0aW9ucy5yb2xlQXJuLFxuICAgICAgICAgICAgZnJvbURlcGxveTogdHJ1ZSxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIGlmIChyZXF1aXJlQXBwcm92YWwgIT09IFJlcXVpcmVBcHByb3ZhbC5ORVZFUikge1xuICAgICAgICBjb25zdCBjdXJyZW50VGVtcGxhdGUgPSBhd2FpdCB0aGlzLnByb3BzLmRlcGxveW1lbnRzLnJlYWRDdXJyZW50VGVtcGxhdGUoc3RhY2spO1xuICAgICAgICBjb25zdCBmb3JtYXR0ZXIgPSBuZXcgRGlmZkZvcm1hdHRlcih7XG4gICAgICAgICAgdGVtcGxhdGVJbmZvOiB7XG4gICAgICAgICAgICBvbGRUZW1wbGF0ZTogY3VycmVudFRlbXBsYXRlLFxuICAgICAgICAgICAgbmV3VGVtcGxhdGU6IHN0YWNrLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0pO1xuICAgICAgICBjb25zdCBzZWN1cml0eURpZmYgPSBmb3JtYXR0ZXIuZm9ybWF0U2VjdXJpdHlEaWZmKCk7XG4gICAgICAgIGlmIChyZXF1aXJlc0FwcHJvdmFsKHJlcXVpcmVBcHByb3ZhbCwgc2VjdXJpdHlEaWZmLnBlcm1pc3Npb25DaGFuZ2VUeXBlKSkge1xuICAgICAgICAgIGNvbnN0IG1vdGl2YXRpb24gPSAnXCItLXJlcXVpcmUtYXBwcm92YWxcIiBpcyBlbmFibGVkIGFuZCBzdGFjayBpbmNsdWRlcyBzZWN1cml0eS1zZW5zaXRpdmUgdXBkYXRlcyc7XG4gICAgICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLmluZm8oc2VjdXJpdHlEaWZmLmZvcm1hdHRlZERpZmYpO1xuICAgICAgICAgIGF3YWl0IGFza1VzZXJDb25maXJtYXRpb24oXG4gICAgICAgICAgICB0aGlzLmlvSG9zdCxcbiAgICAgICAgICAgIElPLkNES19UT09MS0lUX0k1MDYwLnJlcShgJHttb3RpdmF0aW9ufTogJ0RvIHlvdSB3aXNoIHRvIGRlcGxveSB0aGVzZSBjaGFuZ2VzJ2AsIHtcbiAgICAgICAgICAgICAgbW90aXZhdGlvbixcbiAgICAgICAgICAgICAgY29uY3VycmVuY3ksXG4gICAgICAgICAgICAgIHBlcm1pc3Npb25DaGFuZ2VUeXBlOiBzZWN1cml0eURpZmYucGVybWlzc2lvbkNoYW5nZVR5cGUsXG4gICAgICAgICAgICAgIHRlbXBsYXRlRGlmZnM6IGZvcm1hdHRlci5kaWZmcyxcbiAgICAgICAgICAgIH0pLFxuICAgICAgICAgICk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgLy8gRm9sbG93aW5nIGFyZSB0aGUgc2FtZSBzZW1hbnRpY3Mgd2UgYXBwbHkgd2l0aCByZXNwZWN0IHRvIE5vdGlmaWNhdGlvbiBBUk5zIChkaWN0YXRlZCBieSB0aGUgU0RLKVxuICAgICAgLy9cbiAgICAgIC8vICAtIHVuZGVmaW5lZCAgPT4gIGNkayBpZ25vcmVzIGl0LCBhcyBpZiBpdCB3YXNuJ3Qgc3VwcG9ydGVkIChhbGxvd3MgZXh0ZXJuYWwgbWFuYWdlbWVudCkuXG4gICAgICAvLyAgLSBbXTogICAgICAgID0+ICBjZGsgbWFuYWdlcyBpdCwgYW5kIHRoZSB1c2VyIHdhbnRzIHRvIHdpcGUgaXQgb3V0LlxuICAgICAgLy8gIC0gWydhcm4tMSddICA9PiAgY2RrIG1hbmFnZXMgaXQsIGFuZCB0aGUgdXNlciB3YW50cyB0byBzZXQgaXQgdG8gWydhcm4tMSddLlxuICAgICAgY29uc3Qgbm90aWZpY2F0aW9uQXJucyA9ICghIW9wdGlvbnMubm90aWZpY2F0aW9uQXJucyB8fCAhIXN0YWNrLm5vdGlmaWNhdGlvbkFybnMpXG4gICAgICAgID8gKG9wdGlvbnMubm90aWZpY2F0aW9uQXJucyA/PyBbXSkuY29uY2F0KHN0YWNrLm5vdGlmaWNhdGlvbkFybnMgPz8gW10pXG4gICAgICAgIDogdW5kZWZpbmVkO1xuXG4gICAgICBmb3IgKGNvbnN0IG5vdGlmaWNhdGlvbkFybiBvZiBub3RpZmljYXRpb25Bcm5zID8/IFtdKSB7XG4gICAgICAgIGlmICghdmFsaWRhdGVTbnNUb3BpY0Fybihub3RpZmljYXRpb25Bcm4pKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihgTm90aWZpY2F0aW9uIGFybiAke25vdGlmaWNhdGlvbkFybn0gaXMgbm90IGEgdmFsaWQgYXJuIGZvciBhbiBTTlMgdG9waWNgKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBjb25zdCBzdGFja0luZGV4ID0gc3RhY2tzLmluZGV4T2Yoc3RhY2spICsgMTtcbiAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKGAke2NoYWxrLmJvbGQoc3RhY2suZGlzcGxheU5hbWUpfTogZGVwbG95aW5nLi4uIFske3N0YWNrSW5kZXh9LyR7c3RhY2tDb2xsZWN0aW9uLnN0YWNrQ291bnR9XWApO1xuICAgICAgY29uc3Qgc3RhcnREZXBsb3lUaW1lID0gbmV3IERhdGUoKS5nZXRUaW1lKCk7XG4gICAgICBsZXQgdGFncyA9IG9wdGlvbnMudGFncztcbiAgICAgIGlmICghdGFncyB8fCB0YWdzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICB0YWdzID0gdGFnc0ZvclN0YWNrKHN0YWNrKTtcbiAgICAgIH1cblxuICAgICAgLy8gVGhlcmUgaXMgYWxyZWFkeSBhIHN0YXJ0RGVwbG95VGltZSBjb25zdGFudCwgYnV0IHRoYXQgZG9lcyBub3Qgd29yayB3aXRoIHRlbGVtZXRyeS5cbiAgICAgIC8vIFdlIHNob3VsZCBpbnRlZ3JhdGUgdGhlIHR3byBpbiB0aGUgZnV0dXJlXG4gICAgICBjb25zdCBkZXBsb3lTcGFuID0gYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLnNwYW4oQ0xJX1BSSVZBVEVfU1BBTi5ERVBMT1kpLmJlZ2luKHt9KTtcbiAgICAgIGxldCBlcnJvcjogRXJyb3JEZXRhaWxzIHwgdW5kZWZpbmVkO1xuICAgICAgbGV0IGVsYXBzZWREZXBsb3lUaW1lID0gMDtcbiAgICAgIHRyeSB7XG4gICAgICAgIGxldCBkZXBsb3lSZXN1bHQ6IFN1Y2Nlc3NmdWxEZXBsb3lTdGFja1Jlc3VsdCB8IHVuZGVmaW5lZDtcblxuICAgICAgICBsZXQgcm9sbGJhY2sgPSBvcHRpb25zLnJvbGxiYWNrO1xuICAgICAgICBsZXQgaXRlcmF0aW9uID0gMDtcbiAgICAgICAgd2hpbGUgKCFkZXBsb3lSZXN1bHQpIHtcbiAgICAgICAgICBpZiAoKytpdGVyYXRpb24gPiAyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKCdUaGlzIGxvb3Agc2hvdWxkIGhhdmUgc3RhYmlsaXplZCBpbiAyIGl0ZXJhdGlvbnMsIGJ1dCBkaWRuXFwndC4gSWYgeW91IGFyZSBzZWVpbmcgdGhpcyBlcnJvciwgcGxlYXNlIHJlcG9ydCBpdCBhdCBodHRwczovL2dpdGh1Yi5jb20vYXdzL2F3cy1jZGsvaXNzdWVzL25ldy9jaG9vc2UnKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBjb25zdCByID0gYXdhaXQgdGhpcy5wcm9wcy5kZXBsb3ltZW50cy5kZXBsb3lTdGFjayh7XG4gICAgICAgICAgICBzdGFjayxcbiAgICAgICAgICAgIGRlcGxveU5hbWU6IHN0YWNrLnN0YWNrTmFtZSxcbiAgICAgICAgICAgIHJvbGVBcm46IG9wdGlvbnMucm9sZUFybixcbiAgICAgICAgICAgIHRvb2xraXRTdGFja05hbWU6IG9wdGlvbnMudG9vbGtpdFN0YWNrTmFtZSxcbiAgICAgICAgICAgIHJldXNlQXNzZXRzOiBvcHRpb25zLnJldXNlQXNzZXRzLFxuICAgICAgICAgICAgbm90aWZpY2F0aW9uQXJucyxcbiAgICAgICAgICAgIHRhZ3MsXG4gICAgICAgICAgICBleGVjdXRlOiBvcHRpb25zLmV4ZWN1dGUsXG4gICAgICAgICAgICBjaGFuZ2VTZXROYW1lOiBvcHRpb25zLmNoYW5nZVNldE5hbWUsXG4gICAgICAgICAgICBkZXBsb3ltZW50TWV0aG9kOiBvcHRpb25zLmRlcGxveW1lbnRNZXRob2QsXG4gICAgICAgICAgICBmb3JjZURlcGxveW1lbnQ6IG9wdGlvbnMuZm9yY2UsXG4gICAgICAgICAgICBwYXJhbWV0ZXJzOiBPYmplY3QuYXNzaWduKHt9LCBwYXJhbWV0ZXJNYXBbJyonXSwgcGFyYW1ldGVyTWFwW3N0YWNrLnN0YWNrTmFtZV0pLFxuICAgICAgICAgICAgdXNlUHJldmlvdXNQYXJhbWV0ZXJzOiBvcHRpb25zLnVzZVByZXZpb3VzUGFyYW1ldGVycyxcbiAgICAgICAgICAgIHJvbGxiYWNrLFxuICAgICAgICAgICAgZXh0cmFVc2VyQWdlbnQ6IG9wdGlvbnMuZXh0cmFVc2VyQWdlbnQsXG4gICAgICAgICAgICBhc3NldFBhcmFsbGVsaXNtOiBvcHRpb25zLmFzc2V0UGFyYWxsZWxpc20sXG4gICAgICAgICAgICBpZ25vcmVOb1N0YWNrczogb3B0aW9ucy5pZ25vcmVOb1N0YWNrcyxcbiAgICAgICAgICB9KTtcblxuICAgICAgICAgIHN3aXRjaCAoci50eXBlKSB7XG4gICAgICAgICAgICBjYXNlICdkaWQtZGVwbG95LXN0YWNrJzpcbiAgICAgICAgICAgICAgZGVwbG95UmVzdWx0ID0gcjtcbiAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgIGNhc2UgJ2ZhaWxwYXVzZWQtbmVlZC1yb2xsYmFjay1maXJzdCc6IHtcbiAgICAgICAgICAgICAgY29uc3QgbW90aXZhdGlvbiA9IHIucmVhc29uID09PSAncmVwbGFjZW1lbnQnXG4gICAgICAgICAgICAgICAgPyBgU3RhY2sgaXMgaW4gYSBwYXVzZWQgZmFpbCBzdGF0ZSAoJHtyLnN0YXR1c30pIGFuZCBjaGFuZ2UgaW5jbHVkZXMgYSByZXBsYWNlbWVudCB3aGljaCBjYW5ub3QgYmUgZGVwbG95ZWQgd2l0aCBcIi0tbm8tcm9sbGJhY2tcImBcbiAgICAgICAgICAgICAgICA6IGBTdGFjayBpcyBpbiBhIHBhdXNlZCBmYWlsIHN0YXRlICgke3Iuc3RhdHVzfSkgYW5kIGNvbW1hbmQgbGluZSBhcmd1bWVudHMgZG8gbm90IGluY2x1ZGUgXCItLW5vLXJvbGxiYWNrXCJgO1xuXG4gICAgICAgICAgICAgIGlmIChvcHRpb25zLmZvcmNlKSB7XG4gICAgICAgICAgICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLndhcm4oYCR7bW90aXZhdGlvbn0uIFJvbGxpbmcgYmFjayBmaXJzdCAoLS1mb3JjZSkuYCk7XG4gICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgYXdhaXQgYXNrVXNlckNvbmZpcm1hdGlvbihcbiAgICAgICAgICAgICAgICAgIHRoaXMuaW9Ib3N0LFxuICAgICAgICAgICAgICAgICAgSU8uQ0RLX1RPT0xLSVRfSTUwNTAucmVxKGAke21vdGl2YXRpb259LiBSb2xsIGJhY2sgZmlyc3QgYW5kIHRoZW4gcHJvY2VlZCB3aXRoIGRlcGxveW1lbnRgLCB7XG4gICAgICAgICAgICAgICAgICAgIG1vdGl2YXRpb24sXG4gICAgICAgICAgICAgICAgICAgIGNvbmN1cnJlbmN5LFxuICAgICAgICAgICAgICAgICAgfSksXG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgIC8vIFBlcmZvcm0gYSByb2xsYmFja1xuICAgICAgICAgICAgICBhd2FpdCB0aGlzLnJvbGxiYWNrKHtcbiAgICAgICAgICAgICAgICBzZWxlY3RvcjogeyBwYXR0ZXJuczogW3N0YWNrLmhpZXJhcmNoaWNhbElkXSB9LFxuICAgICAgICAgICAgICAgIHRvb2xraXRTdGFja05hbWU6IG9wdGlvbnMudG9vbGtpdFN0YWNrTmFtZSxcbiAgICAgICAgICAgICAgICBmb3JjZTogb3B0aW9ucy5mb3JjZSxcbiAgICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgICAgLy8gR28gYXJvdW5kIHRocm91Z2ggdGhlICd3aGlsZScgbG9vcCBhZ2FpbiBidXQgc3dpdGNoIHJvbGxiYWNrIHRvIHRydWUuXG4gICAgICAgICAgICAgIHJvbGxiYWNrID0gdHJ1ZTtcbiAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGNhc2UgJ3JlcGxhY2VtZW50LXJlcXVpcmVzLXJvbGxiYWNrJzoge1xuICAgICAgICAgICAgICBjb25zdCBtb3RpdmF0aW9uID0gJ0NoYW5nZSBpbmNsdWRlcyBhIHJlcGxhY2VtZW50IHdoaWNoIGNhbm5vdCBiZSBkZXBsb3llZCB3aXRoIFwiLS1uby1yb2xsYmFja1wiJztcblxuICAgICAgICAgICAgICBpZiAob3B0aW9ucy5mb3JjZSkge1xuICAgICAgICAgICAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy53YXJuKGAke21vdGl2YXRpb259LiBQcm9jZWVkaW5nIHdpdGggcmVndWxhciBkZXBsb3ltZW50ICgtLWZvcmNlKS5gKTtcbiAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBhd2FpdCBhc2tVc2VyQ29uZmlybWF0aW9uKFxuICAgICAgICAgICAgICAgICAgdGhpcy5pb0hvc3QsXG4gICAgICAgICAgICAgICAgICBJTy5DREtfVE9PTEtJVF9JNTA1MC5yZXEoYCR7bW90aXZhdGlvbn0uIFBlcmZvcm0gYSByZWd1bGFyIGRlcGxveW1lbnRgLCB7XG4gICAgICAgICAgICAgICAgICAgIGNvbmN1cnJlbmN5LFxuICAgICAgICAgICAgICAgICAgICBtb3RpdmF0aW9uLFxuICAgICAgICAgICAgICAgICAgfSksXG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgIC8vIEdvIGFyb3VuZCB0aHJvdWdoIHRoZSAnd2hpbGUnIGxvb3AgYWdhaW4gYnV0IHN3aXRjaCByb2xsYmFjayB0byB0cnVlLlxuICAgICAgICAgICAgICByb2xsYmFjayA9IHRydWU7XG4gICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKGBVbmV4cGVjdGVkIHJlc3VsdCB0eXBlIGZyb20gZGVwbG95U3RhY2s6ICR7SlNPTi5zdHJpbmdpZnkocil9LiBJZiB5b3UgYXJlIHNlZWluZyB0aGlzIGVycm9yLCBwbGVhc2UgcmVwb3J0IGl0IGF0IGh0dHBzOi8vZ2l0aHViLmNvbS9hd3MvYXdzLWNkay9pc3N1ZXMvbmV3L2Nob29zZWApO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IG1lc3NhZ2UgPSBkZXBsb3lSZXN1bHQubm9PcFxuICAgICAgICAgID8gJyDinIUgICVzIChubyBjaGFuZ2VzKSdcbiAgICAgICAgICA6ICcg4pyFICAlcyc7XG5cbiAgICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLmluZm8oY2hhbGsuZ3JlZW4oJ1xcbicgKyBtZXNzYWdlKSwgc3RhY2suZGlzcGxheU5hbWUpO1xuICAgICAgICBlbGFwc2VkRGVwbG95VGltZSA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpIC0gc3RhcnREZXBsb3lUaW1lO1xuICAgICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbyhgXFxu4pyoICBEZXBsb3ltZW50IHRpbWU6ICR7Zm9ybWF0VGltZShlbGFwc2VkRGVwbG95VGltZSl9c1xcbmApO1xuXG4gICAgICAgIGlmIChPYmplY3Qua2V5cyhkZXBsb3lSZXN1bHQub3V0cHV0cykubGVuZ3RoID4gMCkge1xuICAgICAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKCdPdXRwdXRzOicpO1xuXG4gICAgICAgICAgc3RhY2tPdXRwdXRzW3N0YWNrLnN0YWNrTmFtZV0gPSBkZXBsb3lSZXN1bHQub3V0cHV0cztcbiAgICAgICAgfVxuXG4gICAgICAgIGZvciAoY29uc3QgbmFtZSBvZiBPYmplY3Qua2V5cyhkZXBsb3lSZXN1bHQub3V0cHV0cykuc29ydCgpKSB7XG4gICAgICAgICAgY29uc3QgdmFsdWUgPSBkZXBsb3lSZXN1bHQub3V0cHV0c1tuYW1lXTtcbiAgICAgICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbyhgJHtjaGFsay5jeWFuKHN0YWNrLmlkKX0uJHtjaGFsay5jeWFuKG5hbWUpfSA9ICR7Y2hhbGsudW5kZXJsaW5lKGNoYWxrLmN5YW4odmFsdWUpKX1gKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKCdTdGFjayBBUk46Jyk7XG5cbiAgICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLnJlc3VsdChkZXBsb3lSZXN1bHQuc3RhY2tBcm4pO1xuICAgICAgfSBjYXRjaCAoZTogYW55KSB7XG4gICAgICAgIC8vIEl0IGhhcyB0byBiZSBleGFjdGx5IHRoaXMgc3RyaW5nIGJlY2F1c2UgYW4gaW50ZWdyYXRpb24gdGVzdCB0ZXN0cyBmb3JcbiAgICAgICAgLy8gXCJib2xkKHN0YWNrbmFtZSkgZmFpbGVkOiBSZXNvdXJjZU5vdFJlYWR5OiA8ZXJyb3I+XCJcbiAgICAgICAgY29uc3Qgd3JhcHBlZEVycm9yID0gbmV3IFRvb2xraXRFcnJvcihcbiAgICAgICAgICBbYOKdjCAgJHtjaGFsay5ib2xkKHN0YWNrLnN0YWNrTmFtZSl9IGZhaWxlZDpgLCAuLi4oZS5uYW1lID8gW2Ake2UubmFtZX06YF0gOiBbXSksIGZvcm1hdEVycm9yTWVzc2FnZShlKV0uam9pbignICcpLFxuICAgICAgICApO1xuXG4gICAgICAgIGVycm9yID0ge1xuICAgICAgICAgIG5hbWU6IGNka0NsaUVycm9yTmFtZSh3cmFwcGVkRXJyb3IubmFtZSksXG4gICAgICAgIH07XG5cbiAgICAgICAgdGhyb3cgd3JhcHBlZEVycm9yO1xuICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgYXdhaXQgZGVwbG95U3Bhbi5lbmQoeyBlcnJvciB9KTtcblxuICAgICAgICBpZiAob3B0aW9ucy5jbG91ZFdhdGNoTG9nTW9uaXRvcikge1xuICAgICAgICAgIGNvbnN0IGZvdW5kTG9nR3JvdXBzUmVzdWx0ID0gYXdhaXQgZmluZENsb3VkV2F0Y2hMb2dHcm91cHModGhpcy5wcm9wcy5zZGtQcm92aWRlciwgYXNJb0hlbHBlcih0aGlzLmlvSG9zdCwgJ2RlcGxveScpLCBzdGFjayk7XG4gICAgICAgICAgb3B0aW9ucy5jbG91ZFdhdGNoTG9nTW9uaXRvci5hZGRMb2dHcm91cHMoXG4gICAgICAgICAgICBmb3VuZExvZ0dyb3Vwc1Jlc3VsdC5lbnYsXG4gICAgICAgICAgICBmb3VuZExvZ0dyb3Vwc1Jlc3VsdC5zZGssXG4gICAgICAgICAgICBmb3VuZExvZ0dyb3Vwc1Jlc3VsdC5sb2dHcm91cE5hbWVzLFxuICAgICAgICAgICk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gSWYgYW4gb3V0cHV0cyBmaWxlIGhhcyBiZWVuIHNwZWNpZmllZCwgY3JlYXRlIHRoZSBmaWxlIHBhdGggYW5kIHdyaXRlIHN0YWNrIG91dHB1dHMgdG8gaXQgb25jZS5cbiAgICAgICAgLy8gT3V0cHV0cyBhcmUgd3JpdHRlbiBhZnRlciBhbGwgc3RhY2tzIGhhdmUgYmVlbiBkZXBsb3llZC4gSWYgYSBzdGFjayBkZXBsb3ltZW50IGZhaWxzLFxuICAgICAgICAvLyBhbGwgb2YgdGhlIG91dHB1dHMgZnJvbSBzdWNjZXNzZnVsbHkgZGVwbG95ZWQgc3RhY2tzIGJlZm9yZSB0aGUgZmFpbHVyZSB3aWxsIHN0aWxsIGJlIHdyaXR0ZW4uXG4gICAgICAgIGlmIChvdXRwdXRzRmlsZSkge1xuICAgICAgICAgIGZzLmVuc3VyZUZpbGVTeW5jKG91dHB1dHNGaWxlKTtcbiAgICAgICAgICBhd2FpdCBmcy53cml0ZUpzb24ob3V0cHV0c0ZpbGUsIHN0YWNrT3V0cHV0cywge1xuICAgICAgICAgICAgc3BhY2VzOiAyLFxuICAgICAgICAgICAgZW5jb2Rpbmc6ICd1dGY4JyxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLmluZm8oYFxcbuKcqCAgVG90YWwgdGltZTogJHtmb3JtYXRUaW1lKGVsYXBzZWRTeW50aFRpbWUgKyBlbGFwc2VkRGVwbG95VGltZSl9c1xcbmApO1xuICAgIH07XG5cbiAgICBjb25zdCBhc3NldEJ1aWxkVGltZSA9IG9wdGlvbnMuYXNzZXRCdWlsZFRpbWUgPz8gQXNzZXRCdWlsZFRpbWUuQUxMX0JFRk9SRV9ERVBMT1k7XG4gICAgY29uc3QgcHJlYnVpbGRBc3NldHMgPSBhc3NldEJ1aWxkVGltZSA9PT0gQXNzZXRCdWlsZFRpbWUuQUxMX0JFRk9SRV9ERVBMT1k7XG4gICAgY29uc3QgY29uY3VycmVuY3kgPSBvcHRpb25zLmNvbmN1cnJlbmN5IHx8IDE7XG4gICAgaWYgKGNvbmN1cnJlbmN5ID4gMSkge1xuICAgICAgLy8gYWx3YXlzIGZvcmNlIFwiZXZlbnRzXCIgcHJvZ3Jlc3Mgb3V0cHV0IHdoZW4gd2UgaGF2ZSBjb25jdXJyZW5jeVxuICAgICAgdGhpcy5pb0hvc3Quc3RhY2tQcm9ncmVzcyA9IFN0YWNrQWN0aXZpdHlQcm9ncmVzcy5FVkVOVFM7XG5cbiAgICAgIC8vIC4uLmJ1dCBvbmx5IHdhcm4gaWYgdGhlIHVzZXIgZXhwbGljaXRseSByZXF1ZXN0ZWQgXCJiYXJcIiBwcm9ncmVzc1xuICAgICAgaWYgKG9wdGlvbnMucHJvZ3Jlc3MgJiYgb3B0aW9ucy5wcm9ncmVzcyAhPSBTdGFja0FjdGl2aXR5UHJvZ3Jlc3MuRVZFTlRTKSB7XG4gICAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy53YXJuKCfimqDvuI8gVGhlIC0tY29uY3VycmVuY3kgZmxhZyBvbmx5IHN1cHBvcnRzIC0tcHJvZ3Jlc3MgXCJldmVudHNcIi4gU3dpdGNoaW5nIHRvIFwiZXZlbnRzXCIuJyk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgY29uc3Qgc3RhY2tzQW5kVGhlaXJBc3NldE1hbmlmZXN0cyA9IHN0YWNrcy5mbGF0TWFwKChzdGFjaykgPT4gW1xuICAgICAgc3RhY2ssXG4gICAgICAuLi5zdGFjay5kZXBlbmRlbmNpZXMuZmlsdGVyKHggPT4gY3hhcGkuQXNzZXRNYW5pZmVzdEFydGlmYWN0LmlzQXNzZXRNYW5pZmVzdEFydGlmYWN0KHgpKSxcbiAgICBdKTtcbiAgICBjb25zdCB3b3JrR3JhcGggPSBuZXcgV29ya0dyYXBoQnVpbGRlcihcbiAgICAgIGFzSW9IZWxwZXIodGhpcy5pb0hvc3QsICdkZXBsb3knKSxcbiAgICAgIHByZWJ1aWxkQXNzZXRzLFxuICAgICkuYnVpbGQoc3RhY2tzQW5kVGhlaXJBc3NldE1hbmlmZXN0cyk7XG5cbiAgICAvLyBVbmxlc3Mgd2UgYXJlIHJ1bm5pbmcgd2l0aCAnLS1mb3JjZScsIHNraXAgYWxyZWFkeSBwdWJsaXNoZWQgYXNzZXRzXG4gICAgaWYgKCFvcHRpb25zLmZvcmNlKSB7XG4gICAgICBhd2FpdCB0aGlzLnJlbW92ZVB1Ymxpc2hlZEFzc2V0cyh3b3JrR3JhcGgsIG9wdGlvbnMpO1xuICAgIH1cblxuICAgIGNvbnN0IGdyYXBoQ29uY3VycmVuY3k6IENvbmN1cnJlbmN5ID0ge1xuICAgICAgJ3N0YWNrJzogY29uY3VycmVuY3ksXG4gICAgICAnYXNzZXQtYnVpbGQnOiAxLCAvLyBUaGlzIHdpbGwgYmUgQ1BVLWJvdW5kL21lbW9yeSBib3VuZCwgbW9zdGx5IG1hdHRlcnMgZm9yIERvY2tlciBidWlsZHNcbiAgICAgICdhc3NldC1wdWJsaXNoJzogKG9wdGlvbnMuYXNzZXRQYXJhbGxlbGlzbSA/PyB0cnVlKSA/IDggOiAxLCAvLyBUaGlzIHdpbGwgYmUgSS9PLWJvdW5kLCA4IGluIHBhcmFsbGVsIHNlZW1zIHJlYXNvbmFibGVcbiAgICB9O1xuXG4gICAgYXdhaXQgd29ya0dyYXBoLmRvUGFyYWxsZWwoZ3JhcGhDb25jdXJyZW5jeSwge1xuICAgICAgZGVwbG95U3RhY2ssXG4gICAgICBidWlsZEFzc2V0LFxuICAgICAgcHVibGlzaEFzc2V0LFxuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIERldGVjdCBpbmZyYXN0cnVjdHVyZSBkcmlmdCBmb3IgdGhlIGdpdmVuIHN0YWNrKHMpXG4gICAqL1xuICBwdWJsaWMgYXN5bmMgZHJpZnQob3B0aW9uczogRHJpZnRPcHRpb25zKTogUHJvbWlzZTxudW1iZXI+IHtcbiAgICBjb25zdCBkcmlmdFJlc3VsdHMgPSBhd2FpdCB0aGlzLnRvb2xraXQuZHJpZnQodGhpcy5wcm9wcy5jbG91ZEV4ZWN1dGFibGUsIHtcbiAgICAgIHN0YWNrczoge1xuICAgICAgICBwYXR0ZXJuczogb3B0aW9ucy5zZWxlY3Rvci5wYXR0ZXJucyxcbiAgICAgICAgc3RyYXRlZ3k6IG9wdGlvbnMuc2VsZWN0b3IucGF0dGVybnMubGVuZ3RoID4gMCA/IFN0YWNrU2VsZWN0aW9uU3RyYXRlZ3kuUEFUVEVSTl9NQVRDSCA6IFN0YWNrU2VsZWN0aW9uU3RyYXRlZ3kuQUxMX1NUQUNLUyxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICBjb25zdCB0b3RhbERyaWZ0cyA9IE9iamVjdC52YWx1ZXMoZHJpZnRSZXN1bHRzKS5yZWR1Y2UoKHRvdGFsLCBjdXJyZW50KSA9PiB0b3RhbCArIChjdXJyZW50Lm51bVJlc291cmNlc1dpdGhEcmlmdCA/PyAwKSwgMCk7XG4gICAgcmV0dXJuIHRvdGFsRHJpZnRzID4gMCAmJiBvcHRpb25zLmZhaWwgPyAxIDogMDtcbiAgfVxuXG4gIC8qKlxuICAgKiBSb2xsIGJhY2sgdGhlIGdpdmVuIHN0YWNrIG9yIHN0YWNrcy5cbiAgICovXG4gIHB1YmxpYyBhc3luYyByb2xsYmFjayhvcHRpb25zOiBSb2xsYmFja09wdGlvbnMpIHtcbiAgICBjb25zdCBzdGFydFN5bnRoVGltZSA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpO1xuICAgIGNvbnN0IHN0YWNrQ29sbGVjdGlvbiA9IGF3YWl0IHRoaXMuc2VsZWN0U3RhY2tzRm9yRGVwbG95KG9wdGlvbnMuc2VsZWN0b3IsIHRydWUpO1xuICAgIGNvbnN0IGVsYXBzZWRTeW50aFRpbWUgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKSAtIHN0YXJ0U3ludGhUaW1lO1xuICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKGBcXG7inKggIFN5bnRoZXNpcyB0aW1lOiAke2Zvcm1hdFRpbWUoZWxhcHNlZFN5bnRoVGltZSl9c1xcbmApO1xuXG4gICAgaWYgKHN0YWNrQ29sbGVjdGlvbi5zdGFja0NvdW50ID09PSAwKSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuZXJyb3IoJ05vIHN0YWNrcyBzZWxlY3RlZCcpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGxldCBhbnlSb2xsYmFja2FibGUgPSBmYWxzZTtcblxuICAgIGZvciAoY29uc3Qgc3RhY2sgb2Ygc3RhY2tDb2xsZWN0aW9uLnN0YWNrQXJ0aWZhY3RzKSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbygnUm9sbGluZyBiYWNrICVzJywgY2hhbGsuYm9sZChzdGFjay5kaXNwbGF5TmFtZSkpO1xuICAgICAgY29uc3Qgc3RhcnRSb2xsYmFja1RpbWUgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKTtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IHRoaXMucHJvcHMuZGVwbG95bWVudHMucm9sbGJhY2tTdGFjayh7XG4gICAgICAgICAgc3RhY2ssXG4gICAgICAgICAgcm9sZUFybjogb3B0aW9ucy5yb2xlQXJuLFxuICAgICAgICAgIHRvb2xraXRTdGFja05hbWU6IG9wdGlvbnMudG9vbGtpdFN0YWNrTmFtZSxcbiAgICAgICAgICBvcnBoYW5GYWlsZWRSZXNvdXJjZXM6IG9wdGlvbnMuZm9yY2UsXG4gICAgICAgICAgdmFsaWRhdGVCb290c3RyYXBTdGFja1ZlcnNpb246IG9wdGlvbnMudmFsaWRhdGVCb290c3RyYXBTdGFja1ZlcnNpb24sXG4gICAgICAgICAgb3JwaGFuTG9naWNhbElkczogb3B0aW9ucy5vcnBoYW5Mb2dpY2FsSWRzLFxuICAgICAgICB9KTtcbiAgICAgICAgaWYgKCFyZXN1bHQubm90SW5Sb2xsYmFja2FibGVTdGF0ZSkge1xuICAgICAgICAgIGFueVJvbGxiYWNrYWJsZSA9IHRydWU7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgZWxhcHNlZFJvbGxiYWNrVGltZSA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpIC0gc3RhcnRSb2xsYmFja1RpbWU7XG4gICAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKGBcXG7inKggIFJvbGxiYWNrIHRpbWU6ICR7Zm9ybWF0VGltZShlbGFwc2VkUm9sbGJhY2tUaW1lKS50b1N0cmluZygpfXNcXG5gKTtcbiAgICAgIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuZXJyb3IoJ1xcbiDinYwgICVzIGZhaWxlZDogJXMnLCBjaGFsay5ib2xkKHN0YWNrLmRpc3BsYXlOYW1lKSwgZm9ybWF0RXJyb3JNZXNzYWdlKGUpKTtcbiAgICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcignUm9sbGJhY2sgZmFpbGVkICh1c2UgLS1mb3JjZSB0byBvcnBoYW4gZmFpbGluZyByZXNvdXJjZXMpJyk7XG4gICAgICB9XG4gICAgfVxuICAgIGlmICghYW55Um9sbGJhY2thYmxlKSB7XG4gICAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKCdObyBzdGFja3Mgd2VyZSBpbiBhIHN0YXRlIHRoYXQgY291bGQgYmUgcm9sbGVkIGJhY2snKTtcbiAgICB9XG4gIH1cblxuICBwdWJsaWMgYXN5bmMgd2F0Y2gob3B0aW9uczogV2F0Y2hPcHRpb25zKSB7XG4gICAgY29uc3Qgcm9vdERpciA9IHBhdGguZGlybmFtZShwYXRoLnJlc29sdmUoUFJPSkVDVF9DT05GSUcpKTtcbiAgICBjb25zdCBpb0hlbHBlciA9IGFzSW9IZWxwZXIodGhpcy5pb0hvc3QsICd3YXRjaCcpO1xuICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5kZWJ1ZyhcInJvb3QgZGlyZWN0b3J5IHVzZWQgZm9yICd3YXRjaCcgaXM6ICVzXCIsIHJvb3REaXIpO1xuXG4gICAgY29uc3Qgd2F0Y2hTZXR0aW5nczogeyBpbmNsdWRlPzogc3RyaW5nIHwgc3RyaW5nW107IGV4Y2x1ZGU6IHN0cmluZyB8IHN0cmluZ1tdIH0gfCB1bmRlZmluZWQgPVxuICAgICAgdGhpcy5wcm9wcy5jb25maWd1cmF0aW9uLnNldHRpbmdzLmdldChbJ3dhdGNoJ10pO1xuICAgIGlmICghd2F0Y2hTZXR0aW5ncykge1xuICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihcbiAgICAgICAgXCJDYW5ub3QgdXNlIHRoZSAnd2F0Y2gnIGNvbW1hbmQgd2l0aG91dCBzcGVjaWZ5aW5nIGF0IGxlYXN0IG9uZSBkaXJlY3RvcnkgdG8gbW9uaXRvci4gXCIgK1xuICAgICAgICAnTWFrZSBzdXJlIHRvIGFkZCBhIFwid2F0Y2hcIiBrZXkgdG8geW91ciBjZGsuanNvbicsXG4gICAgICApO1xuICAgIH1cblxuICAgIC8vIEZvciB0aGUgXCJpbmNsdWRlXCIgc3Via2V5IHVuZGVyIHRoZSBcIndhdGNoXCIga2V5LCB0aGUgYmVoYXZpb3IgaXM6XG4gICAgLy8gMS4gTm8gXCJ3YXRjaFwiIHNldHRpbmc/IFdlIGVycm9yIG91dC5cbiAgICAvLyAyLiBcIndhdGNoXCIgc2V0dGluZyB3aXRob3V0IGFuIFwiaW5jbHVkZVwiIGtleT8gV2UgZGVmYXVsdCB0byBvYnNlcnZpbmcgXCIuLyoqXCIuXG4gICAgLy8gMy4gXCJ3YXRjaFwiIHNldHRpbmcgd2l0aCBhbiBlbXB0eSBcImluY2x1ZGVcIiBrZXk/IFdlIGRlZmF1bHQgdG8gb2JzZXJ2aW5nIFwiLi8qKlwiLlxuICAgIC8vIDQuIE5vbi1lbXB0eSBcImluY2x1ZGVcIiBrZXk/IEp1c3QgdXNlIHRoZSBcImluY2x1ZGVcIiBrZXkuXG4gICAgY29uc3Qgd2F0Y2hJbmNsdWRlcyA9IHRoaXMucGF0dGVybnNBcnJheUZvcldhdGNoKHdhdGNoU2V0dGluZ3MuaW5jbHVkZSwge1xuICAgICAgcm9vdERpcixcbiAgICAgIHJldHVyblJvb3REaXJJZkVtcHR5OiB0cnVlLFxuICAgIH0pO1xuICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5kZWJ1ZyhcIidpbmNsdWRlJyBwYXR0ZXJucyBmb3IgJ3dhdGNoJzogJXNcIiwgd2F0Y2hJbmNsdWRlcyk7XG5cbiAgICAvLyBGb3IgdGhlIFwiZXhjbHVkZVwiIHN1YmtleSB1bmRlciB0aGUgXCJ3YXRjaFwiIGtleSxcbiAgICAvLyB0aGUgYmVoYXZpb3IgaXMgdG8gYWRkIHNvbWUgZGVmYXVsdCBleGNsdWRlcyBpbiBhZGRpdGlvbiB0byB0aGUgb25lcyBzcGVjaWZpZWQgYnkgdGhlIHVzZXI6XG4gICAgLy8gMS4gVGhlIENESyBvdXRwdXQgZGlyZWN0b3J5LlxuICAgIC8vIDIuIEFueSBmaWxlIHdob3NlIG5hbWUgc3RhcnRzIHdpdGggYSBkb3QuXG4gICAgLy8gMy4gQW55IGRpcmVjdG9yeSdzIGNvbnRlbnQgd2hvc2UgbmFtZSBzdGFydHMgd2l0aCBhIGRvdC5cbiAgICAvLyA0LiBBbnkgbm9kZV9tb2R1bGVzIGFuZCBpdHMgY29udGVudCAoZXZlbiBpZiBpdCdzIG5vdCBhIEpTL1RTIHByb2plY3QsIHlvdSBtaWdodCBiZSB1c2luZyBhIGxvY2FsIGF3cy1jbGkgcGFja2FnZSlcbiAgICBjb25zdCBvdXRwdXREaXIgPSB0aGlzLnByb3BzLmNvbmZpZ3VyYXRpb24uc2V0dGluZ3MuZ2V0KFsnb3V0cHV0J10pO1xuICAgIGNvbnN0IHdhdGNoRXhjbHVkZXMgPSB0aGlzLnBhdHRlcm5zQXJyYXlGb3JXYXRjaCh3YXRjaFNldHRpbmdzLmV4Y2x1ZGUsIHtcbiAgICAgIHJvb3REaXIsXG4gICAgICByZXR1cm5Sb290RGlySWZFbXB0eTogZmFsc2UsXG4gICAgfSkuY29uY2F0KGAke291dHB1dERpcn0vKipgLCAnKiovLionLCAnKiovLiovKionLCAnKiovbm9kZV9tb2R1bGVzLyoqJyk7XG4gICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLmRlYnVnKFwiJ2V4Y2x1ZGUnIHBhdHRlcm5zIGZvciAnd2F0Y2gnOiAlc1wiLCB3YXRjaEV4Y2x1ZGVzKTtcblxuICAgIC8vIFNpbmNlICdjZGsgZGVwbG95JyBpcyBhIHJlbGF0aXZlbHkgc2xvdyBvcGVyYXRpb24gZm9yIGEgJ3dhdGNoJyBwcm9jZXNzLFxuICAgIC8vIGludHJvZHVjZSBhIGNvbmN1cnJlbmN5IGxhdGNoIHRoYXQgdHJhY2tzIHRoZSBzdGF0ZS5cbiAgICAvLyBUaGlzIHdheSwgaWYgZmlsZSBjaGFuZ2UgZXZlbnRzIGFycml2ZSB3aGVuIGEgJ2NkayBkZXBsb3knIGlzIHN0aWxsIGV4ZWN1dGluZyxcbiAgICAvLyB3ZSB3aWxsIGJhdGNoIHRoZW0sIGFuZCB0cmlnZ2VyIGFub3RoZXIgJ2NkayBkZXBsb3knIGFmdGVyIHRoZSBjdXJyZW50IG9uZSBmaW5pc2hlcyxcbiAgICAvLyBtYWtpbmcgc3VyZSAnY2RrIGRlcGxveSdzICBhbHdheXMgZXhlY3V0ZSBvbmUgYXQgYSB0aW1lLlxuICAgIC8vIEhlcmUncyBhIGRpYWdyYW0gc2hvd2luZyB0aGUgc3RhdGUgdHJhbnNpdGlvbnM6XG4gICAgLy8gLS0tLS0tLS0tLS0tLS0gICAgICAgICAgICAgICAgLS0tLS0tLS0gICAgZmlsZSBjaGFuZ2VkICAgICAtLS0tLS0tLS0tLS0tLSAgICBmaWxlIGNoYW5nZWQgICAgIC0tLS0tLS0tLS0tLS0tICBmaWxlIGNoYW5nZWRcbiAgICAvLyB8ICAgICAgICAgICAgfCAgcmVhZHkgZXZlbnQgICB8ICAgICAgfCAtLS0tLS0tLS0tLS0tLS0tLS0+IHwgICAgICAgICAgICB8IC0tLS0tLS0tLS0tLS0tLS0tLT4gfCAgICAgICAgICAgIHwgLS0tLS0tLS0tLS0tLS18XG4gICAgLy8gfCBwcmUtcmVhZHkgIHwgLS0tLS0tLS0tLS0tLT4gfCBvcGVuIHwgICAgICAgICAgICAgICAgICAgICB8IGRlcGxveWluZyAgfCAgICAgICAgICAgICAgICAgICAgIHwgICBxdWV1ZWQgICB8ICAgICAgICAgICAgICAgfFxuICAgIC8vIHwgICAgICAgICAgICB8ICAgICAgICAgICAgICAgIHwgICAgICB8IDwtLS0tLS0tLS0tLS0tLS0tLS0gfCAgICAgICAgICAgIHwgPC0tLS0tLS0tLS0tLS0tLS0tLSB8ICAgICAgICAgICAgfCA8LS0tLS0tLS0tLS0tLXxcbiAgICAvLyAtLS0tLS0tLS0tLS0tLSAgICAgICAgICAgICAgICAtLS0tLS0tLSAgJ2NkayBkZXBsb3knIGRvbmUgIC0tLS0tLS0tLS0tLS0tICAnY2RrIGRlcGxveScgZG9uZSAgLS0tLS0tLS0tLS0tLS1cbiAgICBsZXQgbGF0Y2g6ICdwcmUtcmVhZHknIHwgJ29wZW4nIHwgJ2RlcGxveWluZycgfCAncXVldWVkJyA9ICdwcmUtcmVhZHknO1xuXG4gICAgY29uc3QgY2xvdWRXYXRjaExvZ01vbml0b3IgPSBvcHRpb25zLnRyYWNlTG9ncyA/IG5ldyBDbG91ZFdhdGNoTG9nRXZlbnRNb25pdG9yKHtcbiAgICAgIGlvSGVscGVyLFxuICAgIH0pIDogdW5kZWZpbmVkO1xuICAgIGNvbnN0IGRlcGxveUFuZFdhdGNoID0gYXN5bmMgKCkgPT4ge1xuICAgICAgbGF0Y2ggPSAnZGVwbG95aW5nJztcbiAgICAgIGF3YWl0IGNsb3VkV2F0Y2hMb2dNb25pdG9yPy5kZWFjdGl2YXRlKCk7XG5cbiAgICAgIGF3YWl0IHRoaXMuaW52b2tlRGVwbG95RnJvbVdhdGNoKG9wdGlvbnMsIGNsb3VkV2F0Y2hMb2dNb25pdG9yKTtcblxuICAgICAgLy8gSWYgbGF0Y2ggaXMgc3RpbGwgJ2RlcGxveWluZycgYWZ0ZXIgdGhlICdhd2FpdCcsIHRoYXQncyBmaW5lLFxuICAgICAgLy8gYnV0IGlmIGl0J3MgJ3F1ZXVlZCcsIHRoYXQgbWVhbnMgd2UgbmVlZCB0byBkZXBsb3kgYWdhaW5cbiAgICAgIHdoaWxlICgobGF0Y2ggYXMgJ2RlcGxveWluZycgfCAncXVldWVkJykgPT09ICdxdWV1ZWQnKSB7XG4gICAgICAgIC8vIFR5cGVTY3JpcHQgZG9lc24ndCByZWFsaXplIGxhdGNoIGNhbiBjaGFuZ2UgYmV0d2VlbiAnYXdhaXRzJyxcbiAgICAgICAgLy8gYW5kIHRoaW5rcyB0aGUgYWJvdmUgJ3doaWxlJyBjb25kaXRpb24gaXMgYWx3YXlzICdmYWxzZScgd2l0aG91dCB0aGUgY2FzdFxuICAgICAgICBsYXRjaCA9ICdkZXBsb3lpbmcnO1xuICAgICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbyhcIkRldGVjdGVkIGZpbGUgY2hhbmdlcyBkdXJpbmcgZGVwbG95bWVudC4gSW52b2tpbmcgJ2NkayBkZXBsb3knIGFnYWluXCIpO1xuICAgICAgICBhd2FpdCB0aGlzLmludm9rZURlcGxveUZyb21XYXRjaChvcHRpb25zLCBjbG91ZFdhdGNoTG9nTW9uaXRvcik7XG4gICAgICB9XG4gICAgICBsYXRjaCA9ICdvcGVuJztcbiAgICAgIGF3YWl0IGNsb3VkV2F0Y2hMb2dNb25pdG9yPy5hY3RpdmF0ZSgpO1xuICAgIH07XG5cbiAgICBjaG9raWRhclxuICAgICAgLndhdGNoKHdhdGNoSW5jbHVkZXMsIHtcbiAgICAgICAgaWdub3JlZDogd2F0Y2hFeGNsdWRlcyxcbiAgICAgICAgY3dkOiByb290RGlyLFxuICAgICAgfSlcbiAgICAgIC5vbigncmVhZHknLCBhc3luYyAoKSA9PiB7XG4gICAgICAgIGxhdGNoID0gJ29wZW4nO1xuICAgICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuZGVidWcoXCInd2F0Y2gnIHJlY2VpdmVkIHRoZSAncmVhZHknIGV2ZW50LiBGcm9tIG5vdyBvbiwgYWxsIGZpbGUgY2hhbmdlcyB3aWxsIHRyaWdnZXIgYSBkZXBsb3ltZW50XCIpO1xuICAgICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbyhcIlRyaWdnZXJpbmcgaW5pdGlhbCAnY2RrIGRlcGxveSdcIik7XG4gICAgICAgIGF3YWl0IGRlcGxveUFuZFdhdGNoKCk7XG4gICAgICB9KVxuICAgICAgLm9uKCdhbGwnLCBhc3luYyAoZXZlbnQ6ICdhZGQnIHwgJ2FkZERpcicgfCAnY2hhbmdlJyB8ICd1bmxpbmsnIHwgJ3VubGlua0RpcicsIGZpbGVQYXRoPzogc3RyaW5nKSA9PiB7XG4gICAgICAgIGlmIChsYXRjaCA9PT0gJ3ByZS1yZWFkeScpIHtcbiAgICAgICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbyhgJ3dhdGNoJyBpcyBvYnNlcnZpbmcgJHtldmVudCA9PT0gJ2FkZERpcicgPyAnZGlyZWN0b3J5JyA6ICd0aGUgZmlsZSd9ICclcycgZm9yIGNoYW5nZXNgLCBmaWxlUGF0aCk7XG4gICAgICAgIH0gZWxzZSBpZiAobGF0Y2ggPT09ICdvcGVuJykge1xuICAgICAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKFwiRGV0ZWN0ZWQgY2hhbmdlIHRvICclcycgKHR5cGU6ICVzKS4gVHJpZ2dlcmluZyAnY2RrIGRlcGxveSdcIiwgZmlsZVBhdGgsIGV2ZW50KTtcbiAgICAgICAgICBhd2FpdCBkZXBsb3lBbmRXYXRjaCgpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIC8vIHRoaXMgbWVhbnMgbGF0Y2ggaXMgZWl0aGVyICdkZXBsb3lpbmcnIG9yICdxdWV1ZWQnXG4gICAgICAgICAgbGF0Y2ggPSAncXVldWVkJztcbiAgICAgICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbyhcbiAgICAgICAgICAgIFwiRGV0ZWN0ZWQgY2hhbmdlIHRvICclcycgKHR5cGU6ICVzKSB3aGlsZSAnY2RrIGRlcGxveScgaXMgc3RpbGwgcnVubmluZy4gXCIgK1xuICAgICAgICAgICAgJ1dpbGwgcXVldWUgZm9yIGFub3RoZXIgZGVwbG95bWVudCBhZnRlciB0aGlzIG9uZSBmaW5pc2hlcycsXG4gICAgICAgICAgICBmaWxlUGF0aCxcbiAgICAgICAgICAgIGV2ZW50LFxuICAgICAgICAgICk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICB9XG5cbiAgcHVibGljIGFzeW5jIGltcG9ydChvcHRpb25zOiBJbXBvcnRPcHRpb25zKSB7XG4gICAgY29uc3Qgc3RhY2tzID0gYXdhaXQgdGhpcy5zZWxlY3RTdGFja3NGb3JEZXBsb3kob3B0aW9ucy5zZWxlY3RvciwgdHJ1ZSwgdHJ1ZSwgZmFsc2UpO1xuXG4gICAgLy8gc2V0IHByb2dyZXNzIGZyb20gb3B0aW9ucywgdGhpcyBpbmNsdWRlcyB1c2VyIGFuZCBhcHAgY29uZmlnXG4gICAgaWYgKG9wdGlvbnMucHJvZ3Jlc3MpIHtcbiAgICAgIHRoaXMuaW9Ib3N0LnN0YWNrUHJvZ3Jlc3MgPSBvcHRpb25zLnByb2dyZXNzO1xuICAgIH1cblxuICAgIGlmIChzdGFja3Muc3RhY2tDb3VudCA+IDEpIHtcbiAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoXG4gICAgICAgIGBTdGFjayBzZWxlY3Rpb24gaXMgYW1iaWd1b3VzLCBwbGVhc2UgY2hvb3NlIGEgc3BlY2lmaWMgc3RhY2sgZm9yIGltcG9ydCBbJHtzdGFja3Muc3RhY2tBcnRpZmFjdHMubWFwKCh4KSA9PiB4LmlkKS5qb2luKCcsICcpfV1gLFxuICAgICAgKTtcbiAgICB9XG5cbiAgICBpZiAoIXByb2Nlc3Muc3Rkb3V0LmlzVFRZICYmICFvcHRpb25zLnJlc291cmNlTWFwcGluZ0ZpbGUpIHtcbiAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoJy0tcmVzb3VyY2UtbWFwcGluZyBpcyByZXF1aXJlZCB3aGVuIGlucHV0IGlzIG5vdCBhIHRlcm1pbmFsJyk7XG4gICAgfVxuXG4gICAgY29uc3Qgc3RhY2sgPSBzdGFja3Muc3RhY2tBcnRpZmFjdHNbMF07XG5cbiAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbyhjaGFsay5ib2xkKHN0YWNrLmRpc3BsYXlOYW1lKSk7XG5cbiAgICBjb25zdCByZXNvdXJjZUltcG9ydGVyID0gbmV3IFJlc291cmNlSW1wb3J0ZXIoc3RhY2ssIHtcbiAgICAgIGRlcGxveW1lbnRzOiB0aGlzLnByb3BzLmRlcGxveW1lbnRzLFxuICAgICAgaW9IZWxwZXI6IGFzSW9IZWxwZXIodGhpcy5pb0hvc3QsICdpbXBvcnQnKSxcbiAgICB9KTtcbiAgICBjb25zdCB7IGFkZGl0aW9ucywgaGFzTm9uQWRkaXRpb25zIH0gPSBhd2FpdCByZXNvdXJjZUltcG9ydGVyLmRpc2NvdmVySW1wb3J0YWJsZVJlc291cmNlcyhvcHRpb25zLmZvcmNlKTtcbiAgICBpZiAoYWRkaXRpb25zLmxlbmd0aCA9PT0gMCkge1xuICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLndhcm4oXG4gICAgICAgICclczogbm8gbmV3IHJlc291cmNlcyBjb21wYXJlZCB0byB0aGUgY3VycmVudGx5IGRlcGxveWVkIHN0YWNrLCBza2lwcGluZyBpbXBvcnQuJyxcbiAgICAgICAgY2hhbGsuYm9sZChzdGFjay5kaXNwbGF5TmFtZSksXG4gICAgICApO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIFByZXBhcmUgYSBtYXBwaW5nIG9mIHBoeXNpY2FsIHJlc291cmNlcyB0byBDREsgY29uc3RydWN0c1xuICAgIGNvbnN0IGFjdHVhbEltcG9ydCA9ICFvcHRpb25zLnJlc291cmNlTWFwcGluZ0ZpbGVcbiAgICAgID8gYXdhaXQgcmVzb3VyY2VJbXBvcnRlci5hc2tGb3JSZXNvdXJjZUlkZW50aWZpZXJzKGFkZGl0aW9ucylcbiAgICAgIDogYXdhaXQgcmVzb3VyY2VJbXBvcnRlci5sb2FkUmVzb3VyY2VJZGVudGlmaWVycyhhZGRpdGlvbnMsIG9wdGlvbnMucmVzb3VyY2VNYXBwaW5nRmlsZSk7XG5cbiAgICBpZiAoYWN0dWFsSW1wb3J0LmltcG9ydFJlc291cmNlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy53YXJuKCdObyByZXNvdXJjZXMgc2VsZWN0ZWQgZm9yIGltcG9ydC4nKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBJZiBcIi0tY3JlYXRlLXJlc291cmNlLW1hcHBpbmdcIiBvcHRpb24gd2FzIHBhc3NlZCwgd3JpdGUgdGhlIHJlc291cmNlIG1hcHBpbmcgdG8gdGhlIGdpdmVuIGZpbGUgYW5kIGV4aXRcbiAgICBpZiAob3B0aW9ucy5yZWNvcmRSZXNvdXJjZU1hcHBpbmcpIHtcbiAgICAgIGNvbnN0IG91dHB1dEZpbGUgPSBvcHRpb25zLnJlY29yZFJlc291cmNlTWFwcGluZztcbiAgICAgIGZzLmVuc3VyZUZpbGVTeW5jKG91dHB1dEZpbGUpO1xuICAgICAgYXdhaXQgZnMud3JpdGVKc29uKG91dHB1dEZpbGUsIGFjdHVhbEltcG9ydC5yZXNvdXJjZU1hcCwge1xuICAgICAgICBzcGFjZXM6IDIsXG4gICAgICAgIGVuY29kaW5nOiAndXRmOCcsXG4gICAgICB9KTtcbiAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKCclczogbWFwcGluZyBmaWxlIHdyaXR0ZW4uJywgb3V0cHV0RmlsZSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gSW1wb3J0IHRoZSByZXNvdXJjZXMgYWNjb3JkaW5nIHRvIHRoZSBnaXZlbiBtYXBwaW5nXG4gICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLmluZm8oJyVzOiBpbXBvcnRpbmcgcmVzb3VyY2VzIGludG8gc3RhY2suLi4nLCBjaGFsay5ib2xkKHN0YWNrLmRpc3BsYXlOYW1lKSk7XG4gICAgY29uc3QgdGFncyA9IHRhZ3NGb3JTdGFjayhzdGFjayk7XG4gICAgYXdhaXQgcmVzb3VyY2VJbXBvcnRlci5pbXBvcnRSZXNvdXJjZXNGcm9tTWFwKGFjdHVhbEltcG9ydCwge1xuICAgICAgcm9sZUFybjogb3B0aW9ucy5yb2xlQXJuLFxuICAgICAgdGFncyxcbiAgICAgIGRlcGxveW1lbnRNZXRob2Q6IG9wdGlvbnMuZGVwbG95bWVudE1ldGhvZCxcbiAgICAgIHVzZVByZXZpb3VzUGFyYW1ldGVyczogdHJ1ZSxcbiAgICAgIHJvbGxiYWNrOiBvcHRpb25zLnJvbGxiYWNrLFxuICAgIH0pO1xuXG4gICAgLy8gTm90aWZ5IHVzZXIgb2YgbmV4dCBzdGVwc1xuICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKFxuICAgICAgYEltcG9ydCBvcGVyYXRpb24gY29tcGxldGUuIFdlIHJlY29tbWVuZCB5b3UgcnVuIGEgJHtjaGFsay5ibHVlQnJpZ2h0KCdkcmlmdCBkZXRlY3Rpb24nKX0gb3BlcmF0aW9uIGAgK1xuICAgICAgJ3RvIGNvbmZpcm0geW91ciBDREsgYXBwIHJlc291cmNlIGRlZmluaXRpb25zIGFyZSB1cC10by1kYXRlLiBSZWFkIG1vcmUgaGVyZTogJyArXG4gICAgICBjaGFsay51bmRlcmxpbmUuYmx1ZUJyaWdodChcbiAgICAgICAgJ2h0dHBzOi8vZG9jcy5hd3MuYW1hem9uLmNvbS9BV1NDbG91ZEZvcm1hdGlvbi9sYXRlc3QvVXNlckd1aWRlL2RldGVjdC1kcmlmdC1zdGFjay5odG1sJyxcbiAgICAgICksXG4gICAgKTtcbiAgICBpZiAoYWN0dWFsSW1wb3J0LmltcG9ydFJlc291cmNlcy5sZW5ndGggPCBhZGRpdGlvbnMubGVuZ3RoKSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbygnJyk7XG4gICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMud2FybihcbiAgICAgICAgYFNvbWUgcmVzb3VyY2VzIHdlcmUgc2tpcHBlZC4gUnVuIGFub3RoZXIgJHtjaGFsay5ibHVlQnJpZ2h0KCdjZGsgaW1wb3J0Jyl9IG9yIGEgJHtjaGFsay5ibHVlQnJpZ2h0KCdjZGsgZGVwbG95Jyl9IHRvIGJyaW5nIHRoZSBzdGFjayB1cC10by1kYXRlIHdpdGggeW91ciBDREsgYXBwIGRlZmluaXRpb24uYCxcbiAgICAgICk7XG4gICAgfSBlbHNlIGlmIChoYXNOb25BZGRpdGlvbnMpIHtcbiAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKCcnKTtcbiAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy53YXJuKFxuICAgICAgICBgWW91ciBhcHAgaGFzIHBlbmRpbmcgdXBkYXRlcyBvciBkZWxldGVzIGV4Y2x1ZGVkIGZyb20gdGhpcyBpbXBvcnQgb3BlcmF0aW9uLiBSdW4gYSAke2NoYWxrLmJsdWVCcmlnaHQoJ2NkayBkZXBsb3knKX0gdG8gYnJpbmcgdGhlIHN0YWNrIHVwLXRvLWRhdGUgd2l0aCB5b3VyIENESyBhcHAgZGVmaW5pdGlvbi5gLFxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICBwdWJsaWMgYXN5bmMgZGVzdHJveShvcHRpb25zOiBEZXN0cm95T3B0aW9ucykge1xuICAgIGNvbnN0IGlvSGVscGVyID0gdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpO1xuXG4gICAgLy8gVGhlIHN0YWNrcyB3aWxsIGhhdmUgYmVlbiBvcmRlcmVkIGZvciBkZXBsb3ltZW50LCBzbyByZXZlcnNlIHRoZW0gZm9yIGRlbGV0aW9uLlxuICAgIGNvbnN0IHN0YWNrcyA9IChhd2FpdCB0aGlzLnNlbGVjdFN0YWNrc0ZvckRlc3Ryb3kob3B0aW9ucy5zZWxlY3Rvciwgb3B0aW9ucy5leGNsdXNpdmVseSkpLnJldmVyc2VkKCk7XG5cbiAgICBpZiAoIW9wdGlvbnMuZm9yY2UpIHtcbiAgICAgIGNvbnN0IG1vdGl2YXRpb24gPSAnRGVzdHJveWluZyBzdGFja3MgaXMgYW4gaXJyZXZlcnNpYmxlIGFjdGlvbic7XG4gICAgICBjb25zdCBxdWVzdGlvbiA9IGBBcmUgeW91IHN1cmUgeW91IHdhbnQgdG8gZGVsZXRlOiAke2NoYWxrLmJsdWUoc3RhY2tzLnN0YWNrQXJ0aWZhY3RzLm1hcCgocykgPT4gcy5oaWVyYXJjaGljYWxJZCkuam9pbignLCAnKSl9YDtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IGlvSGVscGVyLnJlcXVlc3RSZXNwb25zZShJTy5DREtfVE9PTEtJVF9JNzAxMC5yZXEocXVlc3Rpb24sIHsgbW90aXZhdGlvbiB9KSk7XG4gICAgICB9IGNhdGNoIChlcnI6IHVua25vd24pIHtcbiAgICAgICAgaWYgKCFUb29sa2l0RXJyb3IuaXNUb29sa2l0RXJyb3IoZXJyKSB8fCBlcnIubWVzc2FnZSAhPSAnQWJvcnRlZCBieSB1c2VyJykge1xuICAgICAgICAgIHRocm93IGVycjsgLy8gdW5leHBlY3RlZCBlcnJvclxuICAgICAgICB9XG4gICAgICAgIGF3YWl0IGlvSGVscGVyLm5vdGlmeShJTy5DREtfVE9PTEtJVF9FNzAxMC5tc2coZXJyLm1lc3NhZ2UpKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgIH1cblxuICAgIGNvbnN0IGFjdGlvbiA9IG9wdGlvbnMuZnJvbURlcGxveSA/ICdkZXBsb3knIDogJ2Rlc3Ryb3knO1xuICAgIGZvciAoY29uc3QgW2luZGV4LCBzdGFja10gb2Ygc3RhY2tzLnN0YWNrQXJ0aWZhY3RzLmVudHJpZXMoKSkge1xuICAgICAgYXdhaXQgaW9IZWxwZXIuZGVmYXVsdHMuaW5mbyhjaGFsay5ncmVlbignJXM6IGRlc3Ryb3lpbmcuLi4gWyVzLyVzXScpLCBjaGFsay5ibHVlKHN0YWNrLmRpc3BsYXlOYW1lKSwgaW5kZXggKyAxLCBzdGFja3Muc3RhY2tDb3VudCk7XG4gICAgICB0cnkge1xuICAgICAgICBhd2FpdCB0aGlzLnByb3BzLmRlcGxveW1lbnRzLmRlc3Ryb3lTdGFjayh7XG4gICAgICAgICAgc3RhY2ssXG4gICAgICAgICAgZGVwbG95TmFtZTogc3RhY2suc3RhY2tOYW1lLFxuICAgICAgICAgIHJvbGVBcm46IG9wdGlvbnMucm9sZUFybixcbiAgICAgICAgfSk7XG4gICAgICAgIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLmluZm8oY2hhbGsuZ3JlZW4oYFxcbiDinIUgICVzOiAke2FjdGlvbn1lZGApLCBjaGFsay5ibHVlKHN0YWNrLmRpc3BsYXlOYW1lKSk7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLmVycm9yKGBcXG4g4p2MICAlczogJHthY3Rpb259IGZhaWxlZGAsIGNoYWxrLmJsdWUoc3RhY2suZGlzcGxheU5hbWUpLCBlKTtcbiAgICAgICAgdGhyb3cgZTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICBwdWJsaWMgYXN5bmMgbGlzdChcbiAgICBzZWxlY3RvcnM6IHN0cmluZ1tdLFxuICAgIG9wdGlvbnM6IHsgbG9uZz86IGJvb2xlYW47IGpzb24/OiBib29sZWFuOyBzaG93RGVwcz86IGJvb2xlYW4gfSA9IHt9LFxuICApOiBQcm9taXNlPG51bWJlcj4ge1xuICAgIGNvbnN0IHN0YWNrcyA9IGF3YWl0IGxpc3RTdGFja3ModGhpcywge1xuICAgICAgc2VsZWN0b3JzOiBzZWxlY3RvcnMsXG4gICAgfSk7XG5cbiAgICBpZiAob3B0aW9ucy5sb25nICYmIG9wdGlvbnMuc2hvd0RlcHMpIHtcbiAgICAgIGF3YWl0IHByaW50U2VyaWFsaXplZE9iamVjdCh0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCksIHN0YWNrcywgb3B0aW9ucy5qc29uID8/IGZhbHNlKTtcbiAgICAgIHJldHVybiAwO1xuICAgIH1cblxuICAgIGlmIChvcHRpb25zLnNob3dEZXBzKSB7XG4gICAgICBjb25zdCBzdGFja0RlcHMgPSBzdGFja3MubWFwKHN0YWNrID0+ICh7XG4gICAgICAgIGlkOiBzdGFjay5pZCxcbiAgICAgICAgZGVwZW5kZW5jaWVzOiBzdGFjay5kZXBlbmRlbmNpZXMsXG4gICAgICB9KSk7XG4gICAgICBhd2FpdCBwcmludFNlcmlhbGl6ZWRPYmplY3QodGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLCBzdGFja0RlcHMsIG9wdGlvbnMuanNvbiA/PyBmYWxzZSk7XG4gICAgICByZXR1cm4gMDtcbiAgICB9XG5cbiAgICBpZiAob3B0aW9ucy5sb25nKSB7XG4gICAgICBjb25zdCBsb25nID0gc3RhY2tzLm1hcChzdGFjayA9PiAoe1xuICAgICAgICBpZDogc3RhY2suaWQsXG4gICAgICAgIG5hbWU6IHN0YWNrLm5hbWUsXG4gICAgICAgIGVudmlyb25tZW50OiBzdGFjay5lbnZpcm9ubWVudCxcbiAgICAgIH0pKTtcbiAgICAgIGF3YWl0IHByaW50U2VyaWFsaXplZE9iamVjdCh0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCksIGxvbmcsIG9wdGlvbnMuanNvbiA/PyBmYWxzZSk7XG4gICAgICByZXR1cm4gMDtcbiAgICB9XG5cbiAgICAvLyBqdXN0IHByaW50IHN0YWNrIElEc1xuICAgIGZvciAoY29uc3Qgc3RhY2sgb2Ygc3RhY2tzKSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMucmVzdWx0KHN0YWNrLmlkKTtcbiAgICB9XG4gICAgcmV0dXJuIDA7IC8vIGV4aXQtY29kZVxuICB9XG5cbiAgLyoqXG4gICAqIFN5bnRoZXNpemUgdGhlIGdpdmVuIHNldCBvZiBzdGFja3MgKGNhbGxlZCB3aGVuIHRoZSB1c2VyIHJ1bnMgJ2NkayBzeW50aCcpXG4gICAqXG4gICAqIElOUFVUOiBTdGFjayBuYW1lcyBjYW4gYmUgc3VwcGxpZWQgdXNpbmcgYSBnbG9iIGZpbHRlci4gSWYgbm8gc3RhY2tzIGFyZVxuICAgKiBnaXZlbiwgYWxsIHN0YWNrcyBmcm9tIHRoZSBhcHBsaWNhdGlvbiBhcmUgaW1wbGljaXRseSBzZWxlY3RlZC5cbiAgICpcbiAgICogT1VUUFVUOiBJZiBtb3JlIHRoYW4gb25lIHN0YWNrIGVuZHMgdXAgYmVpbmcgc2VsZWN0ZWQsIGFuIG91dHB1dCBkaXJlY3RvcnlcbiAgICogc2hvdWxkIGJlIHN1cHBsaWVkLCB3aGVyZSB0aGUgdGVtcGxhdGVzIHdpbGwgYmUgd3JpdHRlbi5cbiAgICovXG4gIHB1YmxpYyBhc3luYyBzeW50aChcbiAgICBzdGFja05hbWVzOiBzdHJpbmdbXSxcbiAgICBleGNsdXNpdmVseTogYm9vbGVhbixcbiAgICBxdWlldDogYm9vbGVhbixcbiAgICBhdXRvVmFsaWRhdGU/OiBib29sZWFuLFxuICAgIGpzb24/OiBib29sZWFuLFxuICApOiBQcm9taXNlPGFueT4ge1xuICAgIGNvbnN0IHN0YWNrcyA9IGF3YWl0IHRoaXMuc2VsZWN0U3RhY2tzRm9yRGlmZihzdGFja05hbWVzLCBleGNsdXNpdmVseSwgYXV0b1ZhbGlkYXRlKTtcblxuICAgIC8vIGlmIHdlIGhhdmUgYSBzaW5nbGUgc3RhY2ssIHByaW50IGl0IHRvIFNURE9VVFxuICAgIGlmIChzdGFja3Muc3RhY2tDb3VudCA9PT0gMSkge1xuICAgICAgaWYgKCFxdWlldCkge1xuICAgICAgICBhd2FpdCBwcmludFNlcmlhbGl6ZWRPYmplY3QodGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLCBvYnNjdXJlVGVtcGxhdGUoc3RhY2tzLmZpcnN0U3RhY2sudGVtcGxhdGUpLCBqc29uID8/IGZhbHNlKTtcbiAgICAgIH1cblxuICAgICAgYXdhaXQgZGlzcGxheUZsYWdzTWVzc2FnZSh0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCksIHRoaXMudG9vbGtpdCwgdGhpcy5wcm9wcy5jbG91ZEV4ZWN1dGFibGUpO1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG5cbiAgICAvLyBub3Qgb3V0cHV0dGluZyB0ZW1wbGF0ZSB0byBzdGRvdXQsIGxldCdzIGV4cGxhaW4gdGhpbmdzIHRvIHRoZSB1c2VyIGEgbGl0dGxlIGJpdC4uLlxuICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKGNoYWxrLmdyZWVuKGBTdWNjZXNzZnVsbHkgc3ludGhlc2l6ZWQgdG8gJHtjaGFsay5ibHVlKHBhdGgucmVzb2x2ZShzdGFja3MuYXNzZW1ibHkuZGlyZWN0b3J5KSl9YCkpO1xuICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKFxuICAgICAgYFN1cHBseSBhIHN0YWNrIGlkICgke3N0YWNrcy5zdGFja0FydGlmYWN0cy5tYXAoKHMpID0+IGNoYWxrLmdyZWVuKHMuaGllcmFyY2hpY2FsSWQpKS5qb2luKCcsICcpfSkgdG8gZGlzcGxheSBpdHMgdGVtcGxhdGUuYCxcbiAgICApO1xuXG4gICAgYXdhaXQgZGlzcGxheUZsYWdzTWVzc2FnZSh0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCksIHRoaXMudG9vbGtpdCwgdGhpcy5wcm9wcy5jbG91ZEV4ZWN1dGFibGUpO1xuICAgIHJldHVybiB1bmRlZmluZWQ7XG4gIH1cblxuICAvKipcbiAgICogQm9vdHN0cmFwIHRoZSBDREsgVG9vbGtpdCBzdGFjayBpbiB0aGUgYWNjb3VudHMgdXNlZCBieSB0aGUgc3BlY2lmaWVkIHN0YWNrKHMpLlxuICAgKlxuICAgKiBAcGFyYW0gdXNlckVudmlyb25tZW50U3BlY3MgLSBlbnZpcm9ubWVudCBuYW1lcyB0aGF0IG5lZWQgdG8gaGF2ZSB0b29sa2l0IHN1cHBvcnRcbiAgICogICAgICAgICAgICAgcHJvdmlzaW9uZWQsIGFzIGEgZ2xvYiBmaWx0ZXIuIElmIG5vbmUgaXMgcHJvdmlkZWQsIGFsbCBzdGFja3MgYXJlIGltcGxpY2l0bHkgc2VsZWN0ZWQuXG4gICAqIEBwYXJhbSBvcHRpb25zIC0gVGhlIG5hbWUsIHJvbGUgQVJOLCBib290c3RyYXBwaW5nIHBhcmFtZXRlcnMsIGV0Yy4gdG8gYmUgdXNlZCBmb3IgdGhlIENESyBUb29sa2l0IHN0YWNrLlxuICAgKi9cbiAgcHVibGljIGFzeW5jIGJvb3RzdHJhcChcbiAgICB1c2VyRW52aXJvbm1lbnRTcGVjczogc3RyaW5nW10sXG4gICAgb3B0aW9uczogQm9vdHN0cmFwRW52aXJvbm1lbnRPcHRpb25zLFxuICApOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBib290c3RyYXBwZXIgPSBuZXcgQm9vdHN0cmFwcGVyKG9wdGlvbnMuc291cmNlLCBhc0lvSGVscGVyKHRoaXMuaW9Ib3N0LCAnYm9vdHN0cmFwJykpO1xuICAgIC8vIElmIHRoZXJlIGlzIGFuICctLWFwcCcgYXJndW1lbnQgYW5kIGFuIGVudmlyb25tZW50IGxvb2tzIGxpa2UgYSBnbG9iLCB3ZVxuICAgIC8vIHNlbGVjdCB0aGUgZW52aXJvbm1lbnRzIGZyb20gdGhlIGFwcC4gT3RoZXJ3aXNlLCB1c2Ugd2hhdCB0aGUgdXNlciBzYWlkLlxuXG4gICAgY29uc3QgZW52aXJvbm1lbnRzID0gYXdhaXQgdGhpcy5kZWZpbmVFbnZpcm9ubWVudHModXNlckVudmlyb25tZW50U3BlY3MpO1xuXG4gICAgY29uc3QgbGltaXQgPSBwTGltaXQoMjApO1xuXG4gICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIEBjZGtsYWJzL3Byb21pc2VhbGwtbm8tdW5ib3VuZGVkLXBhcmFsbGVsaXNtXG4gICAgYXdhaXQgUHJvbWlzZS5hbGwoZW52aXJvbm1lbnRzLm1hcCgoZW52aXJvbm1lbnQpID0+IGxpbWl0KGFzeW5jICgpID0+IHtcbiAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKGNoYWxrLmdyZWVuKCcg4o+zICBCb290c3RyYXBwaW5nIGVudmlyb25tZW50ICVzLi4uJyksIGNoYWxrLmJsdWUoZW52aXJvbm1lbnQubmFtZSkpO1xuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgYm9vdHN0cmFwcGVyLmJvb3RzdHJhcEVudmlyb25tZW50KGVudmlyb25tZW50LCB0aGlzLnByb3BzLnNka1Byb3ZpZGVyLCBvcHRpb25zKTtcbiAgICAgICAgY29uc3QgbWVzc2FnZSA9IHJlc3VsdC5ub09wXG4gICAgICAgICAgPyAnIOKchSAgRW52aXJvbm1lbnQgJXMgYm9vdHN0cmFwcGVkIChubyBjaGFuZ2VzKS4nXG4gICAgICAgICAgOiAnIOKchSAgRW52aXJvbm1lbnQgJXMgYm9vdHN0cmFwcGVkLic7XG4gICAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKGNoYWxrLmdyZWVuKG1lc3NhZ2UpLCBjaGFsay5ibHVlKGVudmlyb25tZW50Lm5hbWUpKTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLmVycm9yKCcg4p2MICBFbnZpcm9ubWVudCAlcyBmYWlsZWQgYm9vdHN0cmFwcGluZzogJXMnLCBjaGFsay5ibHVlKGVudmlyb25tZW50Lm5hbWUpLCBlKTtcbiAgICAgICAgdGhyb3cgZTtcbiAgICAgIH1cbiAgICB9KSkpO1xuICB9XG5cbiAgLyoqXG4gICAqIEdhcmJhZ2UgY29sbGVjdHMgYXNzZXRzIGZyb20gYSBDREsgYXBwJ3MgZW52aXJvbm1lbnRcbiAgICogQHBhcmFtIG9wdGlvbnMgLSBPcHRpb25zIGZvciBHYXJiYWdlIENvbGxlY3Rpb25cbiAgICovXG4gIHB1YmxpYyBhc3luYyBnYXJiYWdlQ29sbGVjdCh1c2VyRW52aXJvbm1lbnRTcGVjczogc3RyaW5nW10sIG9wdGlvbnM6IEdhcmJhZ2VDb2xsZWN0aW9uT3B0aW9ucykge1xuICAgIGNvbnN0IGVudmlyb25tZW50cyA9IGF3YWl0IHRoaXMuZGVmaW5lRW52aXJvbm1lbnRzKHVzZXJFbnZpcm9ubWVudFNwZWNzKTtcblxuICAgIGZvciAoY29uc3QgZW52aXJvbm1lbnQgb2YgZW52aXJvbm1lbnRzKSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuaW5mbyhjaGFsay5ncmVlbignIOKPsyAgR2FyYmFnZSBDb2xsZWN0aW5nIGVudmlyb25tZW50ICVzLi4uJyksIGNoYWxrLmJsdWUoZW52aXJvbm1lbnQubmFtZSkpO1xuICAgICAgY29uc3QgZ2MgPSBuZXcgR2FyYmFnZUNvbGxlY3Rvcih7XG4gICAgICAgIHNka1Byb3ZpZGVyOiB0aGlzLnByb3BzLnNka1Byb3ZpZGVyLFxuICAgICAgICBpb0hlbHBlcjogYXNJb0hlbHBlcih0aGlzLmlvSG9zdCwgJ2djJyksXG4gICAgICAgIHJlc29sdmVkRW52aXJvbm1lbnQ6IGVudmlyb25tZW50LFxuICAgICAgICBib290c3RyYXBTdGFja05hbWU6IG9wdGlvbnMuYm9vdHN0cmFwU3RhY2tOYW1lLFxuICAgICAgICByb2xsYmFja0J1ZmZlckRheXM6IG9wdGlvbnMucm9sbGJhY2tCdWZmZXJEYXlzLFxuICAgICAgICBjcmVhdGVkQnVmZmVyRGF5czogb3B0aW9ucy5jcmVhdGVkQnVmZmVyRGF5cyxcbiAgICAgICAgYWN0aW9uOiBvcHRpb25zLmFjdGlvbiA/PyAnZnVsbCcsXG4gICAgICAgIHR5cGU6IG9wdGlvbnMudHlwZSA/PyAnYWxsJyxcbiAgICAgICAgY29uZmlybTogb3B0aW9ucy5jb25maXJtID8/IHRydWUsXG4gICAgICB9KTtcbiAgICAgIGF3YWl0IGdjLmdhcmJhZ2VDb2xsZWN0KCk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBkZWZpbmVFbnZpcm9ubWVudHModXNlckVudmlyb25tZW50U3BlY3M6IHN0cmluZ1tdKTogUHJvbWlzZTxjeGFwaS5FbnZpcm9ubWVudFtdPiB7XG4gICAgLy8gQnkgZGVmYXVsdCwgZ2xvYiBmb3IgZXZlcnl0aGluZ1xuICAgIGNvbnN0IGVudmlyb25tZW50U3BlY3MgPSB1c2VyRW52aXJvbm1lbnRTcGVjcy5sZW5ndGggPiAwID8gWy4uLnVzZXJFbnZpcm9ubWVudFNwZWNzXSA6IFsnKionXTtcblxuICAgIC8vIFBhcnRpdGlvbiBpbnRvIGdsb2JzIGFuZCBub24tZ2xvYnMgKHRoaXMgd2lsbCBtdXRhdGUgZW52aXJvbm1lbnRTcGVjcykuXG4gICAgY29uc3QgZ2xvYlNwZWNzID0gcGFydGl0aW9uKGVudmlyb25tZW50U3BlY3MsIGxvb2tzTGlrZUdsb2IpO1xuICAgIGlmIChnbG9iU3BlY3MubGVuZ3RoID4gMCAmJiAhdGhpcy5wcm9wcy5jbG91ZEV4ZWN1dGFibGUuaGFzQXBwKSB7XG4gICAgICBpZiAodXNlckVudmlyb25tZW50U3BlY3MubGVuZ3RoID4gMCkge1xuICAgICAgICAvLyBVc2VyIGRpZCByZXF1ZXN0IHRoaXMgZ2xvYlxuICAgICAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKFxuICAgICAgICAgIGAnJHtnbG9iU3BlY3N9JyBpcyBub3QgYW4gZW52aXJvbm1lbnQgbmFtZS4gU3BlY2lmeSBhbiBlbnZpcm9ubWVudCBuYW1lIGxpa2UgJ2F3czovLzEyMzQ1Njc4OTAxMi91cy1lYXN0LTEnLCBvciBydW4gaW4gYSBkaXJlY3Rvcnkgd2l0aCAnY2RrLmpzb24nIHRvIHVzZSB3aWxkY2FyZHMuYCxcbiAgICAgICAgKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vIFVzZXIgZGlkIG5vdCByZXF1ZXN0IGFueXRoaW5nXG4gICAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoXG4gICAgICAgICAgXCJTcGVjaWZ5IGFuIGVudmlyb25tZW50IG5hbWUgbGlrZSAnYXdzOi8vMTIzNDU2Nzg5MDEyL3VzLWVhc3QtMScsIG9yIHJ1biBpbiBhIGRpcmVjdG9yeSB3aXRoICdjZGsuanNvbicuXCIsXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgY29uc3QgZW52aXJvbm1lbnRzOiBjeGFwaS5FbnZpcm9ubWVudFtdID0gWy4uLmVudmlyb25tZW50c0Zyb21EZXNjcmlwdG9ycyhlbnZpcm9ubWVudFNwZWNzKV07XG5cbiAgICAvLyBJZiB0aGVyZSBpcyBhbiAnLS1hcHAnIGFyZ3VtZW50LCBzZWxlY3QgdGhlIGVudmlyb25tZW50cyBmcm9tIHRoZSBhcHAuXG4gICAgaWYgKHRoaXMucHJvcHMuY2xvdWRFeGVjdXRhYmxlLmhhc0FwcCkge1xuICAgICAgZW52aXJvbm1lbnRzLnB1c2goXG4gICAgICAgIC4uLihhd2FpdCBnbG9iRW52aXJvbm1lbnRzRnJvbVN0YWNrcyhhd2FpdCB0aGlzLnNlbGVjdFN0YWNrc0Zvckxpc3QoW10pLCBnbG9iU3BlY3MsIHRoaXMucHJvcHMuc2RrUHJvdmlkZXIpKSxcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGVudmlyb25tZW50cztcbiAgfVxuXG4gIC8qKlxuICAgKiBNaWdyYXRlcyBhIENsb3VkRm9ybWF0aW9uIHN0YWNrL3RlbXBsYXRlIHRvIGEgQ0RLIGFwcFxuICAgKiBAcGFyYW0gb3B0aW9ucyAtIE9wdGlvbnMgZm9yIENESyBhcHAgY3JlYXRpb25cbiAgICovXG4gIHB1YmxpYyBhc3luYyBtaWdyYXRlKG9wdGlvbnM6IE1pZ3JhdGVPcHRpb25zKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLndhcm4oJ1RoaXMgY29tbWFuZCBpcyBhbiBleHBlcmltZW50YWwgZmVhdHVyZS4nKTtcbiAgICBjb25zdCBsYW5ndWFnZSA9IG9wdGlvbnMubGFuZ3VhZ2U/LnRvTG93ZXJDYXNlKCkgPz8gJ3R5cGVzY3JpcHQnO1xuICAgIGNvbnN0IGVudmlyb25tZW50ID0gc2V0RW52aXJvbm1lbnQob3B0aW9ucy5hY2NvdW50LCBvcHRpb25zLnJlZ2lvbik7XG4gICAgbGV0IGdlbmVyYXRlVGVtcGxhdGVPdXRwdXQ6IEdlbmVyYXRlVGVtcGxhdGVPdXRwdXQgfCB1bmRlZmluZWQ7XG4gICAgbGV0IGNmbjogQ2ZuVGVtcGxhdGVHZW5lcmF0b3JQcm92aWRlciB8IHVuZGVmaW5lZDtcbiAgICBsZXQgdGVtcGxhdGVUb0RlbGV0ZTogc3RyaW5nIHwgdW5kZWZpbmVkO1xuXG4gICAgdHJ5IHtcbiAgICAgIC8vIGlmIG5laXRoZXIgZnJvbVBhdGggbm9yIGZyb21TdGFjayBpcyBwcm92aWRlZCwgZ2VuZXJhdGUgYSB0ZW1wbGF0ZSB1c2luZyBjbG91ZGZvcm1hdGlvblxuICAgICAgY29uc3Qgc2NhblR5cGUgPSBwYXJzZVNvdXJjZU9wdGlvbnMob3B0aW9ucy5mcm9tUGF0aCwgb3B0aW9ucy5mcm9tU3RhY2ssIG9wdGlvbnMuc3RhY2tOYW1lKS5zb3VyY2U7XG4gICAgICBpZiAoc2NhblR5cGUgPT0gVGVtcGxhdGVTb3VyY2VPcHRpb25zLlNDQU4pIHtcbiAgICAgICAgZ2VuZXJhdGVUZW1wbGF0ZU91dHB1dCA9IGF3YWl0IGdlbmVyYXRlVGVtcGxhdGUoe1xuICAgICAgICAgIHN0YWNrTmFtZTogb3B0aW9ucy5zdGFja05hbWUsXG4gICAgICAgICAgZmlsdGVyczogb3B0aW9ucy5maWx0ZXIsXG4gICAgICAgICAgZnJvbVNjYW46IG9wdGlvbnMuZnJvbVNjYW4sXG4gICAgICAgICAgc2RrUHJvdmlkZXI6IHRoaXMucHJvcHMuc2RrUHJvdmlkZXIsXG4gICAgICAgICAgZW52aXJvbm1lbnQ6IGVudmlyb25tZW50LFxuICAgICAgICAgIGlvSGVscGVyOiB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCksXG4gICAgICAgIH0pO1xuICAgICAgICB0ZW1wbGF0ZVRvRGVsZXRlID0gZ2VuZXJhdGVUZW1wbGF0ZU91dHB1dC50ZW1wbGF0ZUlkO1xuICAgICAgfSBlbHNlIGlmIChzY2FuVHlwZSA9PSBUZW1wbGF0ZVNvdXJjZU9wdGlvbnMuUEFUSCkge1xuICAgICAgICBjb25zdCB0ZW1wbGF0ZUJvZHkgPSByZWFkRnJvbVBhdGgob3B0aW9ucy5mcm9tUGF0aCEpO1xuXG4gICAgICAgIGNvbnN0IHBhcnNlZFRlbXBsYXRlID0gZGVzZXJpYWxpemVTdHJ1Y3R1cmUodGVtcGxhdGVCb2R5KTtcbiAgICAgICAgY29uc3QgdGVtcGxhdGVJZCA9IHBhcnNlZFRlbXBsYXRlLk1ldGFkYXRhPy5BV1NUb29sc01ldHJpY3M/LklhQ19HZW5lcmF0b3I/LnRvU3RyaW5nKCk7XG4gICAgICAgIGlmICh0ZW1wbGF0ZUlkKSB7XG4gICAgICAgICAgLy8gaWYgd2UgaGF2ZSBhIHRlbXBsYXRlIGlkLCB3ZSBjYW4gY2FsbCBkZXNjcmliZSBnZW5lcmF0ZWQgdGVtcGxhdGUgdG8gZ2V0IHRoZSByZXNvdXJjZSBpZGVudGlmaWVyc1xuICAgICAgICAgIC8vIHJlc291cmNlIG1ldGFkYXRhLCBhbmQgdGVtcGxhdGUgc291cmNlIHRvIGdlbmVyYXRlIHRoZSB0ZW1wbGF0ZVxuICAgICAgICAgIGNmbiA9IG5ldyBDZm5UZW1wbGF0ZUdlbmVyYXRvclByb3ZpZGVyKGF3YWl0IGJ1aWxkQ2ZuQ2xpZW50KHRoaXMucHJvcHMuc2RrUHJvdmlkZXIsIGVudmlyb25tZW50KSwgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpKTtcbiAgICAgICAgICBjb25zdCBnZW5lcmF0ZWRUZW1wbGF0ZVN1bW1hcnkgPSBhd2FpdCBjZm4uZGVzY3JpYmVHZW5lcmF0ZWRUZW1wbGF0ZSh0ZW1wbGF0ZUlkKTtcbiAgICAgICAgICBnZW5lcmF0ZVRlbXBsYXRlT3V0cHV0ID0gYnVpbGRHZW5lcmF0ZWRUZW1wbGF0ZU91dHB1dChcbiAgICAgICAgICAgIGdlbmVyYXRlZFRlbXBsYXRlU3VtbWFyeSxcbiAgICAgICAgICAgIHRlbXBsYXRlQm9keSxcbiAgICAgICAgICAgIGdlbmVyYXRlZFRlbXBsYXRlU3VtbWFyeS5HZW5lcmF0ZWRUZW1wbGF0ZUlkISxcbiAgICAgICAgICApO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGdlbmVyYXRlVGVtcGxhdGVPdXRwdXQgPSB7XG4gICAgICAgICAgICBtaWdyYXRlSnNvbjoge1xuICAgICAgICAgICAgICB0ZW1wbGF0ZUJvZHk6IHRlbXBsYXRlQm9keSxcbiAgICAgICAgICAgICAgc291cmNlOiAnbG9jYWxmaWxlJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfTtcbiAgICAgICAgfVxuICAgICAgfSBlbHNlIGlmIChzY2FuVHlwZSA9PSBUZW1wbGF0ZVNvdXJjZU9wdGlvbnMuU1RBQ0spIHtcbiAgICAgICAgY29uc3QgdGVtcGxhdGUgPSBhd2FpdCByZWFkRnJvbVN0YWNrKG9wdGlvbnMuc3RhY2tOYW1lLCB0aGlzLnByb3BzLnNka1Byb3ZpZGVyLCBlbnZpcm9ubWVudCk7XG4gICAgICAgIGlmICghdGVtcGxhdGUpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKGBObyB0ZW1wbGF0ZSBmb3VuZCBmb3Igc3RhY2stbmFtZTogJHtvcHRpb25zLnN0YWNrTmFtZX1gKTtcbiAgICAgICAgfVxuICAgICAgICBnZW5lcmF0ZVRlbXBsYXRlT3V0cHV0ID0ge1xuICAgICAgICAgIG1pZ3JhdGVKc29uOiB7XG4gICAgICAgICAgICB0ZW1wbGF0ZUJvZHk6IHRlbXBsYXRlLFxuICAgICAgICAgICAgc291cmNlOiBvcHRpb25zLnN0YWNrTmFtZSxcbiAgICAgICAgICB9LFxuICAgICAgICB9O1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gV2Ugc2hvdWxkbid0IGV2ZXIgZ2V0IGhlcmUsIGJ1dCBqdXN0IGluIGNhc2UuXG4gICAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoYEludmFsaWQgc291cmNlIG9wdGlvbiBwcm92aWRlZDogJHtzY2FuVHlwZX1gKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHN0YWNrID0gZ2VuZXJhdGVTdGFjayhnZW5lcmF0ZVRlbXBsYXRlT3V0cHV0Lm1pZ3JhdGVKc29uLnRlbXBsYXRlQm9keSwgb3B0aW9ucy5zdGFja05hbWUsIGxhbmd1YWdlKTtcbiAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5pbmZvKGNoYWxrLmdyZWVuKCcg4o+zICBHZW5lcmF0aW5nIENESyBhcHAgZm9yICVzLi4uJyksIGNoYWxrLmJsdWUob3B0aW9ucy5zdGFja05hbWUpKTtcbiAgICAgIGF3YWl0IGdlbmVyYXRlQ2RrQXBwKHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKSwgb3B0aW9ucy5zdGFja05hbWUsIHN0YWNrISwgbGFuZ3VhZ2UsIG9wdGlvbnMub3V0cHV0UGF0aCwgb3B0aW9ucy5jb21wcmVzcyk7XG4gICAgICBpZiAoZ2VuZXJhdGVUZW1wbGF0ZU91dHB1dCkge1xuICAgICAgICB3cml0ZU1pZ3JhdGVKc29uRmlsZShvcHRpb25zLm91dHB1dFBhdGgsIG9wdGlvbnMuc3RhY2tOYW1lLCBnZW5lcmF0ZVRlbXBsYXRlT3V0cHV0Lm1pZ3JhdGVKc29uKTtcbiAgICAgIH1cbiAgICAgIGlmIChpc1RoZXJlQVdhcm5pbmcoZ2VuZXJhdGVUZW1wbGF0ZU91dHB1dCkpIHtcbiAgICAgICAgYXdhaXQgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLmRlZmF1bHRzLndhcm4oXG4gICAgICAgICAgJyDimqDvuI8gIFNvbWUgcmVzb3VyY2VzIGNvdWxkIG5vdCBiZSBtaWdyYXRlZCBjb21wbGV0ZWx5LiBQbGVhc2UgcmV2aWV3IHRoZSBSRUFETUUubWQgZmlsZSBmb3IgbW9yZSBpbmZvcm1hdGlvbi4nLFxuICAgICAgICApO1xuICAgICAgICBhcHBlbmRXYXJuaW5nc1RvUmVhZG1lKFxuICAgICAgICAgIGAke3BhdGguam9pbihvcHRpb25zLm91dHB1dFBhdGggPz8gcHJvY2Vzcy5jd2QoKSwgb3B0aW9ucy5zdGFja05hbWUpfS9SRUFETUUubWRgLFxuICAgICAgICAgIGdlbmVyYXRlVGVtcGxhdGVPdXRwdXQucmVzb3VyY2VzISxcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBhd2FpdCB0aGlzLmlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMuZXJyb3IoJyDinYwgIE1pZ3JhdGUgZmFpbGVkIGZvciBgJXNgOiAlcycsIG9wdGlvbnMuc3RhY2tOYW1lLCAoZSBhcyBFcnJvcikubWVzc2FnZSk7XG4gICAgICB0aHJvdyBlO1xuICAgIH0gZmluYWxseSB7XG4gICAgICBpZiAodGVtcGxhdGVUb0RlbGV0ZSkge1xuICAgICAgICBpZiAoIWNmbikge1xuICAgICAgICAgIGNmbiA9IG5ldyBDZm5UZW1wbGF0ZUdlbmVyYXRvclByb3ZpZGVyKGF3YWl0IGJ1aWxkQ2ZuQ2xpZW50KHRoaXMucHJvcHMuc2RrUHJvdmlkZXIsIGVudmlyb25tZW50KSwgdGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXByb2Nlc3MuZW52Lk1JR1JBVEVfSU5URUdfVEVTVCkge1xuICAgICAgICAgIGF3YWl0IGNmbi5kZWxldGVHZW5lcmF0ZWRUZW1wbGF0ZSh0ZW1wbGF0ZVRvRGVsZXRlKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIHB1YmxpYyBhc3luYyByZWZhY3RvcihvcHRpb25zOiBSZWZhY3Rvck9wdGlvbnMpOiBQcm9taXNlPG51bWJlcj4ge1xuICAgIGlmIChvcHRpb25zLnJldmVydCAmJiAhb3B0aW9ucy5vdmVycmlkZUZpbGUpIHtcbiAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoJ1RoZSAtLXJldmVydCBvcHRpb24gY2FuIG9ubHkgYmUgdXNlZCB3aXRoIHRoZSAtLW92ZXJyaWRlLWZpbGUgb3B0aW9uLicpO1xuICAgIH1cblxuICAgIHRyeSB7XG4gICAgICBjb25zdCBwYXR0ZXJucyA9IG9wdGlvbnMuc3RhY2tzPy5wYXR0ZXJucyA/PyBbXTtcbiAgICAgIGF3YWl0IHRoaXMudG9vbGtpdC5yZWZhY3Rvcih0aGlzLnByb3BzLmNsb3VkRXhlY3V0YWJsZSwge1xuICAgICAgICBkcnlSdW46IG9wdGlvbnMuZHJ5UnVuLFxuICAgICAgICBzdGFja3M6IHtcbiAgICAgICAgICBwYXR0ZXJuczogcGF0dGVybnMsXG4gICAgICAgICAgc3RyYXRlZ3k6IHBhdHRlcm5zLmxlbmd0aCA+IDAgPyBTdGFja1NlbGVjdGlvblN0cmF0ZWd5LlBBVFRFUk5fTUFUQ0ggOiBTdGFja1NlbGVjdGlvblN0cmF0ZWd5LkFMTF9TVEFDS1MsXG4gICAgICAgIH0sXG4gICAgICAgIGZvcmNlOiBvcHRpb25zLmZvcmNlLFxuICAgICAgICBhZGRpdGlvbmFsU3RhY2tOYW1lczogb3B0aW9ucy5hZGRpdGlvbmFsU3RhY2tOYW1lcyxcbiAgICAgICAgb3ZlcnJpZGVzOiByZWFkT3ZlcnJpZGVzKG9wdGlvbnMub3ZlcnJpZGVGaWxlLCBvcHRpb25zLnJldmVydCksXG4gICAgICAgIHJvbGVBcm46IG9wdGlvbnMucm9sZUFybixcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGF3YWl0IHRoaXMuaW9Ib3N0LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy5lcnJvcigoZSBhcyBFcnJvcikubWVzc2FnZSk7XG4gICAgICB0aHJvdyBlO1xuICAgIH1cblxuICAgIHJldHVybiAwO1xuXG4gICAgZnVuY3Rpb24gcmVhZE92ZXJyaWRlcyhmaWxlUGF0aDogc3RyaW5nIHwgdW5kZWZpbmVkLCByZXZlcnQ6IGJvb2xlYW4gPSBmYWxzZSkge1xuICAgICAgaWYgKGZpbGVQYXRoID09IG51bGwpIHtcbiAgICAgICAgcmV0dXJuIFtdO1xuICAgICAgfVxuICAgICAgaWYgKCFmcy5wYXRoRXhpc3RzU3luYyhmaWxlUGF0aCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihgVGhlIG1hcHBpbmcgZmlsZSAke2ZpbGVQYXRofSBkb2VzIG5vdCBleGlzdGApO1xuICAgICAgfVxuICAgICAgY29uc3QgZ3JvdXBzID0gcGFyc2VNYXBwaW5nR3JvdXBzKGZzLnJlYWRGaWxlU3luYyhmaWxlUGF0aCkudG9TdHJpbmcoJ3V0Zi04JykpO1xuXG4gICAgICByZXR1cm4gcmV2ZXJ0XG4gICAgICAgID8gZ3JvdXBzLm1hcCgoZ3JvdXApID0+ICh7XG4gICAgICAgICAgLi4uZ3JvdXAsXG4gICAgICAgICAgcmVzb3VyY2VzOiBPYmplY3QuZnJvbUVudHJpZXMoT2JqZWN0LmVudHJpZXMoZ3JvdXAucmVzb3VyY2VzID8/IHt9KS5tYXAoKFtzcmMsIGRzdF0pID0+IFtkc3QsIHNyY10pKSxcbiAgICAgICAgfSkpXG4gICAgICAgIDogZ3JvdXBzO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgc2VsZWN0U3RhY2tzRm9yTGlzdChwYXR0ZXJuczogc3RyaW5nW10pIHtcbiAgICBjb25zdCBhc3NlbWJseSA9IGF3YWl0IHRoaXMuYXNzZW1ibHkoKTtcbiAgICBjb25zdCBzdGFja3MgPSBhd2FpdCBhc3NlbWJseS5zZWxlY3RTdGFja3MoeyBwYXR0ZXJucyB9LCB7IGRlZmF1bHRCZWhhdmlvcjogRGVmYXVsdFNlbGVjdGlvbi5BbGxTdGFja3MgfSk7XG5cbiAgICAvLyBObyB2YWxpZGF0aW9uXG5cbiAgICByZXR1cm4gc3RhY2tzO1xuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBzZWxlY3RTdGFja3NGb3JEZXBsb3koXG4gICAgc2VsZWN0b3I6IFN0YWNrU2VsZWN0b3IsXG4gICAgZXhjbHVzaXZlbHk/OiBib29sZWFuLFxuICAgIGNhY2hlQ2xvdWRBc3NlbWJseT86IGJvb2xlYW4sXG4gICAgaWdub3JlTm9TdGFja3M/OiBib29sZWFuLFxuICApOiBQcm9taXNlPFN0YWNrQ29sbGVjdGlvbj4ge1xuICAgIGNvbnN0IGFzc2VtYmx5ID0gYXdhaXQgdGhpcy5hc3NlbWJseShjYWNoZUNsb3VkQXNzZW1ibHkpO1xuICAgIGNvbnN0IHN0YWNrcyA9IGF3YWl0IGFzc2VtYmx5LnNlbGVjdFN0YWNrcyhzZWxlY3Rvciwge1xuICAgICAgZXh0ZW5kOiBleGNsdXNpdmVseSA/IEV4dGVuZGVkU3RhY2tTZWxlY3Rpb24uTm9uZSA6IEV4dGVuZGVkU3RhY2tTZWxlY3Rpb24uVXBzdHJlYW0sXG4gICAgICBkZWZhdWx0QmVoYXZpb3I6IERlZmF1bHRTZWxlY3Rpb24uT25seVNpbmdsZSxcbiAgICAgIGlnbm9yZU5vU3RhY2tzLFxuICAgIH0pO1xuXG4gICAgdGhpcy52YWxpZGF0ZVN0YWNrc1NlbGVjdGVkKHN0YWNrcywgc2VsZWN0b3IucGF0dGVybnMpO1xuICAgIGF3YWl0IHRoaXMudmFsaWRhdGVTdGFja3Moc3RhY2tzKTtcblxuICAgIHJldHVybiBzdGFja3M7XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIHNlbGVjdFN0YWNrc0ZvckRpZmYoXG4gICAgc3RhY2tOYW1lczogc3RyaW5nW10sXG4gICAgZXhjbHVzaXZlbHk/OiBib29sZWFuLFxuICAgIGF1dG9WYWxpZGF0ZT86IGJvb2xlYW4sXG4gICk6IFByb21pc2U8U3RhY2tDb2xsZWN0aW9uPiB7XG4gICAgY29uc3QgYXNzZW1ibHkgPSBhd2FpdCB0aGlzLmFzc2VtYmx5KCk7XG5cbiAgICBjb25zdCBzZWxlY3RlZEZvckRpZmYgPSBhd2FpdCBhc3NlbWJseS5zZWxlY3RTdGFja3MoXG4gICAgICB7IHBhdHRlcm5zOiBzdGFja05hbWVzIH0sXG4gICAgICB7XG4gICAgICAgIGV4dGVuZDogZXhjbHVzaXZlbHkgPyBFeHRlbmRlZFN0YWNrU2VsZWN0aW9uLk5vbmUgOiBFeHRlbmRlZFN0YWNrU2VsZWN0aW9uLlVwc3RyZWFtLFxuICAgICAgICBkZWZhdWx0QmVoYXZpb3I6IERlZmF1bHRTZWxlY3Rpb24uTWFpbkFzc2VtYmx5LFxuICAgICAgfSxcbiAgICApO1xuXG4gICAgY29uc3QgYWxsU3RhY2tzID0gYXdhaXQgdGhpcy5zZWxlY3RTdGFja3NGb3JMaXN0KFtdKTtcbiAgICBjb25zdCBhdXRvVmFsaWRhdGVTdGFja3MgPSBhdXRvVmFsaWRhdGVcbiAgICAgID8gYWxsU3RhY2tzLmZpbHRlcigoYXJ0KSA9PiBhcnQudmFsaWRhdGVPblN5bnRoID8/IGZhbHNlKVxuICAgICAgOiBuZXcgU3RhY2tDb2xsZWN0aW9uKGFzc2VtYmx5LCBbXSk7XG5cbiAgICB0aGlzLnZhbGlkYXRlU3RhY2tzU2VsZWN0ZWQoc2VsZWN0ZWRGb3JEaWZmLmNvbmNhdChhdXRvVmFsaWRhdGVTdGFja3MpLCBzdGFja05hbWVzKTtcbiAgICBhd2FpdCB0aGlzLnZhbGlkYXRlU3RhY2tzKHNlbGVjdGVkRm9yRGlmZi5jb25jYXQoYXV0b1ZhbGlkYXRlU3RhY2tzKSk7XG5cbiAgICByZXR1cm4gc2VsZWN0ZWRGb3JEaWZmO1xuICB9XG5cbiAgcHJpdmF0ZSBhc3luYyBzZWxlY3RTdGFja3NGb3JEZXN0cm95KHNlbGVjdG9yOiBTdGFja1NlbGVjdG9yLCBleGNsdXNpdmVseT86IGJvb2xlYW4pIHtcbiAgICBjb25zdCBhc3NlbWJseSA9IGF3YWl0IHRoaXMuYXNzZW1ibHkoKTtcbiAgICBjb25zdCBzdGFja3MgPSBhd2FpdCBhc3NlbWJseS5zZWxlY3RTdGFja3Moc2VsZWN0b3IsIHtcbiAgICAgIGV4dGVuZDogZXhjbHVzaXZlbHkgPyBFeHRlbmRlZFN0YWNrU2VsZWN0aW9uLk5vbmUgOiBFeHRlbmRlZFN0YWNrU2VsZWN0aW9uLkRvd25zdHJlYW0sXG4gICAgICBkZWZhdWx0QmVoYXZpb3I6IERlZmF1bHRTZWxlY3Rpb24uT25seVNpbmdsZSxcbiAgICB9KTtcblxuICAgIC8vIE5vIHZhbGlkYXRpb25cblxuICAgIHJldHVybiBzdGFja3M7XG4gIH1cblxuICAvKipcbiAgICogVmFsaWRhdGUgdGhlIHN0YWNrcyBmb3IgZXJyb3JzIGFuZCB3YXJuaW5ncyBhY2NvcmRpbmcgdG8gdGhlIENMSSdzIGN1cnJlbnQgc2V0dGluZ3NcbiAgICovXG4gIHByaXZhdGUgYXN5bmMgdmFsaWRhdGVTdGFja3Moc3RhY2tzOiBTdGFja0NvbGxlY3Rpb24pIHtcbiAgICBjb25zdCBmYWlsQXQgPSB0aGlzLnZhbGlkYXRlTWV0YWRhdGFGYWlsQXQoKTtcbiAgICBhd2FpdCBzdGFja3MudmFsaWRhdGVNZXRhZGF0YShmYWlsQXQsIHN0YWNrTWV0YWRhdGFMb2dnZXIodGhpcy5pb0hvc3QuYXNJb0hlbHBlcigpLCB0aGlzLnByb3BzLnZlcmJvc2UpKTtcbiAgfVxuXG4gIHByaXZhdGUgdmFsaWRhdGVNZXRhZGF0YUZhaWxBdCgpOiAnd2FybicgfCAnZXJyb3InIHwgJ25vbmUnIHtcbiAgICBsZXQgZmFpbEF0OiAnd2FybicgfCAnZXJyb3InIHwgJ25vbmUnID0gJ2Vycm9yJztcbiAgICBpZiAodGhpcy5wcm9wcy5pZ25vcmVFcnJvcnMpIHtcbiAgICAgIGZhaWxBdCA9ICdub25lJztcbiAgICB9XG4gICAgaWYgKHRoaXMucHJvcHMuc3RyaWN0KSB7XG4gICAgICBmYWlsQXQgPSAnd2Fybic7XG4gICAgfVxuXG4gICAgcmV0dXJuIGZhaWxBdDtcbiAgfVxuXG4gIC8qKlxuICAgKiBWYWxpZGF0ZSB0aGF0IGlmIGEgdXNlciBzcGVjaWZpZWQgYSBzdGFjayBuYW1lIHRoZXJlIGV4aXN0cyBhdCBsZWFzdCAxIHN0YWNrIHNlbGVjdGVkXG4gICAqL1xuICBwcml2YXRlIHZhbGlkYXRlU3RhY2tzU2VsZWN0ZWQoc3RhY2tzOiBTdGFja0NvbGxlY3Rpb24sIHN0YWNrTmFtZXM6IHN0cmluZ1tdKSB7XG4gICAgaWYgKHN0YWNrTmFtZXMubGVuZ3RoICE9IDAgJiYgc3RhY2tzLnN0YWNrQ291bnQgPT0gMCkge1xuICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihgTm8gc3RhY2tzIG1hdGNoIHRoZSBuYW1lKHMpICR7c3RhY2tOYW1lc31gKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogU2VsZWN0IGEgc2luZ2xlIHN0YWNrIGJ5IGl0cyBuYW1lXG4gICAqL1xuICBwcml2YXRlIGFzeW5jIHNlbGVjdFNpbmdsZVN0YWNrQnlOYW1lKHN0YWNrTmFtZTogc3RyaW5nKSB7XG4gICAgY29uc3QgYXNzZW1ibHkgPSBhd2FpdCB0aGlzLmFzc2VtYmx5KCk7XG5cbiAgICBjb25zdCBzdGFja3MgPSBhd2FpdCBhc3NlbWJseS5zZWxlY3RTdGFja3MoXG4gICAgICB7IHBhdHRlcm5zOiBbc3RhY2tOYW1lXSB9LFxuICAgICAge1xuICAgICAgICBleHRlbmQ6IEV4dGVuZGVkU3RhY2tTZWxlY3Rpb24uTm9uZSxcbiAgICAgICAgZGVmYXVsdEJlaGF2aW9yOiBEZWZhdWx0U2VsZWN0aW9uLk5vbmUsXG4gICAgICB9LFxuICAgICk7XG5cbiAgICAvLyBDb3VsZCBoYXZlIGJlZW4gYSBnbG9iIHNvIGNoZWNrIHRoYXQgd2UgZXZhbHVhdGVkIHRvIGV4YWN0bHkgb25lXG4gICAgaWYgKHN0YWNrcy5zdGFja0NvdW50ID4gMSkge1xuICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihgVGhpcyBjb21tYW5kIHJlcXVpcmVzIGV4YWN0bHkgb25lIHN0YWNrIGFuZCB3ZSBtYXRjaGVkIG1vcmUgdGhhbiBvbmU6ICR7c3RhY2tzLnN0YWNrSWRzfWApO1xuICAgIH1cblxuICAgIHJldHVybiBhc3NlbWJseS5zdGFja0J5SWQoc3RhY2tzLmZpcnN0U3RhY2suaWQpO1xuICB9XG5cbiAgcHVibGljIGFzc2VtYmx5KGNhY2hlQ2xvdWRBc3NlbWJseT86IGJvb2xlYW4pOiBQcm9taXNlPENsb3VkQXNzZW1ibHk+IHtcbiAgICByZXR1cm4gdGhpcy5wcm9wcy5jbG91ZEV4ZWN1dGFibGUuc3ludGhlc2l6ZShjYWNoZUNsb3VkQXNzZW1ibHkpO1xuICB9XG5cbiAgcHJpdmF0ZSBwYXR0ZXJuc0FycmF5Rm9yV2F0Y2goXG4gICAgcGF0dGVybnM6IHN0cmluZyB8IHN0cmluZ1tdIHwgdW5kZWZpbmVkLFxuICAgIG9wdGlvbnM6IHsgcm9vdERpcjogc3RyaW5nOyByZXR1cm5Sb290RGlySWZFbXB0eTogYm9vbGVhbiB9LFxuICApOiBzdHJpbmdbXSB7XG4gICAgY29uc3QgcGF0dGVybnNBcnJheTogc3RyaW5nW10gPSBwYXR0ZXJucyAhPT0gdW5kZWZpbmVkID8gKEFycmF5LmlzQXJyYXkocGF0dGVybnMpID8gcGF0dGVybnMgOiBbcGF0dGVybnNdKSA6IFtdO1xuICAgIHJldHVybiBwYXR0ZXJuc0FycmF5Lmxlbmd0aCA+IDAgPyBwYXR0ZXJuc0FycmF5IDogb3B0aW9ucy5yZXR1cm5Sb290RGlySWZFbXB0eSA/IFtvcHRpb25zLnJvb3REaXJdIDogW107XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIGludm9rZURlcGxveUZyb21XYXRjaChcbiAgICBvcHRpb25zOiBXYXRjaE9wdGlvbnMsXG4gICAgY2xvdWRXYXRjaExvZ01vbml0b3I/OiBDbG91ZFdhdGNoTG9nRXZlbnRNb25pdG9yLFxuICApOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBkZXBsb3lPcHRpb25zOiBEZXBsb3lPcHRpb25zID0ge1xuICAgICAgLi4ub3B0aW9ucyxcbiAgICAgIHJlcXVpcmVBcHByb3ZhbDogUmVxdWlyZUFwcHJvdmFsLk5FVkVSLFxuICAgICAgLy8gaWYgJ3dhdGNoJyBpcyBjYWxsZWQgYnkgaW52b2tpbmcgJ2NkayBkZXBsb3kgLS13YXRjaCcsXG4gICAgICAvLyB3ZSBuZWVkIHRvIG1ha2Ugc3VyZSB0byBub3QgY2FsbCAnZGVwbG95JyB3aXRoICd3YXRjaCcgYWdhaW4sXG4gICAgICAvLyBhcyB0aGF0IHdvdWxkIGxlYWQgdG8gYSBjeWNsZVxuICAgICAgd2F0Y2g6IGZhbHNlLFxuICAgICAgY2xvdWRXYXRjaExvZ01vbml0b3IsXG4gICAgICBjYWNoZUNsb3VkQXNzZW1ibHk6IGZhbHNlLFxuICAgICAgZXh0cmFVc2VyQWdlbnQ6IGBjZGstd2F0Y2gvaG90c3dhcC0ke29wdGlvbnMuZGVwbG95bWVudE1ldGhvZD8ubWV0aG9kID09PSAnaG90c3dhcCcgPyAnb24nIDogJ29mZid9YCxcbiAgICAgIGNvbmN1cnJlbmN5OiBvcHRpb25zLmNvbmN1cnJlbmN5LFxuICAgIH07XG5cbiAgICB0cnkge1xuICAgICAgYXdhaXQgdGhpcy5kZXBsb3koZGVwbG95T3B0aW9ucyk7XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBqdXN0IGNvbnRpbnVlIC0gZGVwbG95IHdpbGwgc2hvdyB0aGUgZXJyb3JcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogUmVtb3ZlIHRoZSBhc3NldCBwdWJsaXNoaW5nIGFuZCBidWlsZGluZyBmcm9tIHRoZSB3b3JrIGdyYXBoIGZvciBhc3NldHMgdGhhdCBhcmUgYWxyZWFkeSBpbiBwbGFjZVxuICAgKi9cbiAgcHJpdmF0ZSBhc3luYyByZW1vdmVQdWJsaXNoZWRBc3NldHMoZ3JhcGg6IFdvcmtHcmFwaCwgb3B0aW9uczogRGVwbG95T3B0aW9ucykge1xuICAgIGF3YWl0IGdyYXBoLnJlbW92ZVVubmVjZXNzYXJ5QXNzZXRzKGFzc2V0Tm9kZSA9PiB0aGlzLnByb3BzLmRlcGxveW1lbnRzLmlzU2luZ2xlQXNzZXRQdWJsaXNoZWQoYXNzZXROb2RlLmFzc2V0TWFuaWZlc3QsIGFzc2V0Tm9kZS5hc3NldCwge1xuICAgICAgc3RhY2s6IGFzc2V0Tm9kZS5wYXJlbnRTdGFjayxcbiAgICAgIHJvbGVBcm46IG9wdGlvbnMucm9sZUFybixcbiAgICAgIHN0YWNrTmFtZTogYXNzZXROb2RlLnBhcmVudFN0YWNrLnN0YWNrTmFtZSxcbiAgICB9KSk7XG4gIH1cbn1cblxuLyoqXG4gKiBQcmludCBhIHNlcmlhbGl6ZWQgb2JqZWN0IChZQU1MIG9yIEpTT04pIHRvIHN0ZG91dC5cbiAqL1xuYXN5bmMgZnVuY3Rpb24gcHJpbnRTZXJpYWxpemVkT2JqZWN0KGlvSGVscGVyOiBJb0hlbHBlciwgb2JqOiBhbnksIGpzb246IGJvb2xlYW4pIHtcbiAgYXdhaXQgaW9IZWxwZXIuZGVmYXVsdHMucmVzdWx0KHNlcmlhbGl6ZVN0cnVjdHVyZShvYmosIGpzb24pKTtcbn1cblxuLyoqXG4gKiBPcHRpb25zIGZvciB0aGUgZGlmZiBjb21tYW5kXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgRGlmZk9wdGlvbnMge1xuICAvKipcbiAgICogU3RhY2sgbmFtZXMgdG8gZGlmZlxuICAgKi9cbiAgcmVhZG9ubHkgc3RhY2tOYW1lczogc3RyaW5nW107XG5cbiAgLyoqXG4gICAqIE5hbWUgb2YgdGhlIHRvb2xraXQgc3RhY2ssIGlmIG5vdCB0aGUgZGVmYXVsdCBuYW1lXG4gICAqXG4gICAqIEBkZWZhdWx0ICdDREtUb29sa2l0J1xuICAgKi9cbiAgcmVhZG9ubHkgdG9vbGtpdFN0YWNrTmFtZT86IHN0cmluZztcblxuICAvKipcbiAgICogT25seSBzZWxlY3QgdGhlIGdpdmVuIHN0YWNrXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBleGNsdXNpdmVseT86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFVzZWQgYSB0ZW1wbGF0ZSBmcm9tIGRpc2sgaW5zdGVhZCBvZiBmcm9tIHRoZSBzZXJ2ZXJcbiAgICpcbiAgICogQGRlZmF1bHQgVXNlIGZyb20gdGhlIHNlcnZlclxuICAgKi9cbiAgcmVhZG9ubHkgdGVtcGxhdGVQYXRoPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBTdHJpY3QgZGlmZiBtb2RlXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBzdHJpY3Q/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBIb3cgbWFueSBsaW5lcyBvZiBjb250ZXh0IHRvIHNob3cgaW4gdGhlIGRpZmZcbiAgICpcbiAgICogQGRlZmF1bHQgM1xuICAgKi9cbiAgcmVhZG9ubHkgY29udGV4dExpbmVzPzogbnVtYmVyO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIGZhaWwgd2l0aCBleGl0IGNvZGUgMSBpbiBjYXNlIG9mIGRpZmZcbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGZhaWw/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBPbmx5IHJ1biBkaWZmIG9uIGJyb2FkZW5lZCBzZWN1cml0eSBjaGFuZ2VzXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBzZWN1cml0eU9ubHk/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIHJ1biB0aGUgZGlmZiBhZ2FpbnN0IHRoZSB0ZW1wbGF0ZSBhZnRlciB0aGUgQ2xvdWRGb3JtYXRpb24gVHJhbnNmb3JtcyBpbnNpZGUgaXQgaGF2ZSBiZWVuIGV4ZWN1dGVkXG4gICAqIChhcyBvcHBvc2VkIHRvIHRoZSBvcmlnaW5hbCB0ZW1wbGF0ZSwgdGhlIGRlZmF1bHQsIHdoaWNoIGNvbnRhaW5zIHRoZSB1bnByb2Nlc3NlZCBUcmFuc2Zvcm1zKS5cbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGNvbXBhcmVBZ2FpbnN0UHJvY2Vzc2VkVGVtcGxhdGU/OiBib29sZWFuO1xuXG4gIC8qXG4gICAqIFJ1biBkaWZmIGluIHF1aWV0IG1vZGUgd2l0aG91dCBwcmludGluZyB0aGUgZGlmZiBzdGF0dXNlc1xuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgcXVpZXQ/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBBZGRpdGlvbmFsIHBhcmFtZXRlcnMgZm9yIENsb3VkRm9ybWF0aW9uIGF0IGRpZmYgdGltZSwgdXNlZCB0byBjcmVhdGUgYSBjaGFuZ2Ugc2V0XG4gICAqIEBkZWZhdWx0IHt9XG4gICAqL1xuICByZWFkb25seSBwYXJhbWV0ZXJzPzogeyBbbmFtZTogc3RyaW5nXTogc3RyaW5nIHwgdW5kZWZpbmVkIH07XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgb3Igbm90IHRvIGNyZWF0ZSwgYW5hbHl6ZSwgYW5kIHN1YnNlcXVlbnRseSBkZWxldGUgYSBjaGFuZ2VzZXRcbiAgICpcbiAgICogQGRlZmF1bHQgdHJ1ZVxuICAgKi9cbiAgcmVhZG9ubHkgY2hhbmdlU2V0PzogYm9vbGVhbjtcblxuICAvKipcbiAgICogV2hldGhlciBvciBub3QgdGhlIGNoYW5nZSBzZXQgaW1wb3J0cyByZXNvdXJjZXMgdGhhdCBhbHJlYWR5IGV4aXN0LlxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgaW1wb3J0RXhpc3RpbmdSZXNvdXJjZXM/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIGluY2x1ZGUgcmVzb3VyY2UgbW92ZXMgaW4gdGhlIGRpZmZcbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGluY2x1ZGVNb3Zlcz86IGJvb2xlYW47XG59XG5cbmludGVyZmFjZSBDZm5EZXBsb3lPcHRpb25zIHtcbiAgLyoqXG4gICAqIENyaXRlcmlhIGZvciBzZWxlY3Rpbmcgc3RhY2tzIHRvIGRlcGxveVxuICAgKi9cbiAgc2VsZWN0b3I6IFN0YWNrU2VsZWN0b3I7XG5cbiAgLyoqXG4gICAqIE5hbWUgb2YgdGhlIHRvb2xraXQgc3RhY2sgdG8gdXNlL2RlcGxveVxuICAgKlxuICAgKiBAZGVmYXVsdCBDREtUb29sa2l0XG4gICAqL1xuICB0b29sa2l0U3RhY2tOYW1lPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBSb2xlIHRvIHBhc3MgdG8gQ2xvdWRGb3JtYXRpb24gZm9yIGRlcGxveW1lbnRcbiAgICovXG4gIHJvbGVBcm4/OiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIE9wdGlvbmFsIG5hbWUgdG8gdXNlIGZvciB0aGUgQ2xvdWRGb3JtYXRpb24gY2hhbmdlIHNldC5cbiAgICogSWYgbm90IHByb3ZpZGVkLCBhIG5hbWUgd2lsbCBiZSBnZW5lcmF0ZWQgYXV0b21hdGljYWxseS5cbiAgICpcbiAgICogQGRlcHJlY2F0ZWQgVXNlICdkZXBsb3ltZW50TWV0aG9kJyBpbnN0ZWFkXG4gICAqL1xuICBjaGFuZ2VTZXROYW1lPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIGV4ZWN1dGUgdGhlIENoYW5nZVNldFxuICAgKiBOb3QgcHJvdmlkaW5nIGBleGVjdXRlYCBwYXJhbWV0ZXIgd2lsbCByZXN1bHQgaW4gZXhlY3V0aW9uIG9mIENoYW5nZVNldFxuICAgKlxuICAgKiBAZGVmYXVsdCB0cnVlXG4gICAqIEBkZXByZWNhdGVkIFVzZSAnZGVwbG95bWVudE1ldGhvZCcgaW5zdGVhZFxuICAgKi9cbiAgZXhlY3V0ZT86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIERlcGxveW1lbnQgbWV0aG9kXG4gICAqL1xuICByZWFkb25seSBkZXBsb3ltZW50TWV0aG9kPzogRGVwbG95bWVudE1ldGhvZDtcblxuICAvKipcbiAgICogRGlzcGxheSBtb2RlIGZvciBzdGFjayBkZXBsb3ltZW50IHByb2dyZXNzLlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIFN0YWNrQWN0aXZpdHlQcm9ncmVzcy5CYXIgLSBzdGFjayBldmVudHMgd2lsbCBiZSBkaXNwbGF5ZWQgZm9yXG4gICAqICAgdGhlIHJlc291cmNlIGN1cnJlbnRseSBiZWluZyBkZXBsb3llZC5cbiAgICovXG4gIHByb2dyZXNzPzogU3RhY2tBY3Rpdml0eVByb2dyZXNzO1xuXG4gIC8qKlxuICAgKiBSb2xsYmFjayBmYWlsZWQgZGVwbG95bWVudHNcbiAgICpcbiAgICogQGRlZmF1bHQgdHJ1ZVxuICAgKi9cbiAgcmVhZG9ubHkgcm9sbGJhY2s/OiBib29sZWFuO1xufVxuXG5pbnRlcmZhY2UgV2F0Y2hPcHRpb25zIGV4dGVuZHMgT21pdDxDZm5EZXBsb3lPcHRpb25zLCAnZXhlY3V0ZSc+IHtcbiAgLyoqXG4gICAqIE9ubHkgc2VsZWN0IHRoZSBnaXZlbiBzdGFja1xuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgZXhjbHVzaXZlbHk/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBSZXVzZSB0aGUgYXNzZXRzIHdpdGggdGhlIGdpdmVuIGFzc2V0IElEc1xuICAgKi9cbiAgcmV1c2VBc3NldHM/OiBzdHJpbmdbXTtcblxuICAvKipcbiAgICogQWx3YXlzIGRlcGxveSwgZXZlbiBpZiB0ZW1wbGF0ZXMgYXJlIGlkZW50aWNhbC5cbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIGZvcmNlPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogVGhlIGV4dHJhIHN0cmluZyB0byBhcHBlbmQgdG8gdGhlIFVzZXItQWdlbnQgaGVhZGVyIHdoZW4gcGVyZm9ybWluZyBBV1MgU0RLIGNhbGxzLlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIG5vdGhpbmcgZXh0cmEgaXMgYXBwZW5kZWQgdG8gdGhlIFVzZXItQWdlbnQgaGVhZGVyXG4gICAqL1xuICByZWFkb25seSBleHRyYVVzZXJBZ2VudD86IHN0cmluZztcblxuICAvKipcbiAgICogV2hldGhlciB0byBzaG93IENsb3VkV2F0Y2ggbG9ncyBmb3IgaG90c3dhcHBlZCByZXNvdXJjZXNcbiAgICogbG9jYWxseSBpbiB0aGUgdXNlcnMgdGVybWluYWxcbiAgICpcbiAgICogQGRlZmF1bHQgLSBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgdHJhY2VMb2dzPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogTWF4aW11bSBudW1iZXIgb2Ygc2ltdWx0YW5lb3VzIGRlcGxveW1lbnRzIChkZXBlbmRlbmN5IHBlcm1pdHRpbmcpIHRvIGV4ZWN1dGUuXG4gICAqIFRoZSBkZWZhdWx0IGlzICcxJywgd2hpY2ggZXhlY3V0ZXMgYWxsIGRlcGxveW1lbnRzIHNlcmlhbGx5LlxuICAgKlxuICAgKiBAZGVmYXVsdCAxXG4gICAqL1xuICByZWFkb25seSBjb25jdXJyZW5jeT86IG51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBEZXBsb3lPcHRpb25zIGV4dGVuZHMgQ2ZuRGVwbG95T3B0aW9ucywgV2F0Y2hPcHRpb25zIHtcbiAgLyoqXG4gICAqIEFSTnMgb2YgU05TIHRvcGljcyB0aGF0IENsb3VkRm9ybWF0aW9uIHdpbGwgbm90aWZ5IHdpdGggc3RhY2sgcmVsYXRlZCBldmVudHNcbiAgICovXG4gIG5vdGlmaWNhdGlvbkFybnM/OiBzdHJpbmdbXTtcblxuICAvKipcbiAgICogV2hhdCBraW5kIG9mIHNlY3VyaXR5IGNoYW5nZXMgcmVxdWlyZSBhcHByb3ZhbFxuICAgKlxuICAgKiBAZGVmYXVsdCBSZXF1aXJlQXBwcm92YWwuQnJvYWRlbmluZ1xuICAgKi9cbiAgcmVxdWlyZUFwcHJvdmFsPzogUmVxdWlyZUFwcHJvdmFsO1xuXG4gIC8qKlxuICAgKiBUYWdzIHRvIHBhc3MgdG8gQ2xvdWRGb3JtYXRpb24gZm9yIGRlcGxveW1lbnRcbiAgICovXG4gIHRhZ3M/OiBUYWdbXTtcblxuICAvKipcbiAgICogQWRkaXRpb25hbCBwYXJhbWV0ZXJzIGZvciBDbG91ZEZvcm1hdGlvbiBhdCBkZXBsb3kgdGltZVxuICAgKiBAZGVmYXVsdCB7fVxuICAgKi9cbiAgcGFyYW1ldGVycz86IHsgW25hbWU6IHN0cmluZ106IHN0cmluZyB8IHVuZGVmaW5lZCB9O1xuXG4gIC8qKlxuICAgKiBVc2UgcHJldmlvdXMgdmFsdWVzIGZvciB1bnNwZWNpZmllZCBwYXJhbWV0ZXJzXG4gICAqXG4gICAqIElmIG5vdCBzZXQsIGFsbCBwYXJhbWV0ZXJzIG11c3QgYmUgc3BlY2lmaWVkIGZvciBldmVyeSBkZXBsb3ltZW50LlxuICAgKlxuICAgKiBAZGVmYXVsdCB0cnVlXG4gICAqL1xuICB1c2VQcmV2aW91c1BhcmFtZXRlcnM/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBQYXRoIHRvIGZpbGUgd2hlcmUgc3RhY2sgb3V0cHV0cyB3aWxsIGJlIHdyaXR0ZW4gYWZ0ZXIgYSBzdWNjZXNzZnVsIGRlcGxveSBhcyBKU09OXG4gICAqIEBkZWZhdWx0IC0gT3V0cHV0cyBhcmUgbm90IHdyaXR0ZW4gdG8gYW55IGZpbGVcbiAgICovXG4gIG91dHB1dHNGaWxlPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHdlIGFyZSBvbiBhIENJIHN5c3RlbVxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgY2k/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRoaXMgJ2RlcGxveScgY29tbWFuZCBzaG91bGQgYWN0dWFsbHkgZGVsZWdhdGUgdG8gdGhlICd3YXRjaCcgY29tbWFuZC5cbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IHdhdGNoPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogV2hldGhlciB3ZSBzaG91bGQgY2FjaGUgdGhlIENsb3VkIEFzc2VtYmx5IGFmdGVyIHRoZSBmaXJzdCB0aW1lIGl0IGhhcyBiZWVuIHN5bnRoZXNpemVkLlxuICAgKiBUaGUgZGVmYXVsdCBpcyAndHJ1ZScsIHdlIG9ubHkgZG9uJ3Qgd2FudCB0byBkbyBpdCBpbiBjYXNlIHRoZSBkZXBsb3ltZW50IGlzIHRyaWdnZXJlZCBieVxuICAgKiAnY2RrIHdhdGNoJy5cbiAgICpcbiAgICogQGRlZmF1bHQgdHJ1ZVxuICAgKi9cbiAgcmVhZG9ubHkgY2FjaGVDbG91ZEFzc2VtYmx5PzogYm9vbGVhbjtcblxuICAvKipcbiAgICogQWxsb3dzIGFkZGluZyBDbG91ZFdhdGNoIGxvZyBncm91cHMgdG8gdGhlIGxvZyBtb25pdG9yIHZpYVxuICAgKiBjbG91ZFdhdGNoTG9nTW9uaXRvci5zZXRMb2dHcm91cHMoKTtcbiAgICpcbiAgICogQGRlZmF1bHQgLSBub3QgbW9uaXRvcmluZyBDbG91ZFdhdGNoIGxvZ3NcbiAgICovXG4gIHJlYWRvbmx5IGNsb3VkV2F0Y2hMb2dNb25pdG9yPzogQ2xvdWRXYXRjaExvZ0V2ZW50TW9uaXRvcjtcblxuICAvKipcbiAgICogTWF4aW11bSBudW1iZXIgb2Ygc2ltdWx0YW5lb3VzIGRlcGxveW1lbnRzIChkZXBlbmRlbmN5IHBlcm1pdHRpbmcpIHRvIGV4ZWN1dGUuXG4gICAqIFRoZSBkZWZhdWx0IGlzICcxJywgd2hpY2ggZXhlY3V0ZXMgYWxsIGRlcGxveW1lbnRzIHNlcmlhbGx5LlxuICAgKlxuICAgKiBAZGVmYXVsdCAxXG4gICAqL1xuICByZWFkb25seSBjb25jdXJyZW5jeT86IG51bWJlcjtcblxuICAvKipcbiAgICogQnVpbGQvcHVibGlzaCBhc3NldHMgZm9yIGEgc2luZ2xlIHN0YWNrIGluIHBhcmFsbGVsXG4gICAqXG4gICAqIEluZGVwZW5kZW50IG9mIHdoZXRoZXIgc3RhY2tzIGFyZSBiZWluZyBkb25lIGluIHBhcmFsbGVsIG9yIG5vLlxuICAgKlxuICAgKiBAZGVmYXVsdCB0cnVlXG4gICAqL1xuICByZWFkb25seSBhc3NldFBhcmFsbGVsaXNtPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogV2hlbiB0byBidWlsZCBhc3NldHNcbiAgICpcbiAgICogVGhlIGRlZmF1bHQgaXMgdGhlIERvY2tlci1mcmllbmRseSBkZWZhdWx0LlxuICAgKlxuICAgKiBAZGVmYXVsdCBBc3NldEJ1aWxkVGltZS5BTExfQkVGT1JFX0RFUExPWVxuICAgKi9cbiAgcmVhZG9ubHkgYXNzZXRCdWlsZFRpbWU/OiBBc3NldEJ1aWxkVGltZTtcblxuICAvKipcbiAgICogV2hldGhlciB0byBkZXBsb3kgaWYgdGhlIGFwcCBjb250YWlucyBubyBzdGFja3MuXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBpZ25vcmVOb1N0YWNrcz86IGJvb2xlYW47XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgUm9sbGJhY2tPcHRpb25zIHtcbiAgLyoqXG4gICAqIENyaXRlcmlhIGZvciBzZWxlY3Rpbmcgc3RhY2tzIHRvIGRlcGxveVxuICAgKi9cbiAgcmVhZG9ubHkgc2VsZWN0b3I6IFN0YWNrU2VsZWN0b3I7XG5cbiAgLyoqXG4gICAqIE5hbWUgb2YgdGhlIHRvb2xraXQgc3RhY2sgdG8gdXNlL2RlcGxveVxuICAgKlxuICAgKiBAZGVmYXVsdCBDREtUb29sa2l0XG4gICAqL1xuICByZWFkb25seSB0b29sa2l0U3RhY2tOYW1lPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBSb2xlIHRvIHBhc3MgdG8gQ2xvdWRGb3JtYXRpb24gZm9yIGRlcGxveW1lbnRcbiAgICpcbiAgICogQGRlZmF1bHQgLSBEZWZhdWx0IHN0YWNrIHJvbGVcbiAgICovXG4gIHJlYWRvbmx5IHJvbGVBcm4/OiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gZm9yY2UgdGhlIHJvbGxiYWNrIG9yIG5vdFxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgZm9yY2U/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBMb2dpY2FsIElEcyBvZiByZXNvdXJjZXMgdG8gb3JwaGFuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTm8gb3JwaGFuaW5nXG4gICAqL1xuICByZWFkb25seSBvcnBoYW5Mb2dpY2FsSWRzPzogc3RyaW5nW107XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gdmFsaWRhdGUgdGhlIHZlcnNpb24gb2YgdGhlIGJvb3RzdHJhcCBzdGFjayBwZXJtaXNzaW9uc1xuICAgKlxuICAgKiBAZGVmYXVsdCB0cnVlXG4gICAqL1xuICByZWFkb25seSB2YWxpZGF0ZUJvb3RzdHJhcFN0YWNrVmVyc2lvbj86IGJvb2xlYW47XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgSW1wb3J0T3B0aW9ucyBleHRlbmRzIENmbkRlcGxveU9wdGlvbnMge1xuICAvKipcbiAgICogQnVpbGQgYSBwaHlzaWNhbCByZXNvdXJjZSBtYXBwaW5nIGFuZCB3cml0ZSBpdCB0byB0aGUgZ2l2ZW4gZmlsZSwgd2l0aG91dCBwZXJmb3JtaW5nIHRoZSBhY3R1YWwgaW1wb3J0IG9wZXJhdGlvblxuICAgKlxuICAgKiBAZGVmYXVsdCAtIE5vIGZpbGVcbiAgICovXG5cbiAgcmVhZG9ubHkgcmVjb3JkUmVzb3VyY2VNYXBwaW5nPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBQYXRoIHRvIGEgZmlsZSB3aXRoIHRoZSBwaHlzaWNhbCByZXNvdXJjZSBtYXBwaW5nIHRvIENESyBjb25zdHJ1Y3RzIGluIEpTT04gZm9ybWF0XG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTm8gbWFwcGluZyBmaWxlXG4gICAqL1xuICByZWFkb25seSByZXNvdXJjZU1hcHBpbmdGaWxlPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBBbGxvdyBub24tYWRkaXRpb24gY2hhbmdlcyB0byB0aGUgdGVtcGxhdGVcbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGZvcmNlPzogYm9vbGVhbjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBEZXN0cm95T3B0aW9ucyB7XG4gIC8qKlxuICAgKiBDcml0ZXJpYSBmb3Igc2VsZWN0aW5nIHN0YWNrcyB0byBkZXBsb3lcbiAgICovXG4gIHNlbGVjdG9yOiBTdGFja1NlbGVjdG9yO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIGV4Y2x1ZGUgc3RhY2tzIHRoYXQgZGVwZW5kIG9uIHRoZSBzdGFja3MgdG8gYmUgZGVsZXRlZFxuICAgKi9cbiAgZXhjbHVzaXZlbHk6IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gc2tpcCBwcm9tcHRpbmcgZm9yIGNvbmZpcm1hdGlvblxuICAgKi9cbiAgZm9yY2U6IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFRoZSBhcm4gb2YgdGhlIElBTSByb2xlIHRvIHVzZVxuICAgKi9cbiAgcm9sZUFybj86IHN0cmluZztcblxuICAvKipcbiAgICogV2hldGhlciB0aGUgZGVzdHJveSByZXF1ZXN0IGNhbWUgZnJvbSBhIGRlcGxveS5cbiAgICovXG4gIGZyb21EZXBsb3k/OiBib29sZWFuO1xufVxuXG4vKipcbiAqIE9wdGlvbnMgZm9yIHRoZSBnYXJiYWdlIGNvbGxlY3Rpb25cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBHYXJiYWdlQ29sbGVjdGlvbk9wdGlvbnMge1xuICAvKipcbiAgICogVGhlIGFjdGlvbiB0byBwZXJmb3JtLlxuICAgKlxuICAgKiBAZGVmYXVsdCAnZnVsbCdcbiAgICovXG4gIHJlYWRvbmx5IGFjdGlvbjogJ3ByaW50JyB8ICd0YWcnIHwgJ2RlbGV0ZS10YWdnZWQnIHwgJ2Z1bGwnO1xuXG4gIC8qKlxuICAgKiBUaGUgdHlwZSBvZiB0aGUgYXNzZXRzIHRvIGJlIGdhcmJhZ2UgY29sbGVjdGVkLlxuICAgKlxuICAgKiBAZGVmYXVsdCAnYWxsJ1xuICAgKi9cbiAgcmVhZG9ubHkgdHlwZTogJ3MzJyB8ICdlY3InIHwgJ2FsbCc7XG5cbiAgLyoqXG4gICAqIEVsYXBzZWQgdGltZSBiZXR3ZWVuIGFuIGFzc2V0IGJlaW5nIG1hcmtlZCBhcyBpc29sYXRlZCBhbmQgYWN0dWFsbHkgZGVsZXRlZC5cbiAgICpcbiAgICogQGRlZmF1bHQgMFxuICAgKi9cbiAgcmVhZG9ubHkgcm9sbGJhY2tCdWZmZXJEYXlzOiBudW1iZXI7XG5cbiAgLyoqXG4gICAqIFJlZnVzZSBkZWxldGlvbiBvZiBhbnkgYXNzZXRzIHlvdW5nZXIgdGhhbiB0aGlzIG51bWJlciBvZiBkYXlzLlxuICAgKi9cbiAgcmVhZG9ubHkgY3JlYXRlZEJ1ZmZlckRheXM6IG51bWJlcjtcblxuICAvKipcbiAgICogVGhlIHN0YWNrIG5hbWUgb2YgdGhlIGJvb3RzdHJhcCBzdGFjay5cbiAgICpcbiAgICogQGRlZmF1bHQgREVGQVVMVF9UT09MS0lUX1NUQUNLX05BTUVcbiAgICovXG4gIHJlYWRvbmx5IGJvb3RzdHJhcFN0YWNrTmFtZT86IHN0cmluZztcblxuICAvKipcbiAgICogU2tpcHMgdGhlIHByb21wdCBiZWZvcmUgYWN0dWFsIGRlbGV0aW9uIGJlZ2luc1xuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgY29uZmlybT86IGJvb2xlYW47XG59XG5leHBvcnQgaW50ZXJmYWNlIE1pZ3JhdGVPcHRpb25zIHtcbiAgLyoqXG4gICAqIFRoZSBuYW1lIGFzc2lnbmVkIHRvIHRoZSBnZW5lcmF0ZWQgc3RhY2suIFRoaXMgaXMgYWxzbyB1c2VkIHRvIGdldFxuICAgKiB0aGUgc3RhY2sgZnJvbSB0aGUgdXNlcidzIGFjY291bnQgaWYgYC0tZnJvbS1zdGFja2AgaXMgdXNlZC5cbiAgICovXG4gIHJlYWRvbmx5IHN0YWNrTmFtZTogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBUaGUgdGFyZ2V0IGxhbmd1YWdlIGZvciB0aGUgZ2VuZXJhdGVkIHRoZSBDREsgYXBwLlxuICAgKlxuICAgKiBAZGVmYXVsdCB0eXBlc2NyaXB0XG4gICAqL1xuICByZWFkb25seSBsYW5ndWFnZT86IHN0cmluZztcblxuICAvKipcbiAgICogVGhlIGxvY2FsIHBhdGggb2YgdGhlIHRlbXBsYXRlIHVzZWQgdG8gZ2VuZXJhdGUgdGhlIENESyBhcHAuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTG9jYWwgcGF0aCBpcyBub3QgdXNlZCBmb3IgdGhlIHRlbXBsYXRlIHNvdXJjZS5cbiAgICovXG4gIHJlYWRvbmx5IGZyb21QYXRoPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIGdldCB0aGUgdGVtcGxhdGUgZnJvbSBhbiBleGlzdGluZyBDbG91ZEZvcm1hdGlvbiBzdGFjay5cbiAgICpcbiAgICogQGRlZmF1bHQgZmFsc2VcbiAgICovXG4gIHJlYWRvbmx5IGZyb21TdGFjaz86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFRoZSBvdXRwdXQgcGF0aCBhdCB3aGljaCB0byBjcmVhdGUgdGhlIENESyBhcHAuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gVGhlIGN1cnJlbnQgZGlyZWN0b3J5XG4gICAqL1xuICByZWFkb25seSBvdXRwdXRQYXRoPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBUaGUgYWNjb3VudCBmcm9tIHdoaWNoIHRvIHJldHJpZXZlIHRoZSB0ZW1wbGF0ZSBvZiB0aGUgQ2xvdWRGb3JtYXRpb24gc3RhY2suXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gVXNlcyB0aGUgYWNjb3VudCBmb3IgdGhlIGNyZWRlbnRpYWxzIGluIHVzZSBieSB0aGUgdXNlci5cbiAgICovXG4gIHJlYWRvbmx5IGFjY291bnQ/OiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSByZWdpb24gZnJvbSB3aGljaCB0byByZXRyaWV2ZSB0aGUgdGVtcGxhdGUgb2YgdGhlIENsb3VkRm9ybWF0aW9uIHN0YWNrLlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIFVzZXMgdGhlIGRlZmF1bHQgcmVnaW9uIGZvciB0aGUgY3JlZGVudGlhbHMgaW4gdXNlIGJ5IHRoZSB1c2VyLlxuICAgKi9cbiAgcmVhZG9ubHkgcmVnaW9uPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBGaWx0ZXJpbmcgY3JpdGVyaWEgdXNlZCB0byBzZWxlY3QgdGhlIHJlc291cmNlcyB0byBiZSBpbmNsdWRlZCBpbiB0aGUgZ2VuZXJhdGVkIENESyBhcHAuXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gSW5jbHVkZSBhbGwgcmVzb3VyY2VzXG4gICAqL1xuICByZWFkb25seSBmaWx0ZXI/OiBzdHJpbmdbXTtcblxuICAvKipcbiAgICogV2hldGhlciB0byBpbml0aWF0ZSBhIG5ldyBhY2NvdW50IHNjYW4gZm9yIGdlbmVyYXRpbmcgdGhlIENESyBhcHAuXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBmcm9tU2Nhbj86IEZyb21TY2FuO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIHppcCB0aGUgZ2VuZXJhdGVkIGNkayBhcHAgZm9sZGVyLlxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgY29tcHJlc3M/OiBib29sZWFuO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIFJlZmFjdG9yT3B0aW9ucyB7XG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIG9ubHkgc2hvdyB0aGUgcHJvcG9zZWQgcmVmYWN0b3IsIHdpdGhvdXQgYXBwbHlpbmcgaXRcbiAgICovXG4gIHJlYWRvbmx5IGRyeVJ1bjogYm9vbGVhbjtcblxuICAvKipcbiAgICogVGhlIGFic29sdXRlIHBhdGggdG8gYSBmaWxlIHRoYXQgY29udGFpbnMgb3ZlcnJpZGVzIHRvIHRoZSBtYXBwaW5nc1xuICAgKiBjb21wdXRlZCBieSB0aGUgQ0xJLiBUaGlzIGZpbGUgc2hvdWxkIGNvbnRhaW4gYSBKU09OIG9iamVjdCB3aXRoXG4gICAqIHRoZSBmb2xsb3dpbmcgZm9ybWF0OlxuICAgKlxuICAgKiAgICAge1xuICAgKiAgICAgICBcImVudmlyb25tZW50c1wiOiBbXG4gICAqICAgICAgICAge1xuICAgKiAgICAgICAgICAgXCJhY2NvdW50XCI6IFwiMTIzNDU2Nzg5MDEyXCIsXG4gICAqICAgICAgICAgICBcInJlZ2lvblwiOiBcInVzLWVhc3QtMVwiLFxuICAgKiAgICAgICAgICAgXCJyZXNvdXJjZXNcIjoge1xuICAgKiAgICAgICAgICAgICBcIkZvby5PbGROYW1lXCI6IFwiQmFyLk5ld05hbWVcIixcbiAgICogICAgICAgICAgIH1cbiAgICogICAgICAgICB9LFxuICAgKiAgICAgICBdXG4gICAqICAgICB9XG4gICAqXG4gICAqIHdoZXJlIG1hcHBpbmdzIGFyZSBncm91cGVkIGJ5IGVudmlyb25tZW50LiBUaGUgYHJlc291cmNlc2Agb2JqZWN0IGNvbnRhaW5zXG4gICAqIGEgbWFwcGluZyB3aGVyZSBlYWNoIGtleSBpcyB0aGUgc291cmNlIGxvY2F0aW9uIGFuZCB0aGUgdmFsdWUgaXMgdGhlXG4gICAqIGRlc3RpbmF0aW9uIGxvY2F0aW9uLiBMb2NhdGlvbnMgbXVzdCBiZSBpbiB0aGUgZm9ybWF0IGBTdGFja05hbWUuTG9naWNhbElkYC5cbiAgICogVGhlIHNvdXJjZSBtdXN0IHJlZmVyIHRvIGEgbG9jYXRpb24gd2hlcmUgdGhlcmUgaXMgYSByZXNvdXJjZSBjdXJyZW50bHlcbiAgICogZGVwbG95ZWQsIHdoaWxlIHRoZSBkZXN0aW5hdGlvbiBtdXN0IHJlZmVyIHRvIGEgbG9jYXRpb24gdGhhdCBpcyBub3QgYWxyZWFkeVxuICAgKiBvY2N1cGllZCBieSBhbnkgcmVzb3VyY2UuXG4gICAqL1xuICBvdmVycmlkZUZpbGU/OiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIE1vZGlmaWVzIHRoZSBiZWhhdmlvciBvZiB0aGUgYG92ZXJyaWRlRmlsZWAgb3B0aW9uIGJ5IHN3YXBwaW5nIHNvdXJjZSBhbmRcbiAgICogZGVzdGluYXRpb24gbG9jYXRpb25zLiBUaGlzIGlzIHVzZWZ1bCB3aGVuIHlvdSB3YW50IHRvIHVuZG8gYSByZWZhY3RvclxuICAgKiB0aGF0IHdhcyBwcmV2aW91c2x5IGFwcGxpZWQuXG4gICAqL1xuICByZXZlcnQ/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRvIGRvIHRoZSByZWZhY3RvciB3aXRob3V0IHByb21wdGluZyB0aGUgdXNlciBmb3IgY29uZmlybWF0aW9uLlxuICAgKi9cbiAgZm9yY2U/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBDcml0ZXJpYSBmb3Igc2VsZWN0aW5nIHN0YWNrcyB0byBjb21wYXJlIHdpdGggdGhlIGRlcGxveWVkIHN0YWNrcyBpbiB0aGVcbiAgICogdGFyZ2V0IGVudmlyb25tZW50LlxuICAgKi9cbiAgc3RhY2tzPzogU3RhY2tTZWxlY3RvcjtcblxuICAvKipcbiAgICogQSBsaXN0IG9mIG5hbWVzIG9mIGFkZGl0aW9uYWwgZGVwbG95ZWQgc3RhY2tzIHRvIGJlIGluY2x1ZGVkIGluIHRoZSBjb21wYXJpc29uLlxuICAgKi9cbiAgYWRkaXRpb25hbFN0YWNrTmFtZXM/OiBzdHJpbmdbXTtcblxuICAvKipcbiAgICogUm9sZSB0byBhc3N1bWUgaW4gdGhlIHRhcmdldCBlbnZpcm9ubWVudCBiZWZvcmUgcGVyZm9ybWluZyB0aGUgcmVmYWN0b3IuXG4gICAqL1xuICByb2xlQXJuPzogc3RyaW5nO1xufVxuXG4vKipcbiAqIE9wdGlvbnMgZm9yIHRoZSBkcmlmdCBjb21tYW5kXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgRHJpZnRPcHRpb25zIHtcbiAgLyoqXG4gICAqIENyaXRlcmlhIGZvciBzZWxlY3Rpbmcgc3RhY2tzIHRvIGRldGVjdCBkcmlmdCBvblxuICAgKi9cbiAgcmVhZG9ubHkgc2VsZWN0b3I6IFN0YWNrU2VsZWN0b3I7XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdG8gZmFpbCB3aXRoIGV4aXQgY29kZSAxIGlmIGRyaWZ0IGlzIGRldGVjdGVkXG4gICAqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBmYWlsPzogYm9vbGVhbjtcbn1cblxuZnVuY3Rpb24gYnVpbGRQYXJhbWV0ZXJNYXAoXG4gIHBhcmFtZXRlcnM6XG4gICAgfCB7XG4gICAgICBbbmFtZTogc3RyaW5nXTogc3RyaW5nIHwgdW5kZWZpbmVkO1xuICAgIH1cbiAgICB8IHVuZGVmaW5lZCxcbik6IHsgW25hbWU6IHN0cmluZ106IHsgW25hbWU6IHN0cmluZ106IHN0cmluZyB8IHVuZGVmaW5lZCB9IH0ge1xuICBjb25zdCBwYXJhbWV0ZXJNYXA6IHtcbiAgICBbbmFtZTogc3RyaW5nXTogeyBbbmFtZTogc3RyaW5nXTogc3RyaW5nIHwgdW5kZWZpbmVkIH07XG4gIH0gPSB7ICcqJzoge30gfTtcbiAgZm9yIChjb25zdCBrZXkgaW4gcGFyYW1ldGVycykge1xuICAgIGlmIChwYXJhbWV0ZXJzLmhhc093blByb3BlcnR5KGtleSkpIHtcbiAgICAgIGNvbnN0IFtzdGFjaywgcGFyYW1ldGVyXSA9IGtleS5zcGxpdCgnOicsIDIpO1xuICAgICAgaWYgKCFwYXJhbWV0ZXIpIHtcbiAgICAgICAgcGFyYW1ldGVyTWFwWycqJ11bc3RhY2tdID0gcGFyYW1ldGVyc1trZXldO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgaWYgKCFwYXJhbWV0ZXJNYXBbc3RhY2tdKSB7XG4gICAgICAgICAgcGFyYW1ldGVyTWFwW3N0YWNrXSA9IHt9O1xuICAgICAgICB9XG4gICAgICAgIHBhcmFtZXRlck1hcFtzdGFja11bcGFyYW1ldGVyXSA9IHBhcmFtZXRlcnNba2V5XTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICByZXR1cm4gcGFyYW1ldGVyTWFwO1xufVxuXG4vKipcbiAqIEFzayB0aGUgdXNlciBmb3IgYSB5ZXMvbm8gY29uZmlybWF0aW9uXG4gKlxuICogQXV0b21hdGljYWxseSBmYWlsIHRoZSBjb25maXJtYXRpb24gaW4gY2FzZSB3ZSdyZSBpbiBhIHNpdHVhdGlvbiB3aGVyZSB0aGUgY29uZmlybWF0aW9uXG4gKiBjYW5ub3QgYmUgaW50ZXJhY3RpdmVseSBvYnRhaW5lZCBmcm9tIGEgaHVtYW4gYXQgdGhlIGtleWJvYXJkLlxuICovXG5hc3luYyBmdW5jdGlvbiBhc2tVc2VyQ29uZmlybWF0aW9uKFxuICBpb0hvc3Q6IENsaUlvSG9zdCxcbiAgcmVxOiBBY3Rpb25MZXNzUmVxdWVzdDxDb25maXJtYXRpb25SZXF1ZXN0LCBib29sZWFuPixcbikge1xuICBhd2FpdCBpb0hvc3Qud2l0aENvcmtlZExvZ2dpbmcoYXN5bmMgKCkgPT4ge1xuICAgIGF3YWl0IGlvSG9zdC5hc0lvSGVscGVyKCkucmVxdWVzdFJlc3BvbnNlKHJlcSk7XG4gIH0pO1xufVxuXG4vKipcbiAqIERpc3BsYXkgYSB3YXJuaW5nIGlmIHRoZXJlIGFyZSBmbGFncyB0aGF0IGFyZSBkaWZmZXJlbnQgZnJvbSB0aGUgcmVjb21tZW5kZWQgdmFsdWVcbiAqXG4gKiBUaGlzIGhhcHBlbnMgaWYgYm90aCBvZiB0aGUgZm9sbG93aW5nIGFyZSB0cnVlOlxuICpcbiAqIC0gVGhlIHVzZXIgZGlkbid0IGNvbmZpZ3VyZSB0aGUgdmFsdWVcbiAqIC0gVGhlIGRlZmF1bHQgdmFsdWUgZm9yIHRoZSBmbGFnICh1bmNvbmZpZ3VyZWRCZWhhdmVzTGlrZSkgaXMgZGlmZmVyZW50IGZyb20gdGhlIHJlY29tbWVuZGVkIHZhbHVlXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkaXNwbGF5RmxhZ3NNZXNzYWdlKGlvSG9zdDogSW9IZWxwZXIsIHRvb2xraXQ6IEludGVybmFsVG9vbGtpdCwgY2xvdWRFeGVjdXRhYmxlOiBDbG91ZEV4ZWN1dGFibGUpOiBQcm9taXNlPHZvaWQ+IHtcbiAgY29uc3QgZmxhZ3MgPSBhd2FpdCB0b29sa2l0LmZsYWdzKGNsb3VkRXhlY3V0YWJsZSk7XG5cbiAgLy8gVGhlIFwidW5jb25maWd1cmVkQmVoYXZlc0xpa2VcIiBpbmZvcm1hdGlvbiBnb3QgYWRkZWQgbGF0ZXIuIElmIG5vbmUgb2YgdGhlIGZsYWdzIGhhdmUgdGhpcyBpbmZvcm1hdGlvbixcbiAgLy8gd2UgZG9uJ3QgaGF2ZSBlbm91Z2ggaW5mb3JtYXRpb24gdG8gcmVsaWFibHkgZGlzcGxheSB0aGlzIGluZm9ybWF0aW9uIHdpdGhvdXQgc2NhcmluZyB1c2Vycywgc28gZG9uJ3QgZG8gYW55dGhpbmcuXG4gIGlmIChmbGFncy5ldmVyeShmbGFnID0+IGZsYWcudW5jb25maWd1cmVkQmVoYXZlc0xpa2UgPT09IHVuZGVmaW5lZCkpIHtcbiAgICByZXR1cm47XG4gIH1cblxuICBjb25zdCB1bmNvbmZpZ3VyZWRGbGFncyA9IGZsYWdzXG4gICAgLmZpbHRlcihmbGFnID0+ICFPQlNPTEVURV9GTEFHUy5pbmNsdWRlcyhmbGFnLm5hbWUpKVxuICAgIC5maWx0ZXIoZmxhZyA9PiAoZmxhZy51bmNvbmZpZ3VyZWRCZWhhdmVzTGlrZT8udjIgPz8gZmFsc2UpICE9PSBmbGFnLnJlY29tbWVuZGVkVmFsdWUpXG4gICAgLmZpbHRlcihmbGFnID0+IGZsYWcudXNlclZhbHVlID09PSB1bmRlZmluZWQpO1xuXG4gIGNvbnN0IG51bVVuY29uZmlndXJlZCA9IHVuY29uZmlndXJlZEZsYWdzLmxlbmd0aDtcbiAgaWYgKG51bVVuY29uZmlndXJlZCA+IDApIHtcbiAgICBhd2FpdCBpb0hvc3QuZGVmYXVsdHMud2FybihgJHtudW1VbmNvbmZpZ3VyZWR9IGZlYXR1cmUgZmxhZ3MgYXJlIG5vdCBjb25maWd1cmVkLiBSdW4gJ2NkayBmbGFncyAtLXVuc3RhYmxlPWZsYWdzJyB0byBsZWFybiBtb3JlLmApO1xuICB9XG59XG5cbi8qKlxuICogTG9nZ2VyIGZvciBwcm9jZXNzaW5nIHN0YWNrIG1ldGFkYXRhXG4gKi9cbmZ1bmN0aW9uIHN0YWNrTWV0YWRhdGFMb2dnZXIoaW9IZWxwZXI6IElvSGVscGVyLCB2ZXJib3NlPzogYm9vbGVhbik6IChsZXZlbDogJ2luZm8nIHwgJ2Vycm9yJyB8ICd3YXJuJywgbXNnOiBjeGFwaS5TeW50aGVzaXNNZXNzYWdlKSA9PiBQcm9taXNlPHZvaWQ+IHtcbiAgY29uc3QgbWFrZUxvZ2dlciA9IChsZXZlbDogc3RyaW5nKTogW2xvZ2dlcjogKG06IHN0cmluZykgPT4gdm9pZCwgcHJlZml4OiBzdHJpbmddID0+IHtcbiAgICBzd2l0Y2ggKGxldmVsKSB7XG4gICAgICBjYXNlICdlcnJvcic6XG4gICAgICAgIHJldHVybiBbKG0pID0+IGlvSGVscGVyLmRlZmF1bHRzLmVycm9yKG0pLCAnRXJyb3InXTtcbiAgICAgIGNhc2UgJ3dhcm4nOlxuICAgICAgICByZXR1cm4gWyhtKSA9PiBpb0hlbHBlci5kZWZhdWx0cy53YXJuKG0pLCAnV2FybmluZyddO1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgcmV0dXJuIFsobSkgPT4gaW9IZWxwZXIuZGVmYXVsdHMuaW5mbyhtKSwgJ0luZm8nXTtcbiAgICB9XG4gIH07XG5cbiAgcmV0dXJuIGFzeW5jIChsZXZlbCwgbXNnKSA9PiB7XG4gICAgY29uc3QgW2xvZ0ZuLCBwcmVmaXhdID0gbWFrZUxvZ2dlcihsZXZlbCk7XG4gICAgYXdhaXQgbG9nRm4oYFske3ByZWZpeH0gYXQgJHttc2cuaWR9XSAke21zZy5lbnRyeS5kYXRhfWApO1xuXG4gICAgaWYgKHZlcmJvc2UgJiYgbXNnLmVudHJ5LnRyYWNlKSB7XG4gICAgICBsb2dGbihgICAke21zZy5lbnRyeS50cmFjZS5qb2luKCdcXG4gICcpfWApO1xuICAgIH1cbiAgfTtcbn1cblxuLyoqXG4gKiBEZXRlcm1pbmUgaWYgbWFudWFsIGFwcHJvdmFsIGlzIHJlcXVpcmVkIG9yIG5vdC4gUmVxdWlyZXMgYXBwcm92YWwgZm9yXG4gKiAtIFJlcXVpcmVBcHByb3ZhbC5BTllfQ0hBTkdFXG4gKiAtIFJlcXVpcmVBcHByb3ZhbC5CUk9BREVOSU5HIGFuZCB0aGUgY2hhbmdlcyBhcmUgaW5kZWVkIGJyb2FkZW5pbmcgcGVybWlzc2lvbnNcbiAqL1xuZnVuY3Rpb24gcmVxdWlyZXNBcHByb3ZhbChyZXF1aXJlQXBwcm92YWw6IFJlcXVpcmVBcHByb3ZhbCwgcGVybWlzc2lvbkNoYW5nZVR5cGU6IFBlcm1pc3Npb25DaGFuZ2VUeXBlKSB7XG4gIHJldHVybiByZXF1aXJlQXBwcm92YWwgPT09IFJlcXVpcmVBcHByb3ZhbC5BTllDSEFOR0UgfHxcbiAgICByZXF1aXJlQXBwcm92YWwgPT09IFJlcXVpcmVBcHByb3ZhbC5CUk9BREVOSU5HICYmIHBlcm1pc3Npb25DaGFuZ2VUeXBlID09PSBQZXJtaXNzaW9uQ2hhbmdlVHlwZS5CUk9BREVOSU5HO1xufVxuIl19