"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.exec = exec;
exports.cli = cli;
/* eslint-disable @typescript-eslint/no-shadow */ // yargs
const cxapi = require("@aws-cdk/cx-api");
const toolkit_lib_1 = require("@aws-cdk/toolkit-lib");
const chalk = require("chalk");
const cdk_toolkit_1 = require("./cdk-toolkit");
const ci_systems_1 = require("./ci-systems");
const display_version_1 = require("./display-version");
const io_host_1 = require("./io-host");
const parse_command_line_arguments_1 = require("./parse-command-line-arguments");
const platform_warnings_1 = require("./platform-warnings");
const pretty_print_error_1 = require("./pretty-print-error");
const singleton_plugin_host_1 = require("./singleton-plugin-host");
const user_configuration_1 = require("./user-configuration");
const api_private_1 = require("../../lib/api-private");
const api_1 = require("../api");
const aws_auth_1 = require("../api/aws-auth");
const bootstrap_1 = require("../api/bootstrap");
const deployments_1 = require("../api/deployments");
const hotswap_1 = require("../api/hotswap");
const context_1 = require("../commands/context");
const docs_1 = require("../commands/docs");
const doctor_1 = require("../commands/doctor");
const flags_1 = require("../commands/flags/flags");
const init_1 = require("../commands/init");
const migrate_1 = require("../commands/migrate");
const cxapp_1 = require("../cxapp");
const proxy_agent_1 = require("./proxy-agent");
const error_1 = require("./telemetry/error");
const ci_1 = require("./util/ci");
const version_1 = require("./version");
const language_1 = require("../commands/language");
if (!process.stdout.isTTY) {
    // Disable chalk color highlighting
    process.env.FORCE_COLOR = '0';
}
async function exec(args, synthesizer) {
    const argv = await (0, parse_command_line_arguments_1.parseCommandLineArguments)(args);
    argv.language = (0, language_1.getLanguageFromAlias)(argv.language) ?? argv.language;
    const cmd = argv._[0];
    // if one -v, log at a DEBUG level
    // if 2 -v, log at a TRACE level
    let ioMessageLevel = 'info';
    if (argv.verbose) {
        switch (argv.verbose) {
            case 1:
                ioMessageLevel = 'debug';
                break;
            case 2:
            default:
                ioMessageLevel = 'trace';
                break;
        }
    }
    const ioHost = io_host_1.CliIoHost.instance({
        logLevel: ioMessageLevel,
        isTTY: process.stdout.isTTY,
        isCI: Boolean(argv.ci),
        currentAction: cmd,
        stackProgress: argv.progress,
        autoRespond: argv.yes,
    }, true);
    const ioHelper = (0, api_private_1.asIoHelper)(ioHost, ioHost.currentAction);
    // Debug should always imply tracing
    (0, aws_auth_1.setSdkTracing)(argv.debug || argv.verbose > 2);
    try {
        await (0, platform_warnings_1.checkForPlatformWarnings)(ioHelper);
    }
    catch (e) {
        await ioHost.defaults.debug(`Error while checking for platform warnings: ${e}`);
    }
    await ioHost.defaults.debug('CDK Toolkit CLI version:', (0, version_1.versionWithBuild)());
    await ioHost.defaults.debug('Command line arguments:', argv);
    const configuration = await user_configuration_1.Configuration.fromArgsAndFiles(ioHelper, {
        commandLineArguments: {
            ...argv,
            _: argv._, // TypeScript at its best
        },
    });
    // Always create and use ProxyAgent to support configuration via env vars
    const proxyAgent = await new proxy_agent_1.ProxyAgentProvider(ioHelper).create({
        proxyAddress: configuration.settings.get(['proxy']),
        caBundlePath: configuration.settings.get(['caBundlePath']),
    });
    if (argv['telemetry-file'] && !configuration.settings.get(['unstable']).includes('telemetry')) {
        throw new toolkit_lib_1.ToolkitError('Unstable feature use: \'telemetry-file\' is unstable. It must be opted in via \'--unstable\', e.g. \'cdk deploy --unstable=telemetry --telemetry-file=my/file/path\'');
    }
    try {
        await ioHost.startTelemetry(argv, configuration.context);
    }
    catch (e) {
        await ioHost.asIoHelper().defaults.trace(`Telemetry instantiation failed: ${e.message}`);
    }
    /**
     * The default value for displaying (and refreshing) notices on all commands.
     *
     * If the user didn't supply either `--notices` or `--no-notices`, we do
     * autodetection. The autodetection currently is: do write notices if we are
     * not on CI, or are on a CI system where we know that writing to stderr is
     * safe. We fail "closed"; that is, we decide to NOT print for unknown CI
     * systems, even though technically we maybe could.
     */
    const isSafeToWriteNotices = !(0, ci_1.isCI)() || Boolean((0, ci_systems_1.ciSystemIsStdErrSafe)());
    // Determine if notices should be displayed based on CLI args and configuration
    let shouldDisplayNotices;
    if (argv.notices !== undefined) {
        // CLI argument takes precedence
        shouldDisplayNotices = argv.notices;
    }
    else {
        // Fall back to configuration file setting, then autodetection
        const configNotices = configuration.settings.get(['notices']);
        if (configNotices !== undefined) {
            // Consider string "false" to be falsy in this context
            shouldDisplayNotices = configNotices !== 'false' && Boolean(configNotices);
        }
        else {
            // Default autodetection behavior
            shouldDisplayNotices = isSafeToWriteNotices;
        }
    }
    // Notices either go to stderr, or nowhere
    ioHost.noticesDestination = shouldDisplayNotices ? 'stderr' : 'drop';
    const notices = api_1.Notices.create({
        ioHost,
        context: configuration.context,
        output: configuration.settings.get(['outdir']),
        httpOptions: { agent: proxyAgent },
        cliVersion: (0, version_1.versionNumber)(),
    });
    const refreshNotices = (async () => {
        // the cdk notices command has it's own refresh
        if (shouldDisplayNotices && cmd !== 'notices') {
            try {
                return await notices.refresh();
            }
            catch (e) {
                await ioHelper.defaults.debug(`Could not refresh notices: ${e}`);
            }
        }
    })();
    const sdkProvider = await aws_auth_1.SdkProvider.withAwsCliCompatibleDefaults({
        ioHelper,
        requestHandler: (0, aws_auth_1.sdkRequestHandler)(proxyAgent),
        logger: new aws_auth_1.IoHostSdkLogger((0, api_private_1.asIoHelper)(ioHost, ioHost.currentAction)),
        pluginHost: singleton_plugin_host_1.GLOBAL_PLUGIN_HOST,
    }, configuration.settings.get(['profile']));
    try {
        await ioHost.telemetry?.attachRegion(sdkProvider.defaultRegion);
    }
    catch (e) {
        await ioHost.asIoHelper().defaults.trace(`Telemetry attach region failed: ${e.message}`);
    }
    let outDirLock;
    const cloudExecutable = new cxapp_1.CloudExecutable({
        configuration,
        sdkProvider,
        synthesizer: synthesizer ??
            (async (aws, config) => {
                // Invoke 'execProgram', and copy the lock for the directory in the global
                // variable here. It will be released when the CLI exits. Locks are not re-entrant
                // so release it if we have to synthesize more than once (because of context lookups).
                await outDirLock?.release();
                const { assembly, lock } = await (0, cxapp_1.execProgram)(aws, ioHost.asIoHelper(), config);
                outDirLock = lock;
                return assembly;
            }),
        ioHelper: ioHost.asIoHelper(),
    });
    /** Function to load plug-ins, using configurations additively. */
    async function loadPlugins(...settings) {
        for (const source of settings) {
            const plugins = source.get(['plugin']) || [];
            for (const plugin of plugins) {
                await singleton_plugin_host_1.GLOBAL_PLUGIN_HOST.load(plugin, ioHost);
            }
        }
    }
    await loadPlugins(configuration.settings);
    if ((typeof cmd) !== 'string') {
        throw new toolkit_lib_1.ToolkitError(`First argument should be a string. Got: ${cmd} (${typeof cmd})`);
    }
    try {
        return await main(cmd, argv);
    }
    finally {
        // If we locked the 'cdk.out' directory, release it here.
        await outDirLock?.release();
        // Do PSAs here
        await (0, display_version_1.displayVersionMessage)(ioHelper);
        await refreshNotices;
        if (cmd === 'notices') {
            await notices.refresh({ force: true });
            await notices.display({
                includeAcknowledged: !argv.unacknowledged,
                showTotal: argv.unacknowledged,
            });
        }
        else if (shouldDisplayNotices && cmd !== 'version') {
            await notices.display();
        }
    }
    async function main(command, args) {
        ioHost.currentAction = command;
        const toolkitStackName = api_1.ToolkitInfo.determineName(configuration.settings.get(['toolkitStackName']));
        await ioHost.defaults.debug(`Toolkit stack: ${chalk.bold(toolkitStackName)}`);
        const cloudFormation = new deployments_1.Deployments({
            sdkProvider,
            toolkitStackName,
            ioHelper: (0, api_private_1.asIoHelper)(ioHost, ioHost.currentAction),
        });
        if (args.all && args.STACKS) {
            throw new toolkit_lib_1.ToolkitError('You must either specify a list of Stacks or the `--all` argument');
        }
        args.STACKS = args.STACKS ?? (args.STACK ? [args.STACK] : []);
        args.ENVIRONMENTS = args.ENVIRONMENTS ?? [];
        const selector = {
            allTopLevel: args.all,
            patterns: args.STACKS,
        };
        const cli = new cdk_toolkit_1.CdkToolkit({
            ioHost,
            cloudExecutable,
            toolkitStackName,
            deployments: cloudFormation,
            verbose: argv.trace || argv.verbose > 0,
            ignoreErrors: argv['ignore-errors'],
            strict: argv.strict,
            configuration,
            sdkProvider,
        });
        switch (command) {
            case 'context':
                ioHost.currentAction = 'context';
                return (0, context_1.contextHandler)({
                    ioHelper,
                    context: configuration.context,
                    clear: argv.clear,
                    json: argv.json,
                    force: argv.force,
                    reset: argv.reset,
                });
            case 'docs':
            case 'doc':
                ioHost.currentAction = 'docs';
                return (0, docs_1.docs)({
                    ioHelper,
                    browser: configuration.settings.get(['browser']),
                });
            case 'doctor':
                ioHost.currentAction = 'doctor';
                return (0, doctor_1.doctor)({
                    ioHelper,
                });
            case 'ls':
            case 'list':
                ioHost.currentAction = 'list';
                return cli.list(args.STACKS, {
                    long: args.long,
                    json: argv.json,
                    showDeps: args.showDependencies,
                });
            case 'diff':
                ioHost.currentAction = 'diff';
                const enableDiffNoFail = isFeatureEnabled(configuration, cxapi.ENABLE_DIFF_NO_FAIL_CONTEXT);
                return cli.diff({
                    stackNames: args.STACKS,
                    exclusively: args.exclusively,
                    templatePath: args.template,
                    strict: args.strict,
                    contextLines: args.contextLines,
                    securityOnly: args.securityOnly,
                    fail: args.fail != null ? args.fail : !enableDiffNoFail,
                    compareAgainstProcessedTemplate: args.processed,
                    quiet: args.quiet,
                    changeSet: args['change-set'],
                    toolkitStackName: toolkitStackName,
                    importExistingResources: args.importExistingResources,
                    includeMoves: args['include-moves'],
                });
            case 'drift':
                ioHost.currentAction = 'drift';
                return cli.drift({
                    selector,
                    fail: args.fail,
                });
            case 'refactor':
                if (!configuration.settings.get(['unstable']).includes('refactor')) {
                    throw new toolkit_lib_1.ToolkitError('Unstable feature use: \'refactor\' is unstable. It must be opted in via \'--unstable\', e.g. \'cdk refactor --unstable=refactor\'');
                }
                ioHost.currentAction = 'refactor';
                return cli.refactor({
                    dryRun: args.dryRun,
                    overrideFile: args.overrideFile,
                    revert: args.revert,
                    stacks: selector,
                    additionalStackNames: arrayFromYargs(args.additionalStackName ?? []),
                    force: args.force ?? false,
                    roleArn: args.roleArn,
                });
            case 'bootstrap':
                ioHost.currentAction = 'bootstrap';
                const source = await determineBootstrapVersion(ioHost, args);
                if (args.showTemplate) {
                    const bootstrapper = new bootstrap_1.Bootstrapper(source, (0, api_private_1.asIoHelper)(ioHost, ioHost.currentAction));
                    return bootstrapper.showTemplate(args.json);
                }
                return cli.bootstrap(args.ENVIRONMENTS, {
                    source,
                    roleArn: args.roleArn,
                    forceDeployment: argv.force,
                    toolkitStackName: toolkitStackName,
                    execute: args.execute,
                    tags: configuration.settings.get(['tags']),
                    terminationProtection: args.terminationProtection,
                    usePreviousParameters: args['previous-parameters'],
                    parameters: {
                        bucketName: configuration.settings.get(['toolkitBucket', 'bucketName']),
                        kmsKeyId: configuration.settings.get(['toolkitBucket', 'kmsKeyId']),
                        createCustomerMasterKey: args.bootstrapCustomerKey,
                        qualifier: args.qualifier ?? configuration.context.get('@aws-cdk/core:bootstrapQualifier'),
                        publicAccessBlockConfiguration: args.publicAccessBlockConfiguration,
                        examplePermissionsBoundary: argv.examplePermissionsBoundary,
                        customPermissionsBoundary: argv.customPermissionsBoundary,
                        trustedAccounts: arrayFromYargs(args.trust),
                        trustedAccountsForLookup: arrayFromYargs(args.trustForLookup),
                        untrustedAccounts: arrayFromYargs(args.untrust),
                        cloudFormationExecutionPolicies: arrayFromYargs(args.cloudformationExecutionPolicies),
                        denyExternalId: args.denyExternalId,
                    },
                });
            case 'deploy':
                ioHost.currentAction = 'deploy';
                const parameterMap = {};
                for (const parameter of args.parameters) {
                    if (typeof parameter === 'string') {
                        const keyValue = parameter.split('=');
                        parameterMap[keyValue[0]] = keyValue.slice(1).join('=');
                    }
                }
                if (args.execute !== undefined && args.method !== undefined) {
                    throw new toolkit_lib_1.ToolkitError('Can not supply both --[no-]execute and --method at the same time');
                }
                return cli.deploy({
                    selector,
                    exclusively: args.exclusively,
                    toolkitStackName,
                    roleArn: args.roleArn,
                    notificationArns: args.notificationArns,
                    requireApproval: configuration.settings.get(['requireApproval']),
                    reuseAssets: args['build-exclude'],
                    tags: configuration.settings.get(['tags']),
                    deploymentMethod: determineDeploymentMethod(args, configuration),
                    force: args.force,
                    parameters: parameterMap,
                    usePreviousParameters: args['previous-parameters'],
                    outputsFile: configuration.settings.get(['outputsFile']),
                    progress: configuration.settings.get(['progress']),
                    ci: args.ci,
                    rollback: configuration.settings.get(['rollback']),
                    watch: args.watch,
                    traceLogs: args.logs,
                    concurrency: args.concurrency,
                    assetParallelism: configuration.settings.get(['assetParallelism']),
                    assetBuildTime: configuration.settings.get(['assetPrebuild'])
                        ? cdk_toolkit_1.AssetBuildTime.ALL_BEFORE_DEPLOY
                        : cdk_toolkit_1.AssetBuildTime.JUST_IN_TIME,
                    ignoreNoStacks: args.ignoreNoStacks,
                });
            case 'rollback':
                ioHost.currentAction = 'rollback';
                return cli.rollback({
                    selector,
                    toolkitStackName,
                    roleArn: args.roleArn,
                    force: args.force,
                    validateBootstrapStackVersion: args['validate-bootstrap-version'],
                    orphanLogicalIds: args.orphan,
                });
            case 'import':
                ioHost.currentAction = 'import';
                return cli.import({
                    selector,
                    toolkitStackName,
                    roleArn: args.roleArn,
                    deploymentMethod: {
                        method: 'change-set',
                        execute: args.execute,
                        changeSetName: args.changeSetName,
                    },
                    progress: configuration.settings.get(['progress']),
                    rollback: configuration.settings.get(['rollback']),
                    recordResourceMapping: args['record-resource-mapping'],
                    resourceMappingFile: args['resource-mapping'],
                    force: args.force,
                });
            case 'watch':
                ioHost.currentAction = 'watch';
                await cli.watch({
                    selector,
                    exclusively: args.exclusively,
                    toolkitStackName,
                    roleArn: args.roleArn,
                    reuseAssets: args['build-exclude'],
                    deploymentMethod: determineDeploymentMethod(args, configuration, true),
                    force: args.force,
                    progress: configuration.settings.get(['progress']),
                    rollback: configuration.settings.get(['rollback']),
                    traceLogs: args.logs,
                    concurrency: args.concurrency,
                });
                return;
            case 'destroy':
                ioHost.currentAction = 'destroy';
                return cli.destroy({
                    selector,
                    exclusively: args.exclusively,
                    force: args.force,
                    roleArn: args.roleArn,
                });
            case 'gc':
                ioHost.currentAction = 'gc';
                if (!configuration.settings.get(['unstable']).includes('gc')) {
                    throw new toolkit_lib_1.ToolkitError('Unstable feature use: \'gc\' is unstable. It must be opted in via \'--unstable\', e.g. \'cdk gc --unstable=gc\'');
                }
                if (args.bootstrapStackName) {
                    await ioHost.defaults.warn('--bootstrap-stack-name is deprecated and will be removed when gc is GA. Use --toolkit-stack-name.');
                }
                // roleArn is defined for when cloudformation is invoked
                // This conflicts with direct sdk calls existing in the gc command to s3 and ecr
                if (args.roleArn) {
                    await ioHost.defaults.warn('The --role-arn option is not supported for the gc command and will be ignored.');
                }
                return cli.garbageCollect(args.ENVIRONMENTS, {
                    action: args.action,
                    type: args.type,
                    rollbackBufferDays: args['rollback-buffer-days'],
                    createdBufferDays: args['created-buffer-days'],
                    bootstrapStackName: args.toolkitStackName ?? args.bootstrapStackName,
                    confirm: args.confirm,
                });
            case 'flags':
                ioHost.currentAction = 'flags';
                if (!configuration.settings.get(['unstable']).includes('flags')) {
                    throw new toolkit_lib_1.ToolkitError('Unstable feature use: \'flags\' is unstable. It must be opted in via \'--unstable\', e.g. \'cdk flags --unstable=flags\'');
                }
                const toolkit = new toolkit_lib_1.Toolkit({
                    ioHost,
                    toolkitStackName,
                    unstableFeatures: configuration.settings.get(['unstable']),
                });
                const flagsData = await toolkit.flags(cloudExecutable);
                const handler = new flags_1.FlagCommandHandler(flagsData, ioHelper, args, toolkit);
                return handler.processFlagsCommand();
            case 'synthesize':
            case 'synth':
                ioHost.currentAction = 'synth';
                const quiet = configuration.settings.get(['quiet']) ?? args.quiet;
                if (args.exclusively) {
                    return cli.synth(args.STACKS, args.exclusively, quiet, args.validation, argv.json);
                }
                else {
                    return cli.synth(args.STACKS, true, quiet, args.validation, argv.json);
                }
            case 'notices':
                ioHost.currentAction = 'notices';
                // If the user explicitly asks for notices, they are now the primary output
                // of the command and they should go to stdout.
                ioHost.noticesDestination = 'stdout';
                // This is a valid command, but we're postponing its execution because displaying
                // notices automatically happens after every command.
                return;
            case 'metadata':
                ioHost.currentAction = 'metadata';
                return cli.metadata(args.STACK, argv.json);
            case 'acknowledge':
            case 'ack':
                ioHost.currentAction = 'notices';
                return cli.acknowledge(args.ID);
            case 'cli-telemetry':
                ioHost.currentAction = 'cli-telemetry';
                if (args.enable === undefined && args.disable === undefined && args.status === undefined) {
                    throw new toolkit_lib_1.ToolkitError('Must specify \'--enable\', \'--disable\', or \'--status\'');
                }
                if (args.status) {
                    return cli.cliTelemetryStatus(args['version-reporting']);
                }
                else {
                    const enable = args.enable ?? !args.disable;
                    return cli.cliTelemetry(enable);
                }
            case 'init':
                ioHost.currentAction = 'init';
                const language = configuration.settings.get(['language']);
                if (args.list) {
                    return (0, init_1.printAvailableTemplates)(ioHelper, language);
                }
                else {
                    // Gate custom template support with unstable flag
                    if (args['from-path'] && !configuration.settings.get(['unstable']).includes('init')) {
                        throw new toolkit_lib_1.ToolkitError('Unstable feature use: \'init\' with custom templates is unstable. It must be opted in via \'--unstable\', e.g. \'cdk init --from-path=./my-template --unstable=init\'');
                    }
                    return (0, init_1.cliInit)({
                        ioHelper,
                        type: args.TEMPLATE,
                        language,
                        canUseNetwork: undefined,
                        generateOnly: args.generateOnly,
                        libVersion: args.libVersion,
                        fromPath: args['from-path'],
                        templatePath: args['template-path'],
                    });
                }
            case 'migrate':
                ioHost.currentAction = 'migrate';
                return cli.migrate({
                    stackName: args['stack-name'],
                    fromPath: args['from-path'],
                    fromStack: args['from-stack'],
                    language: args.language,
                    outputPath: args['output-path'],
                    fromScan: (0, migrate_1.getMigrateScanType)(args['from-scan']),
                    filter: args.filter,
                    account: args.account,
                    region: args.region,
                    compress: args.compress,
                });
            case 'version':
                ioHost.currentAction = 'version';
                return ioHost.defaults.result((0, version_1.versionWithBuild)());
            default:
                throw new toolkit_lib_1.ToolkitError('Unknown command: ' + command);
        }
    }
}
/**
 * Determine which version of bootstrapping
 */
async function determineBootstrapVersion(ioHost, args) {
    let source;
    if (args.template) {
        await ioHost.defaults.info(`Using bootstrapping template from ${args.template}`);
        source = { source: 'custom', templateFile: args.template };
    }
    else if (process.env.CDK_LEGACY_BOOTSTRAP) {
        await ioHost.defaults.info('CDK_LEGACY_BOOTSTRAP set, using legacy-style bootstrapping');
        source = { source: 'legacy' };
    }
    else {
        // in V2, the "new" bootstrapping is the default
        source = { source: 'default' };
    }
    return source;
}
function isFeatureEnabled(configuration, featureFlag) {
    return configuration.context.get(featureFlag) ?? cxapi.futureFlagDefault(featureFlag);
}
/**
 * Translate a Yargs input array to something that makes more sense in a programming language
 * model (telling the difference between absence and an empty array)
 *
 * - An empty array is the default case, meaning the user didn't pass any arguments. We return
 *   undefined.
 * - If the user passed a single empty string, they did something like `--array=`, which we'll
 *   take to mean they passed an empty array.
 */
function arrayFromYargs(xs) {
    if (xs.length === 0) {
        return undefined;
    }
    return xs.filter((x) => x !== '');
}
function determineDeploymentMethod(args, configuration, watch) {
    let deploymentMethod;
    switch (args.method) {
        case 'direct':
            if (args.changeSetName) {
                throw new toolkit_lib_1.ToolkitError('--change-set-name cannot be used with method=direct');
            }
            if (args.importExistingResources) {
                throw new toolkit_lib_1.ToolkitError('--import-existing-resources cannot be enabled with method=direct');
            }
            deploymentMethod = { method: 'direct' };
            break;
        case 'change-set':
            deploymentMethod = {
                method: 'change-set',
                execute: true,
                changeSetName: args.changeSetName,
                importExistingResources: args.importExistingResources,
            };
            break;
        case 'prepare-change-set':
            deploymentMethod = {
                method: 'change-set',
                execute: false,
                changeSetName: args.changeSetName,
                importExistingResources: args.importExistingResources,
            };
            break;
        case undefined:
        default:
            deploymentMethod = {
                method: 'change-set',
                execute: watch ? true : args.execute ?? true,
                changeSetName: args.changeSetName,
                importExistingResources: args.importExistingResources,
            };
            break;
    }
    const hotswapMode = determineHotswapMode(args.hotswap, args.hotswapFallback, watch);
    const hotswapProperties = configuration.settings.get(['hotswap']) || {};
    switch (hotswapMode) {
        case hotswap_1.HotswapMode.FALL_BACK:
            return {
                method: 'hotswap',
                properties: hotswapProperties,
                fallback: deploymentMethod,
            };
        case hotswap_1.HotswapMode.HOTSWAP_ONLY:
            return {
                method: 'hotswap',
                properties: hotswapProperties,
            };
        default:
        case hotswap_1.HotswapMode.FULL_DEPLOYMENT:
            return deploymentMethod;
    }
}
function determineHotswapMode(hotswap, hotswapFallback, watch) {
    if (hotswap && hotswapFallback) {
        throw new toolkit_lib_1.ToolkitError('Can not supply both --hotswap and --hotswap-fallback at the same time');
    }
    else if (!hotswap && !hotswapFallback) {
        if (hotswap === undefined && hotswapFallback === undefined) {
            return watch ? hotswap_1.HotswapMode.HOTSWAP_ONLY : hotswap_1.HotswapMode.FULL_DEPLOYMENT;
        }
        else if (hotswap === false || hotswapFallback === false) {
            return hotswap_1.HotswapMode.FULL_DEPLOYMENT;
        }
    }
    let hotswapMode;
    if (hotswap) {
        hotswapMode = hotswap_1.HotswapMode.HOTSWAP_ONLY;
        /* if (hotswapFallback)*/
    }
    else {
        hotswapMode = hotswap_1.HotswapMode.FALL_BACK;
    }
    return hotswapMode;
}
/* c8 ignore start */ // we never call this in unit tests
function cli(args = process.argv.slice(2)) {
    let error;
    exec(args)
        .then(async (value) => {
        if (typeof value === 'number') {
            process.exitCode = value;
        }
    })
        .catch(async (err) => {
        // Log the stack trace if we're on a developer workstation. Otherwise this will be into a minified
        // file and the printed code line and stack trace are huge and useless.
        (0, pretty_print_error_1.prettyPrintError)(err, (0, version_1.isDeveloperBuildVersion)());
        error = {
            name: (0, error_1.cdkCliErrorName)(err.name),
        };
        process.exitCode = 1;
    })
        .finally(async () => {
        try {
            await io_host_1.CliIoHost.get()?.telemetry?.end(error);
        }
        catch (e) {
            await io_host_1.CliIoHost.get()?.asIoHelper().defaults.trace(`Ending Telemetry failed: ${e.message}`);
        }
    });
}
/* c8 ignore stop */
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2xpLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiY2xpLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBNkNBLG9CQWtpQkM7QUEwSEQsa0JBd0JDO0FBanVCRCxpREFBaUQsQ0FBQyxRQUFRO0FBQzFELHlDQUF5QztBQUV6QyxzREFBNkQ7QUFDN0QsK0JBQStCO0FBQy9CLCtDQUEyRDtBQUMzRCw2Q0FBb0Q7QUFDcEQsdURBQTBEO0FBRTFELHVDQUFzQztBQUN0QyxpRkFBMkU7QUFDM0UsMkRBQStEO0FBQy9ELDZEQUF3RDtBQUN4RCxtRUFBNkQ7QUFFN0QsNkRBQXFEO0FBQ3JELHVEQUFtRDtBQUVuRCxnQ0FBOEM7QUFDOUMsOENBQWlHO0FBRWpHLGdEQUFnRDtBQUNoRCxvREFBaUQ7QUFDakQsNENBQTZDO0FBRTdDLGlEQUFnRTtBQUNoRSwyQ0FBd0M7QUFDeEMsK0NBQTRDO0FBQzVDLG1EQUE2RDtBQUM3RCwyQ0FBb0U7QUFDcEUsaURBQXlEO0FBQ3pELG9DQUF3RDtBQUV4RCwrQ0FBbUQ7QUFDbkQsNkNBQW9EO0FBRXBELGtDQUFpQztBQUNqQyx1Q0FBcUY7QUFDckYsbURBQTREO0FBRTVELElBQUksQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLEtBQUssRUFBRSxDQUFDO0lBQzFCLG1DQUFtQztJQUNuQyxPQUFPLENBQUMsR0FBRyxDQUFDLFdBQVcsR0FBRyxHQUFHLENBQUM7QUFDaEMsQ0FBQztBQUVNLEtBQUssVUFBVSxJQUFJLENBQUMsSUFBYyxFQUFFLFdBQXlCO0lBQ2xFLE1BQU0sSUFBSSxHQUFHLE1BQU0sSUFBQSx3REFBeUIsRUFBQyxJQUFJLENBQUMsQ0FBQztJQUNuRCxJQUFJLENBQUMsUUFBUSxHQUFHLElBQUEsK0JBQW9CLEVBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxJQUFJLElBQUksQ0FBQyxRQUFRLENBQUM7SUFFckUsTUFBTSxHQUFHLEdBQUcsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUV0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QUM7SUFDSCxDQUFDLENBQUM7U0FDRCxLQUFLLENBQUMsS0FBSyxFQUFFLEdBQUcsRUFBRSxFQUFFO1FBQ25CLGtHQUFrRztRQUNsRyx1RUFBdUU7UUFDdkUsSUFBQSxxQ0FBZ0IsRUFBQyxHQUFHLEVBQUUsSUFBQSxpQ0FBdUIsR0FBRSxDQUFDLENBQUM7UUFDakQsS0FBSyxHQUFHO1lBQ04sSUFBSSxFQUFFLElBQUEsdUJBQWUsRUFBQyxHQUFHLENBQUMsSUFBSSxDQUFDO1NBQ2hDLENBQUM7UUFDRixPQUFPLENBQUMsUUFBUSxHQUFHLENBQUMsQ0FBQztJQUN2QixDQUFDLENBQUM7U0FDRCxPQUFPLENBQUMsS0FBSyxJQUFJLEVBQUU7UUFDbEIsSUFBSSxDQUFDO1lBQ0gsTUFBTSxtQkFBUyxDQUFDLEdBQUcsRUFBRSxFQUFFLFNBQVMsRUFBRSxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUM7UUFDL0MsQ0FBQztRQUFDLE9BQU8sQ0FBTSxFQUFFLENBQUM7WUFDaEIsTUFBTSxtQkFBUyxDQUFDLEdBQUcsRUFBRSxFQUFFLFVBQVUsRUFBRSxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsNEJBQTRCLENBQUMsQ0FBQyxPQUFPLEVBQUUsQ0FBQyxDQUFDO1FBQzlGLENBQUM7SUFDSCxDQUFDLENBQUMsQ0FBQztBQUNQLENBQUM7QUFDRCxvQkFBb0IiLCJzb3VyY2VzQ29udGVudCI6WyIvKiBlc2xpbnQtZGlzYWJsZSBAdHlwZXNjcmlwdC1lc2xpbnQvbm8tc2hhZG93ICovIC8vIHlhcmdzXG5pbXBvcnQgKiBhcyBjeGFwaSBmcm9tICdAYXdzLWNkay9jeC1hcGknO1xuaW1wb3J0IHR5cGUgeyBDaGFuZ2VTZXREZXBsb3ltZW50LCBEZXBsb3ltZW50TWV0aG9kLCBEaXJlY3REZXBsb3ltZW50IH0gZnJvbSAnQGF3cy1jZGsvdG9vbGtpdC1saWInO1xuaW1wb3J0IHsgVG9vbGtpdEVycm9yLCBUb29sa2l0IH0gZnJvbSAnQGF3cy1jZGsvdG9vbGtpdC1saWInO1xuaW1wb3J0ICogYXMgY2hhbGsgZnJvbSAnY2hhbGsnO1xuaW1wb3J0IHsgQ2RrVG9vbGtpdCwgQXNzZXRCdWlsZFRpbWUgfSBmcm9tICcuL2Nkay10b29sa2l0JztcbmltcG9ydCB7IGNpU3lzdGVtSXNTdGRFcnJTYWZlIH0gZnJvbSAnLi9jaS1zeXN0ZW1zJztcbmltcG9ydCB7IGRpc3BsYXlWZXJzaW9uTWVzc2FnZSB9IGZyb20gJy4vZGlzcGxheS12ZXJzaW9uJztcbmltcG9ydCB0eXBlIHsgSW9NZXNzYWdlTGV2ZWwgfSBmcm9tICcuL2lvLWhvc3QnO1xuaW1wb3J0IHsgQ2xpSW9Ib3N0IH0gZnJvbSAnLi9pby1ob3N0JztcbmltcG9ydCB7IHBhcnNlQ29tbWFuZExpbmVBcmd1bWVudHMgfSBmcm9tICcuL3BhcnNlLWNvbW1hbmQtbGluZS1hcmd1bWVudHMnO1xuaW1wb3J0IHsgY2hlY2tGb3JQbGF0Zm9ybVdhcm5pbmdzIH0gZnJvbSAnLi9wbGF0Zm9ybS13YXJuaW5ncyc7XG5pbXBvcnQgeyBwcmV0dHlQcmludEVycm9yIH0gZnJvbSAnLi9wcmV0dHktcHJpbnQtZXJyb3InO1xuaW1wb3J0IHsgR0xPQkFMX1BMVUdJTl9IT1NUIH0gZnJvbSAnLi9zaW5nbGV0b24tcGx1Z2luLWhvc3QnO1xuaW1wb3J0IHR5cGUgeyBDb21tYW5kIH0gZnJvbSAnLi91c2VyLWNvbmZpZ3VyYXRpb24nO1xuaW1wb3J0IHsgQ29uZmlndXJhdGlvbiB9IGZyb20gJy4vdXNlci1jb25maWd1cmF0aW9uJztcbmltcG9ydCB7IGFzSW9IZWxwZXIgfSBmcm9tICcuLi8uLi9saWIvYXBpLXByaXZhdGUnO1xuaW1wb3J0IHR5cGUgeyBJUmVhZExvY2sgfSBmcm9tICcuLi9hcGknO1xuaW1wb3J0IHsgVG9vbGtpdEluZm8sIE5vdGljZXMgfSBmcm9tICcuLi9hcGknO1xuaW1wb3J0IHsgU2RrUHJvdmlkZXIsIElvSG9zdFNka0xvZ2dlciwgc2V0U2RrVHJhY2luZywgc2RrUmVxdWVzdEhhbmRsZXIgfSBmcm9tICcuLi9hcGkvYXdzLWF1dGgnO1xuaW1wb3J0IHR5cGUgeyBCb290c3RyYXBTb3VyY2UgfSBmcm9tICcuLi9hcGkvYm9vdHN0cmFwJztcbmltcG9ydCB7IEJvb3RzdHJhcHBlciB9IGZyb20gJy4uL2FwaS9ib290c3RyYXAnO1xuaW1wb3J0IHsgRGVwbG95bWVudHMgfSBmcm9tICcuLi9hcGkvZGVwbG95bWVudHMnO1xuaW1wb3J0IHsgSG90c3dhcE1vZGUgfSBmcm9tICcuLi9hcGkvaG90c3dhcCc7XG5pbXBvcnQgdHlwZSB7IFNldHRpbmdzIH0gZnJvbSAnLi4vYXBpL3NldHRpbmdzJztcbmltcG9ydCB7IGNvbnRleHRIYW5kbGVyIGFzIGNvbnRleHQgfSBmcm9tICcuLi9jb21tYW5kcy9jb250ZXh0JztcbmltcG9ydCB7IGRvY3MgfSBmcm9tICcuLi9jb21tYW5kcy9kb2NzJztcbmltcG9ydCB7IGRvY3RvciB9IGZyb20gJy4uL2NvbW1hbmRzL2RvY3Rvcic7XG5pbXBvcnQgeyBGbGFnQ29tbWFuZEhhbmRsZXIgfSBmcm9tICcuLi9jb21tYW5kcy9mbGFncy9mbGFncyc7XG5pbXBvcnQgeyBjbGlJbml0LCBwcmludEF2YWlsYWJsZVRlbXBsYXRlcyB9IGZyb20gJy4uL2NvbW1hbmRzL2luaXQnO1xuaW1wb3J0IHsgZ2V0TWlncmF0ZVNjYW5UeXBlIH0gZnJvbSAnLi4vY29tbWFuZHMvbWlncmF0ZSc7XG5pbXBvcnQgeyBleGVjUHJvZ3JhbSwgQ2xvdWRFeGVjdXRhYmxlIH0gZnJvbSAnLi4vY3hhcHAnO1xuaW1wb3J0IHR5cGUgeyBTdGFja1NlbGVjdG9yLCBTeW50aGVzaXplciB9IGZyb20gJy4uL2N4YXBwJztcbmltcG9ydCB7IFByb3h5QWdlbnRQcm92aWRlciB9IGZyb20gJy4vcHJveHktYWdlbnQnO1xuaW1wb3J0IHsgY2RrQ2xpRXJyb3JOYW1lIH0gZnJvbSAnLi90ZWxlbWV0cnkvZXJyb3InO1xuaW1wb3J0IHR5cGUgeyBFcnJvckRldGFpbHMgfSBmcm9tICcuL3RlbGVtZXRyeS9zY2hlbWEnO1xuaW1wb3J0IHsgaXNDSSB9IGZyb20gJy4vdXRpbC9jaSc7XG5pbXBvcnQgeyBpc0RldmVsb3BlckJ1aWxkVmVyc2lvbiwgdmVyc2lvbldpdGhCdWlsZCwgdmVyc2lvbk51bWJlciB9IGZyb20gJy4vdmVyc2lvbic7XG5pbXBvcnQgeyBnZXRMYW5ndWFnZUZyb21BbGlhcyB9IGZyb20gJy4uL2NvbW1hbmRzL2xhbmd1YWdlJztcblxuaWYgKCFwcm9jZXNzLnN0ZG91dC5pc1RUWSkge1xuICAvLyBEaXNhYmxlIGNoYWxrIGNvbG9yIGhpZ2hsaWdodGluZ1xuICBwcm9jZXNzLmVudi5GT1JDRV9DT0xPUiA9ICcwJztcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGV4ZWMoYXJnczogc3RyaW5nW10sIHN5bnRoZXNpemVyPzogU3ludGhlc2l6ZXIpOiBQcm9taXNlPG51bWJlciB8IHZvaWQ+IHtcbiAgY29uc3QgYXJndiA9IGF3YWl0IHBhcnNlQ29tbWFuZExpbmVBcmd1bWVudHMoYXJncyk7XG4gIGFyZ3YubGFuZ3VhZ2UgPSBnZXRMYW5ndWFnZUZyb21BbGlhcyhhcmd2Lmxhbmd1YWdlKSA/PyBhcmd2Lmxhbmd1YWdlO1xuXG4gIGNvbnN0IGNtZCA9IGFyZ3YuX1swXTtcblxuICAvLyBpZiBvbmUgLXYsIGxvZyBhdCBhIERFQlVHIGxldmVsXG4gIC8vIGlmIDIgLXYsIGxvZyBhdCBhIFRSQUNFIGxldmVsXG4gIGxldCBpb01lc3NhZ2VMZXZlbDogSW9NZXNzYWdlTGV2ZWwgPSAnaW5mbyc7XG4gIGlmIChhcmd2LnZlcmJvc2UpIHtcbiAgICBzd2l0Y2ggKGFyZ3YudmVyYm9zZSkge1xuICAgICAgY2FzZSAxOlxuICAgICAgICBpb01lc3NhZ2VMZXZlbCA9ICdkZWJ1Zyc7XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSAyOlxuICAgICAgZGVmYXVsdDpcbiAgICAgICAgaW9NZXNzYWdlTGV2ZWwgPSAndHJhY2UnO1xuICAgICAgICBicmVhaztcbiAgICB9XG4gIH1cblxuICBjb25zdCBpb0hvc3QgPSBDbGlJb0hvc3QuaW5zdGFuY2Uoe1xuICAgIGxvZ0xldmVsOiBpb01lc3NhZ2VMZXZlbCxcbiAgICBpc1RUWTogcHJvY2Vzcy5zdGRvdXQuaXNUVFksXG4gICAgaXNDSTogQm9vbGVhbihhcmd2LmNpKSxcbiAgICBjdXJyZW50QWN0aW9uOiBjbWQsXG4gICAgc3RhY2tQcm9ncmVzczogYXJndi5wcm9ncmVzcyxcbiAgICBhdXRvUmVzcG9uZDogYXJndi55ZXMsXG4gIH0sIHRydWUpO1xuICBjb25zdCBpb0hlbHBlciA9IGFzSW9IZWxwZXIoaW9Ib3N0LCBpb0hvc3QuY3VycmVudEFjdGlvbiBhcyBhbnkpO1xuXG4gIC8vIERlYnVnIHNob3VsZCBhbHdheXMgaW1wbHkgdHJhY2luZ1xuICBzZXRTZGtUcmFjaW5nKGFyZ3YuZGVidWcgfHwgYXJndi52ZXJib3NlID4gMik7XG5cbiAgdHJ5IHtcbiAgICBhd2FpdCBjaGVja0ZvclBsYXRmb3JtV2FybmluZ3MoaW9IZWxwZXIpO1xuICB9IGNhdGNoIChlKSB7XG4gICAgYXdhaXQgaW9Ib3N0LmRlZmF1bHRzLmRlYnVnKGBFcnJvciB3aGlsZSBjaGVja2luZyBmb3IgcGxhdGZvcm0gd2FybmluZ3M6ICR7ZX1gKTtcbiAgfVxuXG4gIGF3YWl0IGlvSG9zdC5kZWZhdWx0cy5kZWJ1ZygnQ0RLIFRvb2xraXQgQ0xJIHZlcnNpb246JywgdmVyc2lvbldpdGhCdWlsZCgpKTtcbiAgYXdhaXQgaW9Ib3N0LmRlZmF1bHRzLmRlYnVnKCdDb21tYW5kIGxpbmUgYXJndW1lbnRzOicsIGFyZ3YpO1xuXG4gIGNvbnN0IGNvbmZpZ3VyYXRpb24gPSBhd2FpdCBDb25maWd1cmF0aW9uLmZyb21BcmdzQW5kRmlsZXMoaW9IZWxwZXIsXG4gICAge1xuICAgICAgY29tbWFuZExpbmVBcmd1bWVudHM6IHtcbiAgICAgICAgLi4uYXJndixcbiAgICAgICAgXzogYXJndi5fIGFzIFtDb21tYW5kLCAuLi5zdHJpbmdbXV0sIC8vIFR5cGVTY3JpcHQgYXQgaXRzIGJlc3RcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgLy8gQWx3YXlzIGNyZWF0ZSBhbmQgdXNlIFByb3h5QWdlbnQgdG8gc3VwcG9ydCBjb25maWd1cmF0aW9uIHZpYSBlbnYgdmFyc1xuICBjb25zdCBwcm94eUFnZW50ID0gYXdhaXQgbmV3IFByb3h5QWdlbnRQcm92aWRlcihpb0hlbHBlcikuY3JlYXRlKHtcbiAgICBwcm94eUFkZHJlc3M6IGNvbmZpZ3VyYXRpb24uc2V0dGluZ3MuZ2V0KFsncHJveHknXSksXG4gICAgY2FCdW5kbGVQYXRoOiBjb25maWd1cmF0aW9uLnNldHRpbmdzLmdldChbJ2NhQnVuZGxlUGF0aCddKSxcbiAgfSk7XG5cbiAgaWYgKGFyZ3ZbJ3RlbGVtZXRyeS1maWxlJ10gJiYgIWNvbmZpZ3VyYXRpb24uc2V0dGluZ3MuZ2V0KFsndW5zdGFibGUnXSkuaW5jbHVkZXMoJ3RlbGVtZXRyeScpKSB7XG4gICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcignVW5zdGFibGUgZmVhdHVyZSB1c2U6IFxcJ3RlbGVtZXRyeS1maWxlXFwnIGlzIHVuc3RhYmxlLiBJdCBtdXN0IGJlIG9wdGVkIGluIHZpYSBcXCctLXVuc3RhYmxlXFwnLCBlLmcuIFxcJ2NkayBkZXBsb3kgLS11bnN0YWJsZT10ZWxlbWV0cnkgLS10ZWxlbWV0cnktZmlsZT1teS9maWxlL3BhdGhcXCcnKTtcbiAgfVxuXG4gIHRyeSB7XG4gICAgYXdhaXQgaW9Ib3N0LnN0YXJ0VGVsZW1ldHJ5KGFyZ3YsIGNvbmZpZ3VyYXRpb24uY29udGV4dCk7XG4gIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgIGF3YWl0IGlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMudHJhY2UoYFRlbGVtZXRyeSBpbnN0YW50aWF0aW9uIGZhaWxlZDogJHtlLm1lc3NhZ2V9YCk7XG4gIH1cblxuICAvKipcbiAgICogVGhlIGRlZmF1bHQgdmFsdWUgZm9yIGRpc3BsYXlpbmcgKGFuZCByZWZyZXNoaW5nKSBub3RpY2VzIG9uIGFsbCBjb21tYW5kcy5cbiAgICpcbiAgICogSWYgdGhlIHVzZXIgZGlkbid0IHN1cHBseSBlaXRoZXIgYC0tbm90aWNlc2Agb3IgYC0tbm8tbm90aWNlc2AsIHdlIGRvXG4gICAqIGF1dG9kZXRlY3Rpb24uIFRoZSBhdXRvZGV0ZWN0aW9uIGN1cnJlbnRseSBpczogZG8gd3JpdGUgbm90aWNlcyBpZiB3ZSBhcmVcbiAgICogbm90IG9uIENJLCBvciBhcmUgb24gYSBDSSBzeXN0ZW0gd2hlcmUgd2Uga25vdyB0aGF0IHdyaXRpbmcgdG8gc3RkZXJyIGlzXG4gICAqIHNhZmUuIFdlIGZhaWwgXCJjbG9zZWRcIjsgdGhhdCBpcywgd2UgZGVjaWRlIHRvIE5PVCBwcmludCBmb3IgdW5rbm93biBDSVxuICAgKiBzeXN0ZW1zLCBldmVuIHRob3VnaCB0ZWNobmljYWxseSB3ZSBtYXliZSBjb3VsZC5cbiAgICovXG4gIGNvbnN0IGlzU2FmZVRvV3JpdGVOb3RpY2VzID0gIWlzQ0koKSB8fCBCb29sZWFuKGNpU3lzdGVtSXNTdGRFcnJTYWZlKCkpO1xuXG4gIC8vIERldGVybWluZSBpZiBub3RpY2VzIHNob3VsZCBiZSBkaXNwbGF5ZWQgYmFzZWQgb24gQ0xJIGFyZ3MgYW5kIGNvbmZpZ3VyYXRpb25cbiAgbGV0IHNob3VsZERpc3BsYXlOb3RpY2VzOiBib29sZWFuO1xuICBpZiAoYXJndi5ub3RpY2VzICE9PSB1bmRlZmluZWQpIHtcbiAgICAvLyBDTEkgYXJndW1lbnQgdGFrZXMgcHJlY2VkZW5jZVxuICAgIHNob3VsZERpc3BsYXlOb3RpY2VzID0gYXJndi5ub3RpY2VzO1xuICB9IGVsc2Uge1xuICAgIC8vIEZhbGwgYmFjayB0byBjb25maWd1cmF0aW9uIGZpbGUgc2V0dGluZywgdGhlbiBhdXRvZGV0ZWN0aW9uXG4gICAgY29uc3QgY29uZmlnTm90aWNlcyA9IGNvbmZpZ3VyYXRpb24uc2V0dGluZ3MuZ2V0KFsnbm90aWNlcyddKTtcbiAgICBpZiAoY29uZmlnTm90aWNlcyAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAvLyBDb25zaWRlciBzdHJpbmcgXCJmYWxzZVwiIHRvIGJlIGZhbHN5IGluIHRoaXMgY29udGV4dFxuICAgICAgc2hvdWxkRGlzcGxheU5vdGljZXMgPSBjb25maWdOb3RpY2VzICE9PSAnZmFsc2UnICYmIEJvb2xlYW4oY29uZmlnTm90aWNlcyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIERlZmF1bHQgYXV0b2RldGVjdGlvbiBiZWhhdmlvclxuICAgICAgc2hvdWxkRGlzcGxheU5vdGljZXMgPSBpc1NhZmVUb1dyaXRlTm90aWNlcztcbiAgICB9XG4gIH1cblxuICAvLyBOb3RpY2VzIGVpdGhlciBnbyB0byBzdGRlcnIsIG9yIG5vd2hlcmVcbiAgaW9Ib3N0Lm5vdGljZXNEZXN0aW5hdGlvbiA9IHNob3VsZERpc3BsYXlOb3RpY2VzID8gJ3N0ZGVycicgOiAnZHJvcCc7XG4gIGNvbnN0IG5vdGljZXMgPSBOb3RpY2VzLmNyZWF0ZSh7XG4gICAgaW9Ib3N0LFxuICAgIGNvbnRleHQ6IGNvbmZpZ3VyYXRpb24uY29udGV4dCxcbiAgICBvdXRwdXQ6IGNvbmZpZ3VyYXRpb24uc2V0dGluZ3MuZ2V0KFsnb3V0ZGlyJ10pLFxuICAgIGh0dHBPcHRpb25zOiB7IGFnZW50OiBwcm94eUFnZW50IH0sXG4gICAgY2xpVmVyc2lvbjogdmVyc2lvbk51bWJlcigpLFxuICB9KTtcbiAgY29uc3QgcmVmcmVzaE5vdGljZXMgPSAoYXN5bmMgKCkgPT4ge1xuICAgIC8vIHRoZSBjZGsgbm90aWNlcyBjb21tYW5kIGhhcyBpdCdzIG93biByZWZyZXNoXG4gICAgaWYgKHNob3VsZERpc3BsYXlOb3RpY2VzICYmIGNtZCAhPT0gJ25vdGljZXMnKSB7XG4gICAgICB0cnkge1xuICAgICAgICByZXR1cm4gYXdhaXQgbm90aWNlcy5yZWZyZXNoKCk7XG4gICAgICB9IGNhdGNoIChlOiBhbnkpIHtcbiAgICAgICAgYXdhaXQgaW9IZWxwZXIuZGVmYXVsdHMuZGVidWcoYENvdWxkIG5vdCByZWZyZXNoIG5vdGljZXM6ICR7ZX1gKTtcbiAgICAgIH1cbiAgICB9XG4gIH0pKCk7XG5cbiAgY29uc3Qgc2RrUHJvdmlkZXIgPSBhd2FpdCBTZGtQcm92aWRlci53aXRoQXdzQ2xpQ29tcGF0aWJsZURlZmF1bHRzKHtcbiAgICBpb0hlbHBlcixcbiAgICByZXF1ZXN0SGFuZGxlcjogc2RrUmVxdWVzdEhhbmRsZXIocHJveHlBZ2VudCksXG4gICAgbG9nZ2VyOiBuZXcgSW9Ib3N0U2RrTG9nZ2VyKGFzSW9IZWxwZXIoaW9Ib3N0LCBpb0hvc3QuY3VycmVudEFjdGlvbiBhcyBhbnkpKSxcbiAgICBwbHVnaW5Ib3N0OiBHTE9CQUxfUExVR0lOX0hPU1QsXG4gIH0sIGNvbmZpZ3VyYXRpb24uc2V0dGluZ3MuZ2V0KFsncHJvZmlsZSddKSk7XG5cbiAgdHJ5IHtcbiAgICBhd2FpdCBpb0hvc3QudGVsZW1ldHJ5Py5hdHRhY2hSZWdpb24oc2RrUHJvdmlkZXIuZGVmYXVsdFJlZ2lvbik7XG4gIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgIGF3YWl0IGlvSG9zdC5hc0lvSGVscGVyKCkuZGVmYXVsdHMudHJhY2UoYFRlbGVtZXRyeSBhdHRhY2ggcmVnaW9uIGZhaWxlZDogJHtlLm1lc3NhZ2V9YCk7XG4gIH1cblxuICBsZXQgb3V0RGlyTG9jazogSVJlYWRMb2NrIHwgdW5kZWZpbmVkO1xuICBjb25zdCBjbG91ZEV4ZWN1dGFibGUgPSBuZXcgQ2xvdWRFeGVjdXRhYmxlKHtcbiAgICBjb25maWd1cmF0aW9uLFxuICAgIHNka1Byb3ZpZGVyLFxuICAgIHN5bnRoZXNpemVyOlxuICAgICAgc3ludGhlc2l6ZXIgPz9cbiAgICAgIChhc3luYyAoYXdzLCBjb25maWcpID0+IHtcbiAgICAgICAgLy8gSW52b2tlICdleGVjUHJvZ3JhbScsIGFuZCBjb3B5IHRoZSBsb2NrIGZvciB0aGUgZGlyZWN0b3J5IGluIHRoZSBnbG9iYWxcbiAgICAgICAgLy8gdmFyaWFibGUgaGVyZS4gSXQgd2lsbCBiZSByZWxlYXNlZCB3aGVuIHRoZSBDTEkgZXhpdHMuIExvY2tzIGFyZSBub3QgcmUtZW50cmFudFxuICAgICAgICAvLyBzbyByZWxlYXNlIGl0IGlmIHdlIGhhdmUgdG8gc3ludGhlc2l6ZSBtb3JlIHRoYW4gb25jZSAoYmVjYXVzZSBvZiBjb250ZXh0IGxvb2t1cHMpLlxuICAgICAgICBhd2FpdCBvdXREaXJMb2NrPy5yZWxlYXNlKCk7XG4gICAgICAgIGNvbnN0IHsgYXNzZW1ibHksIGxvY2sgfSA9IGF3YWl0IGV4ZWNQcm9ncmFtKGF3cywgaW9Ib3N0LmFzSW9IZWxwZXIoKSwgY29uZmlnKTtcbiAgICAgICAgb3V0RGlyTG9jayA9IGxvY2s7XG4gICAgICAgIHJldHVybiBhc3NlbWJseTtcbiAgICAgIH0pLFxuICAgIGlvSGVscGVyOiBpb0hvc3QuYXNJb0hlbHBlcigpLFxuICB9KTtcblxuICAvKiogRnVuY3Rpb24gdG8gbG9hZCBwbHVnLWlucywgdXNpbmcgY29uZmlndXJhdGlvbnMgYWRkaXRpdmVseS4gKi9cbiAgYXN5bmMgZnVuY3Rpb24gbG9hZFBsdWdpbnMoLi4uc2V0dGluZ3M6IFNldHRpbmdzW10pIHtcbiAgICBmb3IgKGNvbnN0IHNvdXJjZSBvZiBzZXR0aW5ncykge1xuICAgICAgY29uc3QgcGx1Z2luczogc3RyaW5nW10gPSBzb3VyY2UuZ2V0KFsncGx1Z2luJ10pIHx8IFtdO1xuICAgICAgZm9yIChjb25zdCBwbHVnaW4gb2YgcGx1Z2lucykge1xuICAgICAgICBhd2FpdCBHTE9CQUxfUExVR0lOX0hPU1QubG9hZChwbHVnaW4sIGlvSG9zdCk7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgYXdhaXQgbG9hZFBsdWdpbnMoY29uZmlndXJhdGlvbi5zZXR0aW5ncyk7XG5cbiAgaWYgKCh0eXBlb2YgY21kKSAhPT0gJ3N0cmluZycpIHtcbiAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKGBGaXJzdCBhcmd1bWVudCBzaG91bGQgYmUgYSBzdHJpbmcuIEdvdDogJHtjbWR9ICgke3R5cGVvZiBjbWR9KWApO1xuICB9XG5cbiAgdHJ5IHtcbiAgICByZXR1cm4gYXdhaXQgbWFpbihjbWQsIGFyZ3YpO1xuICB9IGZpbmFsbHkge1xuICAgIC8vIElmIHdlIGxvY2tlZCB0aGUgJ2Nkay5vdXQnIGRpcmVjdG9yeSwgcmVsZWFzZSBpdCBoZXJlLlxuICAgIGF3YWl0IG91dERpckxvY2s/LnJlbGVhc2UoKTtcblxuICAgIC8vIERvIFBTQXMgaGVyZVxuICAgIGF3YWl0IGRpc3BsYXlWZXJzaW9uTWVzc2FnZShpb0hlbHBlcik7XG5cbiAgICBhd2FpdCByZWZyZXNoTm90aWNlcztcbiAgICBpZiAoY21kID09PSAnbm90aWNlcycpIHtcbiAgICAgIGF3YWl0IG5vdGljZXMucmVmcmVzaCh7IGZvcmNlOiB0cnVlIH0pO1xuICAgICAgYXdhaXQgbm90aWNlcy5kaXNwbGF5KHtcbiAgICAgICAgaW5jbHVkZUFja25vd2xlZGdlZDogIWFyZ3YudW5hY2tub3dsZWRnZWQsXG4gICAgICAgIHNob3dUb3RhbDogYXJndi51bmFja25vd2xlZGdlZCxcbiAgICAgIH0pO1xuICAgIH0gZWxzZSBpZiAoc2hvdWxkRGlzcGxheU5vdGljZXMgJiYgY21kICE9PSAndmVyc2lvbicpIHtcbiAgICAgIGF3YWl0IG5vdGljZXMuZGlzcGxheSgpO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIGZ1bmN0aW9uIG1haW4oY29tbWFuZDogc3RyaW5nLCBhcmdzOiBhbnkpOiBQcm9taXNlPG51bWJlciB8IHZvaWQ+IHtcbiAgICBpb0hvc3QuY3VycmVudEFjdGlvbiA9IGNvbW1hbmQgYXMgYW55O1xuICAgIGNvbnN0IHRvb2xraXRTdGFja05hbWU6IHN0cmluZyA9IFRvb2xraXRJbmZvLmRldGVybWluZU5hbWUoY29uZmlndXJhdGlvbi5zZXR0aW5ncy5nZXQoWyd0b29sa2l0U3RhY2tOYW1lJ10pKTtcbiAgICBhd2FpdCBpb0hvc3QuZGVmYXVsdHMuZGVidWcoYFRvb2xraXQgc3RhY2s6ICR7Y2hhbGsuYm9sZCh0b29sa2l0U3RhY2tOYW1lKX1gKTtcblxuICAgIGNvbnN0IGNsb3VkRm9ybWF0aW9uID0gbmV3IERlcGxveW1lbnRzKHtcbiAgICAgIHNka1Byb3ZpZGVyLFxuICAgICAgdG9vbGtpdFN0YWNrTmFtZSxcbiAgICAgIGlvSGVscGVyOiBhc0lvSGVscGVyKGlvSG9zdCwgaW9Ib3N0LmN1cnJlbnRBY3Rpb24gYXMgYW55KSxcbiAgICB9KTtcblxuICAgIGlmIChhcmdzLmFsbCAmJiBhcmdzLlNUQUNLUykge1xuICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcignWW91IG11c3QgZWl0aGVyIHNwZWNpZnkgYSBsaXN0IG9mIFN0YWNrcyBvciB0aGUgYC0tYWxsYCBhcmd1bWVudCcpO1xuICAgIH1cblxuICAgIGFyZ3MuU1RBQ0tTID0gYXJncy5TVEFDS1MgPz8gKGFyZ3MuU1RBQ0sgPyBbYXJncy5TVEFDS10gOiBbXSk7XG4gICAgYXJncy5FTlZJUk9OTUVOVFMgPSBhcmdzLkVOVklST05NRU5UUyA/PyBbXTtcblxuICAgIGNvbnN0IHNlbGVjdG9yOiBTdGFja1NlbGVjdG9yID0ge1xuICAgICAgYWxsVG9wTGV2ZWw6IGFyZ3MuYWxsLFxuICAgICAgcGF0dGVybnM6IGFyZ3MuU1RBQ0tTLFxuICAgIH07XG5cbiAgICBjb25zdCBjbGkgPSBuZXcgQ2RrVG9vbGtpdCh7XG4gICAgICBpb0hvc3QsXG4gICAgICBjbG91ZEV4ZWN1dGFibGUsXG4gICAgICB0b29sa2l0U3RhY2tOYW1lLFxuICAgICAgZGVwbG95bWVudHM6IGNsb3VkRm9ybWF0aW9uLFxuICAgICAgdmVyYm9zZTogYXJndi50cmFjZSB8fCBhcmd2LnZlcmJvc2UgPiAwLFxuICAgICAgaWdub3JlRXJyb3JzOiBhcmd2WydpZ25vcmUtZXJyb3JzJ10sXG4gICAgICBzdHJpY3Q6IGFyZ3Yuc3RyaWN0LFxuICAgICAgY29uZmlndXJhdGlvbixcbiAgICAgIHNka1Byb3ZpZGVyLFxuICAgIH0pO1xuXG4gICAgc3dpdGNoIChjb21tYW5kKSB7XG4gICAgICBjYXNlICdjb250ZXh0JzpcbiAgICAgICAgaW9Ib3N0LmN1cnJlbnRBY3Rpb24gPSAnY29udGV4dCc7XG4gICAgICAgIHJldHVybiBjb250ZXh0KHtcbiAgICAgICAgICBpb0hlbHBlcixcbiAgICAgICAgICBjb250ZXh0OiBjb25maWd1cmF0aW9uLmNvbnRleHQsXG4gICAgICAgICAgY2xlYXI6IGFyZ3YuY2xlYXIsXG4gICAgICAgICAganNvbjogYXJndi5qc29uLFxuICAgICAgICAgIGZvcmNlOiBhcmd2LmZvcmNlLFxuICAgICAgICAgIHJlc2V0OiBhcmd2LnJlc2V0LFxuICAgICAgICB9KTtcblxuICAgICAgY2FzZSAnZG9jcyc6XG4gICAgICBjYXNlICdkb2MnOlxuICAgICAgICBpb0hvc3QuY3VycmVudEFjdGlvbiA9ICdkb2NzJztcbiAgICAgICAgcmV0dXJuIGRvY3Moe1xuICAgICAgICAgIGlvSGVscGVyLFxuICAgICAgICAgIGJyb3dzZXI6IGNvbmZpZ3VyYXRpb24uc2V0dGluZ3MuZ2V0KFsnYnJvd3NlciddKSxcbiAgICAgICAgfSk7XG5cbiAgICAgIGNhc2UgJ2RvY3Rvcic6XG4gICAgICAgIGlvSG9zdC5jdXJyZW50QWN0aW9uID0gJ2RvY3Rvcic7XG4gICAgICAgIHJldHVybiBkb2N0b3Ioe1xuICAgICAgICAgIGlvSGVscGVyLFxuICAgICAgICB9KTtcblxuICAgICAgY2FzZSAnbHMnOlxuICAgICAgY2FzZSAnbGlzdCc6XG4gICAgICAgIGlvSG9zdC5jdXJyZW50QWN0aW9uID0gJ2xpc3QnO1xuICAgICAgICByZXR1cm4gY2xpLmxpc3QoYXJncy5TVEFDS1MsIHtcbiAgICAgICAgICBsb25nOiBhcmdzLmxvbmcsXG4gICAgICAgICAganNvbjogYXJndi5qc29uLFxuICAgICAgICAgIHNob3dEZXBzOiBhcmdzLnNob3dEZXBlbmRlbmNpZXMsXG4gICAgICAgIH0pO1xuXG4gICAgICBjYXNlICdkaWZmJzpcbiAgICAgICAgaW9Ib3N0LmN1cnJlbnRBY3Rpb24gPSAnZGlmZic7XG4gICAgICAgIGNvbnN0IGVuYWJsZURpZmZOb0ZhaWwgPSBpc0ZlYXR1cmVFbmFibGVkKGNvbmZpZ3VyYXRpb24sIGN4YXBpLkVOQUJMRV9ESUZGX05PX0ZBSUxfQ09OVEVYVCk7XG4gICAgICAgIHJldHVybiBjbGkuZGlmZih7XG4gICAgICAgICAgc3RhY2tOYW1lczogYXJncy5TVEFDS1MsXG4gICAgICAgICAgZXhjbHVzaXZlbHk6IGFyZ3MuZXhjbHVzaXZlbHksXG4gICAgICAgICAgdGVtcGxhdGVQYXRoOiBhcmdzLnRlbXBsYXRlLFxuICAgICAgICAgIHN0cmljdDogYXJncy5zdHJpY3QsXG4gICAgICAgICAgY29udGV4dExpbmVzOiBhcmdzLmNvbnRleHRMaW5lcyxcbiAgICAgICAgICBzZWN1cml0eU9ubHk6IGFyZ3Muc2VjdXJpdHlPbmx5LFxuICAgICAgICAgIGZhaWw6IGFyZ3MuZmFpbCAhPSBudWxsID8gYXJncy5mYWlsIDogIWVuYWJsZURpZmZOb0ZhaWwsXG4gICAgICAgICAgY29tcGFyZUFnYWluc3RQcm9jZXNzZWRUZW1wbGF0ZTogYXJncy5wcm9jZXNzZWQsXG4gICAgICAgICAgcXVpZXQ6IGFyZ3MucXVpZXQsXG4gICAgICAgICAgY2hhbmdlU2V0OiBhcmdzWydjaGFuZ2Utc2V0J10sXG4gICAgICAgICAgdG9vbGtpdFN0YWNrTmFtZTogdG9vbGtpdFN0YWNrTmFtZSxcbiAgICAgICAgICBpbXBvcnRFeGlzdGluZ1Jlc291cmNlczogYXJncy5pbXBvcnRFeGlzdGluZ1Jlc291cmNlcyxcbiAgICAgICAgICBpbmNsdWRlTW92ZXM6IGFyZ3NbJ2luY2x1ZGUtbW92ZXMnXSxcbiAgICAgICAgfSk7XG5cbiAgICAgIGNhc2UgJ2RyaWZ0JzpcbiAgICAgICAgaW9Ib3N0LmN1cnJlbnRBY3Rpb24gPSAnZHJpZnQnO1xuICAgICAgICByZXR1cm4gY2xpLmRyaWZ0KHtcbiAgICAgICAgICBzZWxlY3RvcixcbiAgICAgICAgICBmYWlsOiBhcmdzLmZhaWwsXG4gICAgICAgIH0pO1xuXG4gICAgICBjYXNlICdyZWZhY3Rvcic6XG4gICAgICAgIGlmICghY29uZmlndXJhdGlvbi5zZXR0aW5ncy5nZXQoWyd1bnN0YWJsZSddKS5pbmNsdWRlcygncmVmYWN0b3InKSkge1xuICAgICAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoJ1Vuc3RhYmxlIGZlYXR1cmUgdXNlOiBcXCdyZWZhY3RvclxcJyBpcyB1bnN0YWJsZS4gSXQgbXVzdCBiZSBvcHRlZCBpbiB2aWEgXFwnLS11bnN0YWJsZVxcJywgZS5nLiBcXCdjZGsgcmVmYWN0b3IgLS11bnN0YWJsZT1yZWZhY3RvclxcJycpO1xuICAgICAgICB9XG5cbiAgICAgICAgaW9Ib3N0LmN1cnJlbnRBY3Rpb24gPSAncmVmYWN0b3InO1xuICAgICAgICByZXR1cm4gY2xpLnJlZmFjdG9yKHtcbiAgICAgICAgICBkcnlSdW46IGFyZ3MuZHJ5UnVuLFxuICAgICAgICAgIG92ZXJyaWRlRmlsZTogYXJncy5vdmVycmlkZUZpbGUsXG4gICAgICAgICAgcmV2ZXJ0OiBhcmdzLnJldmVydCxcbiAgICAgICAgICBzdGFja3M6IHNlbGVjdG9yLFxuICAgICAgICAgIGFkZGl0aW9uYWxTdGFja05hbWVzOiBhcnJheUZyb21ZYXJncyhhcmdzLmFkZGl0aW9uYWxTdGFja05hbWUgPz8gW10pLFxuICAgICAgICAgIGZvcmNlOiBhcmdzLmZvcmNlID8/IGZhbHNlLFxuICAgICAgICAgIHJvbGVBcm46IGFyZ3Mucm9sZUFybixcbiAgICAgICAgfSk7XG5cbiAgICAgIGNhc2UgJ2Jvb3RzdHJhcCc6XG4gICAgICAgIGlvSG9zdC5jdXJyZW50QWN0aW9uID0gJ2Jvb3RzdHJhcCc7XG4gICAgICAgIGNvbnN0IHNvdXJjZTogQm9vdHN0cmFwU291cmNlID0gYXdhaXQgZGV0ZXJtaW5lQm9vdHN0cmFwVmVyc2lvbihpb0hvc3QsIGFyZ3MpO1xuXG4gICAgICAgIGlmIChhcmdzLnNob3dUZW1wbGF0ZSkge1xuICAgICAgICAgIGNvbnN0IGJvb3RzdHJhcHBlciA9IG5ldyBCb290c3RyYXBwZXIoc291cmNlLCBhc0lvSGVscGVyKGlvSG9zdCwgaW9Ib3N0LmN1cnJlbnRBY3Rpb24pKTtcbiAgICAgICAgICByZXR1cm4gYm9vdHN0cmFwcGVyLnNob3dUZW1wbGF0ZShhcmdzLmpzb24pO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIGNsaS5ib290c3RyYXAoYXJncy5FTlZJUk9OTUVOVFMsIHtcbiAgICAgICAgICBzb3VyY2UsXG4gICAgICAgICAgcm9sZUFybjogYXJncy5yb2xlQXJuLFxuICAgICAgICAgIGZvcmNlRGVwbG95bWVudDogYXJndi5mb3JjZSxcbiAgICAgICAgICB0b29sa2l0U3RhY2tOYW1lOiB0b29sa2l0U3RhY2tOYW1lLFxuICAgICAgICAgIGV4ZWN1dGU6IGFyZ3MuZXhlY3V0ZSxcbiAgICAgICAgICB0YWdzOiBjb25maWd1cmF0aW9uLnNldHRpbmdzLmdldChbJ3RhZ3MnXSksXG4gICAgICAgICAgdGVybWluYXRpb25Qcm90ZWN0aW9uOiBhcmdzLnRlcm1pbmF0aW9uUHJvdGVjdGlvbixcbiAgICAgICAgICB1c2VQcmV2aW91c1BhcmFtZXRlcnM6IGFyZ3NbJ3ByZXZpb3VzLXBhcmFtZXRlcnMnXSxcbiAgICAgICAgICBwYXJhbWV0ZXJzOiB7XG4gICAgICAgICAgICBidWNrZXROYW1lOiBjb25maWd1cmF0aW9uLnNldHRpbmdzLmdldChbJ3Rvb2xraXRCdWNrZXQnLCAnYnVja2V0TmFtZSddKSxcbiAgICAgICAgICAgIGttc0tleUlkOiBjb25maWd1cmF0aW9uLnNldHRpbmdzLmdldChbJ3Rvb2xraXRCdWNrZXQnLCAna21zS2V5SWQnXSksXG4gICAgICAgICAgICBjcmVhdGVDdXN0b21lck1hc3RlcktleTogYXJncy5ib290c3RyYXBDdXN0b21lcktleSxcbiAgICAgICAgICAgIHF1YWxpZmllcjogYXJncy5xdWFsaWZpZXIgPz8gY29uZmlndXJhdGlvbi5jb250ZXh0LmdldCgnQGF3cy1jZGsvY29yZTpib290c3RyYXBRdWFsaWZpZXInKSxcbiAgICAgICAgICAgIHB1YmxpY0FjY2Vzc0Jsb2NrQ29uZmlndXJhdGlvbjogYXJncy5wdWJsaWNBY2Nlc3NCbG9ja0NvbmZpZ3VyYXRpb24sXG4gICAgICAgICAgICBleGFtcGxlUGVybWlzc2lvbnNCb3VuZGFyeTogYXJndi5leGFtcGxlUGVybWlzc2lvbnNCb3VuZGFyeSxcbiAgICAgICAgICAgIGN1c3RvbVBlcm1pc3Npb25zQm91bmRhcnk6IGFyZ3YuY3VzdG9tUGVybWlzc2lvbnNCb3VuZGFyeSxcbiAgICAgICAgICAgIHRydXN0ZWRBY2NvdW50czogYXJyYXlGcm9tWWFyZ3MoYXJncy50cnVzdCksXG4gICAgICAgICAgICB0cnVzdGVkQWNjb3VudHNGb3JMb29rdXA6IGFycmF5RnJvbVlhcmdzKGFyZ3MudHJ1c3RGb3JMb29rdXApLFxuICAgICAgICAgICAgdW50cnVzdGVkQWNjb3VudHM6IGFycmF5RnJvbVlhcmdzKGFyZ3MudW50cnVzdCksXG4gICAgICAgICAgICBjbG91ZEZvcm1hdGlvbkV4ZWN1dGlvblBvbGljaWVzOiBhcnJheUZyb21ZYXJncyhhcmdzLmNsb3VkZm9ybWF0aW9uRXhlY3V0aW9uUG9saWNpZXMpLFxuICAgICAgICAgICAgZGVueUV4dGVybmFsSWQ6IGFyZ3MuZGVueUV4dGVybmFsSWQsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSk7XG5cbiAgICAgIGNhc2UgJ2RlcGxveSc6XG4gICAgICAgIGlvSG9zdC5jdXJyZW50QWN0aW9uID0gJ2RlcGxveSc7XG4gICAgICAgIGNvbnN0IHBhcmFtZXRlck1hcDogeyBbbmFtZTogc3RyaW5nXTogc3RyaW5nIHwgdW5kZWZpbmVkIH0gPSB7fTtcbiAgICAgICAgZm9yIChjb25zdCBwYXJhbWV0ZXIgb2YgYXJncy5wYXJhbWV0ZXJzKSB7XG4gICAgICAgICAgaWYgKHR5cGVvZiBwYXJhbWV0ZXIgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICBjb25zdCBrZXlWYWx1ZSA9IChwYXJhbWV0ZXIgYXMgc3RyaW5nKS5zcGxpdCgnPScpO1xuICAgICAgICAgICAgcGFyYW1ldGVyTWFwW2tleVZhbHVlWzBdXSA9IGtleVZhbHVlLnNsaWNlKDEpLmpvaW4oJz0nKTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoYXJncy5leGVjdXRlICE9PSB1bmRlZmluZWQgJiYgYXJncy5tZXRob2QgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoJ0NhbiBub3Qgc3VwcGx5IGJvdGggLS1bbm8tXWV4ZWN1dGUgYW5kIC0tbWV0aG9kIGF0IHRoZSBzYW1lIHRpbWUnKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBjbGkuZGVwbG95KHtcbiAgICAgICAgICBzZWxlY3RvcixcbiAgICAgICAgICBleGNsdXNpdmVseTogYXJncy5leGNsdXNpdmVseSxcbiAgICAgICAgICB0b29sa2l0U3RhY2tOYW1lLFxuICAgICAgICAgIHJvbGVBcm46IGFyZ3Mucm9sZUFybixcbiAgICAgICAgICBub3RpZmljYXRpb25Bcm5zOiBhcmdzLm5vdGlmaWNhdGlvbkFybnMsXG4gICAgICAgICAgcmVxdWlyZUFwcHJvdmFsOiBjb25maWd1cmF0aW9uLnNldHRpbmdzLmdldChbJ3JlcXVpcmVBcHByb3ZhbCddKSxcbiAgICAgICAgICByZXVzZUFzc2V0czogYXJnc1snYnVpbGQtZXhjbHVkZSddLFxuICAgICAgICAgIHRhZ3M6IGNvbmZpZ3VyYXRpb24uc2V0dGluZ3MuZ2V0KFsndGFncyddKSxcbiAgICAgICAgICBkZXBsb3ltZW50TWV0aG9kOiBkZXRlcm1pbmVEZXBsb3ltZW50TWV0aG9kKGFyZ3MsIGNvbmZpZ3VyYXRpb24pLFxuICAgICAgICAgIGZvcmNlOiBhcmdzLmZvcmNlLFxuICAgICAgICAgIHBhcmFtZXRlcnM6IHBhcmFtZXRlck1hcCxcbiAgICAgICAgICB1c2VQcmV2aW91c1BhcmFtZXRlcnM6IGFyZ3NbJ3ByZXZpb3VzLXBhcmFtZXRlcnMnXSxcbiAgICAgICAgICBvdXRwdXRzRmlsZTogY29uZmlndXJhdGlvbi5zZXR0aW5ncy5nZXQoWydvdXRwdXRzRmlsZSddKSxcbiAgICAgICAgICBwcm9ncmVzczogY29uZmlndXJhdGlvbi5zZXR0aW5ncy5nZXQoWydwcm9ncmVzcyddKSxcbiAgICAgICAgICBjaTogYXJncy5jaSxcbiAgICAgICAgICByb2xsYmFjazogY29uZmlndXJhdGlvbi5zZXR0aW5ncy5nZXQoWydyb2xsYmFjayddKSxcbiAgICAgICAgICB3YXRjaDogYXJncy53YXRjaCxcbiAgICAgICAgICB0cmFjZUxvZ3M6IGFyZ3MubG9ncyxcbiAgICAgICAgICBjb25jdXJyZW5jeTogYXJncy5jb25jdXJyZW5jeSxcbiAgICAgICAgICBhc3NldFBhcmFsbGVsaXNtOiBjb25maWd1cmF0aW9uLnNldHRpbmdzLmdldChbJ2Fzc2V0UGFyYWxsZWxpc20nXSksXG4gICAgICAgICAgYXNzZXRCdWlsZFRpbWU6IGNvbmZpZ3VyYXRpb24uc2V0dGluZ3MuZ2V0KFsnYXNzZXRQcmVidWlsZCddKVxuICAgICAgICAgICAgPyBBc3NldEJ1aWxkVGltZS5BTExfQkVGT1JFX0RFUExPWVxuICAgICAgICAgICAgOiBBc3NldEJ1aWxkVGltZS5KVVNUX0lOX1RJTUUsXG4gICAgICAgICAgaWdub3JlTm9TdGFja3M6IGFyZ3MuaWdub3JlTm9TdGFja3MsXG4gICAgICAgIH0pO1xuXG4gICAgICBjYXNlICdyb2xsYmFjayc6XG4gICAgICAgIGlvSG9zdC5jdXJyZW50QWN0aW9uID0gJ3JvbGxiYWNrJztcbiAgICAgICAgcmV0dXJuIGNsaS5yb2xsYmFjayh7XG4gICAgICAgICAgc2VsZWN0b3IsXG4gICAgICAgICAgdG9vbGtpdFN0YWNrTmFtZSxcbiAgICAgICAgICByb2xlQXJuOiBhcmdzLnJvbGVBcm4sXG4gICAgICAgICAgZm9yY2U6IGFyZ3MuZm9yY2UsXG4gICAgICAgICAgdmFsaWRhdGVCb290c3RyYXBTdGFja1ZlcnNpb246IGFyZ3NbJ3ZhbGlkYXRlLWJvb3RzdHJhcC12ZXJzaW9uJ10sXG4gICAgICAgICAgb3JwaGFuTG9naWNhbElkczogYXJncy5vcnBoYW4sXG4gICAgICAgIH0pO1xuXG4gICAgICBjYXNlICdpbXBvcnQnOlxuICAgICAgICBpb0hvc3QuY3VycmVudEFjdGlvbiA9ICdpbXBvcnQnO1xuICAgICAgICByZXR1cm4gY2xpLmltcG9ydCh7XG4gICAgICAgICAgc2VsZWN0b3IsXG4gICAgICAgICAgdG9vbGtpdFN0YWNrTmFtZSxcbiAgICAgICAgICByb2xlQXJuOiBhcmdzLnJvbGVBcm4sXG4gICAgICAgICAgZGVwbG95bWVudE1ldGhvZDoge1xuICAgICAgICAgICAgbWV0aG9kOiAnY2hhbmdlLXNldCcsXG4gICAgICAgICAgICBleGVjdXRlOiBhcmdzLmV4ZWN1dGUsXG4gICAgICAgICAgICBjaGFuZ2VTZXROYW1lOiBhcmdzLmNoYW5nZVNldE5hbWUsXG4gICAgICAgICAgfSxcbiAgICAgICAgICBwcm9ncmVzczogY29uZmlndXJhdGlvbi5zZXR0aW5ncy5nZXQoWydwcm9ncmVzcyddKSxcbiAgICAgICAgICByb2xsYmFjazogY29uZmlndXJhdGlvbi5zZXR0aW5ncy5nZXQoWydyb2xsYmFjayddKSxcbiAgICAgICAgICByZWNvcmRSZXNvdXJjZU1hcHBpbmc6IGFyZ3NbJ3JlY29yZC1yZXNvdXJjZS1tYXBwaW5nJ10sXG4gICAgICAgICAgcmVzb3VyY2VNYXBwaW5nRmlsZTogYXJnc1sncmVzb3VyY2UtbWFwcGluZyddLFxuICAgICAgICAgIGZvcmNlOiBhcmdzLmZvcmNlLFxuICAgICAgICB9KTtcblxuICAgICAgY2FzZSAnd2F0Y2gnOlxuICAgICAgICBpb0hvc3QuY3VycmVudEFjdGlvbiA9ICd3YXRjaCc7XG4gICAgICAgIGF3YWl0IGNsaS53YXRjaCh7XG4gICAgICAgICAgc2VsZWN0b3IsXG4gICAgICAgICAgZXhjbHVzaXZlbHk6IGFyZ3MuZXhjbHVzaXZlbHksXG4gICAgICAgICAgdG9vbGtpdFN0YWNrTmFtZSxcbiAgICAgICAgICByb2xlQXJuOiBhcmdzLnJvbGVBcm4sXG4gICAgICAgICAgcmV1c2VBc3NldHM6IGFyZ3NbJ2J1aWxkLWV4Y2x1ZGUnXSxcbiAgICAgICAgICBkZXBsb3ltZW50TWV0aG9kOiBkZXRlcm1pbmVEZXBsb3ltZW50TWV0aG9kKGFyZ3MsIGNvbmZpZ3VyYXRpb24sIHRydWUpLFxuICAgICAgICAgIGZvcmNlOiBhcmdzLmZvcmNlLFxuICAgICAgICAgIHByb2dyZXNzOiBjb25maWd1cmF0aW9uLnNldHRpbmdzLmdldChbJ3Byb2dyZXNzJ10pLFxuICAgICAgICAgIHJvbGxiYWNrOiBjb25maWd1cmF0aW9uLnNldHRpbmdzLmdldChbJ3JvbGxiYWNrJ10pLFxuICAgICAgICAgIHRyYWNlTG9nczogYXJncy5sb2dzLFxuICAgICAgICAgIGNvbmN1cnJlbmN5OiBhcmdzLmNvbmN1cnJlbmN5LFxuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuO1xuXG4gICAgICBjYXNlICdkZXN0cm95JzpcbiAgICAgICAgaW9Ib3N0LmN1cnJlbnRBY3Rpb24gPSAnZGVzdHJveSc7XG4gICAgICAgIHJldHVybiBjbGkuZGVzdHJveSh7XG4gICAgICAgICAgc2VsZWN0b3IsXG4gICAgICAgICAgZXhjbHVzaXZlbHk6IGFyZ3MuZXhjbHVzaXZlbHksXG4gICAgICAgICAgZm9yY2U6IGFyZ3MuZm9yY2UsXG4gICAgICAgICAgcm9sZUFybjogYXJncy5yb2xlQXJuLFxuICAgICAgICB9KTtcblxuICAgICAgY2FzZSAnZ2MnOlxuICAgICAgICBpb0hvc3QuY3VycmVudEFjdGlvbiA9ICdnYyc7XG4gICAgICAgIGlmICghY29uZmlndXJhdGlvbi5zZXR0aW5ncy5nZXQoWyd1bnN0YWJsZSddKS5pbmNsdWRlcygnZ2MnKSkge1xuICAgICAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoJ1Vuc3RhYmxlIGZlYXR1cmUgdXNlOiBcXCdnY1xcJyBpcyB1bnN0YWJsZS4gSXQgbXVzdCBiZSBvcHRlZCBpbiB2aWEgXFwnLS11bnN0YWJsZVxcJywgZS5nLiBcXCdjZGsgZ2MgLS11bnN0YWJsZT1nY1xcJycpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChhcmdzLmJvb3RzdHJhcFN0YWNrTmFtZSkge1xuICAgICAgICAgIGF3YWl0IGlvSG9zdC5kZWZhdWx0cy53YXJuKCctLWJvb3RzdHJhcC1zdGFjay1uYW1lIGlzIGRlcHJlY2F0ZWQgYW5kIHdpbGwgYmUgcmVtb3ZlZCB3aGVuIGdjIGlzIEdBLiBVc2UgLS10b29sa2l0LXN0YWNrLW5hbWUuJyk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gcm9sZUFybiBpcyBkZWZpbmVkIGZvciB3aGVuIGNsb3VkZm9ybWF0aW9uIGlzIGludm9rZWRcbiAgICAgICAgLy8gVGhpcyBjb25mbGljdHMgd2l0aCBkaXJlY3Qgc2RrIGNhbGxzIGV4aXN0aW5nIGluIHRoZSBnYyBjb21tYW5kIHRvIHMzIGFuZCBlY3JcbiAgICAgICAgaWYgKGFyZ3Mucm9sZUFybikge1xuICAgICAgICAgIGF3YWl0IGlvSG9zdC5kZWZhdWx0cy53YXJuKCdUaGUgLS1yb2xlLWFybiBvcHRpb24gaXMgbm90IHN1cHBvcnRlZCBmb3IgdGhlIGdjIGNvbW1hbmQgYW5kIHdpbGwgYmUgaWdub3JlZC4nKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gY2xpLmdhcmJhZ2VDb2xsZWN0KGFyZ3MuRU5WSVJPTk1FTlRTLCB7XG4gICAgICAgICAgYWN0aW9uOiBhcmdzLmFjdGlvbixcbiAgICAgICAgICB0eXBlOiBhcmdzLnR5cGUsXG4gICAgICAgICAgcm9sbGJhY2tCdWZmZXJEYXlzOiBhcmdzWydyb2xsYmFjay1idWZmZXItZGF5cyddLFxuICAgICAgICAgIGNyZWF0ZWRCdWZmZXJEYXlzOiBhcmdzWydjcmVhdGVkLWJ1ZmZlci1kYXlzJ10sXG4gICAgICAgICAgYm9vdHN0cmFwU3RhY2tOYW1lOiBhcmdzLnRvb2xraXRTdGFja05hbWUgPz8gYXJncy5ib290c3RyYXBTdGFja05hbWUsXG4gICAgICAgICAgY29uZmlybTogYXJncy5jb25maXJtLFxuICAgICAgICB9KTtcblxuICAgICAgY2FzZSAnZmxhZ3MnOlxuICAgICAgICBpb0hvc3QuY3VycmVudEFjdGlvbiA9ICdmbGFncyc7XG5cbiAgICAgICAgaWYgKCFjb25maWd1cmF0aW9uLnNldHRpbmdzLmdldChbJ3Vuc3RhYmxlJ10pLmluY2x1ZGVzKCdmbGFncycpKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcignVW5zdGFibGUgZmVhdHVyZSB1c2U6IFxcJ2ZsYWdzXFwnIGlzIHVuc3RhYmxlLiBJdCBtdXN0IGJlIG9wdGVkIGluIHZpYSBcXCctLXVuc3RhYmxlXFwnLCBlLmcuIFxcJ2NkayBmbGFncyAtLXVuc3RhYmxlPWZsYWdzXFwnJyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgdG9vbGtpdCA9IG5ldyBUb29sa2l0KHtcbiAgICAgICAgICBpb0hvc3QsXG4gICAgICAgICAgdG9vbGtpdFN0YWNrTmFtZSxcbiAgICAgICAgICB1bnN0YWJsZUZlYXR1cmVzOiBjb25maWd1cmF0aW9uLnNldHRpbmdzLmdldChbJ3Vuc3RhYmxlJ10pLFxuICAgICAgICB9KTtcbiAgICAgICAgY29uc3QgZmxhZ3NEYXRhID0gYXdhaXQgdG9vbGtpdC5mbGFncyhjbG91ZEV4ZWN1dGFibGUpO1xuICAgICAgICBjb25zdCBoYW5kbGVyID0gbmV3IEZsYWdDb21tYW5kSGFuZGxlcihmbGFnc0RhdGEsIGlvSGVscGVyLCBhcmdzLCB0b29sa2l0KTtcbiAgICAgICAgcmV0dXJuIGhhbmRsZXIucHJvY2Vzc0ZsYWdzQ29tbWFuZCgpO1xuXG4gICAgICBjYXNlICdzeW50aGVzaXplJzpcbiAgICAgIGNhc2UgJ3N5bnRoJzpcbiAgICAgICAgaW9Ib3N0LmN1cnJlbnRBY3Rpb24gPSAnc3ludGgnO1xuICAgICAgICBjb25zdCBxdWlldCA9IGNvbmZpZ3VyYXRpb24uc2V0dGluZ3MuZ2V0KFsncXVpZXQnXSkgPz8gYXJncy5xdWlldDtcbiAgICAgICAgaWYgKGFyZ3MuZXhjbHVzaXZlbHkpIHtcbiAgICAgICAgICByZXR1cm4gY2xpLnN5bnRoKGFyZ3MuU1RBQ0tTLCBhcmdzLmV4Y2x1c2l2ZWx5LCBxdWlldCwgYXJncy52YWxpZGF0aW9uLCBhcmd2Lmpzb24pO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHJldHVybiBjbGkuc3ludGgoYXJncy5TVEFDS1MsIHRydWUsIHF1aWV0LCBhcmdzLnZhbGlkYXRpb24sIGFyZ3YuanNvbik7XG4gICAgICAgIH1cblxuICAgICAgY2FzZSAnbm90aWNlcyc6XG4gICAgICAgIGlvSG9zdC5jdXJyZW50QWN0aW9uID0gJ25vdGljZXMnO1xuICAgICAgICAvLyBJZiB0aGUgdXNlciBleHBsaWNpdGx5IGFza3MgZm9yIG5vdGljZXMsIHRoZXkgYXJlIG5vdyB0aGUgcHJpbWFyeSBvdXRwdXRcbiAgICAgICAgLy8gb2YgdGhlIGNvbW1hbmQgYW5kIHRoZXkgc2hvdWxkIGdvIHRvIHN0ZG91dC5cbiAgICAgICAgaW9Ib3N0Lm5vdGljZXNEZXN0aW5hdGlvbiA9ICdzdGRvdXQnO1xuXG4gICAgICAgIC8vIFRoaXMgaXMgYSB2YWxpZCBjb21tYW5kLCBidXQgd2UncmUgcG9zdHBvbmluZyBpdHMgZXhlY3V0aW9uIGJlY2F1c2UgZGlzcGxheWluZ1xuICAgICAgICAvLyBub3RpY2VzIGF1dG9tYXRpY2FsbHkgaGFwcGVucyBhZnRlciBldmVyeSBjb21tYW5kLlxuICAgICAgICByZXR1cm47XG5cbiAgICAgIGNhc2UgJ21ldGFkYXRhJzpcbiAgICAgICAgaW9Ib3N0LmN1cnJlbnRBY3Rpb24gPSAnbWV0YWRhdGEnO1xuICAgICAgICByZXR1cm4gY2xpLm1ldGFkYXRhKGFyZ3MuU1RBQ0ssIGFyZ3YuanNvbik7XG5cbiAgICAgIGNhc2UgJ2Fja25vd2xlZGdlJzpcbiAgICAgIGNhc2UgJ2Fjayc6XG4gICAgICAgIGlvSG9zdC5jdXJyZW50QWN0aW9uID0gJ25vdGljZXMnO1xuICAgICAgICByZXR1cm4gY2xpLmFja25vd2xlZGdlKGFyZ3MuSUQpO1xuXG4gICAgICBjYXNlICdjbGktdGVsZW1ldHJ5JzpcbiAgICAgICAgaW9Ib3N0LmN1cnJlbnRBY3Rpb24gPSAnY2xpLXRlbGVtZXRyeSc7XG4gICAgICAgIGlmIChhcmdzLmVuYWJsZSA9PT0gdW5kZWZpbmVkICYmIGFyZ3MuZGlzYWJsZSA9PT0gdW5kZWZpbmVkICYmIGFyZ3Muc3RhdHVzID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKCdNdXN0IHNwZWNpZnkgXFwnLS1lbmFibGVcXCcsIFxcJy0tZGlzYWJsZVxcJywgb3IgXFwnLS1zdGF0dXNcXCcnKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChhcmdzLnN0YXR1cykge1xuICAgICAgICAgIHJldHVybiBjbGkuY2xpVGVsZW1ldHJ5U3RhdHVzKGFyZ3NbJ3ZlcnNpb24tcmVwb3J0aW5nJ10pO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGNvbnN0IGVuYWJsZSA9IGFyZ3MuZW5hYmxlID8/ICFhcmdzLmRpc2FibGU7XG4gICAgICAgICAgcmV0dXJuIGNsaS5jbGlUZWxlbWV0cnkoZW5hYmxlKTtcbiAgICAgICAgfVxuICAgICAgY2FzZSAnaW5pdCc6XG4gICAgICAgIGlvSG9zdC5jdXJyZW50QWN0aW9uID0gJ2luaXQnO1xuICAgICAgICBjb25zdCBsYW5ndWFnZSA9IGNvbmZpZ3VyYXRpb24uc2V0dGluZ3MuZ2V0KFsnbGFuZ3VhZ2UnXSk7XG4gICAgICAgIGlmIChhcmdzLmxpc3QpIHtcbiAgICAgICAgICByZXR1cm4gcHJpbnRBdmFpbGFibGVUZW1wbGF0ZXMoaW9IZWxwZXIsIGxhbmd1YWdlKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAvLyBHYXRlIGN1c3RvbSB0ZW1wbGF0ZSBzdXBwb3J0IHdpdGggdW5zdGFibGUgZmxhZ1xuICAgICAgICAgIGlmIChhcmdzWydmcm9tLXBhdGgnXSAmJiAhY29uZmlndXJhdGlvbi5zZXR0aW5ncy5nZXQoWyd1bnN0YWJsZSddKS5pbmNsdWRlcygnaW5pdCcpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKCdVbnN0YWJsZSBmZWF0dXJlIHVzZTogXFwnaW5pdFxcJyB3aXRoIGN1c3RvbSB0ZW1wbGF0ZXMgaXMgdW5zdGFibGUuIEl0IG11c3QgYmUgb3B0ZWQgaW4gdmlhIFxcJy0tdW5zdGFibGVcXCcsIGUuZy4gXFwnY2RrIGluaXQgLS1mcm9tLXBhdGg9Li9teS10ZW1wbGF0ZSAtLXVuc3RhYmxlPWluaXRcXCcnKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuIGNsaUluaXQoe1xuICAgICAgICAgICAgaW9IZWxwZXIsXG4gICAgICAgICAgICB0eXBlOiBhcmdzLlRFTVBMQVRFLFxuICAgICAgICAgICAgbGFuZ3VhZ2UsXG4gICAgICAgICAgICBjYW5Vc2VOZXR3b3JrOiB1bmRlZmluZWQsXG4gICAgICAgICAgICBnZW5lcmF0ZU9ubHk6IGFyZ3MuZ2VuZXJhdGVPbmx5LFxuICAgICAgICAgICAgbGliVmVyc2lvbjogYXJncy5saWJWZXJzaW9uLFxuICAgICAgICAgICAgZnJvbVBhdGg6IGFyZ3NbJ2Zyb20tcGF0aCddLFxuICAgICAgICAgICAgdGVtcGxhdGVQYXRoOiBhcmdzWyd0ZW1wbGF0ZS1wYXRoJ10sXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIGNhc2UgJ21pZ3JhdGUnOlxuICAgICAgICBpb0hvc3QuY3VycmVudEFjdGlvbiA9ICdtaWdyYXRlJztcbiAgICAgICAgcmV0dXJuIGNsaS5taWdyYXRlKHtcbiAgICAgICAgICBzdGFja05hbWU6IGFyZ3NbJ3N0YWNrLW5hbWUnXSxcbiAgICAgICAgICBmcm9tUGF0aDogYXJnc1snZnJvbS1wYXRoJ10sXG4gICAgICAgICAgZnJvbVN0YWNrOiBhcmdzWydmcm9tLXN0YWNrJ10sXG4gICAgICAgICAgbGFuZ3VhZ2U6IGFyZ3MubGFuZ3VhZ2UsXG4gICAgICAgICAgb3V0cHV0UGF0aDogYXJnc1snb3V0cHV0LXBhdGgnXSxcbiAgICAgICAgICBmcm9tU2NhbjogZ2V0TWlncmF0ZVNjYW5UeXBlKGFyZ3NbJ2Zyb20tc2NhbiddKSxcbiAgICAgICAgICBmaWx0ZXI6IGFyZ3MuZmlsdGVyLFxuICAgICAgICAgIGFjY291bnQ6IGFyZ3MuYWNjb3VudCxcbiAgICAgICAgICByZWdpb246IGFyZ3MucmVnaW9uLFxuICAgICAgICAgIGNvbXByZXNzOiBhcmdzLmNvbXByZXNzLFxuICAgICAgICB9KTtcbiAgICAgIGNhc2UgJ3ZlcnNpb24nOlxuICAgICAgICBpb0hvc3QuY3VycmVudEFjdGlvbiA9ICd2ZXJzaW9uJztcbiAgICAgICAgcmV0dXJuIGlvSG9zdC5kZWZhdWx0cy5yZXN1bHQodmVyc2lvbldpdGhCdWlsZCgpKTtcblxuICAgICAgZGVmYXVsdDpcbiAgICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcignVW5rbm93biBjb21tYW5kOiAnICsgY29tbWFuZCk7XG4gICAgfVxuICB9XG59XG5cbi8qKlxuICogRGV0ZXJtaW5lIHdoaWNoIHZlcnNpb24gb2YgYm9vdHN0cmFwcGluZ1xuICovXG5hc3luYyBmdW5jdGlvbiBkZXRlcm1pbmVCb290c3RyYXBWZXJzaW9uKGlvSG9zdDogQ2xpSW9Ib3N0LCBhcmdzOiB7IHRlbXBsYXRlPzogc3RyaW5nIH0pOiBQcm9taXNlPEJvb3RzdHJhcFNvdXJjZT4ge1xuICBsZXQgc291cmNlOiBCb290c3RyYXBTb3VyY2U7XG4gIGlmIChhcmdzLnRlbXBsYXRlKSB7XG4gICAgYXdhaXQgaW9Ib3N0LmRlZmF1bHRzLmluZm8oYFVzaW5nIGJvb3RzdHJhcHBpbmcgdGVtcGxhdGUgZnJvbSAke2FyZ3MudGVtcGxhdGV9YCk7XG4gICAgc291cmNlID0geyBzb3VyY2U6ICdjdXN0b20nLCB0ZW1wbGF0ZUZpbGU6IGFyZ3MudGVtcGxhdGUgfTtcbiAgfSBlbHNlIGlmIChwcm9jZXNzLmVudi5DREtfTEVHQUNZX0JPT1RTVFJBUCkge1xuICAgIGF3YWl0IGlvSG9zdC5kZWZhdWx0cy5pbmZvKCdDREtfTEVHQUNZX0JPT1RTVFJBUCBzZXQsIHVzaW5nIGxlZ2FjeS1zdHlsZSBib290c3RyYXBwaW5nJyk7XG4gICAgc291cmNlID0geyBzb3VyY2U6ICdsZWdhY3knIH07XG4gIH0gZWxzZSB7XG4gICAgLy8gaW4gVjIsIHRoZSBcIm5ld1wiIGJvb3RzdHJhcHBpbmcgaXMgdGhlIGRlZmF1bHRcbiAgICBzb3VyY2UgPSB7IHNvdXJjZTogJ2RlZmF1bHQnIH07XG4gIH1cbiAgcmV0dXJuIHNvdXJjZTtcbn1cblxuZnVuY3Rpb24gaXNGZWF0dXJlRW5hYmxlZChjb25maWd1cmF0aW9uOiBDb25maWd1cmF0aW9uLCBmZWF0dXJlRmxhZzogc3RyaW5nKSB7XG4gIHJldHVybiBjb25maWd1cmF0aW9uLmNvbnRleHQuZ2V0KGZlYXR1cmVGbGFnKSA/PyBjeGFwaS5mdXR1cmVGbGFnRGVmYXVsdChmZWF0dXJlRmxhZyk7XG59XG5cbi8qKlxuICogVHJhbnNsYXRlIGEgWWFyZ3MgaW5wdXQgYXJyYXkgdG8gc29tZXRoaW5nIHRoYXQgbWFrZXMgbW9yZSBzZW5zZSBpbiBhIHByb2dyYW1taW5nIGxhbmd1YWdlXG4gKiBtb2RlbCAodGVsbGluZyB0aGUgZGlmZmVyZW5jZSBiZXR3ZWVuIGFic2VuY2UgYW5kIGFuIGVtcHR5IGFycmF5KVxuICpcbiAqIC0gQW4gZW1wdHkgYXJyYXkgaXMgdGhlIGRlZmF1bHQgY2FzZSwgbWVhbmluZyB0aGUgdXNlciBkaWRuJ3QgcGFzcyBhbnkgYXJndW1lbnRzLiBXZSByZXR1cm5cbiAqICAgdW5kZWZpbmVkLlxuICogLSBJZiB0aGUgdXNlciBwYXNzZWQgYSBzaW5nbGUgZW1wdHkgc3RyaW5nLCB0aGV5IGRpZCBzb21ldGhpbmcgbGlrZSBgLS1hcnJheT1gLCB3aGljaCB3ZSdsbFxuICogICB0YWtlIHRvIG1lYW4gdGhleSBwYXNzZWQgYW4gZW1wdHkgYXJyYXkuXG4gKi9cbmZ1bmN0aW9uIGFycmF5RnJvbVlhcmdzKHhzOiBzdHJpbmdbXSk6IHN0cmluZ1tdIHwgdW5kZWZpbmVkIHtcbiAgaWYgKHhzLmxlbmd0aCA9PT0gMCkge1xuICAgIHJldHVybiB1bmRlZmluZWQ7XG4gIH1cbiAgcmV0dXJuIHhzLmZpbHRlcigoeCkgPT4geCAhPT0gJycpO1xufVxuXG5mdW5jdGlvbiBkZXRlcm1pbmVEZXBsb3ltZW50TWV0aG9kKGFyZ3M6IGFueSwgY29uZmlndXJhdGlvbjogQ29uZmlndXJhdGlvbiwgd2F0Y2g/OiBib29sZWFuKTogRGVwbG95bWVudE1ldGhvZCB7XG4gIGxldCBkZXBsb3ltZW50TWV0aG9kOiBDaGFuZ2VTZXREZXBsb3ltZW50IHwgRGlyZWN0RGVwbG95bWVudCB8IHVuZGVmaW5lZDtcbiAgc3dpdGNoIChhcmdzLm1ldGhvZCkge1xuICAgIGNhc2UgJ2RpcmVjdCc6XG4gICAgICBpZiAoYXJncy5jaGFuZ2VTZXROYW1lKSB7XG4gICAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoJy0tY2hhbmdlLXNldC1uYW1lIGNhbm5vdCBiZSB1c2VkIHdpdGggbWV0aG9kPWRpcmVjdCcpO1xuICAgICAgfVxuICAgICAgaWYgKGFyZ3MuaW1wb3J0RXhpc3RpbmdSZXNvdXJjZXMpIHtcbiAgICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcignLS1pbXBvcnQtZXhpc3RpbmctcmVzb3VyY2VzIGNhbm5vdCBiZSBlbmFibGVkIHdpdGggbWV0aG9kPWRpcmVjdCcpO1xuICAgICAgfVxuICAgICAgZGVwbG95bWVudE1ldGhvZCA9IHsgbWV0aG9kOiAnZGlyZWN0JyB9O1xuICAgICAgYnJlYWs7XG4gICAgY2FzZSAnY2hhbmdlLXNldCc6XG4gICAgICBkZXBsb3ltZW50TWV0aG9kID0ge1xuICAgICAgICBtZXRob2Q6ICdjaGFuZ2Utc2V0JyxcbiAgICAgICAgZXhlY3V0ZTogdHJ1ZSxcbiAgICAgICAgY2hhbmdlU2V0TmFtZTogYXJncy5jaGFuZ2VTZXROYW1lLFxuICAgICAgICBpbXBvcnRFeGlzdGluZ1Jlc291cmNlczogYXJncy5pbXBvcnRFeGlzdGluZ1Jlc291cmNlcyxcbiAgICAgIH07XG4gICAgICBicmVhaztcbiAgICBjYXNlICdwcmVwYXJlLWNoYW5nZS1zZXQnOlxuICAgICAgZGVwbG95bWVudE1ldGhvZCA9IHtcbiAgICAgICAgbWV0aG9kOiAnY2hhbmdlLXNldCcsXG4gICAgICAgIGV4ZWN1dGU6IGZhbHNlLFxuICAgICAgICBjaGFuZ2VTZXROYW1lOiBhcmdzLmNoYW5nZVNldE5hbWUsXG4gICAgICAgIGltcG9ydEV4aXN0aW5nUmVzb3VyY2VzOiBhcmdzLmltcG9ydEV4aXN0aW5nUmVzb3VyY2VzLFxuICAgICAgfTtcbiAgICAgIGJyZWFrO1xuICAgIGNhc2UgdW5kZWZpbmVkOlxuICAgIGRlZmF1bHQ6XG4gICAgICBkZXBsb3ltZW50TWV0aG9kID0ge1xuICAgICAgICBtZXRob2Q6ICdjaGFuZ2Utc2V0JyxcbiAgICAgICAgZXhlY3V0ZTogd2F0Y2ggPyB0cnVlIDogYXJncy5leGVjdXRlID8/IHRydWUsXG4gICAgICAgIGNoYW5nZVNldE5hbWU6IGFyZ3MuY2hhbmdlU2V0TmFtZSxcbiAgICAgICAgaW1wb3J0RXhpc3RpbmdSZXNvdXJjZXM6IGFyZ3MuaW1wb3J0RXhpc3RpbmdSZXNvdXJjZXMsXG4gICAgICB9O1xuICAgICAgYnJlYWs7XG4gIH1cblxuICBjb25zdCBob3Rzd2FwTW9kZSA9IGRldGVybWluZUhvdHN3YXBNb2RlKGFyZ3MuaG90c3dhcCwgYXJncy5ob3Rzd2FwRmFsbGJhY2ssIHdhdGNoKTtcbiAgY29uc3QgaG90c3dhcFByb3BlcnRpZXMgPSBjb25maWd1cmF0aW9uLnNldHRpbmdzLmdldChbJ2hvdHN3YXAnXSkgfHwge307XG4gIHN3aXRjaCAoaG90c3dhcE1vZGUpIHtcbiAgICBjYXNlIEhvdHN3YXBNb2RlLkZBTExfQkFDSzpcbiAgICAgIHJldHVybiB7XG4gICAgICAgIG1ldGhvZDogJ2hvdHN3YXAnLFxuICAgICAgICBwcm9wZXJ0aWVzOiBob3Rzd2FwUHJvcGVydGllcyxcbiAgICAgICAgZmFsbGJhY2s6IGRlcGxveW1lbnRNZXRob2QsXG4gICAgICB9O1xuICAgIGNhc2UgSG90c3dhcE1vZGUuSE9UU1dBUF9PTkxZOlxuICAgICAgcmV0dXJuIHtcbiAgICAgICAgbWV0aG9kOiAnaG90c3dhcCcsXG4gICAgICAgIHByb3BlcnRpZXM6IGhvdHN3YXBQcm9wZXJ0aWVzLFxuICAgICAgfTtcbiAgICBkZWZhdWx0OlxuICAgIGNhc2UgSG90c3dhcE1vZGUuRlVMTF9ERVBMT1lNRU5UOlxuICAgICAgcmV0dXJuIGRlcGxveW1lbnRNZXRob2Q7XG4gIH1cbn1cblxuZnVuY3Rpb24gZGV0ZXJtaW5lSG90c3dhcE1vZGUoaG90c3dhcD86IGJvb2xlYW4sIGhvdHN3YXBGYWxsYmFjaz86IGJvb2xlYW4sIHdhdGNoPzogYm9vbGVhbik6IEhvdHN3YXBNb2RlIHtcbiAgaWYgKGhvdHN3YXAgJiYgaG90c3dhcEZhbGxiYWNrKSB7XG4gICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcignQ2FuIG5vdCBzdXBwbHkgYm90aCAtLWhvdHN3YXAgYW5kIC0taG90c3dhcC1mYWxsYmFjayBhdCB0aGUgc2FtZSB0aW1lJyk7XG4gIH0gZWxzZSBpZiAoIWhvdHN3YXAgJiYgIWhvdHN3YXBGYWxsYmFjaykge1xuICAgIGlmIChob3Rzd2FwID09PSB1bmRlZmluZWQgJiYgaG90c3dhcEZhbGxiYWNrID09PSB1bmRlZmluZWQpIHtcbiAgICAgIHJldHVybiB3YXRjaCA/IEhvdHN3YXBNb2RlLkhPVFNXQVBfT05MWSA6IEhvdHN3YXBNb2RlLkZVTExfREVQTE9ZTUVOVDtcbiAgICB9IGVsc2UgaWYgKGhvdHN3YXAgPT09IGZhbHNlIHx8IGhvdHN3YXBGYWxsYmFjayA9PT0gZmFsc2UpIHtcbiAgICAgIHJldHVybiBIb3Rzd2FwTW9kZS5GVUxMX0RFUExPWU1FTlQ7XG4gICAgfVxuICB9XG5cbiAgbGV0IGhvdHN3YXBNb2RlOiBIb3Rzd2FwTW9kZTtcbiAgaWYgKGhvdHN3YXApIHtcbiAgICBob3Rzd2FwTW9kZSA9IEhvdHN3YXBNb2RlLkhPVFNXQVBfT05MWTtcbiAgICAvKiBpZiAoaG90c3dhcEZhbGxiYWNrKSovXG4gIH0gZWxzZSB7XG4gICAgaG90c3dhcE1vZGUgPSBIb3Rzd2FwTW9kZS5GQUxMX0JBQ0s7XG4gIH1cblxuICByZXR1cm4gaG90c3dhcE1vZGU7XG59XG5cbi8qIGM4IGlnbm9yZSBzdGFydCAqLyAvLyB3ZSBuZXZlciBjYWxsIHRoaXMgaW4gdW5pdCB0ZXN0c1xuZXhwb3J0IGZ1bmN0aW9uIGNsaShhcmdzOiBzdHJpbmdbXSA9IHByb2Nlc3MuYXJndi5zbGljZSgyKSkge1xuICBsZXQgZXJyb3I6IEVycm9yRGV0YWlscyB8IHVuZGVmaW5lZDtcbiAgZXhlYyhhcmdzKVxuICAgIC50aGVuKGFzeW5jICh2YWx1ZSkgPT4ge1xuICAgICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ251bWJlcicpIHtcbiAgICAgICAgcHJvY2Vzcy5leGl0Q29kZSA9IHZhbHVlO1xuICAgICAgfVxuICAgIH0pXG4gICAgLmNhdGNoKGFzeW5jIChlcnIpID0+IHtcbiAgICAgIC8vIExvZyB0aGUgc3RhY2sgdHJhY2UgaWYgd2UncmUgb24gYSBkZXZlbG9wZXIgd29ya3N0YXRpb24uIE90aGVyd2lzZSB0aGlzIHdpbGwgYmUgaW50byBhIG1pbmlmaWVkXG4gICAgICAvLyBmaWxlIGFuZCB0aGUgcHJpbnRlZCBjb2RlIGxpbmUgYW5kIHN0YWNrIHRyYWNlIGFyZSBodWdlIGFuZCB1c2VsZXNzLlxuICAgICAgcHJldHR5UHJpbnRFcnJvcihlcnIsIGlzRGV2ZWxvcGVyQnVpbGRWZXJzaW9uKCkpO1xuICAgICAgZXJyb3IgPSB7XG4gICAgICAgIG5hbWU6IGNka0NsaUVycm9yTmFtZShlcnIubmFtZSksXG4gICAgICB9O1xuICAgICAgcHJvY2Vzcy5leGl0Q29kZSA9IDE7XG4gICAgfSlcbiAgICAuZmluYWxseShhc3luYyAoKSA9PiB7XG4gICAgICB0cnkge1xuICAgICAgICBhd2FpdCBDbGlJb0hvc3QuZ2V0KCk/LnRlbGVtZXRyeT8uZW5kKGVycm9yKTtcbiAgICAgIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgICAgICBhd2FpdCBDbGlJb0hvc3QuZ2V0KCk/LmFzSW9IZWxwZXIoKS5kZWZhdWx0cy50cmFjZShgRW5kaW5nIFRlbGVtZXRyeSBmYWlsZWQ6ICR7ZS5tZXNzYWdlfWApO1xuICAgICAgfVxuICAgIH0pO1xufVxuLyogYzggaWdub3JlIHN0b3AgKi9cbiJdfQ==