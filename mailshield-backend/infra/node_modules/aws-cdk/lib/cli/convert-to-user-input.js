"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.convertYargsToUserInput = convertYargsToUserInput;
exports.convertConfigToUserInput = convertConfigToUserInput;
// @ts-ignore TS6133
function convertYargsToUserInput(args) {
    const globalOptions = {
        app: args.app,
        build: args.build,
        context: args.context,
        plugin: args.plugin,
        trace: args.trace,
        strict: args.strict,
        lookups: args.lookups,
        ignoreErrors: args.ignoreErrors,
        json: args.json,
        verbose: args.verbose,
        debug: args.debug,
        profile: args.profile,
        proxy: args.proxy,
        caBundlePath: args.caBundlePath,
        ec2creds: args.ec2creds,
        versionReporting: args.versionReporting,
        pathMetadata: args.pathMetadata,
        assetMetadata: args.assetMetadata,
        roleArn: args.roleArn,
        staging: args.staging,
        output: args.output,
        notices: args.notices,
        noColor: args.noColor,
        ci: args.ci,
        unstable: args.unstable,
        telemetryFile: args.telemetryFile,
        yes: args.yes,
    };
    let commandOptions;
    switch (args._[0]) {
        case 'list':
        case 'ls':
            commandOptions = {
                long: args.long,
                showDependencies: args.showDependencies,
                STACKS: args.STACKS,
            };
            break;
        case 'synth':
        case 'synthesize':
            commandOptions = {
                exclusively: args.exclusively,
                validation: args.validation,
                quiet: args.quiet,
                STACKS: args.STACKS,
            };
            break;
        case 'bootstrap':
            commandOptions = {
                bootstrapBucketName: args.bootstrapBucketName,
                bootstrapKmsKeyId: args.bootstrapKmsKeyId,
                examplePermissionsBoundary: args.examplePermissionsBoundary,
                customPermissionsBoundary: args.customPermissionsBoundary,
                bootstrapCustomerKey: args.bootstrapCustomerKey,
                qualifier: args.qualifier,
                publicAccessBlockConfiguration: args.publicAccessBlockConfiguration,
                denyExternalId: args.denyExternalId,
                tags: args.tags,
                execute: args.execute,
                trust: args.trust,
                trustForLookup: args.trustForLookup,
                untrust: args.untrust,
                cloudformationExecutionPolicies: args.cloudformationExecutionPolicies,
                force: args.force,
                terminationProtection: args.terminationProtection,
                showTemplate: args.showTemplate,
                toolkitStackName: args.toolkitStackName,
                template: args.template,
                previousParameters: args.previousParameters,
                ENVIRONMENTS: args.ENVIRONMENTS,
            };
            break;
        case 'gc':
            commandOptions = {
                action: args.action,
                type: args.type,
                rollbackBufferDays: args.rollbackBufferDays,
                createdBufferDays: args.createdBufferDays,
                confirm: args.confirm,
                toolkitStackName: args.toolkitStackName,
                bootstrapStackName: args.bootstrapStackName,
                ENVIRONMENTS: args.ENVIRONMENTS,
            };
            break;
        case 'flags':
            commandOptions = {
                value: args.value,
                set: args.set,
                all: args.all,
                unconfigured: args.unconfigured,
                recommended: args.recommended,
                default: args.default,
                interactive: args.interactive,
                safe: args.safe,
                concurrency: args.concurrency,
                FLAGNAME: args.FLAGNAME,
            };
            break;
        case 'deploy':
            commandOptions = {
                all: args.all,
                buildExclude: args.buildExclude,
                exclusively: args.exclusively,
                requireApproval: args.requireApproval,
                notificationArns: args.notificationArns,
                tags: args.tags,
                execute: args.execute,
                changeSetName: args.changeSetName,
                method: args.method,
                importExistingResources: args.importExistingResources,
                force: args.force,
                parameters: args.parameters,
                outputsFile: args.outputsFile,
                previousParameters: args.previousParameters,
                toolkitStackName: args.toolkitStackName,
                progress: args.progress,
                rollback: args.rollback,
                hotswap: args.hotswap,
                hotswapFallback: args.hotswapFallback,
                hotswapEcsMinimumHealthyPercent: args.hotswapEcsMinimumHealthyPercent,
                hotswapEcsMaximumHealthyPercent: args.hotswapEcsMaximumHealthyPercent,
                hotswapEcsStabilizationTimeoutSeconds: args.hotswapEcsStabilizationTimeoutSeconds,
                watch: args.watch,
                logs: args.logs,
                concurrency: args.concurrency,
                assetParallelism: args.assetParallelism,
                assetPrebuild: args.assetPrebuild,
                ignoreNoStacks: args.ignoreNoStacks,
                STACKS: args.STACKS,
            };
            break;
        case 'rollback':
            commandOptions = {
                all: args.all,
                toolkitStackName: args.toolkitStackName,
                force: args.force,
                validateBootstrapVersion: args.validateBootstrapVersion,
                orphan: args.orphan,
                STACKS: args.STACKS,
            };
            break;
        case 'import':
            commandOptions = {
                execute: args.execute,
                changeSetName: args.changeSetName,
                toolkitStackName: args.toolkitStackName,
                rollback: args.rollback,
                force: args.force,
                recordResourceMapping: args.recordResourceMapping,
                resourceMapping: args.resourceMapping,
                STACK: args.STACK,
            };
            break;
        case 'watch':
            commandOptions = {
                buildExclude: args.buildExclude,
                exclusively: args.exclusively,
                changeSetName: args.changeSetName,
                force: args.force,
                toolkitStackName: args.toolkitStackName,
                progress: args.progress,
                rollback: args.rollback,
                hotswap: args.hotswap,
                hotswapFallback: args.hotswapFallback,
                hotswapEcsMinimumHealthyPercent: args.hotswapEcsMinimumHealthyPercent,
                hotswapEcsMaximumHealthyPercent: args.hotswapEcsMaximumHealthyPercent,
                hotswapEcsStabilizationTimeoutSeconds: args.hotswapEcsStabilizationTimeoutSeconds,
                logs: args.logs,
                concurrency: args.concurrency,
                STACKS: args.STACKS,
            };
            break;
        case 'destroy':
            commandOptions = {
                all: args.all,
                exclusively: args.exclusively,
                force: args.force,
                STACKS: args.STACKS,
            };
            break;
        case 'diff':
            commandOptions = {
                exclusively: args.exclusively,
                contextLines: args.contextLines,
                template: args.template,
                strict: args.strict,
                securityOnly: args.securityOnly,
                fail: args.fail,
                processed: args.processed,
                quiet: args.quiet,
                changeSet: args.changeSet,
                importExistingResources: args.importExistingResources,
                includeMoves: args.includeMoves,
                STACKS: args.STACKS,
            };
            break;
        case 'drift':
            commandOptions = {
                fail: args.fail,
                STACKS: args.STACKS,
            };
            break;
        case 'metadata':
            commandOptions = {
                STACK: args.STACK,
            };
            break;
        case 'acknowledge':
        case 'ack':
            commandOptions = {
                ID: args.ID,
            };
            break;
        case 'notices':
            commandOptions = {
                unacknowledged: args.unacknowledged,
            };
            break;
        case 'init':
            commandOptions = {
                language: args.language,
                list: args.list,
                generateOnly: args.generateOnly,
                libVersion: args.libVersion,
                fromPath: args.fromPath,
                templatePath: args.templatePath,
                TEMPLATE: args.TEMPLATE,
            };
            break;
        case 'migrate':
            commandOptions = {
                stackName: args.stackName,
                language: args.language,
                account: args.account,
                region: args.region,
                fromPath: args.fromPath,
                fromStack: args.fromStack,
                outputPath: args.outputPath,
                fromScan: args.fromScan,
                filter: args.filter,
                compress: args.compress,
            };
            break;
        case 'context':
            commandOptions = {
                reset: args.reset,
                force: args.force,
                clear: args.clear,
            };
            break;
        case 'docs':
        case 'doc':
            commandOptions = {
                browser: args.browser,
            };
            break;
        case 'doctor':
            commandOptions = {};
            break;
        case 'refactor':
            commandOptions = {
                additionalStackName: args.additionalStackName,
                dryRun: args.dryRun,
                overrideFile: args.overrideFile,
                revert: args.revert,
                force: args.force,
                STACKS: args.STACKS,
            };
            break;
        case 'cli-telemetry':
            commandOptions = {
                enable: args.enable,
                disable: args.disable,
                status: args.status,
            };
            break;
    }
    const userInput = {
        command: args._[0],
        globalOptions,
        [args._[0]]: commandOptions,
    };
    return userInput;
}
// @ts-ignore TS6133
function convertConfigToUserInput(config) {
    const globalOptions = {
        app: config.app,
        build: config.build,
        context: config.context,
        plugin: config.plugin,
        trace: config.trace,
        strict: config.strict,
        lookups: config.lookups,
        ignoreErrors: config.ignoreErrors,
        json: config.json,
        verbose: config.verbose,
        debug: config.debug,
        profile: config.profile,
        proxy: config.proxy,
        caBundlePath: config.caBundlePath,
        ec2creds: config.ec2creds,
        versionReporting: config.versionReporting,
        pathMetadata: config.pathMetadata,
        assetMetadata: config.assetMetadata,
        roleArn: config.roleArn,
        staging: config.staging,
        output: config.output,
        notices: config.notices,
        noColor: config.noColor,
        ci: config.ci,
        unstable: config.unstable,
        telemetryFile: config.telemetryFile,
        yes: config.yes,
    };
    const listOptions = {
        long: config.list?.long,
        showDependencies: config.list?.showDependencies,
    };
    const synthOptions = {
        exclusively: config.synth?.exclusively,
        validation: config.synth?.validation,
        quiet: config.synth?.quiet,
    };
    const bootstrapOptions = {
        bootstrapBucketName: config.bootstrap?.bootstrapBucketName,
        bootstrapKmsKeyId: config.bootstrap?.bootstrapKmsKeyId,
        examplePermissionsBoundary: config.bootstrap?.examplePermissionsBoundary,
        customPermissionsBoundary: config.bootstrap?.customPermissionsBoundary,
        bootstrapCustomerKey: config.bootstrap?.bootstrapCustomerKey,
        qualifier: config.bootstrap?.qualifier,
        publicAccessBlockConfiguration: config.bootstrap?.publicAccessBlockConfiguration,
        denyExternalId: config.bootstrap?.denyExternalId,
        tags: config.bootstrap?.tags,
        execute: config.bootstrap?.execute,
        trust: config.bootstrap?.trust,
        trustForLookup: config.bootstrap?.trustForLookup,
        untrust: config.bootstrap?.untrust,
        cloudformationExecutionPolicies: config.bootstrap?.cloudformationExecutionPolicies,
        force: config.bootstrap?.force,
        terminationProtection: config.bootstrap?.terminationProtection,
        showTemplate: config.bootstrap?.showTemplate,
        toolkitStackName: config.bootstrap?.toolkitStackName,
        template: config.bootstrap?.template,
        previousParameters: config.bootstrap?.previousParameters,
    };
    const gcOptions = {
        action: config.gc?.action,
        type: config.gc?.type,
        rollbackBufferDays: config.gc?.rollbackBufferDays,
        createdBufferDays: config.gc?.createdBufferDays,
        confirm: config.gc?.confirm,
        toolkitStackName: config.gc?.toolkitStackName,
        bootstrapStackName: config.gc?.bootstrapStackName,
    };
    const flagsOptions = {
        value: config.flags?.value,
        set: config.flags?.set,
        all: config.flags?.all,
        unconfigured: config.flags?.unconfigured,
        recommended: config.flags?.recommended,
        default: config.flags?.default,
        interactive: config.flags?.interactive,
        safe: config.flags?.safe,
        concurrency: config.flags?.concurrency,
    };
    const deployOptions = {
        all: config.deploy?.all,
        buildExclude: config.deploy?.buildExclude,
        exclusively: config.deploy?.exclusively,
        requireApproval: config.deploy?.requireApproval,
        notificationArns: config.deploy?.notificationArns,
        tags: config.deploy?.tags,
        execute: config.deploy?.execute,
        changeSetName: config.deploy?.changeSetName,
        method: config.deploy?.method,
        importExistingResources: config.deploy?.importExistingResources,
        force: config.deploy?.force,
        parameters: config.deploy?.parameters,
        outputsFile: config.deploy?.outputsFile,
        previousParameters: config.deploy?.previousParameters,
        toolkitStackName: config.deploy?.toolkitStackName,
        progress: config.deploy?.progress,
        rollback: config.deploy?.rollback,
        hotswap: config.deploy?.hotswap,
        hotswapFallback: config.deploy?.hotswapFallback,
        hotswapEcsMinimumHealthyPercent: config.deploy?.hotswapEcsMinimumHealthyPercent,
        hotswapEcsMaximumHealthyPercent: config.deploy?.hotswapEcsMaximumHealthyPercent,
        hotswapEcsStabilizationTimeoutSeconds: config.deploy?.hotswapEcsStabilizationTimeoutSeconds,
        watch: config.deploy?.watch,
        logs: config.deploy?.logs,
        concurrency: config.deploy?.concurrency,
        assetParallelism: config.deploy?.assetParallelism,
        assetPrebuild: config.deploy?.assetPrebuild,
        ignoreNoStacks: config.deploy?.ignoreNoStacks,
    };
    const rollbackOptions = {
        all: config.rollback?.all,
        toolkitStackName: config.rollback?.toolkitStackName,
        force: config.rollback?.force,
        validateBootstrapVersion: config.rollback?.validateBootstrapVersion,
        orphan: config.rollback?.orphan,
    };
    const importOptions = {
        execute: config.import?.execute,
        changeSetName: config.import?.changeSetName,
        toolkitStackName: config.import?.toolkitStackName,
        rollback: config.import?.rollback,
        force: config.import?.force,
        recordResourceMapping: config.import?.recordResourceMapping,
        resourceMapping: config.import?.resourceMapping,
    };
    const watchOptions = {
        buildExclude: config.watch?.buildExclude,
        exclusively: config.watch?.exclusively,
        changeSetName: config.watch?.changeSetName,
        force: config.watch?.force,
        toolkitStackName: config.watch?.toolkitStackName,
        progress: config.watch?.progress,
        rollback: config.watch?.rollback,
        hotswap: config.watch?.hotswap,
        hotswapFallback: config.watch?.hotswapFallback,
        hotswapEcsMinimumHealthyPercent: config.watch?.hotswapEcsMinimumHealthyPercent,
        hotswapEcsMaximumHealthyPercent: config.watch?.hotswapEcsMaximumHealthyPercent,
        hotswapEcsStabilizationTimeoutSeconds: config.watch?.hotswapEcsStabilizationTimeoutSeconds,
        logs: config.watch?.logs,
        concurrency: config.watch?.concurrency,
    };
    const destroyOptions = {
        all: config.destroy?.all,
        exclusively: config.destroy?.exclusively,
        force: config.destroy?.force,
    };
    const diffOptions = {
        exclusively: config.diff?.exclusively,
        contextLines: config.diff?.contextLines,
        template: config.diff?.template,
        strict: config.diff?.strict,
        securityOnly: config.diff?.securityOnly,
        fail: config.diff?.fail,
        processed: config.diff?.processed,
        quiet: config.diff?.quiet,
        changeSet: config.diff?.changeSet,
        importExistingResources: config.diff?.importExistingResources,
        includeMoves: config.diff?.includeMoves,
    };
    const driftOptions = {
        fail: config.drift?.fail,
    };
    const metadataOptions = {};
    const acknowledgeOptions = {};
    const noticesOptions = {
        unacknowledged: config.notices?.unacknowledged,
    };
    const initOptions = {
        language: config.init?.language,
        list: config.init?.list,
        generateOnly: config.init?.generateOnly,
        libVersion: config.init?.libVersion,
        fromPath: config.init?.fromPath,
        templatePath: config.init?.templatePath,
    };
    const migrateOptions = {
        stackName: config.migrate?.stackName,
        language: config.migrate?.language,
        account: config.migrate?.account,
        region: config.migrate?.region,
        fromPath: config.migrate?.fromPath,
        fromStack: config.migrate?.fromStack,
        outputPath: config.migrate?.outputPath,
        fromScan: config.migrate?.fromScan,
        filter: config.migrate?.filter,
        compress: config.migrate?.compress,
    };
    const contextOptions = {
        reset: config.context?.reset,
        force: config.context?.force,
        clear: config.context?.clear,
    };
    const docsOptions = {
        browser: config.docs?.browser,
    };
    const doctorOptions = {};
    const refactorOptions = {
        additionalStackName: config.refactor?.additionalStackName,
        dryRun: config.refactor?.dryRun,
        overrideFile: config.refactor?.overrideFile,
        revert: config.refactor?.revert,
        force: config.refactor?.force,
    };
    const cliTelemetryOptions = {
        enable: config.cliTelemetry?.enable,
        disable: config.cliTelemetry?.disable,
        status: config.cliTelemetry?.status,
    };
    const userInput = {
        globalOptions,
        list: listOptions,
        synth: synthOptions,
        bootstrap: bootstrapOptions,
        gc: gcOptions,
        flags: flagsOptions,
        deploy: deployOptions,
        rollback: rollbackOptions,
        import: importOptions,
        watch: watchOptions,
        destroy: destroyOptions,
        diff: diffOptions,
        drift: driftOptions,
        metadata: metadataOptions,
        acknowledge: acknowledgeOptions,
        notices: noticesOptions,
        init: initOptions,
        migrate: migrateOptions,
        context: contextOptions,
        docs: docsOptions,
        doctor: doctorOptions,
        refactor: refactorOptions,
        cliTelemetry: cliTelemetryOptions,
    };
    return userInput;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29udmVydC10by11c2VyLWlucHV0LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiY29udmVydC10by11c2VyLWlucHV0LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBU0EsMERBbVRDO0FBR0QsNERBNk9DO0FBcGlCRCxvQkFBb0I7QUFDcEIsU0FBZ0IsdUJBQXVCLENBQUMsSUFBUztJQUMvQyxNQUFNLGFBQWEsR0FBa0I7UUFDbkMsR0FBRyxFQUFFLElBQUksQ0FBQyxHQUFHO1FBQ2IsS0FBSyxFQUFFLElBQUksQ0FBQyxLQUFLO1FBQ2pCLE9BQU8sRUFBRSxJQUFJLENBQUMsT0FBTztRQUNyQixNQUFNLEVBQUUsSUFBSSxDQUFDLE1BQU07UUFDbkIsS0FBSyxFQUFFLElBQUksQ0FBQyxLQUFLO1FBQ2pCLE1BQU0sRUFBRSxJQUFJLENBQUMsTUFBTTtRQUNuQixPQUFPLEVBQUUsSUFBSSxDQUFDLE9BQU87UUFDckIsWUFBWSxFQUFFLElBQUksQ0FBQyxZQUFZO1FBQy9CLElBQUksRUFBRSxJQUFJLENBQUMsSUFBSTtRQUNmLE9BQU8sRUFBRSxJQUFJLENBQUMsT0FBTztRQUNyQixLQUFLLEVBQUUsSUFBSSxDQUFDLEtBQUs7UUFDakIsT0FBTyxFQUFFLElBQUksQ0FBQyxPQUFPO1FBQ3JCLEtBQUssRUFBRSxJQUFJLENBQUMsS0FBSztRQUNqQixZQUFZLEVBQUUsSUFBSSxDQUFDLFlBQVk7UUFDL0IsUUFBUSxFQUFFLElBQUksQ0FBQyxRQUFRO1FBQ3ZCLGdCQUFnQixFQUFFLElBQUksQ0FBQyxnQkFBZ0I7UUFDdkMsWUFBWSxFQUFFLElBQUksQ0FBQyxZQUFZO1FBQy9CLGFBQWEsRUFBRSxJQUFJLENBQUMsYUFBYTtRQUNqQyxPQUFPLEVBQUUsSUFBSSxDQUFDLE9BQU87UUFDckIsT0FBTyxFQUFFLElBQUksQ0FBQyxPQUFPO1FBQ3JCLE1BQU0sRUFBRSxJQUFJLENBQUMsTUFBTTtRQUNuQixPQUFPLEVBQUUsSUFBSSxDQUFDLE9BQU87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UUFBUSxFQUFFLGVBQWU7UUFDekIsV0FBVyxFQUFFLGtCQUFrQjtRQUMvQixPQUFPLEVBQUUsY0FBYztRQUN2QixJQUFJLEVBQUUsV0FBVztRQUNqQixPQUFPLEVBQUUsY0FBYztRQUN2QixPQUFPLEVBQUUsY0FBYztRQUN2QixJQUFJLEVBQUUsV0FBVztRQUNqQixNQUFNLEVBQUUsYUFBYTtRQUNyQixRQUFRLEVBQUUsZUFBZTtRQUN6QixZQUFZLEVBQUUsbUJBQW1CO0tBQ2xDLENBQUM7SUFFRixPQUFPLFNBQVMsQ0FBQztBQUNuQixDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuLy8gR0VORVJBVEVEIEZST00gcGFja2FnZXMvYXdzLWNkay9saWIvY2xpL2NsaS1jb25maWcudHMuXG4vLyBEbyBub3QgZWRpdCBieSBoYW5kOyBhbGwgY2hhbmdlcyB3aWxsIGJlIG92ZXJ3cml0dGVuIGF0IGJ1aWxkIHRpbWUgZnJvbSB0aGUgY29uZmlnIGZpbGUuXG4vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vKiBlc2xpbnQtZGlzYWJsZSBAc3R5bGlzdGljL21heC1sZW4sIEB0eXBlc2NyaXB0LWVzbGludC9jb25zaXN0ZW50LXR5cGUtaW1wb3J0cyAqL1xuaW1wb3J0IHsgQ29tbWFuZCB9IGZyb20gJy4vdXNlci1jb25maWd1cmF0aW9uJztcbmltcG9ydCB7IFVzZXJJbnB1dCwgR2xvYmFsT3B0aW9ucyB9IGZyb20gJy4vdXNlci1pbnB1dCc7XG5cbi8vIEB0cy1pZ25vcmUgVFM2MTMzXG5leHBvcnQgZnVuY3Rpb24gY29udmVydFlhcmdzVG9Vc2VySW5wdXQoYXJnczogYW55KTogVXNlcklucHV0IHtcbiAgY29uc3QgZ2xvYmFsT3B0aW9uczogR2xvYmFsT3B0aW9ucyA9IHtcbiAgICBhcHA6IGFyZ3MuYXBwLFxuICAgIGJ1aWxkOiBhcmdzLmJ1aWxkLFxuICAgIGNvbnRleHQ6IGFyZ3MuY29udGV4dCxcbiAgICBwbHVnaW46IGFyZ3MucGx1Z2luLFxuICAgIHRyYWNlOiBhcmdzLnRyYWNlLFxuICAgIHN0cmljdDogYXJncy5zdHJpY3QsXG4gICAgbG9va3VwczogYXJncy5sb29rdXBzLFxuICAgIGlnbm9yZUVycm9yczogYXJncy5pZ25vcmVFcnJvcnMsXG4gICAganNvbjogYXJncy5qc29uLFxuICAgIHZlcmJvc2U6IGFyZ3MudmVyYm9zZSxcbiAgICBkZWJ1ZzogYXJncy5kZWJ1ZyxcbiAgICBwcm9maWxlOiBhcmdzLnByb2ZpbGUsXG4gICAgcHJveHk6IGFyZ3MucHJveHksXG4gICAgY2FCdW5kbGVQYXRoOiBhcmdzLmNhQnVuZGxlUGF0aCxcbiAgICBlYzJjcmVkczogYXJncy5lYzJjcmVkcyxcbiAgICB2ZXJzaW9uUmVwb3J0aW5nOiBhcmdzLnZlcnNpb25SZXBvcnRpbmcsXG4gICAgcGF0aE1ldGFkYXRhOiBhcmdzLnBhdGhNZXRhZGF0YSxcbiAgICBhc3NldE1ldGFkYXRhOiBhcmdzLmFzc2V0TWV0YWRhdGEsXG4gICAgcm9sZUFybjogYXJncy5yb2xlQXJuLFxuICAgIHN0YWdpbmc6IGFyZ3Muc3RhZ2luZyxcbiAgICBvdXRwdXQ6IGFyZ3Mub3V0cHV0LFxuICAgIG5vdGljZXM6IGFyZ3Mubm90aWNlcyxcbiAgICBub0NvbG9yOiBhcmdzLm5vQ29sb3IsXG4gICAgY2k6IGFyZ3MuY2ksXG4gICAgdW5zdGFibGU6IGFyZ3MudW5zdGFibGUsXG4gICAgdGVsZW1ldHJ5RmlsZTogYXJncy50ZWxlbWV0cnlGaWxlLFxuICAgIHllczogYXJncy55ZXMsXG4gIH07XG4gIGxldCBjb21tYW5kT3B0aW9ucztcbiAgc3dpdGNoIChhcmdzLl9bMF0gYXMgQ29tbWFuZCkge1xuICAgIGNhc2UgJ2xpc3QnOlxuICAgIGNhc2UgJ2xzJzpcbiAgICAgIGNvbW1hbmRPcHRpb25zID0ge1xuICAgICAgICBsb25nOiBhcmdzLmxvbmcsXG4gICAgICAgIHNob3dEZXBlbmRlbmNpZXM6IGFyZ3Muc2hvd0RlcGVuZGVuY2llcyxcbiAgICAgICAgU1RBQ0tTOiBhcmdzLlNUQUNLUyxcbiAgICAgIH07XG4gICAgICBicmVhaztcblxuICAgIGNhc2UgJ3N5bnRoJzpcbiAgICBjYXNlICdzeW50aGVzaXplJzpcbiAgICAgIGNvbW1hbmRPcHRpb25zID0ge1xuICAgICAgICBleGNsdXNpdmVseTogYXJncy5leGNsdXNpdmVseSxcbiAgICAgICAgdmFsaWRhdGlvbjogYXJncy52YWxpZGF0aW9uLFxuICAgICAgICBxdWlldDogYXJncy5xdWlldCxcbiAgICAgICAgU1RBQ0tTOiBhcmdzLlNUQUNLUyxcbiAgICAgIH07XG4gICAgICBicmVhaztcblxuICAgIGNhc2UgJ2Jvb3RzdHJhcCc6XG4gICAgICBjb21tYW5kT3B0aW9ucyA9IHtcbiAgICAgICAgYm9vdHN0cmFwQnVja2V0TmFtZTogYXJncy5ib290c3RyYXBCdWNrZXROYW1lLFxuICAgICAgICBib290c3RyYXBLbXNLZXlJZDogYXJncy5ib290c3RyYXBLbXNLZXlJZCxcbiAgICAgICAgZXhhbXBsZVBlcm1pc3Npb25zQm91bmRhcnk6IGFyZ3MuZXhhbXBsZVBlcm1pc3Npb25zQm91bmRhcnksXG4gICAgICAgIGN1c3RvbVBlcm1pc3Npb25zQm91bmRhcnk6IGFyZ3MuY3VzdG9tUGVybWlzc2lvbnNCb3VuZGFyeSxcbiAgICAgICAgYm9vdHN0cmFwQ3VzdG9tZXJLZXk6IGFyZ3MuYm9vdHN0cmFwQ3VzdG9tZXJLZXksXG4gICAgICAgIHF1YWxpZmllcjogYXJncy5xdWFsaWZpZXIsXG4gICAgICAgIHB1YmxpY0FjY2Vzc0Jsb2NrQ29uZmlndXJhdGlvbjogYXJncy5wdWJsaWNBY2Nlc3NCbG9ja0NvbmZpZ3VyYXRpb24sXG4gICAgICAgIGRlbnlFeHRlcm5hbElkOiBhcmdzLmRlbnlFeHRlcm5hbElkLFxuICAgICAgICB0YWdzOiBhcmdzLnRhZ3MsXG4gICAgICAgIGV4ZWN1dGU6IGFyZ3MuZXhlY3V0ZSxcbiAgICAgICAgdHJ1c3Q6IGFyZ3MudHJ1c3QsXG4gICAgICAgIHRydXN0Rm9yTG9va3VwOiBhcmdzLnRydXN0Rm9yTG9va3VwLFxuICAgICAgICB1bnRydXN0OiBhcmdzLnVudHJ1c3QsXG4gICAgICAgIGNsb3VkZm9ybWF0aW9uRXhlY3V0aW9uUG9saWNpZXM6IGFyZ3MuY2xvdWRmb3JtYXRpb25FeGVjdXRpb25Qb2xpY2llcyxcbiAgICAgICAgZm9yY2U6IGFyZ3MuZm9yY2UsXG4gICAgICAgIHRlcm1pbmF0aW9uUHJvdGVjdGlvbjogYXJncy50ZXJtaW5hdGlvblByb3RlY3Rpb24sXG4gICAgICAgIHNob3dUZW1wbGF0ZTogYXJncy5zaG93VGVtcGxhdGUsXG4gICAgICAgIHRvb2xraXRTdGFja05hbWU6IGFyZ3MudG9vbGtpdFN0YWNrTmFtZSxcbiAgICAgICAgdGVtcGxhdGU6IGFyZ3MudGVtcGxhdGUsXG4gICAgICAgIHByZXZpb3VzUGFyYW1ldGVyczogYXJncy5wcmV2aW91c1BhcmFtZXRlcnMsXG4gICAgICAgIEVOVklST05NRU5UUzogYXJncy5FTlZJUk9OTUVOVFMsXG4gICAgICB9O1xuICAgICAgYnJlYWs7XG5cbiAgICBjYXNlICdnYyc6XG4gICAgICBjb21tYW5kT3B0aW9ucyA9IHtcbiAgICAgICAgYWN0aW9uOiBhcmdzLmFjdGlvbixcbiAgICAgICAgdHlwZTogYXJncy50eXBlLFxuICAgICAgICByb2xsYmFja0J1ZmZlckRheXM6IGFyZ3Mucm9sbGJhY2tCdWZmZXJEYXlzLFxuICAgICAgICBjcmVhdGVkQnVmZmVyRGF5czogYXJncy5jcmVhdGVkQnVmZmVyRGF5cyxcbiAgICAgICAgY29uZmlybTogYXJncy5jb25maXJtLFxuICAgICAgICB0b29sa2l0U3RhY2tOYW1lOiBhcmdzLnRvb2xraXRTdGFja05hbWUsXG4gICAgICAgIGJvb3RzdHJhcFN0YWNrTmFtZTogYXJncy5ib290c3RyYXBTdGFja05hbWUsXG4gICAgICAgIEVOVklST05NRU5UUzogYXJncy5FTlZJUk9OTUVOVFMsXG4gICAgICB9O1xuICAgICAgYnJlYWs7XG5cbiAgICBjYXNlICdmbGFncyc6XG4gICAgICBjb21tYW5kT3B0aW9ucyA9IHtcbiAgICAgICAgdmFsdWU6IGFyZ3MudmFsdWUsXG4gICAgICAgIHNldDogYXJncy5zZXQsXG4gICAgICAgIGFsbDogYXJncy5hbGwsXG4gICAgICAgIHVuY29uZmlndXJlZDogYXJncy51bmNvbmZpZ3VyZWQsXG4gICAgICAgIHJlY29tbWVuZGVkOiBhcmdzLnJlY29tbWVuZGVkLFxuICAgICAgICBkZWZhdWx0OiBhcmdzLmRlZmF1bHQsXG4gICAgICAgIGludGVyYWN0aXZlOiBhcmdzLmludGVyYWN0aXZlLFxuICAgICAgICBzYWZlOiBhcmdzLnNhZmUsXG4gICAgICAgIGNvbmN1cnJlbmN5OiBhcmdzLmNvbmN1cnJlbmN5LFxuICAgICAgICBGTEFHTkFNRTogYXJncy5GTEFHTkFNRSxcbiAgICAgIH07XG4gICAgICBicmVhaztcblxuICAgIGNhc2UgJ2RlcGxveSc6XG4gICAgICBjb21tYW5kT3B0aW9ucyA9IHtcbiAgICAgICAgYWxsOiBhcmdzLmFsbCxcbiAgICAgICAgYnVpbGRFeGNsdWRlOiBhcmdzLmJ1aWxkRXhjbHVkZSxcbiAgICAgICAgZXhjbHVzaXZlbHk6IGFyZ3MuZXhjbHVzaXZlbHksXG4gICAgICAgIHJlcXVpcmVBcHByb3ZhbDogYXJncy5yZXF1aXJlQXBwcm92YWwsXG4gICAgICAgIG5vdGlmaWNhdGlvbkFybnM6IGFyZ3Mubm90aWZpY2F0aW9uQXJucyxcbiAgICAgICAgdGFnczogYXJncy50YWdzLFxuICAgICAgICBleGVjdXRlOiBhcmdzLmV4ZWN1dGUsXG4gICAgICAgIGNoYW5nZVNldE5hbWU6IGFyZ3MuY2hhbmdlU2V0TmFtZSxcbiAgICAgICAgbWV0aG9kOiBhcmdzLm1ldGhvZCxcbiAgICAgICAgaW1wb3J0RXhpc3RpbmdSZXNvdXJjZXM6IGFyZ3MuaW1wb3J0RXhpc3RpbmdSZXNvdXJjZXMsXG4gICAgICAgIGZvcmNlOiBhcmdzLmZvcmNlLFxuICAgICAgICBwYXJhbWV0ZXJzOiBhcmdzLnBhcmFtZXRlcnMsXG4gICAgICAgIG91dHB1dHNGaWxlOiBhcmdzLm91dHB1dHNGaWxlLFxuICAgICAgICBwcmV2aW91c1BhcmFtZXRlcnM6IGFyZ3MucHJldmlvdXNQYXJhbWV0ZXJzLFxuICAgICAgICB0b29sa2l0U3RhY2tOYW1lOiBhcmdzLnRvb2xraXRTdGFja05hbWUsXG4gICAgICAgIHByb2dyZXNzOiBhcmdzLnByb2dyZXNzLFxuICAgICAgICByb2xsYmFjazogYXJncy5yb2xsYmFjayxcbiAgICAgICAgaG90c3dhcDogYXJncy5ob3Rzd2FwLFxuICAgICAgICBob3Rzd2FwRmFsbGJhY2s6IGFyZ3MuaG90c3dhcEZhbGxiYWNrLFxuICAgICAgICBob3Rzd2FwRWNzTWluaW11bUhlYWx0aHlQZXJjZW50OiBhcmdzLmhvdHN3YXBFY3NNaW5pbXVtSGVhbHRoeVBlcmNlbnQsXG4gICAgICAgIGhvdHN3YXBFY3NNYXhpbXVtSGVhbHRoeVBlcmNlbnQ6IGFyZ3MuaG90c3dhcEVjc01heGltdW1IZWFsdGh5UGVyY2VudCxcbiAgICAgICAgaG90c3dhcEVjc1N0YWJpbGl6YXRpb25UaW1lb3V0U2Vjb25kczogYXJncy5ob3Rzd2FwRWNzU3RhYmlsaXphdGlvblRpbWVvdXRTZWNvbmRzLFxuICAgICAgICB3YXRjaDogYXJncy53YXRjaCxcbiAgICAgICAgbG9nczogYXJncy5sb2dzLFxuICAgICAgICBjb25jdXJyZW5jeTogYXJncy5jb25jdXJyZW5jeSxcbiAgICAgICAgYXNzZXRQYXJhbGxlbGlzbTogYXJncy5hc3NldFBhcmFsbGVsaXNtLFxuICAgICAgICBhc3NldFByZWJ1aWxkOiBhcmdzLmFzc2V0UHJlYnVpbGQsXG4gICAgICAgIGlnbm9yZU5vU3RhY2tzOiBhcmdzLmlnbm9yZU5vU3RhY2tzLFxuICAgICAgICBTVEFDS1M6IGFyZ3MuU1RBQ0tTLFxuICAgICAgfTtcbiAgICAgIGJyZWFrO1xuXG4gICAgY2FzZSAncm9sbGJhY2snOlxuICAgICAgY29tbWFuZE9wdGlvbnMgPSB7XG4gICAgICAgIGFsbDogYXJncy5hbGwsXG4gICAgICAgIHRvb2xraXRTdGFja05hbWU6IGFyZ3MudG9vbGtpdFN0YWNrTmFtZSxcbiAgICAgICAgZm9yY2U6IGFyZ3MuZm9yY2UsXG4gICAgICAgIHZhbGlkYXRlQm9vdHN0cmFwVmVyc2lvbjogYXJncy52YWxpZGF0ZUJvb3RzdHJhcFZlcnNpb24sXG4gICAgICAgIG9ycGhhbjogYXJncy5vcnBoYW4sXG4gICAgICAgIFNUQUNLUzogYXJncy5TVEFDS1MsXG4gICAgICB9O1xuICAgICAgYnJlYWs7XG5cbiAgICBjYXNlICdpbXBvcnQnOlxuICAgICAgY29tbWFuZE9wdGlvbnMgPSB7XG4gICAgICAgIGV4ZWN1dGU6IGFyZ3MuZXhlY3V0ZSxcbiAgICAgICAgY2hhbmdlU2V0TmFtZTogYXJncy5jaGFuZ2VTZXROYW1lLFxuICAgICAgICB0b29sa2l0U3RhY2tOYW1lOiBhcmdzLnRvb2xraXRTdGFja05hbWUsXG4gICAgICAgIHJvbGxiYWNrOiBhcmdzLnJvbGxiYWNrLFxuICAgICAgICBmb3JjZTogYXJncy5mb3JjZSxcbiAgICAgICAgcmVjb3JkUmVzb3VyY2VNYXBwaW5nOiBhcmdzLnJlY29yZFJlc291cmNlTWFwcGluZyxcbiAgICAgICAgcmVzb3VyY2VNYXBwaW5nOiBhcmdzLnJlc291cmNlTWFwcGluZyxcbiAgICAgICAgU1RBQ0s6IGFyZ3MuU1RBQ0ssXG4gICAgICB9O1xuICAgICAgYnJlYWs7XG5cbiAgICBjYXNlICd3YXRjaCc6XG4gICAgICBjb21tYW5kT3B0aW9ucyA9IHtcbiAgICAgICAgYnVpbGRFeGNsdWRlOiBhcmdzLmJ1aWxkRXhjbHVkZSxcbiAgICAgICAgZXhjbHVzaXZlbHk6IGFyZ3MuZXhjbHVzaXZlbHksXG4gICAgICAgIGNoYW5nZVNldE5hbWU6IGFyZ3MuY2hhbmdlU2V0TmFtZSxcbiAgICAgICAgZm9yY2U6IGFyZ3MuZm9yY2UsXG4gICAgICAgIHRvb2xraXRTdGFja05hbWU6IGFyZ3MudG9vbGtpdFN0YWNrTmFtZSxcbiAgICAgICAgcHJvZ3Jlc3M6IGFyZ3MucHJvZ3Jlc3MsXG4gICAgICAgIHJvbGxiYWNrOiBhcmdzLnJvbGxiYWNrLFxuICAgICAgICBob3Rzd2FwOiBhcmdzLmhvdHN3YXAsXG4gICAgICAgIGhvdHN3YXBGYWxsYmFjazogYXJncy5ob3Rzd2FwRmFsbGJhY2ssXG4gICAgICAgIGhvdHN3YXBFY3NNaW5pbXVtSGVhbHRoeVBlcmNlbnQ6IGFyZ3MuaG90c3dhcEVjc01pbmltdW1IZWFsdGh5UGVyY2VudCxcbiAgICAgICAgaG90c3dhcEVjc01heGltdW1IZWFsdGh5UGVyY2VudDogYXJncy5ob3Rzd2FwRWNzTWF4aW11bUhlYWx0aHlQZXJjZW50LFxuICAgICAgICBob3Rzd2FwRWNzU3RhYmlsaXphdGlvblRpbWVvdXRTZWNvbmRzOiBhcmdzLmhvdHN3YXBFY3NTdGFiaWxpemF0aW9uVGltZW91dFNlY29uZHMsXG4gICAgICAgIGxvZ3M6IGFyZ3MubG9ncyxcbiAgICAgICAgY29uY3VycmVuY3k6IGFyZ3MuY29uY3VycmVuY3ksXG4gICAgICAgIFNUQUNLUzogYXJncy5TVEFDS1MsXG4gICAgICB9O1xuICAgICAgYnJlYWs7XG5cbiAgICBjYXNlICdkZXN0cm95JzpcbiAgICAgIGNvbW1hbmRPcHRpb25zID0ge1xuICAgICAgICBhbGw6IGFyZ3MuYWxsLFxuICAgICAgICBleGNsdXNpdmVseTogYXJncy5leGNsdXNpdmVseSxcbiAgICAgICAgZm9yY2U6IGFyZ3MuZm9yY2UsXG4gICAgICAgIFNUQUNLUzogYXJncy5TVEFDS1MsXG4gICAgICB9O1xuICAgICAgYnJlYWs7XG5cbiAgICBjYXNlICdkaWZmJzpcbiAgICAgIGNvbW1hbmRPcHRpb25zID0ge1xuICAgICAgICBleGNsdXNpdmVseTogYXJncy5leGNsdXNpdmVseSxcbiAgICAgICAgY29udGV4dExpbmVzOiBhcmdzLmNvbnRleHRMaW5lcyxcbiAgICAgICAgdGVtcGxhdGU6IGFyZ3MudGVtcGxhdGUsXG4gICAgICAgIHN0cmljdDogYXJncy5zdHJpY3QsXG4gICAgICAgIHNlY3VyaXR5T25seTogYXJncy5zZWN1cml0eU9ubHksXG4gICAgICAgIGZhaWw6IGFyZ3MuZmFpbCxcbiAgICAgICAgcHJvY2Vzc2VkOiBhcmdzLnByb2Nlc3NlZCxcbiAgICAgICAgcXVpZXQ6IGFyZ3MucXVpZXQsXG4gICAgICAgIGNoYW5nZVNldDogYXJncy5jaGFuZ2VTZXQsXG4gICAgICAgIGltcG9ydEV4aXN0aW5nUmVzb3VyY2VzOiBhcmdzLmltcG9ydEV4aXN0aW5nUmVzb3VyY2VzLFxuICAgICAgICBpbmNsdWRlTW92ZXM6IGFyZ3MuaW5jbHVkZU1vdmVzLFxuICAgICAgICBTVEFDS1M6IGFyZ3MuU1RBQ0tTLFxuICAgICAgfTtcbiAgICAgIGJyZWFrO1xuXG4gICAgY2FzZSAnZHJpZnQnOlxuICAgICAgY29tbWFuZE9wdGlvbnMgPSB7XG4gICAgICAgIGZhaWw6IGFyZ3MuZmFpbCxcbiAgICAgICAgU1RBQ0tTOiBhcmdzLlNUQUNLUyxcbiAgICAgIH07XG4gICAgICBicmVhaztcblxuICAgIGNhc2UgJ21ldGFkYXRhJzpcbiAgICAgIGNvbW1hbmRPcHRpb25zID0ge1xuICAgICAgICBTVEFDSzogYXJncy5TVEFDSyxcbiAgICAgIH07XG4gICAgICBicmVhaztcblxuICAgIGNhc2UgJ2Fja25vd2xlZGdlJzpcbiAgICBjYXNlICdhY2snOlxuICAgICAgY29tbWFuZE9wdGlvbnMgPSB7XG4gICAgICAgIElEOiBhcmdzLklELFxuICAgICAgfTtcbiAgICAgIGJyZWFrO1xuXG4gICAgY2FzZSAnbm90aWNlcyc6XG4gICAgICBjb21tYW5kT3B0aW9ucyA9IHtcbiAgICAgICAgdW5hY2tub3dsZWRnZWQ6IGFyZ3MudW5hY2tub3dsZWRnZWQsXG4gICAgICB9O1xuICAgICAgYnJlYWs7XG5cbiAgICBjYXNlICdpbml0JzpcbiAgICAgIGNvbW1hbmRPcHRpb25zID0ge1xuICAgICAgICBsYW5ndWFnZTogYXJncy5sYW5ndWFnZSxcbiAgICAgICAgbGlzdDogYXJncy5saXN0LFxuICAgICAgICBnZW5lcmF0ZU9ubHk6IGFyZ3MuZ2VuZXJhdGVPbmx5LFxuICAgICAgICBsaWJWZXJzaW9uOiBhcmdzLmxpYlZlcnNpb24sXG4gICAgICAgIGZyb21QYXRoOiBhcmdzLmZyb21QYXRoLFxuICAgICAgICB0ZW1wbGF0ZVBhdGg6IGFyZ3MudGVtcGxhdGVQYXRoLFxuICAgICAgICBURU1QTEFURTogYXJncy5URU1QTEFURSxcbiAgICAgIH07XG4gICAgICBicmVhaztcblxuICAgIGNhc2UgJ21pZ3JhdGUnOlxuICAgICAgY29tbWFuZE9wdGlvbnMgPSB7XG4gICAgICAgIHN0YWNrTmFtZTogYXJncy5zdGFja05hbWUsXG4gICAgICAgIGxhbmd1YWdlOiBhcmdzLmxhbmd1YWdlLFxuICAgICAgICBhY2NvdW50OiBhcmdzLmFjY291bnQsXG4gICAgICAgIHJlZ2lvbjogYXJncy5yZWdpb24sXG4gICAgICAgIGZyb21QYXRoOiBhcmdzLmZyb21QYXRoLFxuICAgICAgICBmcm9tU3RhY2s6IGFyZ3MuZnJvbVN0YWNrLFxuICAgICAgICBvdXRwdXRQYXRoOiBhcmdzLm91dHB1dFBhdGgsXG4gICAgICAgIGZyb21TY2FuOiBhcmdzLmZyb21TY2FuLFxuICAgICAgICBmaWx0ZXI6IGFyZ3MuZmlsdGVyLFxuICAgICAgICBjb21wcmVzczogYXJncy5jb21wcmVzcyxcbiAgICAgIH07XG4gICAgICBicmVhaztcblxuICAgIGNhc2UgJ2NvbnRleHQnOlxuICAgICAgY29tbWFuZE9wdGlvbnMgPSB7XG4gICAgICAgIHJlc2V0OiBhcmdzLnJlc2V0LFxuICAgICAgICBmb3JjZTogYXJncy5mb3JjZSxcbiAgICAgICAgY2xlYXI6IGFyZ3MuY2xlYXIsXG4gICAgICB9O1xuICAgICAgYnJlYWs7XG5cbiAgICBjYXNlICdkb2NzJzpcbiAgICBjYXNlICdkb2MnOlxuICAgICAgY29tbWFuZE9wdGlvbnMgPSB7XG4gICAgICAgIGJyb3dzZXI6IGFyZ3MuYnJvd3NlcixcbiAgICAgIH07XG4gICAgICBicmVhaztcblxuICAgIGNhc2UgJ2RvY3Rvcic6XG4gICAgICBjb21tYW5kT3B0aW9ucyA9IHt9O1xuICAgICAgYnJlYWs7XG5cbiAgICBjYXNlICdyZWZhY3Rvcic6XG4gICAgICBjb21tYW5kT3B0aW9ucyA9IHtcbiAgICAgICAgYWRkaXRpb25hbFN0YWNrTmFtZTogYXJncy5hZGRpdGlvbmFsU3RhY2tOYW1lLFxuICAgICAgICBkcnlSdW46IGFyZ3MuZHJ5UnVuLFxuICAgICAgICBvdmVycmlkZUZpbGU6IGFyZ3Mub3ZlcnJpZGVGaWxlLFxuICAgICAgICByZXZlcnQ6IGFyZ3MucmV2ZXJ0LFxuICAgICAgICBmb3JjZTogYXJncy5mb3JjZSxcbiAgICAgICAgU1RBQ0tTOiBhcmdzLlNUQUNLUyxcbiAgICAgIH07XG4gICAgICBicmVhaztcblxuICAgIGNhc2UgJ2NsaS10ZWxlbWV0cnknOlxuICAgICAgY29tbWFuZE9wdGlvbnMgPSB7XG4gICAgICAgIGVuYWJsZTogYXJncy5lbmFibGUsXG4gICAgICAgIGRpc2FibGU6IGFyZ3MuZGlzYWJsZSxcbiAgICAgICAgc3RhdHVzOiBhcmdzLnN0YXR1cyxcbiAgICAgIH07XG4gICAgICBicmVhaztcbiAgfVxuICBjb25zdCB1c2VySW5wdXQ6IFVzZXJJbnB1dCA9IHtcbiAgICBjb21tYW5kOiBhcmdzLl9bMF0sXG4gICAgZ2xvYmFsT3B0aW9ucyxcbiAgICBbYXJncy5fWzBdXTogY29tbWFuZE9wdGlvbnMsXG4gIH07XG5cbiAgcmV0dXJuIHVzZXJJbnB1dDtcbn1cblxuLy8gQHRzLWlnbm9yZSBUUzYxMzNcbmV4cG9ydCBmdW5jdGlvbiBjb252ZXJ0Q29uZmlnVG9Vc2VySW5wdXQoY29uZmlnOiBhbnkpOiBVc2VySW5wdXQge1xuICBjb25zdCBnbG9iYWxPcHRpb25zOiBHbG9iYWxPcHRpb25zID0ge1xuICAgIGFwcDogY29uZmlnLmFwcCxcbiAgICBidWlsZDogY29uZmlnLmJ1aWxkLFxuICAgIGNvbnRleHQ6IGNvbmZpZy5jb250ZXh0LFxuICAgIHBsdWdpbjogY29uZmlnLnBsdWdpbixcbiAgICB0cmFjZTogY29uZmlnLnRyYWNlLFxuICAgIHN0cmljdDogY29uZmlnLnN0cmljdCxcbiAgICBsb29rdXBzOiBjb25maWcubG9va3VwcyxcbiAgICBpZ25vcmVFcnJvcnM6IGNvbmZpZy5pZ25vcmVFcnJvcnMsXG4gICAganNvbjogY29uZmlnLmpzb24sXG4gICAgdmVyYm9zZTogY29uZmlnLnZlcmJvc2UsXG4gICAgZGVidWc6IGNvbmZpZy5kZWJ1ZyxcbiAgICBwcm9maWxlOiBjb25maWcucHJvZmlsZSxcbiAgICBwcm94eTogY29uZmlnLnByb3h5LFxuICAgIGNhQnVuZGxlUGF0aDogY29uZmlnLmNhQnVuZGxlUGF0aCxcbiAgICBlYzJjcmVkczogY29uZmlnLmVjMmNyZWRzLFxuICAgIHZlcnNpb25SZXBvcnRpbmc6IGNvbmZpZy52ZXJzaW9uUmVwb3J0aW5nLFxuICAgIHBhdGhNZXRhZGF0YTogY29uZmlnLnBhdGhNZXRhZGF0YSxcbiAgICBhc3NldE1ldGFkYXRhOiBjb25maWcuYXNzZXRNZXRhZGF0YSxcbiAgICByb2xlQXJuOiBjb25maWcucm9sZUFybixcbiAgICBzdGFnaW5nOiBjb25maWcuc3RhZ2luZyxcbiAgICBvdXRwdXQ6IGNvbmZpZy5vdXRwdXQsXG4gICAgbm90aWNlczogY29uZmlnLm5vdGljZXMsXG4gICAgbm9Db2xvcjogY29uZmlnLm5vQ29sb3IsXG4gICAgY2k6IGNvbmZpZy5jaSxcbiAgICB1bnN0YWJsZTogY29uZmlnLnVuc3RhYmxlLFxuICAgIHRlbGVtZXRyeUZpbGU6IGNvbmZpZy50ZWxlbWV0cnlGaWxlLFxuICAgIHllczogY29uZmlnLnllcyxcbiAgfTtcbiAgY29uc3QgbGlzdE9wdGlvbnMgPSB7XG4gICAgbG9uZzogY29uZmlnLmxpc3Q/LmxvbmcsXG4gICAgc2hvd0RlcGVuZGVuY2llczogY29uZmlnLmxpc3Q/LnNob3dEZXBlbmRlbmNpZXMsXG4gIH07XG4gIGNvbnN0IHN5bnRoT3B0aW9ucyA9IHtcbiAgICBleGNsdXNpdmVseTogY29uZmlnLnN5bnRoPy5leGNsdXNpdmVseSxcbiAgICB2YWxpZGF0aW9uOiBjb25maWcuc3ludGg/LnZhbGlkYXRpb24sXG4gICAgcXVpZXQ6IGNvbmZpZy5zeW50aD8ucXVpZXQsXG4gIH07XG4gIGNvbnN0IGJvb3RzdHJhcE9wdGlvbnMgPSB7XG4gICAgYm9vdHN0cmFwQnVja2V0TmFtZTogY29uZmlnLmJvb3RzdHJhcD8uYm9vdHN0cmFwQnVja2V0TmFtZSxcbiAgICBib290c3RyYXBLbXNLZXlJZDogY29uZmlnLmJvb3RzdHJhcD8uYm9vdHN0cmFwS21zS2V5SWQsXG4gICAgZXhhbXBsZVBlcm1pc3Npb25zQm91bmRhcnk6IGNvbmZpZy5ib290c3RyYXA/LmV4YW1wbGVQZXJtaXNzaW9uc0JvdW5kYXJ5LFxuICAgIGN1c3RvbVBlcm1pc3Npb25zQm91bmRhcnk6IGNvbmZpZy5ib290c3RyYXA/LmN1c3RvbVBlcm1pc3Npb25zQm91bmRhcnksXG4gICAgYm9vdHN0cmFwQ3VzdG9tZXJLZXk6IGNvbmZpZy5ib290c3RyYXA/LmJvb3RzdHJhcEN1c3RvbWVyS2V5LFxuICAgIHF1YWxpZmllcjogY29uZmlnLmJvb3RzdHJhcD8ucXVhbGlmaWVyLFxuICAgIHB1YmxpY0FjY2Vzc0Jsb2NrQ29uZmlndXJhdGlvbjogY29uZmlnLmJvb3RzdHJhcD8ucHVibGljQWNjZXNzQmxvY2tDb25maWd1cmF0aW9uLFxuICAgIGRlbnlFeHRlcm5hbElkOiBjb25maWcuYm9vdHN0cmFwPy5kZW55RXh0ZXJuYWxJZCxcbiAgICB0YWdzOiBjb25maWcuYm9vdHN0cmFwPy50YWdzLFxuICAgIGV4ZWN1dGU6IGNvbmZpZy5ib290c3RyYXA/LmV4ZWN1dGUsXG4gICAgdHJ1c3Q6IGNvbmZpZy5ib290c3RyYXA/LnRydXN0LFxuICAgIHRydXN0Rm9yTG9va3VwOiBjb25maWcuYm9vdHN0cmFwPy50cnVzdEZvckxvb2t1cCxcbiAgICB1bnRydXN0OiBjb25maWcuYm9vdHN0cmFwPy51bnRydXN0LFxuICAgIGNsb3VkZm9ybWF0aW9uRXhlY3V0aW9uUG9saWNpZXM6IGNvbmZpZy5ib290c3RyYXA/LmNsb3VkZm9ybWF0aW9uRXhlY3V0aW9uUG9saWNpZXMsXG4gICAgZm9yY2U6IGNvbmZpZy5ib290c3RyYXA/LmZvcmNlLFxuICAgIHRlcm1pbmF0aW9uUHJvdGVjdGlvbjogY29uZmlnLmJvb3RzdHJhcD8udGVybWluYXRpb25Qcm90ZWN0aW9uLFxuICAgIHNob3dUZW1wbGF0ZTogY29uZmlnLmJvb3RzdHJhcD8uc2hvd1RlbXBsYXRlLFxuICAgIHRvb2xraXRTdGFja05hbWU6IGNvbmZpZy5ib290c3RyYXA/LnRvb2xraXRTdGFja05hbWUsXG4gICAgdGVtcGxhdGU6IGNvbmZpZy5ib290c3RyYXA/LnRlbXBsYXRlLFxuICAgIHByZXZpb3VzUGFyYW1ldGVyczogY29uZmlnLmJvb3RzdHJhcD8ucHJldmlvdXNQYXJhbWV0ZXJzLFxuICB9O1xuICBjb25zdCBnY09wdGlvbnMgPSB7XG4gICAgYWN0aW9uOiBjb25maWcuZ2M/LmFjdGlvbixcbiAgICB0eXBlOiBjb25maWcuZ2M/LnR5cGUsXG4gICAgcm9sbGJhY2tCdWZmZXJEYXlzOiBjb25maWcuZ2M/LnJvbGxiYWNrQnVmZmVyRGF5cyxcbiAgICBjcmVhdGVkQnVmZmVyRGF5czogY29uZmlnLmdjPy5jcmVhdGVkQnVmZmVyRGF5cyxcbiAgICBjb25maXJtOiBjb25maWcuZ2M/LmNvbmZpcm0sXG4gICAgdG9vbGtpdFN0YWNrTmFtZTogY29uZmlnLmdjPy50b29sa2l0U3RhY2tOYW1lLFxuICAgIGJvb3RzdHJhcFN0YWNrTmFtZTogY29uZmlnLmdjPy5ib290c3RyYXBTdGFja05hbWUsXG4gIH07XG4gIGNvbnN0IGZsYWdzT3B0aW9ucyA9IHtcbiAgICB2YWx1ZTogY29uZmlnLmZsYWdzPy52YWx1ZSxcbiAgICBzZXQ6IGNvbmZpZy5mbGFncz8uc2V0LFxuICAgIGFsbDogY29uZmlnLmZsYWdzPy5hbGwsXG4gICAgdW5jb25maWd1cmVkOiBjb25maWcuZmxhZ3M/LnVuY29uZmlndXJlZCxcbiAgICByZWNvbW1lbmRlZDogY29uZmlnLmZsYWdzPy5yZWNvbW1lbmRlZCxcbiAgICBkZWZhdWx0OiBjb25maWcuZmxhZ3M/LmRlZmF1bHQsXG4gICAgaW50ZXJhY3RpdmU6IGNvbmZpZy5mbGFncz8uaW50ZXJhY3RpdmUsXG4gICAgc2FmZTogY29uZmlnLmZsYWdzPy5zYWZlLFxuICAgIGNvbmN1cnJlbmN5OiBjb25maWcuZmxhZ3M/LmNvbmN1cnJlbmN5LFxuICB9O1xuICBjb25zdCBkZXBsb3lPcHRpb25zID0ge1xuICAgIGFsbDogY29uZmlnLmRlcGxveT8uYWxsLFxuICAgIGJ1aWxkRXhjbHVkZTogY29uZmlnLmRlcGxveT8uYnVpbGRFeGNsdWRlLFxuICAgIGV4Y2x1c2l2ZWx5OiBjb25maWcuZGVwbG95Py5leGNsdXNpdmVseSxcbiAgICByZXF1aXJlQXBwcm92YWw6IGNvbmZpZy5kZXBsb3k/LnJlcXVpcmVBcHByb3ZhbCxcbiAgICBub3RpZmljYXRpb25Bcm5zOiBjb25maWcuZGVwbG95Py5ub3RpZmljYXRpb25Bcm5zLFxuICAgIHRhZ3M6IGNvbmZpZy5kZXBsb3k/LnRhZ3MsXG4gICAgZXhlY3V0ZTogY29uZmlnLmRlcGxveT8uZXhlY3V0ZSxcbiAgICBjaGFuZ2VTZXROYW1lOiBjb25maWcuZGVwbG95Py5jaGFuZ2VTZXROYW1lLFxuICAgIG1ldGhvZDogY29uZmlnLmRlcGxveT8ubWV0aG9kLFxuICAgIGltcG9ydEV4aXN0aW5nUmVzb3VyY2VzOiBjb25maWcuZGVwbG95Py5pbXBvcnRFeGlzdGluZ1Jlc291cmNlcyxcbiAgICBmb3JjZTogY29uZmlnLmRlcGxveT8uZm9yY2UsXG4gICAgcGFyYW1ldGVyczogY29uZmlnLmRlcGxveT8ucGFyYW1ldGVycyxcbiAgICBvdXRwdXRzRmlsZTogY29uZmlnLmRlcGxveT8ub3V0cHV0c0ZpbGUsXG4gICAgcHJldmlvdXNQYXJhbWV0ZXJzOiBjb25maWcuZGVwbG95Py5wcmV2aW91c1BhcmFtZXRlcnMsXG4gICAgdG9vbGtpdFN0YWNrTmFtZTogY29uZmlnLmRlcGxveT8udG9vbGtpdFN0YWNrTmFtZSxcbiAgICBwcm9ncmVzczogY29uZmlnLmRlcGxveT8ucHJvZ3Jlc3MsXG4gICAgcm9sbGJhY2s6IGNvbmZpZy5kZXBsb3k/LnJvbGxiYWNrLFxuICAgIGhvdHN3YXA6IGNvbmZpZy5kZXBsb3k/LmhvdHN3YXAsXG4gICAgaG90c3dhcEZhbGxiYWNrOiBjb25maWcuZGVwbG95Py5ob3Rzd2FwRmFsbGJhY2ssXG4gICAgaG90c3dhcEVjc01pbmltdW1IZWFsdGh5UGVyY2VudDogY29uZmlnLmRlcGxveT8uaG90c3dhcEVjc01pbmltdW1IZWFsdGh5UGVyY2VudCxcbiAgICBob3Rzd2FwRWNzTWF4aW11bUhlYWx0aHlQZXJjZW50OiBjb25maWcuZGVwbG95Py5ob3Rzd2FwRWNzTWF4aW11bUhlYWx0aHlQZXJjZW50LFxuICAgIGhvdHN3YXBFY3NTdGFiaWxpemF0aW9uVGltZW91dFNlY29uZHM6IGNvbmZpZy5kZXBsb3k/LmhvdHN3YXBFY3NTdGFiaWxpemF0aW9uVGltZW91dFNlY29uZHMsXG4gICAgd2F0Y2g6IGNvbmZpZy5kZXBsb3k/LndhdGNoLFxuICAgIGxvZ3M6IGNvbmZpZy5kZXBsb3k/LmxvZ3MsXG4gICAgY29uY3VycmVuY3k6IGNvbmZpZy5kZXBsb3k/LmNvbmN1cnJlbmN5LFxuICAgIGFzc2V0UGFyYWxsZWxpc206IGNvbmZpZy5kZXBsb3k/LmFzc2V0UGFyYWxsZWxpc20sXG4gICAgYXNzZXRQcmVidWlsZDogY29uZmlnLmRlcGxveT8uYXNzZXRQcmVidWlsZCxcbiAgICBpZ25vcmVOb1N0YWNrczogY29uZmlnLmRlcGxveT8uaWdub3JlTm9TdGFja3MsXG4gIH07XG4gIGNvbnN0IHJvbGxiYWNrT3B0aW9ucyA9IHtcbiAgICBhbGw6IGNvbmZpZy5yb2xsYmFjaz8uYWxsLFxuICAgIHRvb2xraXRTdGFja05hbWU6IGNvbmZpZy5yb2xsYmFjaz8udG9vbGtpdFN0YWNrTmFtZSxcbiAgICBmb3JjZTogY29uZmlnLnJvbGxiYWNrPy5mb3JjZSxcbiAgICB2YWxpZGF0ZUJvb3RzdHJhcFZlcnNpb246IGNvbmZpZy5yb2xsYmFjaz8udmFsaWRhdGVCb290c3RyYXBWZXJzaW9uLFxuICAgIG9ycGhhbjogY29uZmlnLnJvbGxiYWNrPy5vcnBoYW4sXG4gIH07XG4gIGNvbnN0IGltcG9ydE9wdGlvbnMgPSB7XG4gICAgZXhlY3V0ZTogY29uZmlnLmltcG9ydD8uZXhlY3V0ZSxcbiAgICBjaGFuZ2VTZXROYW1lOiBjb25maWcuaW1wb3J0Py5jaGFuZ2VTZXROYW1lLFxuICAgIHRvb2xraXRTdGFja05hbWU6IGNvbmZpZy5pbXBvcnQ/LnRvb2xraXRTdGFja05hbWUsXG4gICAgcm9sbGJhY2s6IGNvbmZpZy5pbXBvcnQ/LnJvbGxiYWNrLFxuICAgIGZvcmNlOiBjb25maWcuaW1wb3J0Py5mb3JjZSxcbiAgICByZWNvcmRSZXNvdXJjZU1hcHBpbmc6IGNvbmZpZy5pbXBvcnQ/LnJlY29yZFJlc291cmNlTWFwcGluZyxcbiAgICByZXNvdXJjZU1hcHBpbmc6IGNvbmZpZy5pbXBvcnQ/LnJlc291cmNlTWFwcGluZyxcbiAgfTtcbiAgY29uc3Qgd2F0Y2hPcHRpb25zID0ge1xuICAgIGJ1aWxkRXhjbHVkZTogY29uZmlnLndhdGNoPy5idWlsZEV4Y2x1ZGUsXG4gICAgZXhjbHVzaXZlbHk6IGNvbmZpZy53YXRjaD8uZXhjbHVzaXZlbHksXG4gICAgY2hhbmdlU2V0TmFtZTogY29uZmlnLndhdGNoPy5jaGFuZ2VTZXROYW1lLFxuICAgIGZvcmNlOiBjb25maWcud2F0Y2g/LmZvcmNlLFxuICAgIHRvb2xraXRTdGFja05hbWU6IGNvbmZpZy53YXRjaD8udG9vbGtpdFN0YWNrTmFtZSxcbiAgICBwcm9ncmVzczogY29uZmlnLndhdGNoPy5wcm9ncmVzcyxcbiAgICByb2xsYmFjazogY29uZmlnLndhdGNoPy5yb2xsYmFjayxcbiAgICBob3Rzd2FwOiBjb25maWcud2F0Y2g/LmhvdHN3YXAsXG4gICAgaG90c3dhcEZhbGxiYWNrOiBjb25maWcud2F0Y2g/LmhvdHN3YXBGYWxsYmFjayxcbiAgICBob3Rzd2FwRWNzTWluaW11bUhlYWx0aHlQZXJjZW50OiBjb25maWcud2F0Y2g/LmhvdHN3YXBFY3NNaW5pbXVtSGVhbHRoeVBlcmNlbnQsXG4gICAgaG90c3dhcEVjc01heGltdW1IZWFsdGh5UGVyY2VudDogY29uZmlnLndhdGNoPy5ob3Rzd2FwRWNzTWF4aW11bUhlYWx0aHlQZXJjZW50LFxuICAgIGhvdHN3YXBFY3NTdGFiaWxpemF0aW9uVGltZW91dFNlY29uZHM6IGNvbmZpZy53YXRjaD8uaG90c3dhcEVjc1N0YWJpbGl6YXRpb25UaW1lb3V0U2Vjb25kcyxcbiAgICBsb2dzOiBjb25maWcud2F0Y2g/LmxvZ3MsXG4gICAgY29uY3VycmVuY3k6IGNvbmZpZy53YXRjaD8uY29uY3VycmVuY3ksXG4gIH07XG4gIGNvbnN0IGRlc3Ryb3lPcHRpb25zID0ge1xuICAgIGFsbDogY29uZmlnLmRlc3Ryb3k/LmFsbCxcbiAgICBleGNsdXNpdmVseTogY29uZmlnLmRlc3Ryb3k/LmV4Y2x1c2l2ZWx5LFxuICAgIGZvcmNlOiBjb25maWcuZGVzdHJveT8uZm9yY2UsXG4gIH07XG4gIGNvbnN0IGRpZmZPcHRpb25zID0ge1xuICAgIGV4Y2x1c2l2ZWx5OiBjb25maWcuZGlmZj8uZXhjbHVzaXZlbHksXG4gICAgY29udGV4dExpbmVzOiBjb25maWcuZGlmZj8uY29udGV4dExpbmVzLFxuICAgIHRlbXBsYXRlOiBjb25maWcuZGlmZj8udGVtcGxhdGUsXG4gICAgc3RyaWN0OiBjb25maWcuZGlmZj8uc3RyaWN0LFxuICAgIHNlY3VyaXR5T25seTogY29uZmlnLmRpZmY/LnNlY3VyaXR5T25seSxcbiAgICBmYWlsOiBjb25maWcuZGlmZj8uZmFpbCxcbiAgICBwcm9jZXNzZWQ6IGNvbmZpZy5kaWZmPy5wcm9jZXNzZWQsXG4gICAgcXVpZXQ6IGNvbmZpZy5kaWZmPy5xdWlldCxcbiAgICBjaGFuZ2VTZXQ6IGNvbmZpZy5kaWZmPy5jaGFuZ2VTZXQsXG4gICAgaW1wb3J0RXhpc3RpbmdSZXNvdXJjZXM6IGNvbmZpZy5kaWZmPy5pbXBvcnRFeGlzdGluZ1Jlc291cmNlcyxcbiAgICBpbmNsdWRlTW92ZXM6IGNvbmZpZy5kaWZmPy5pbmNsdWRlTW92ZXMsXG4gIH07XG4gIGNvbnN0IGRyaWZ0T3B0aW9ucyA9IHtcbiAgICBmYWlsOiBjb25maWcuZHJpZnQ/LmZhaWwsXG4gIH07XG4gIGNvbnN0IG1ldGFkYXRhT3B0aW9ucyA9IHt9O1xuICBjb25zdCBhY2tub3dsZWRnZU9wdGlvbnMgPSB7fTtcbiAgY29uc3Qgbm90aWNlc09wdGlvbnMgPSB7XG4gICAgdW5hY2tub3dsZWRnZWQ6IGNvbmZpZy5ub3RpY2VzPy51bmFja25vd2xlZGdlZCxcbiAgfTtcbiAgY29uc3QgaW5pdE9wdGlvbnMgPSB7XG4gICAgbGFuZ3VhZ2U6IGNvbmZpZy5pbml0Py5sYW5ndWFnZSxcbiAgICBsaXN0OiBjb25maWcuaW5pdD8ubGlzdCxcbiAgICBnZW5lcmF0ZU9ubHk6IGNvbmZpZy5pbml0Py5nZW5lcmF0ZU9ubHksXG4gICAgbGliVmVyc2lvbjogY29uZmlnLmluaXQ/LmxpYlZlcnNpb24sXG4gICAgZnJvbVBhdGg6IGNvbmZpZy5pbml0Py5mcm9tUGF0aCxcbiAgICB0ZW1wbGF0ZVBhdGg6IGNvbmZpZy5pbml0Py50ZW1wbGF0ZVBhdGgsXG4gIH07XG4gIGNvbnN0IG1pZ3JhdGVPcHRpb25zID0ge1xuICAgIHN0YWNrTmFtZTogY29uZmlnLm1pZ3JhdGU/LnN0YWNrTmFtZSxcbiAgICBsYW5ndWFnZTogY29uZmlnLm1pZ3JhdGU/Lmxhbmd1YWdlLFxuICAgIGFjY291bnQ6IGNvbmZpZy5taWdyYXRlPy5hY2NvdW50LFxuICAgIHJlZ2lvbjogY29uZmlnLm1pZ3JhdGU/LnJlZ2lvbixcbiAgICBmcm9tUGF0aDogY29uZmlnLm1pZ3JhdGU/LmZyb21QYXRoLFxuICAgIGZyb21TdGFjazogY29uZmlnLm1pZ3JhdGU/LmZyb21TdGFjayxcbiAgICBvdXRwdXRQYXRoOiBjb25maWcubWlncmF0ZT8ub3V0cHV0UGF0aCxcbiAgICBmcm9tU2NhbjogY29uZmlnLm1pZ3JhdGU/LmZyb21TY2FuLFxuICAgIGZpbHRlcjogY29uZmlnLm1pZ3JhdGU/LmZpbHRlcixcbiAgICBjb21wcmVzczogY29uZmlnLm1pZ3JhdGU/LmNvbXByZXNzLFxuICB9O1xuICBjb25zdCBjb250ZXh0T3B0aW9ucyA9IHtcbiAgICByZXNldDogY29uZmlnLmNvbnRleHQ/LnJlc2V0LFxuICAgIGZvcmNlOiBjb25maWcuY29udGV4dD8uZm9yY2UsXG4gICAgY2xlYXI6IGNvbmZpZy5jb250ZXh0Py5jbGVhcixcbiAgfTtcbiAgY29uc3QgZG9jc09wdGlvbnMgPSB7XG4gICAgYnJvd3NlcjogY29uZmlnLmRvY3M/LmJyb3dzZXIsXG4gIH07XG4gIGNvbnN0IGRvY3Rvck9wdGlvbnMgPSB7fTtcbiAgY29uc3QgcmVmYWN0b3JPcHRpb25zID0ge1xuICAgIGFkZGl0aW9uYWxTdGFja05hbWU6IGNvbmZpZy5yZWZhY3Rvcj8uYWRkaXRpb25hbFN0YWNrTmFtZSxcbiAgICBkcnlSdW46IGNvbmZpZy5yZWZhY3Rvcj8uZHJ5UnVuLFxuICAgIG92ZXJyaWRlRmlsZTogY29uZmlnLnJlZmFjdG9yPy5vdmVycmlkZUZpbGUsXG4gICAgcmV2ZXJ0OiBjb25maWcucmVmYWN0b3I/LnJldmVydCxcbiAgICBmb3JjZTogY29uZmlnLnJlZmFjdG9yPy5mb3JjZSxcbiAgfTtcbiAgY29uc3QgY2xpVGVsZW1ldHJ5T3B0aW9ucyA9IHtcbiAgICBlbmFibGU6IGNvbmZpZy5jbGlUZWxlbWV0cnk/LmVuYWJsZSxcbiAgICBkaXNhYmxlOiBjb25maWcuY2xpVGVsZW1ldHJ5Py5kaXNhYmxlLFxuICAgIHN0YXR1czogY29uZmlnLmNsaVRlbGVtZXRyeT8uc3RhdHVzLFxuICB9O1xuICBjb25zdCB1c2VySW5wdXQ6IFVzZXJJbnB1dCA9IHtcbiAgICBnbG9iYWxPcHRpb25zLFxuICAgIGxpc3Q6IGxpc3RPcHRpb25zLFxuICAgIHN5bnRoOiBzeW50aE9wdGlvbnMsXG4gICAgYm9vdHN0cmFwOiBib290c3RyYXBPcHRpb25zLFxuICAgIGdjOiBnY09wdGlvbnMsXG4gICAgZmxhZ3M6IGZsYWdzT3B0aW9ucyxcbiAgICBkZXBsb3k6IGRlcGxveU9wdGlvbnMsXG4gICAgcm9sbGJhY2s6IHJvbGxiYWNrT3B0aW9ucyxcbiAgICBpbXBvcnQ6IGltcG9ydE9wdGlvbnMsXG4gICAgd2F0Y2g6IHdhdGNoT3B0aW9ucyxcbiAgICBkZXN0cm95OiBkZXN0cm95T3B0aW9ucyxcbiAgICBkaWZmOiBkaWZmT3B0aW9ucyxcbiAgICBkcmlmdDogZHJpZnRPcHRpb25zLFxuICAgIG1ldGFkYXRhOiBtZXRhZGF0YU9wdGlvbnMsXG4gICAgYWNrbm93bGVkZ2U6IGFja25vd2xlZGdlT3B0aW9ucyxcbiAgICBub3RpY2VzOiBub3RpY2VzT3B0aW9ucyxcbiAgICBpbml0OiBpbml0T3B0aW9ucyxcbiAgICBtaWdyYXRlOiBtaWdyYXRlT3B0aW9ucyxcbiAgICBjb250ZXh0OiBjb250ZXh0T3B0aW9ucyxcbiAgICBkb2NzOiBkb2NzT3B0aW9ucyxcbiAgICBkb2N0b3I6IGRvY3Rvck9wdGlvbnMsXG4gICAgcmVmYWN0b3I6IHJlZmFjdG9yT3B0aW9ucyxcbiAgICBjbGlUZWxlbWV0cnk6IGNsaVRlbGVtZXRyeU9wdGlvbnMsXG4gIH07XG5cbiAgcmV0dXJuIHVzZXJJbnB1dDtcbn1cbiJdfQ==