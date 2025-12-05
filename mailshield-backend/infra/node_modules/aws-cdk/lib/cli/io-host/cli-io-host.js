"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CliIoHost = void 0;
const util = require("node:util");
const cloud_assembly_schema_1 = require("@aws-cdk/cloud-assembly-schema");
const toolkit_lib_1 = require("@aws-cdk/toolkit-lib");
const chalk = require("chalk");
const promptly = require("promptly");
const api_private_1 = require("../../../lib/api-private");
const deploy_1 = require("../../commands/deploy");
const messages_1 = require("../telemetry/messages");
const session_1 = require("../telemetry/session");
const file_sink_1 = require("../telemetry/sink/file-sink");
const ci_1 = require("../util/ci");
/**
 * A simple IO host for the CLI that writes messages to the console.
 */
class CliIoHost {
    /**
     * Returns the singleton instance
     */
    static instance(props = {}, forceNew = false) {
        if (forceNew || !CliIoHost._instance) {
            CliIoHost._instance = new CliIoHost(props);
        }
        return CliIoHost._instance;
    }
    /**
     * Returns the singleton instance if it exists
     */
    static get() {
        return CliIoHost._instance;
    }
    constructor(props = {}) {
        /**
         * Configure the target stream for notices
         *
         * (Not a setter because there's no need for additional logic when this value
         * is changed yet)
         */
        this.noticesDestination = 'stderr';
        this._progress = deploy_1.StackActivityProgress.BAR;
        // Corked Logging
        this.corkedCounter = 0;
        this.corkedLoggingBuffer = [];
        this.currentAction = props.currentAction ?? 'none';
        this.isTTY = props.isTTY ?? process.stdout.isTTY ?? false;
        this.logLevel = props.logLevel ?? 'info';
        this.isCI = props.isCI ?? (0, ci_1.isCI)();
        this.requireDeployApproval = props.requireDeployApproval ?? cloud_assembly_schema_1.RequireApproval.BROADENING;
        this.stackProgress = props.stackProgress ?? deploy_1.StackActivityProgress.BAR;
        this.autoRespond = props.autoRespond ?? false;
    }
    async startTelemetry(args, context, _proxyAgent) {
        let sink;
        const telemetryFilePath = args['telemetry-file'];
        if (telemetryFilePath) {
            sink = new file_sink_1.FileTelemetrySink({
                ioHost: this,
                logFilePath: telemetryFilePath,
            });
        }
        // TODO: uncomment this at launch
        // if (canCollectTelemetry(args, context)) {
        //   sink = new EndpointTelemetrySink({
        //     ioHost: this,
        //     agent: proxyAgent,
        //     endpoint: '', // TODO: add endpoint
        //   });
        // }
        if (sink) {
            this.telemetry = new session_1.TelemetrySession({
                ioHost: this,
                client: sink,
                arguments: args,
                context: context,
            });
        }
        await this.telemetry?.begin();
    }
    /**
     * Update the stackProgress preference.
     */
    set stackProgress(type) {
        this._progress = type;
    }
    /**
     * Gets the stackProgress value.
     *
     * This takes into account other state of the ioHost,
     * like if isTTY and isCI.
     */
    get stackProgress() {
        // We can always use EVENTS
        if (this._progress === deploy_1.StackActivityProgress.EVENTS) {
            return this._progress;
        }
        // if a debug message (and thus any more verbose messages) are relevant to the current log level, we have verbose logging
        const verboseLogging = (0, api_private_1.isMessageRelevantForLevel)({ level: 'debug' }, this.logLevel);
        if (verboseLogging) {
            return deploy_1.StackActivityProgress.EVENTS;
        }
        // On Windows we cannot use fancy output
        const isWindows = process.platform === 'win32';
        if (isWindows) {
            return deploy_1.StackActivityProgress.EVENTS;
        }
        // On some CI systems (such as CircleCI) output still reports as a TTY so we also
        // need an individual check for whether we're running on CI.
        // see: https://discuss.circleci.com/t/circleci-terminal-is-a-tty-but-term-is-not-set/9965
        const fancyOutputAvailable = this.isTTY && !this.isCI;
        if (!fancyOutputAvailable) {
            return deploy_1.StackActivityProgress.EVENTS;
        }
        // Use the user preference
        return this._progress;
    }
    get defaults() {
        return this.asIoHelper().defaults;
    }
    asIoHelper() {
        return (0, api_private_1.asIoHelper)(this, this.currentAction);
    }
    /**
     * Executes a block of code with corked logging. All log messages during execution
     * are buffered and only written when all nested cork blocks complete (when CORK_COUNTER reaches 0).
     * The corking is bound to the specific instance of the CliIoHost.
     *
     * @param block - Async function to execute with corked logging
     * @returns Promise that resolves with the block's return value
     */
    async withCorkedLogging(block) {
        this.corkedCounter++;
        try {
            return await block();
        }
        finally {
            this.corkedCounter--;
            if (this.corkedCounter === 0) {
                // Process each buffered message through notify
                for (const ioMessage of this.corkedLoggingBuffer) {
                    await this.notify(ioMessage);
                }
                // remove all buffered messages in-place
                this.corkedLoggingBuffer.splice(0);
            }
        }
    }
    /**
     * Notifies the host of a message.
     * The caller waits until the notification completes.
     */
    async notify(msg) {
        await this.maybeEmitTelemetry(msg);
        if (this.isStackActivity(msg)) {
            if (!this.activityPrinter) {
                this.activityPrinter = this.makeActivityPrinter();
            }
            this.activityPrinter.notify(msg);
            return;
        }
        if (!(0, api_private_1.isMessageRelevantForLevel)(msg, this.logLevel)) {
            return;
        }
        if (this.corkedCounter > 0) {
            this.corkedLoggingBuffer.push(msg);
            return;
        }
        const output = this.formatMessage(msg);
        const stream = this.selectStream(msg);
        stream?.write(output);
    }
    async maybeEmitTelemetry(msg) {
        try {
            if (this.telemetry && isTelemetryMessage(msg)) {
                await this.telemetry.emit({
                    eventType: getEventType(msg),
                    duration: msg.data.duration,
                    error: msg.data.error,
                });
            }
        }
        catch (e) {
            await this.defaults.trace(`Emit Telemetry Failed ${e.message}`);
        }
    }
    /**
     * Detect stack activity messages so they can be send to the printer.
     */
    isStackActivity(msg) {
        return msg.code && [
            'CDK_TOOLKIT_I5501',
            'CDK_TOOLKIT_I5502',
            'CDK_TOOLKIT_I5503',
        ].includes(msg.code);
    }
    /**
     * Detect special messages encode information about whether or not
     * they require approval
     */
    skipApprovalStep(msg) {
        const approvalToolkitCodes = ['CDK_TOOLKIT_I5060'];
        if (!(msg.code && approvalToolkitCodes.includes(msg.code))) {
            false;
        }
        switch (this.requireDeployApproval) {
            // Never require approval
            case cloud_assembly_schema_1.RequireApproval.NEVER:
                return true;
            // Always require approval
            case cloud_assembly_schema_1.RequireApproval.ANYCHANGE:
                return false;
            // Require approval if changes include broadening permissions
            case cloud_assembly_schema_1.RequireApproval.BROADENING:
                return ['none', 'non-broadening'].includes(msg.data?.permissionChangeType);
        }
    }
    /**
     * Determines the output stream, based on message and configuration.
     */
    selectStream(msg) {
        if (isNoticesMessage(msg)) {
            return targetStreamObject(this.noticesDestination);
        }
        return this.selectStreamFromLevel(msg.level);
    }
    /**
     * Determines the output stream, based on message level and configuration.
     */
    selectStreamFromLevel(level) {
        // The stream selection policy for the CLI is the following:
        //
        //   (1) Messages of level `result` always go to `stdout`
        //   (2) Messages of level `error` always go to `stderr`.
        //   (3a) All remaining messages go to `stderr`.
        //   (3b) If we are in CI mode, all remaining messages go to `stdout`.
        //
        switch (level) {
            case 'error':
                return process.stderr;
            case 'result':
                return process.stdout;
            default:
                return this.isCI ? process.stdout : process.stderr;
        }
    }
    /**
     * Notifies the host of a message that requires a response.
     *
     * If the host does not return a response the suggested
     * default response from the input message will be used.
     */
    async requestResponse(msg) {
        // If the request cannot be prompted for by the CliIoHost, we just accept the default
        if (!isPromptableRequest(msg)) {
            await this.notify(msg);
            return msg.defaultResponse;
        }
        const response = await this.withCorkedLogging(async () => {
            // prepare prompt data
            // @todo this format is not defined anywhere, probably should be
            const data = msg.data ?? {};
            const motivation = data.motivation ?? 'User input is needed';
            const concurrency = data.concurrency ?? 0;
            const responseDescription = data.responseDescription;
            // Special approval prompt
            // Determine if the message needs approval. If it does, continue (it is a basic confirmation prompt)
            // If it does not, return success (true). We only check messages with codes that we are aware
            // are requires approval codes.
            if (this.skipApprovalStep(msg)) {
                return true;
            }
            // In --yes mode, respond for the user if we can
            if (this.autoRespond) {
                // respond with yes to all confirmations
                if (isConfirmationPrompt(msg)) {
                    await this.notify({
                        ...msg,
                        message: `${chalk.cyan(msg.message)} (auto-confirmed)`,
                    });
                    return true;
                }
                // respond with the default for all other messages
                if (msg.defaultResponse) {
                    await this.notify({
                        ...msg,
                        message: `${chalk.cyan(msg.message)} (auto-responded with default: ${util.format(msg.defaultResponse)})`,
                    });
                    return msg.defaultResponse;
                }
            }
            // only talk to user if STDIN is a terminal (otherwise, fail)
            if (!this.isTTY) {
                throw new toolkit_lib_1.ToolkitError(`${motivation}, but terminal (TTY) is not attached so we are unable to get a confirmation from the user`);
            }
            // only talk to user if concurrency is 1 (otherwise, fail)
            if (concurrency > 1) {
                throw new toolkit_lib_1.ToolkitError(`${motivation}, but concurrency is greater than 1 so we are unable to get a confirmation from the user`);
            }
            // Basic confirmation prompt
            // We treat all requests with a boolean response as confirmation prompts
            if (isConfirmationPrompt(msg)) {
                const confirmed = await promptly.confirm(`${chalk.cyan(msg.message)} (y/n)`);
                if (!confirmed) {
                    throw new toolkit_lib_1.ToolkitError('Aborted by user');
                }
                return confirmed;
            }
            // Asking for a specific value
            const prompt = extractPromptInfo(msg);
            const desc = responseDescription ?? prompt.default;
            const answer = await promptly.prompt(`${chalk.cyan(msg.message)}${desc ? ` (${desc})` : ''}`, {
                default: prompt.default,
                trim: true,
            });
            return prompt.convertAnswer(answer);
        });
        // We need to cast this because it is impossible to narrow the generic type
        // isPromptableRequest ensures that the response type is one we can prompt for
        // the remaining code ensure we are indeed returning the correct type
        return response;
    }
    /**
     * Formats a message for console output with optional color support
     */
    formatMessage(msg) {
        // apply provided style or a default style if we're in TTY mode
        let message_text = this.isTTY
            ? styleMap[msg.level](msg.message)
            : msg.message;
        // prepend timestamp if IoMessageLevel is DEBUG or TRACE. Postpend a newline.
        return ((msg.level === 'debug' || msg.level === 'trace')
            ? `[${this.formatTime(msg.time)}] ${message_text}`
            : message_text) + '\n';
    }
    /**
     * Formats date to HH:MM:SS
     */
    formatTime(d) {
        const pad = (n) => n.toString().padStart(2, '0');
        return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    }
    /**
     * Get an instance of the ActivityPrinter
     */
    makeActivityPrinter() {
        const props = {
            stream: this.selectStreamFromLevel('info'),
        };
        switch (this.stackProgress) {
            case deploy_1.StackActivityProgress.EVENTS:
                return new api_private_1.HistoryActivityPrinter(props);
            case deploy_1.StackActivityProgress.BAR:
                return new api_private_1.CurrentActivityPrinter(props);
        }
    }
}
exports.CliIoHost = CliIoHost;
/**
 * This IoHost implementation considers a request promptable, if:
 * - it's a yes/no confirmation
 * - asking for a string or number value
 */
function isPromptableRequest(msg) {
    return isConfirmationPrompt(msg)
        || typeof msg.defaultResponse === 'string'
        || typeof msg.defaultResponse === 'number';
}
/**
 * Check if the request is a confirmation prompt
 * We treat all requests with a boolean response as confirmation prompts
 */
function isConfirmationPrompt(msg) {
    return typeof msg.defaultResponse === 'boolean';
}
/**
 * Helper to extract information for promptly from the request
 */
function extractPromptInfo(msg) {
    const isNumber = (typeof msg.defaultResponse === 'number');
    const defaultResponse = util.format(msg.defaultResponse);
    return {
        default: defaultResponse,
        defaultDesc: 'defaultDescription' in msg && msg.defaultDescription ? util.format(msg.defaultDescription) : defaultResponse,
        convertAnswer: isNumber ? (v) => Number(v) : (v) => String(v),
    };
}
const styleMap = {
    error: chalk.red,
    warn: chalk.yellow,
    result: chalk.reset,
    info: chalk.reset,
    debug: chalk.gray,
    trace: chalk.gray,
};
function targetStreamObject(x) {
    switch (x) {
        case 'stderr':
            return process.stderr;
        case 'stdout':
            return process.stdout;
        case 'drop':
            return undefined;
    }
}
function isNoticesMessage(msg) {
    return api_private_1.IO.CDK_TOOLKIT_I0100.is(msg) || api_private_1.IO.CDK_TOOLKIT_W0101.is(msg) || api_private_1.IO.CDK_TOOLKIT_E0101.is(msg) || api_private_1.IO.CDK_TOOLKIT_I0101.is(msg);
}
function isTelemetryMessage(msg) {
    return messages_1.CLI_TELEMETRY_CODES.some((c) => c.is(msg));
}
function getEventType(msg) {
    switch (msg.code) {
        case messages_1.CLI_PRIVATE_IO.CDK_CLI_I1001.code:
            return 'SYNTH';
        case messages_1.CLI_PRIVATE_IO.CDK_CLI_I2001.code:
            return 'INVOKE';
        case messages_1.CLI_PRIVATE_IO.CDK_CLI_I3001.code:
            return 'DEPLOY';
        default:
            throw new toolkit_lib_1.ToolkitError(`Unrecognized Telemetry Message Code: ${msg.code}`);
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2xpLWlvLWhvc3QuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJjbGktaW8taG9zdC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSxrQ0FBa0M7QUFDbEMsMEVBQWlFO0FBQ2pFLHNEQUFvRDtBQUdwRCwrQkFBK0I7QUFDL0IscUNBQXFDO0FBRXJDLDBEQUFxSTtBQUNySSxrREFBOEQ7QUFFOUQsb0RBQTRFO0FBRTVFLGtEQUF3RDtBQUN4RCwyREFBZ0U7QUFDaEUsbUNBQWtDO0FBb0ZsQzs7R0FFRztBQUNILE1BQWEsU0FBUztJQUNwQjs7T0FFRztJQUNILE1BQU0sQ0FBQyxRQUFRLENBQUMsUUFBd0IsRUFBRSxFQUFFLFFBQVEsR0FBRyxLQUFLO1FBQzFELElBQUksUUFBUSxJQUFJLENBQUMsU0FBUyxDQUFDLFNBQVMsRUFBRSxDQUFDO1lBQ3JDLFNBQVMsQ0FBQyxTQUFTLEdBQUcsSUFBSSxTQUFTLENBQUMsS0FBSyxDQUFDLENBQUM7UUFDN0MsQ0FBQztRQUNELE9BQU8sU0FBUyxDQUFDLFNBQVMsQ0FBQztJQUM3QixDQUFDO0lBRUQ7O09BRUc7SUFDSCxNQUFNLENBQUMsR0FBRztRQUNSLE9BQU8sU0FBUyxDQUFDLFNBQVMsQ0FBQztJQUM3QixDQUFDO0lBeURELFlBQW9CLFFBQXdCLEVBQUU7UUFyQjlDOzs7OztXQUtHO1FBQ0ksdUJBQWtCLEdBQWlCLFFBQVEsQ0FBQztRQUUzQyxjQUFTLEdBQTBCLDhCQUFxQixDQUFDLEdBQUcsQ0FBQztRQUtyRSxpQkFBaUI7UUFDVCxrQkFBYSxHQUFHLENBQUMsQ0FBQztRQUNULHdCQUFtQixHQUF5QixFQUFFLENBQUM7UUFPOUQsSUFBSSxDQUFDLGFBQWEsR0FBRyxLQUFLLENBQUMsYUFBYSxJQUFJLE1BQU0sQ0FBQztRQUNuRCxJQUFJLENBQUMsS0FBSyxHQUFHLEtBQUssQ0FBQyxLQUFLLElBQUksT0FBTyxDQUFDLE1BQU0sQ0FBQyxLQUFLLElBQUksS0FBSyxDQUFDO1FBQzFELElBQUksQ0FBQyxRQUFRLEdBQUcsS0FBSyxDQUFDLFFBQVEsSUFBSSxNQUFNLENBQUM7UUFDekMsSUFBSSxDQUFDLElBQUksR0FBRyxLQUFLLENBQUMsSUFBSSxJQUFJLElBQUEsU0FBSSxHQUFFLENBQUM7UUFDakMsSUFBSSxDQUFDLHFCQUFxQixHQUFHLEtBQUssQ0FBQyxxQkFBcUIsSUFBSSx1Q0FBZSxDQUFDLFVBQVUsQ0FBQztRQUV2RixJQUFJLENBQUMsYUFBYSxHQUFHLEtBQUssQ0FBQyxhQUFhLElBQUksOEJBQXFCLENBQUMsR0FBRyxDQUFDO1FBQ3RFLElBQUksQ0FBQyxXQUFXLEdBQUcsS0FBSyxDQUFDLFdBQVcsSUFBSSxLQUFLLENBQUM7SUFDaEQsQ0FBQztJQUVNLEtBQUssQ0FBQyxjQUFjLENBQUMsSUFBUyxFQUFFLE9BQWdCLEVBQUUsV0FBbUI7UUFDMUUsSUFBSSxJQUFJLENBQUM7UUFDVCxNQUFNLGlCQUFpQixHQUFHLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDO1FBQ2pELElBQUksaUJBQWlCLEVBQUUsQ0FBQztZQUN0QixJQUFJLEdBQUcsSUFBSSw2QkFBaUIsQ0FBQztnQkFDM0IsTUFBTSxFQUFFLElBQUk7Z0JBQ1osV0FBVyxFQUFFLGlCQUFpQjthQUMvQixDQUFDLENBQUM7UUFDTCxDQUFDO1FBQ0QsaUNBQWlDO1FBQ2pDLDRDQUE0QztRQUM1Qyx1Q0FBdUM7UUFDdkMsb0JBQW9CO1FBQ3BCLHlCQUF5QjtRQUN6QiwwQ0FBMEM7UUFDMUMsUUFBUTtRQUNSLElBQUk7UUFFSixJQUFJLElBQUksRUFBRSxDQUFDO1lBQ1QsSUFBSSxDQUFDLFNBQVMsR0FBRyxJQUFJLDBCQUFnQixDQUFDO2dCQUNwQyxNQUFNLEVBQUUsSUFBSTtnQkFDWixNQUFNLEVBQUUsSUFBSTtnQkFDWixTQUFTLEVBQUUsSUFBSTtnQkFDZixPQUFPLEVBQUUsT0FBTzthQUNqQixDQUFDLENBQUM7UUFDTCxDQUFDO1FBRUQsTUFBTSxJQUFJLENBQUMsU0FBUyxFQUFFLEtBQUssRUFBRSxDQUFDO0lBQ2hDLENBQUM7SUFFRDs7T0FFRztJQUNILElBQVcsYUFBYSxDQUFDLElBQTJCO1FBQ2xELElBQUksQ0FBQyxTQUFTLEdBQUcsSUFBSSxDQUFDO0lBQ3hCLENBQUM7SUFFRDs7Ozs7T0FLRztJQUNILElBQVcsYUFBYTtRQUN0QiwyQkFBMkI7UUFDM0IsSUFBSSxJQUFJLENBQUMsU0FBUyxLQUFLLDhCQUFxQixDQUFDLE1BQU0sRUFBRSxDQUFDO1lBQ3BELE9BQU8sSUFBSSxDQUFDLFNBQVMsQ0FBQztRQUN4QixDQUFDO1FBRUQseUhBQXlIO1FBQ3pILE1BQU0sY0FBYyxHQUFHLElBQUEsdUNBQXlCLEVBQUMsRUFBRSxLQUFLLEVBQUUsT0FBTyxFQUFFLEVBQUUsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDO1FBQ3BGLElBQUksY0FBYyxFQUFFLENBQUM7WUFDbkIsT0FBTyw4QkFBcUIsQ0FBQyxNQUFNLENBQUM7UUFDdEMsQ0FBQztRQUVELHdDQUF3QztRQUN4QyxNQUFNLFNBQVMsR0FBRyxPQUFPLENBQUMsUUFBUSxLQUFLLE9BQU8sQ0FBQztRQUMvQyxJQUFJLFNBQVMsRUFBRSxDQUFDO1lBQ2QsT0FBTyw4QkFBcUIsQ0FBQyxNQUFNLENBQUM7UUFDdEMsQ0FBQztRQUVELGlGQUFpRjtRQUNqRiw0REFBNEQ7UUFDNUQsMEZBQTBGO1FBQzFGLE1BQU0sb0JBQW9CLEdBQUcsSUFBSSxDQUFDLEtBQUssSUFBSSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUM7UUFDdEQsSUFBSSxDQUFDLG9CQUFvQixFQUFFLENBQUM7WUFDMUIsT0FBTyw4QkFBcUIsQ0FBQyxNQUFNLENBQUM7UUFDdEMsQ0FBQztRQUVELDBCQUEwQjtRQUMxQixPQUFPLElBQUksQ0FBQyxTQUFTLENBQUM7SUFDeEIsQ0FBQztJQUVELElBQVcsUUFBUTtRQUNqQixPQUFPLElBQUksQ0FBQyxVQUFVLEVBQUUsQ0FBQyxRQUFRLENBQUM7SUFDcEMsQ0FBQztJQUVNLFVBQVU7UUFDZixPQUFPLElBQUEsd0JBQVUsRUFBQyxJQUFJLEVBQUUsSUFBSSxDQUFDLGFBQW9CLENBQUMsQ0FBQztJQUNyRCxDQUFDO0lBRUQ7Ozs7Ozs7T0FPRztJQUNJLEtBQUssQ0FBQyxpQkFBaUIsQ0FBSSxLQUF1QjtRQUN2RCxJQUFJLENBQUMsYUFBYSxFQUFFLENBQUM7UUFDckIsSUFBSSxDQUFDO1lBQ0gsT0FBTyxNQUFNLEtBQUssRUFBRSxDQUFDO1FBQ3ZCLENBQUM7Z0JBQVMsQ0FBQztZQUNULElBQUksQ0FBQyxhQUFhLEVBQUUsQ0FBQztZQUNyQixJQUFJLElBQUksQ0FBQyxhQUFhLEtBQUssQ0FBQyxFQUFFLENBQUM7Z0JBQzdCLCtDQUErQztnQkFDL0MsS0FBSyxNQUFNLFNBQVMsSUFBSSxJQUFJLENBQUMsbUJBQW1CLEVBQUUsQ0FBQztvQkFDakQsTUFBTSxJQUFJLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxDQUFDO2dCQUMvQixDQUFDO2dCQUNELHdDQUF3QztnQkFDeEMsSUFBSSxDQUFDLG1CQUFtQixDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUNyQyxDQUFDO1FBQ0gsQ0FBQztJQUNILENBQUM7SUFFRDs7O09BR0c7SUFDSSxLQUFLLENBQUMsTUFBTSxDQUFDLEdBQXVCO1FBQ3pDLE1BQU0sSUFBSSxDQUFDLGtCQUFrQixDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBRW5DLElBQUksSUFBSSxDQUFDLGVBQWUsQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDO1lBQzlCLElBQUksQ0FBQyxJQUFJLENBQUMsZUFBZSxFQUFFLENBQUM7Z0JBQzFCLElBQUksQ0FBQyxlQUFlLEdBQUcsSUFBSSxDQUFDLG1CQUFtQixFQUFFLENBQUM7WUFDcEQsQ0FBQztZQUNELElBQUksQ0FBQyxlQUFlLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBQ2pDLE9BQU87UUFDVCxDQUFDO1FBRUQsSUFBSSxDQUFDLElBQUEsdUNBQXlCLEVBQUMsR0FBRyxFQUFFLElBQUksQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFDO1lBQ25ELE9BQU87UUFDVCxDQUFDO1FBRUQsSUFBSSxJQUFJLENBQUMsYUFBYSxHQUFHLENBQUMsRUFBRSxDQUFDO1lBQzNCLElBQUksQ0FBQyxtQkFBbUIsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUM7WUFDbkMsT0FBTztRQUNULENBQUM7UUFFRCxNQUFNLE1BQU0sR0FBRyxJQUFJLENBQUMsYUFBYSxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBQ3ZDLE1BQU0sTUFBTSxHQUFHLElBQUksQ0FBQyxZQUFZLENBQUMsR0FBRyxDQUFDLENBQUM7UUFDdEMsTUFBTSxFQUFFLEtBQUssQ0FBQyxNQUFNLENBQUMsQ0FBQztJQUN4QixDQUFDO0lBRU8sS0FBSyxDQUFDLGtCQUFrQixDQUFDLEdBQXVCO1FBQ3RELElBQUksQ0FBQztZQUNILElBQUksSUFBSSxDQUFDLFNBQVMsSUFBSSxrQkFBa0IsQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDO2dCQUM5QyxNQUFNLElBQUksQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDO29CQUN4QixTQUFTLEVBQUUsWUFBWSxDQUFDLEdBQUcsQ0FBQztvQkFDNUIsUUFBUSxFQUFFLEdBQUcsQ0FBQyxJQUFJLENBQUMsUUFBUTtvQkFDM0IsS0FBSyxFQUFFLEdBQUcsQ0FBQyxJQUFJLENBQUMsS0FBSztpQkFDdEIsQ0FBQyxDQUFDO1lBQ0wsQ0FBQztRQUNILENBQUM7UUFBQyxPQUFPLENBQU0sRUFBRSxDQUFDO1lBQ2hCLE1BQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMseUJBQXlCLENBQUMsQ0FBQyxPQUFPLEVBQUUsQ0FBQyxDQUFDO1FBQ2xFLENBQUM7SUFDSCxDQUFDO0lBRUQ7O09BRUc7SUFDSyxlQUFlLENBQUMsR0FBdUI7UUFDN0MsT0FBTyxHQUFHLENBQUMsSUFBSSxJQUFJO1lBQ2pCLG1CQUFtQjtZQUNuQixtQkFBbUI7WUFDbkIsbUJBQW1CO1NBQ3BCLENBQUMsUUFBUSxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQztJQUN2QixDQUFDO0lBRUQ7OztPQUdHO0lBQ0ssZ0JBQWdCLENBQUMsR0FBd0I7UUFDL0MsTUFBTSxvQkFBb0IsR0FBRyxDQUFDLG1CQUFtQixDQUFDLENBQUM7UUFDbkQsSUFBSSxDQUFDLENBQUMsR0FBRyxDQUFDLElBQUksSUFBSSxvQkFBb0IsQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxDQUFDLEVBQUUsQ0FBQztZQUMzRCxLQUFLLENBQUM7UUFDUixDQUFDO1FBRUQsUUFBUSxJQUFJLENBQUMscUJBQXFCLEVBQUUsQ0FBQztZQUNuQyx5QkFBeUI7WUFDekIsS0FBSyx1Q0FBZSxDQUFDLEtBQUs7Z0JBQ3hCLE9BQU8sSUFBSSxDQUFDO1lBQ2QsMEJBQTBCO1lBQzFCLEtBQUssdUNBQWUsQ0FBQyxTQUFTO2dCQUM1QixPQUFPLEtBQUssQ0FBQztZQUNmLDZEQUE2RDtZQUM3RCxLQUFLLHVDQUFlLENBQUMsVUFBVTtnQkFDN0IsT0FBTyxDQUFDLE1BQU0sRUFBRSxnQkFBZ0IsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsSUFBSSxFQUFFLG9CQUFvQixDQUFDLENBQUM7UUFDL0UsQ0FBQztJQUNILENBQUM7SUFFRDs7T0FFRztJQUNLLFlBQVksQ0FBQyxHQUFtQjtRQUN0QyxJQUFJLGdCQUFnQixDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUM7WUFDMUIsT0FBTyxrQkFBa0IsQ0FBQyxJQUFJLENBQUMsa0JBQWtCLENBQUMsQ0FBQztRQUNyRCxDQUFDO1FBRUQsT0FBTyxJQUFJLENBQUMscUJBQXFCLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQy9DLENBQUM7SUFFRDs7T0FFRztJQUNLLHFCQUFxQixDQUFDLEtBQXFCO1FBQ2pELDREQUE0RDtRQUM1RCxFQUFFO1FBQ0YseURBQXlEO1FBQ3pELHlEQUF5RDtRQUN6RCxnREFBZ0Q7UUFDaEQsc0VBQXNFO1FBQ3RFLEVBQUU7UUFDRixRQUFRLEtBQUssRUFBRSxDQUFDO1lBQ2QsS0FBSyxPQUFPO2dCQUNWLE9BQU8sT0FBTyxDQUFDLE1BQU0sQ0FBQztZQUN4QixLQUFLLFFBQVE7Z0JBQ1gsT0FBTyxPQUFPLENBQUMsTUFBTSxDQUFDO1lBQ3hCO2dCQUNFLE9BQU8sSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQztRQUN2RCxDQUFDO0lBQ0gsQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0ksS0FBSyxDQUFDLGVBQWUsQ0FBeUIsR0FBc0M7UUFDekYscUZBQXFGO1FBQ3JGLElBQUksQ0FBQyxtQkFBbUIsQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDO1lBQzlCLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUN2QixPQUFPLEdBQUcsQ0FBQyxlQUFlLENBQUM7UUFDN0IsQ0FBQztRQUVELE1BQU0sUUFBUSxHQUFHLE1BQU0sSUFBSSxDQUFDLGlCQUFpQixDQUFDLEtBQUssSUFBcUMsRUFBRTtZQUN4RixzQkFBc0I7WUFDdEIsZ0VBQWdFO1lBQ2hFLE1BQU0sSUFBSSxHQUlOLEdBQUcsQ0FBQyxJQUFJLElBQUksRUFBRSxDQUFDO1lBRW5CLE1BQU0sVUFBVSxHQUFHLElBQUksQ0FBQyxVQUFVLElBQUksc0JBQXNCLENBQUM7WUFDN0QsTUFBTSxXQUFXLEdBQUcsSUFBSSxDQUFDLFdBQVcsSUFBSSxDQUFDLENBQUM7WUFDMUMsTUFBTSxtQkFBbUIsR0FBRyxJQUFJLENBQUMsbUJBQW1CLENBQUM7WUFFckQsMEJBQTBCO1lBQzFCLG9HQUFvRztZQUNwRyw2RkFBNkY7WUFDN0YsK0JBQStCO1lBQy9CLElBQUksSUFBSSxDQUFDLGdCQUFnQixDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUM7Z0JBQy9CLE9BQU8sSUFBSSxDQUFDO1lBQ2QsQ0FBQztZQUVELGdEQUFnRDtZQUNoRCxJQUFJLElBQUksQ0FBQyxXQUFXLEVBQUUsQ0FBQztnQkFDckIsd0NBQXdDO2dCQUN4QyxJQUFJLG9CQUFvQixDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUM7b0JBQzlCLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQzt3QkFDaEIsR0FBRyxHQUFHO3dCQUNOLE9BQU8sRUFBRSxHQUFHLEtBQUssQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxtQkFBbUI7cUJBQ3ZELENBQUMsQ0FBQztvQkFDSCxPQUFPLElBQUksQ0FBQztnQkFDZCxDQUFDO2dCQUVELGtEQUFrRDtnQkFDbEQsSUFBSSxHQUFHLENBQUMsZUFBZSxFQUFFLENBQUM7b0JBQ3hCLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQzt3QkFDaEIsR0FBRyxHQUFHO3dCQUNOLE9BQU8sRUFBRSxHQUFHLEtBQUssQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxrQ0FBa0MsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsZUFBZSxDQUFDLEdBQUc7cUJBQ3pHLENBQUMsQ0FBQztvQkFDSCxPQUFPLEdBQUcsQ0FBQyxlQUFlLENBQUM7Z0JBQzdCLENBQUM7WUFDSCxDQUFDO1lBRUQsNkRBQTZEO1lBQzdELElBQUksQ0FBQyxJQUFJLENBQUMsS0FBSyxFQUFFLENBQUM7Z0JBQ2hCLE1BQU0sSUFBSSwwQkFBWSxDQUFDLEdBQUcsVUFBVSwyRkFBMkYsQ0FBQyxDQUFDO1lBQ25JLENBQUM7WUFFRCwwREFBMEQ7WUFDMUQsSUFBSSxXQUFXLEdBQUcsQ0FBQyxFQUFFLENBQUM7Z0JBQ3BCLE1BQU0sSUFBSSwwQkFBWSxDQUFDLEdBQUcsVUFBVSwwRkFBMEYsQ0FBQyxDQUFDO1lBQ2xJLENBQUM7WUFFRCw0QkFBNEI7WUFDNUIsd0VBQXdFO1lBQ3hFLElBQUksb0JBQW9CLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQztnQkFDOUIsTUFBTSxTQUFTLEdBQUcsTUFBTSxRQUFRLENBQUMsT0FBTyxDQUFDLEdBQUcsS0FBSyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxDQUFDO2dCQUM3RSxJQUFJLENBQUMsU0FBUyxFQUFFLENBQUM7b0JBQ2YsTUFBTSxJQUFJLDBCQUFZLENBQUMsaUJBQWlCLENBQUMsQ0FBQztnQkFDNUMsQ0FBQztnQkFDRCxPQUFPLFNBQVMsQ0FBQztZQUNuQixDQUFDO1lBRUQsOEJBQThCO1lBQzlCLE1BQU0sTUFBTSxHQUFHLGlCQUFpQixDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBQ3RDLE1BQU0sSUFBSSxHQUFHLG1CQUFtQixJQUFJLE1BQU0sQ0FBQyxPQUFPLENBQUM7WUFDbkQsTUFBTSxNQUFNLEdBQUcsTUFBTSxRQUFRLENBQUMsTUFBTSxDQUFDLEdBQUcsS0FBSyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLEdBQUcsSUFBSSxDQUFDLENBQUMsQ0FBQyxLQUFLLElBQUksR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsRUFBRTtnQkFDNUYsT0FBTyxFQUFFLE1BQU0sQ0FBQyxPQUFPO2dCQUN2QixJQUFJLEVBQUUsSUFBSTthQUNYLENBQUMsQ0FBQztZQUNILE9BQU8sTUFBTSxDQUFDLGFBQWEsQ0FBQyxNQUFNLENBQUMsQ0FBQztRQUN0QyxDQUFDLENBQUMsQ0FBQztRQUVILDJFQUEyRTtRQUMzRSw4RUFBOEU7UUFDOUUscUVBQXFFO1FBQ3JFLE9BQU8sUUFBd0IsQ0FBQztJQUNsQyxDQUFDO0lBRUQ7O09BRUc7SUFDSyxhQUFhLENBQUMsR0FBdUI7UUFDM0MsK0RBQStEO1FBQy9ELElBQUksWUFBWSxHQUFHLElBQUksQ0FBQyxLQUFLO1lBQzNCLENBQUMsQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUM7WUFDbEMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUM7UUFFaEIsNkVBQTZFO1FBQzdFLE9BQU8sQ0FBQyxDQUFDLEdBQUcsQ0FBQyxLQUFLLEtBQUssT0FBTyxJQUFJLEdBQUcsQ0FBQyxLQUFLLEtBQUssT0FBTyxDQUFDO1lBQ3RELENBQUMsQ0FBQyxJQUFJLElBQUksQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxLQUFLLFlBQVksRUFBRTtZQUNsRCxDQUFDLENBQUMsWUFBWSxDQUFDLEdBQUcsSUFBSSxDQUFDO0lBQzNCLENBQUM7SUFFRDs7T0FFRztJQUNLLFVBQVUsQ0FBQyxDQUFPO1FBQ3hCLE1BQU0sR0FBRyxHQUFHLENBQUMsQ0FBUyxFQUFVLEVBQUUsQ0FBQyxDQUFDLENBQUMsUUFBUSxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUMsRUFBRSxHQUFHLENBQUMsQ0FBQztRQUNqRSxPQUFPLEdBQUcsR0FBRyxDQUFDLENBQUMsQ0FBQyxRQUFRLEVBQUUsQ0FBQyxJQUFJLEdBQUcsQ0FBQyxDQUFDLENBQUMsVUFBVSxFQUFFLENBQUMsSUFBSSxHQUFHLENBQUMsQ0FBQyxDQUFDLFVBQVUsRUFBRSxDQUFDLEVBQUUsQ0FBQztJQUM5RSxDQUFDO0lBRUQ7O09BRUc7SUFDSyxtQkFBbUI7UUFDekIsTUFBTSxLQUFLLEdBQXlCO1lBQ2xDLE1BQU0sRUFBRSxJQUFJLENBQUMscUJBQXFCLENBQUMsTUFBTSxDQUFDO1NBQzNDLENBQUM7UUFFRixRQUFRLElBQUksQ0FBQyxhQUFhLEVBQUUsQ0FBQztZQUMzQixLQUFLLDhCQUFxQixDQUFDLE1BQU07Z0JBQy9CLE9BQU8sSUFBSSxvQ0FBc0IsQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUMzQyxLQUFLLDhCQUFxQixDQUFDLEdBQUc7Z0JBQzVCLE9BQU8sSUFBSSxvQ0FBc0IsQ0FBQyxLQUFLLENBQUMsQ0FBQztRQUM3QyxDQUFDO0lBQ0gsQ0FBQztDQUNGO0FBNWFELDhCQTRhQztBQUVEOzs7O0dBSUc7QUFDSCxTQUFTLG1CQUFtQixDQUFDLEdBQXdCO0lBQ25ELE9BQU8sb0JBQW9CLENBQUMsR0FBRyxDQUFDO1dBQzNCLE9BQU8sR0FBRyxDQUFDLGVBQWUsS0FBSyxRQUFRO1dBQ3ZDLE9BQU8sR0FBRyxDQUFDLGVBQWUsS0FBSyxRQUFRLENBQUM7QUFDL0MsQ0FBQztBQUVEOzs7R0FHRztBQUNILFNBQVMsb0JBQW9CLENBQUMsR0FBd0I7SUFDcEQsT0FBTyxPQUFPLEdBQUcsQ0FBQyxlQUFlLEtBQUssU0FBUyxDQUFDO0FBQ2xELENBQUM7QUFFRDs7R0FFRztBQUNILFNBQVMsaUJBQWlCLENBQUMsR0FBd0I7SUFLakQsTUFBTSxRQUFRLEdBQUcsQ0FBQyxPQUFPLEdBQUcsQ0FBQyxlQUFlLEtBQUssUUFBUSxDQUFDLENBQUM7SUFDM0QsTUFBTSxlQUFlLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsZUFBZSxDQUFDLENBQUM7SUFDekQsT0FBTztRQUNMLE9BQU8sRUFBRSxlQUFlO1FBQ3hCLFdBQVcsRUFBRSxvQkFBb0IsSUFBSSxHQUFHLElBQUksR0FBRyxDQUFDLGtCQUFrQixDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxrQkFBa0IsQ0FBQyxDQUFDLENBQUMsQ0FBQyxlQUFlO1FBQzFILGFBQWEsRUFBRSxRQUFRLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDO0tBQzlELENBQUM7QUFDSixDQUFDO0FBRUQsTUFBTSxRQUFRLEdBQW9EO0lBQ2hFLEtBQUssRUFBRSxLQUFLLENBQUMsR0FBRztJQUNoQixJQUFJLEVBQUUsS0FBSyxDQUFDLE1BQU07SUFDbEIsTUFBTSxFQUFFLEtBQUssQ0FBQyxLQUFLO0lBQ25CLElBQUksRUFBRSxLQUFLLENBQUMsS0FBSztJQUNqQixLQUFLLEVBQUUsS0FBSyxDQUFDLElBQUk7SUFDakIsS0FBSyxFQUFFLEtBQUssQ0FBQyxJQUFJO0NBQ2xCLENBQUM7QUFFRixTQUFTLGtCQUFrQixDQUFDLENBQWU7SUFDekMsUUFBUSxDQUFDLEVBQUUsQ0FBQztRQUNWLEtBQUssUUFBUTtZQUNYLE9BQU8sT0FBTyxDQUFDLE1BQU0sQ0FBQztRQUN4QixLQUFLLFFBQVE7WUFDWCxPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUM7UUFDeEIsS0FBSyxNQUFNO1lBQ1QsT0FBTyxTQUFTLENBQUM7SUFDckIsQ0FBQztBQUNILENBQUM7QUFFRCxTQUFTLGdCQUFnQixDQUFDLEdBQXVCO0lBQy9DLE9BQU8sZ0JBQUUsQ0FBQyxpQkFBaUIsQ0FBQyxFQUFFLENBQUMsR0FBRyxDQUFDLElBQUksZ0JBQUUsQ0FBQyxpQkFBaUIsQ0FBQyxFQUFFLENBQUMsR0FBRyxDQUFDLElBQUksZ0JBQUUsQ0FBQyxpQkFBaUIsQ0FBQyxFQUFFLENBQUMsR0FBRyxDQUFDLElBQUksZ0JBQUUsQ0FBQyxpQkFBaUIsQ0FBQyxFQUFFLENBQUMsR0FBRyxDQUFDLENBQUM7QUFDdEksQ0FBQztBQUVELFNBQVMsa0JBQWtCLENBQUMsR0FBdUI7SUFDakQsT0FBTyw4QkFBbUIsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQztBQUNwRCxDQUFDO0FBRUQsU0FBUyxZQUFZLENBQUMsR0FBdUI7SUFDM0MsUUFBUSxHQUFHLENBQUMsSUFBSSxFQUFFLENBQUM7UUFDakIsS0FBSyx5QkFBYyxDQUFDLGFBQWEsQ0FBQyxJQUFJO1lBQ3BDLE9BQU8sT0FBTyxDQUFDO1FBQ2pCLEtBQUsseUJBQWMsQ0FBQyxhQUFhLENBQUMsSUFBSTtZQUNwQyxPQUFPLFFBQVEsQ0FBQztRQUNsQixLQUFLLHlCQUFjLENBQUMsYUFBYSxDQUFDLElBQUk7WUFDcEMsT0FBTyxRQUFRLENBQUM7UUFDbEI7WUFDRSxNQUFNLElBQUksMEJBQVksQ0FBQyx3Q0FBd0MsR0FBRyxDQUFDLElBQUksRUFBRSxDQUFDLENBQUM7SUFDL0UsQ0FBQztBQUNILENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgdHlwZSB7IEFnZW50IH0gZnJvbSAnbm9kZTpodHRwcyc7XG5pbXBvcnQgKiBhcyB1dGlsIGZyb20gJ25vZGU6dXRpbCc7XG5pbXBvcnQgeyBSZXF1aXJlQXBwcm92YWwgfSBmcm9tICdAYXdzLWNkay9jbG91ZC1hc3NlbWJseS1zY2hlbWEnO1xuaW1wb3J0IHsgVG9vbGtpdEVycm9yIH0gZnJvbSAnQGF3cy1jZGsvdG9vbGtpdC1saWInO1xuaW1wb3J0IHR5cGUgeyBJSW9Ib3N0LCBJb01lc3NhZ2UsIElvTWVzc2FnZUNvZGUsIElvTWVzc2FnZUxldmVsLCBJb1JlcXVlc3QsIFRvb2xraXRBY3Rpb24gfSBmcm9tICdAYXdzLWNkay90b29sa2l0LWxpYic7XG5pbXBvcnQgdHlwZSB7IENvbnRleHQgfSBmcm9tICdAYXdzLWNkay90b29sa2l0LWxpYi9saWIvYXBpJztcbmltcG9ydCAqIGFzIGNoYWxrIGZyb20gJ2NoYWxrJztcbmltcG9ydCAqIGFzIHByb21wdGx5IGZyb20gJ3Byb21wdGx5JztcbmltcG9ydCB0eXBlIHsgSW9IZWxwZXIsIEFjdGl2aXR5UHJpbnRlclByb3BzLCBJQWN0aXZpdHlQcmludGVyIH0gZnJvbSAnLi4vLi4vLi4vbGliL2FwaS1wcml2YXRlJztcbmltcG9ydCB7IGFzSW9IZWxwZXIsIElPLCBpc01lc3NhZ2VSZWxldmFudEZvckxldmVsLCBDdXJyZW50QWN0aXZpdHlQcmludGVyLCBIaXN0b3J5QWN0aXZpdHlQcmludGVyIH0gZnJvbSAnLi4vLi4vLi4vbGliL2FwaS1wcml2YXRlJztcbmltcG9ydCB7IFN0YWNrQWN0aXZpdHlQcm9ncmVzcyB9IGZyb20gJy4uLy4uL2NvbW1hbmRzL2RlcGxveSc7XG5pbXBvcnQgdHlwZSB7IEV2ZW50UmVzdWx0IH0gZnJvbSAnLi4vdGVsZW1ldHJ5L21lc3NhZ2VzJztcbmltcG9ydCB7IENMSV9QUklWQVRFX0lPLCBDTElfVEVMRU1FVFJZX0NPREVTIH0gZnJvbSAnLi4vdGVsZW1ldHJ5L21lc3NhZ2VzJztcbmltcG9ydCB0eXBlIHsgRXZlbnRUeXBlIH0gZnJvbSAnLi4vdGVsZW1ldHJ5L3NjaGVtYSc7XG5pbXBvcnQgeyBUZWxlbWV0cnlTZXNzaW9uIH0gZnJvbSAnLi4vdGVsZW1ldHJ5L3Nlc3Npb24nO1xuaW1wb3J0IHsgRmlsZVRlbGVtZXRyeVNpbmsgfSBmcm9tICcuLi90ZWxlbWV0cnkvc2luay9maWxlLXNpbmsnO1xuaW1wb3J0IHsgaXNDSSB9IGZyb20gJy4uL3V0aWwvY2knO1xuXG5leHBvcnQgdHlwZSB7IElJb0hvc3QsIElvTWVzc2FnZSwgSW9NZXNzYWdlQ29kZSwgSW9NZXNzYWdlTGV2ZWwsIElvUmVxdWVzdCB9O1xuXG4vKipcbiAqIFRoZSBjdXJyZW50IGFjdGlvbiBiZWluZyBwZXJmb3JtZWQgYnkgdGhlIENMSS4gJ25vbmUnIHJlcHJlc2VudHMgdGhlIGFic2VuY2Ugb2YgYW4gYWN0aW9uLlxuICovXG50eXBlIENsaUFjdGlvbiA9XG58IFRvb2xraXRBY3Rpb25cbnwgJ2NvbnRleHQnXG58ICdkb2NzJ1xufCAnZmxhZ3MnXG58ICdub3RpY2VzJ1xufCAndmVyc2lvbidcbnwgJ2NsaS10ZWxlbWV0cnknXG58ICdub25lJztcblxuZXhwb3J0IGludGVyZmFjZSBDbGlJb0hvc3RQcm9wcyB7XG4gIC8qKlxuICAgKiBUaGUgaW5pdGlhbCBUb29sa2l0IGFjdGlvbiB0aGUgaG9zdHMgc3RhcnRzIHdpdGguXG4gICAqXG4gICAqIEBkZWZhdWx0ICdub25lJ1xuICAgKi9cbiAgcmVhZG9ubHkgY3VycmVudEFjdGlvbj86IENsaUFjdGlvbjtcblxuICAvKipcbiAgICogRGV0ZXJtaW5lcyB0aGUgdmVyYm9zaXR5IG9mIHRoZSBvdXRwdXQuXG4gICAqXG4gICAqIFRoZSBDbGlJb0hvc3Qgd2lsbCBzdGlsbCByZWNlaXZlIGFsbCBtZXNzYWdlcyBhbmQgcmVxdWVzdHMsXG4gICAqIGJ1dCBvbmx5IHRoZSBtZXNzYWdlcyBpbmNsdWRlZCBpbiB0aGlzIGxldmVsIHdpbGwgYmUgcHJpbnRlZC5cbiAgICpcbiAgICogQGRlZmF1bHQgJ2luZm8nXG4gICAqL1xuICByZWFkb25seSBsb2dMZXZlbD86IElvTWVzc2FnZUxldmVsO1xuXG4gIC8qKlxuICAgKiBPdmVycmlkZXMgdGhlIGF1dG9tYXRpYyBUVFkgZGV0ZWN0aW9uLlxuICAgKlxuICAgKiBXaGVuIFRUWSBpcyBkaXNhYmxlZCwgdGhlIENMSSB3aWxsIGhhdmUgbm8gaW50ZXJhY3Rpb25zIG9yIGNvbG9yLlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIGRldGVybWluZWQgZnJvbSB0aGUgY3VycmVudCBwcm9jZXNzXG4gICAqL1xuICByZWFkb25seSBpc1RUWT86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFdoZXRoZXIgdGhlIENsaUlvSG9zdCBpcyBydW5uaW5nIGluIENJIG1vZGUuXG4gICAqXG4gICAqIEluIENJIG1vZGUsIGFsbCBub24tZXJyb3Igb3V0cHV0IGdvZXMgdG8gc3Rkb3V0IGluc3RlYWQgb2Ygc3RkZXJyLlxuICAgKiBTZXQgdG8gZmFsc2UgaW4gdGhlIENsaUlvSG9zdCBjb25zdHJ1Y3RvciBpdCB3aWxsIGJlIG92ZXJ3cml0dGVuIGlmIHRoZSBDTEkgQ0kgYXJndW1lbnQgaXMgcGFzc2VkXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gZGV0ZXJtaW5lZCBmcm9tIHRoZSBlbnZpcm9ubWVudCwgc3BlY2lmaWNhbGx5IGJhc2VkIG9uIGBwcm9jZXNzLmVudi5DSWBcbiAgICovXG4gIHJlYWRvbmx5IGlzQ0k/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBJbiB3aGF0IHNjZW5hcmlvcyBzaG91bGQgdGhlIENsaUlvSG9zdCBhc2sgZm9yIGFwcHJvdmFsXG4gICAqXG4gICAqIEBkZWZhdWx0IFJlcXVpcmVBcHByb3ZhbC5CUk9BREVOSU5HXG4gICAqL1xuICByZWFkb25seSByZXF1aXJlRGVwbG95QXBwcm92YWw/OiBSZXF1aXJlQXBwcm92YWw7XG5cbiAgLyoqXG4gICAqIFRoZSBpbml0aWFsIFRvb2xraXQgYWN0aW9uIHRoZSBob3N0cyBzdGFydHMgd2l0aC5cbiAgICpcbiAgICogQGRlZmF1bHQgU3RhY2tBY3Rpdml0eVByb2dyZXNzLkJBUlxuICAgKi9cbiAgcmVhZG9ubHkgc3RhY2tQcm9ncmVzcz86IFN0YWNrQWN0aXZpdHlQcm9ncmVzcztcblxuICAvKipcbiAgICogV2hldGhlciB0aGUgQ0xJIHNob3VsZCBhdHRlbXB0IHRvIGF1dG9tYXRpY2FsbHkgcmVzcG9uZCB0byBwcm9tcHRzLlxuICAgKlxuICAgKiBXaGVuIHRydWUsIG9wZXJhdGlvbiB3aWxsIHVzdWFsbHkgcHJvY2VlZCB3aXRob3V0IGludGVyYWN0aXZlIGNvbmZpcm1hdGlvbi5cbiAgICogQ29uZmlybWF0aW9ucyBhcmUgcmVzcG9uZGVkIHRvIHdpdGggeWVzLiBPdGhlciBwcm9tcHRzIHdpbGwgcmVzcG9uZCB3aXRoIHRoZSBkZWZhdWx0IHZhbHVlLlxuICAgKlxuICAgKiBAZGVmYXVsdCBmYWxzZVxuICAgKi9cbiAgcmVhZG9ubHkgYXV0b1Jlc3BvbmQ/OiBib29sZWFuO1xufVxuXG4vKipcbiAqIEEgdHlwZSBmb3IgY29uZmlndXJpbmcgYSB0YXJnZXQgc3RyZWFtXG4gKi9cbmV4cG9ydCB0eXBlIFRhcmdldFN0cmVhbSA9ICdzdGRvdXQnIHwgJ3N0ZGVycicgfCAnZHJvcCc7XG5cbi8qKlxuICogQSBzaW1wbGUgSU8gaG9zdCBmb3IgdGhlIENMSSB0aGF0IHdyaXRlcyBtZXNzYWdlcyB0byB0aGUgY29uc29sZS5cbiAqL1xuZXhwb3J0IGNsYXNzIENsaUlvSG9zdCBpbXBsZW1lbnRzIElJb0hvc3Qge1xuICAvKipcbiAgICogUmV0dXJucyB0aGUgc2luZ2xldG9uIGluc3RhbmNlXG4gICAqL1xuICBzdGF0aWMgaW5zdGFuY2UocHJvcHM6IENsaUlvSG9zdFByb3BzID0ge30sIGZvcmNlTmV3ID0gZmFsc2UpOiBDbGlJb0hvc3Qge1xuICAgIGlmIChmb3JjZU5ldyB8fCAhQ2xpSW9Ib3N0Ll9pbnN0YW5jZSkge1xuICAgICAgQ2xpSW9Ib3N0Ll9pbnN0YW5jZSA9IG5ldyBDbGlJb0hvc3QocHJvcHMpO1xuICAgIH1cbiAgICByZXR1cm4gQ2xpSW9Ib3N0Ll9pbnN0YW5jZTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSBzaW5nbGV0b24gaW5zdGFuY2UgaWYgaXQgZXhpc3RzXG4gICAqL1xuICBzdGF0aWMgZ2V0KCk6IENsaUlvSG9zdCB8IHVuZGVmaW5lZCB7XG4gICAgcmV0dXJuIENsaUlvSG9zdC5faW5zdGFuY2U7XG4gIH1cblxuICAvKipcbiAgICogU2luZ2xldG9uIGluc3RhbmNlIG9mIHRoZSBDbGlJb0hvc3RcbiAgICovXG4gIHByaXZhdGUgc3RhdGljIF9pbnN0YW5jZTogQ2xpSW9Ib3N0IHwgdW5kZWZpbmVkO1xuXG4gIC8qKlxuICAgKiBUaGUgY3VycmVudCBhY3Rpb24gYmVpbmcgcGVyZm9ybWVkIGJ5IHRoZSBDTEkuXG4gICAqL1xuICBwdWJsaWMgY3VycmVudEFjdGlvbjogQ2xpQWN0aW9uO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRoZSBDbGlJb0hvc3QgaXMgcnVubmluZyBpbiBDSSBtb2RlLlxuICAgKlxuICAgKiBJbiBDSSBtb2RlLCBhbGwgbm9uLWVycm9yIG91dHB1dCBnb2VzIHRvIHN0ZG91dCBpbnN0ZWFkIG9mIHN0ZGVyci5cbiAgICovXG4gIHB1YmxpYyBpc0NJOiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBXaGV0aGVyIHRoZSBob3N0IGNhbiB1c2UgaW50ZXJhY3Rpb25zIGFuZCBtZXNzYWdlIHN0eWxpbmcuXG4gICAqL1xuICBwdWJsaWMgaXNUVFk6IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIFRoZSBjdXJyZW50IHRocmVzaG9sZC5cbiAgICpcbiAgICogTWVzc2FnZXMgd2l0aCBhIGxvd2VyIHByaW9yaXR5IGxldmVsIHdpbGwgYmUgaWdub3JlZC5cbiAgICovXG4gIHB1YmxpYyBsb2dMZXZlbDogSW9NZXNzYWdlTGV2ZWw7XG5cbiAgLyoqXG4gICAqIFRoZSBjb25kaXRpb25zIGZvciByZXF1aXJpbmcgYXBwcm92YWwgaW4gdGhpcyBDbGlJb0hvc3QuXG4gICAqL1xuICBwdWJsaWMgcmVxdWlyZURlcGxveUFwcHJvdmFsOiBSZXF1aXJlQXBwcm92YWw7XG5cbiAgLyoqXG4gICAqIENvbmZpZ3VyZSB0aGUgdGFyZ2V0IHN0cmVhbSBmb3Igbm90aWNlc1xuICAgKlxuICAgKiAoTm90IGEgc2V0dGVyIGJlY2F1c2UgdGhlcmUncyBubyBuZWVkIGZvciBhZGRpdGlvbmFsIGxvZ2ljIHdoZW4gdGhpcyB2YWx1ZVxuICAgKiBpcyBjaGFuZ2VkIHlldClcbiAgICovXG4gIHB1YmxpYyBub3RpY2VzRGVzdGluYXRpb246IFRhcmdldFN0cmVhbSA9ICdzdGRlcnInO1xuXG4gIHByaXZhdGUgX3Byb2dyZXNzOiBTdGFja0FjdGl2aXR5UHJvZ3Jlc3MgPSBTdGFja0FjdGl2aXR5UHJvZ3Jlc3MuQkFSO1xuXG4gIC8vIFN0YWNrIEFjdGl2aXR5IFByaW50ZXJcbiAgcHJpdmF0ZSBhY3Rpdml0eVByaW50ZXI/OiBJQWN0aXZpdHlQcmludGVyO1xuXG4gIC8vIENvcmtlZCBMb2dnaW5nXG4gIHByaXZhdGUgY29ya2VkQ291bnRlciA9IDA7XG4gIHByaXZhdGUgcmVhZG9ubHkgY29ya2VkTG9nZ2luZ0J1ZmZlcjogSW9NZXNzYWdlPHVua25vd24+W10gPSBbXTtcblxuICBwcml2YXRlIHJlYWRvbmx5IGF1dG9SZXNwb25kOiBib29sZWFuO1xuXG4gIHB1YmxpYyB0ZWxlbWV0cnk/OiBUZWxlbWV0cnlTZXNzaW9uO1xuXG4gIHByaXZhdGUgY29uc3RydWN0b3IocHJvcHM6IENsaUlvSG9zdFByb3BzID0ge30pIHtcbiAgICB0aGlzLmN1cnJlbnRBY3Rpb24gPSBwcm9wcy5jdXJyZW50QWN0aW9uID8/ICdub25lJztcbiAgICB0aGlzLmlzVFRZID0gcHJvcHMuaXNUVFkgPz8gcHJvY2Vzcy5zdGRvdXQuaXNUVFkgPz8gZmFsc2U7XG4gICAgdGhpcy5sb2dMZXZlbCA9IHByb3BzLmxvZ0xldmVsID8/ICdpbmZvJztcbiAgICB0aGlzLmlzQ0kgPSBwcm9wcy5pc0NJID8/IGlzQ0koKTtcbiAgICB0aGlzLnJlcXVpcmVEZXBsb3lBcHByb3ZhbCA9IHByb3BzLnJlcXVpcmVEZXBsb3lBcHByb3ZhbCA/PyBSZXF1aXJlQXBwcm92YWwuQlJPQURFTklORztcblxuICAgIHRoaXMuc3RhY2tQcm9ncmVzcyA9IHByb3BzLnN0YWNrUHJvZ3Jlc3MgPz8gU3RhY2tBY3Rpdml0eVByb2dyZXNzLkJBUjtcbiAgICB0aGlzLmF1dG9SZXNwb25kID0gcHJvcHMuYXV0b1Jlc3BvbmQgPz8gZmFsc2U7XG4gIH1cblxuICBwdWJsaWMgYXN5bmMgc3RhcnRUZWxlbWV0cnkoYXJnczogYW55LCBjb250ZXh0OiBDb250ZXh0LCBfcHJveHlBZ2VudD86IEFnZW50KSB7XG4gICAgbGV0IHNpbms7XG4gICAgY29uc3QgdGVsZW1ldHJ5RmlsZVBhdGggPSBhcmdzWyd0ZWxlbWV0cnktZmlsZSddO1xuICAgIGlmICh0ZWxlbWV0cnlGaWxlUGF0aCkge1xuICAgICAgc2luayA9IG5ldyBGaWxlVGVsZW1ldHJ5U2luayh7XG4gICAgICAgIGlvSG9zdDogdGhpcyxcbiAgICAgICAgbG9nRmlsZVBhdGg6IHRlbGVtZXRyeUZpbGVQYXRoLFxuICAgICAgfSk7XG4gICAgfVxuICAgIC8vIFRPRE86IHVuY29tbWVudCB0aGlzIGF0IGxhdW5jaFxuICAgIC8vIGlmIChjYW5Db2xsZWN0VGVsZW1ldHJ5KGFyZ3MsIGNvbnRleHQpKSB7XG4gICAgLy8gICBzaW5rID0gbmV3IEVuZHBvaW50VGVsZW1ldHJ5U2luayh7XG4gICAgLy8gICAgIGlvSG9zdDogdGhpcyxcbiAgICAvLyAgICAgYWdlbnQ6IHByb3h5QWdlbnQsXG4gICAgLy8gICAgIGVuZHBvaW50OiAnJywgLy8gVE9ETzogYWRkIGVuZHBvaW50XG4gICAgLy8gICB9KTtcbiAgICAvLyB9XG5cbiAgICBpZiAoc2luaykge1xuICAgICAgdGhpcy50ZWxlbWV0cnkgPSBuZXcgVGVsZW1ldHJ5U2Vzc2lvbih7XG4gICAgICAgIGlvSG9zdDogdGhpcyxcbiAgICAgICAgY2xpZW50OiBzaW5rLFxuICAgICAgICBhcmd1bWVudHM6IGFyZ3MsXG4gICAgICAgIGNvbnRleHQ6IGNvbnRleHQsXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBhd2FpdCB0aGlzLnRlbGVtZXRyeT8uYmVnaW4oKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBVcGRhdGUgdGhlIHN0YWNrUHJvZ3Jlc3MgcHJlZmVyZW5jZS5cbiAgICovXG4gIHB1YmxpYyBzZXQgc3RhY2tQcm9ncmVzcyh0eXBlOiBTdGFja0FjdGl2aXR5UHJvZ3Jlc3MpIHtcbiAgICB0aGlzLl9wcm9ncmVzcyA9IHR5cGU7XG4gIH1cblxuICAvKipcbiAgICogR2V0cyB0aGUgc3RhY2tQcm9ncmVzcyB2YWx1ZS5cbiAgICpcbiAgICogVGhpcyB0YWtlcyBpbnRvIGFjY291bnQgb3RoZXIgc3RhdGUgb2YgdGhlIGlvSG9zdCxcbiAgICogbGlrZSBpZiBpc1RUWSBhbmQgaXNDSS5cbiAgICovXG4gIHB1YmxpYyBnZXQgc3RhY2tQcm9ncmVzcygpOiBTdGFja0FjdGl2aXR5UHJvZ3Jlc3Mge1xuICAgIC8vIFdlIGNhbiBhbHdheXMgdXNlIEVWRU5UU1xuICAgIGlmICh0aGlzLl9wcm9ncmVzcyA9PT0gU3RhY2tBY3Rpdml0eVByb2dyZXNzLkVWRU5UUykge1xuICAgICAgcmV0dXJuIHRoaXMuX3Byb2dyZXNzO1xuICAgIH1cblxuICAgIC8vIGlmIGEgZGVidWcgbWVzc2FnZSAoYW5kIHRodXMgYW55IG1vcmUgdmVyYm9zZSBtZXNzYWdlcykgYXJlIHJlbGV2YW50IHRvIHRoZSBjdXJyZW50IGxvZyBsZXZlbCwgd2UgaGF2ZSB2ZXJib3NlIGxvZ2dpbmdcbiAgICBjb25zdCB2ZXJib3NlTG9nZ2luZyA9IGlzTWVzc2FnZVJlbGV2YW50Rm9yTGV2ZWwoeyBsZXZlbDogJ2RlYnVnJyB9LCB0aGlzLmxvZ0xldmVsKTtcbiAgICBpZiAodmVyYm9zZUxvZ2dpbmcpIHtcbiAgICAgIHJldHVybiBTdGFja0FjdGl2aXR5UHJvZ3Jlc3MuRVZFTlRTO1xuICAgIH1cblxuICAgIC8vIE9uIFdpbmRvd3Mgd2UgY2Fubm90IHVzZSBmYW5jeSBvdXRwdXRcbiAgICBjb25zdCBpc1dpbmRvd3MgPSBwcm9jZXNzLnBsYXRmb3JtID09PSAnd2luMzInO1xuICAgIGlmIChpc1dpbmRvd3MpIHtcbiAgICAgIHJldHVybiBTdGFja0FjdGl2aXR5UHJvZ3Jlc3MuRVZFTlRTO1xuICAgIH1cblxuICAgIC8vIE9uIHNvbWUgQ0kgc3lzdGVtcyAoc3VjaCBhcyBDaXJjbGVDSSkgb3V0cHV0IHN0aWxsIHJlcG9ydHMgYXMgYSBUVFkgc28gd2UgYWxzb1xuICAgIC8vIG5lZWQgYW4gaW5kaXZpZHVhbCBjaGVjayBmb3Igd2hldGhlciB3ZSdyZSBydW5uaW5nIG9uIENJLlxuICAgIC8vIHNlZTogaHR0cHM6Ly9kaXNjdXNzLmNpcmNsZWNpLmNvbS90L2NpcmNsZWNpLXRlcm1pbmFsLWlzLWEtdHR5LWJ1dC10ZXJtLWlzLW5vdC1zZXQvOTk2NVxuICAgIGNvbnN0IGZhbmN5T3V0cHV0QXZhaWxhYmxlID0gdGhpcy5pc1RUWSAmJiAhdGhpcy5pc0NJO1xuICAgIGlmICghZmFuY3lPdXRwdXRBdmFpbGFibGUpIHtcbiAgICAgIHJldHVybiBTdGFja0FjdGl2aXR5UHJvZ3Jlc3MuRVZFTlRTO1xuICAgIH1cblxuICAgIC8vIFVzZSB0aGUgdXNlciBwcmVmZXJlbmNlXG4gICAgcmV0dXJuIHRoaXMuX3Byb2dyZXNzO1xuICB9XG5cbiAgcHVibGljIGdldCBkZWZhdWx0cygpIHtcbiAgICByZXR1cm4gdGhpcy5hc0lvSGVscGVyKCkuZGVmYXVsdHM7XG4gIH1cblxuICBwdWJsaWMgYXNJb0hlbHBlcigpOiBJb0hlbHBlciB7XG4gICAgcmV0dXJuIGFzSW9IZWxwZXIodGhpcywgdGhpcy5jdXJyZW50QWN0aW9uIGFzIGFueSk7XG4gIH1cblxuICAvKipcbiAgICogRXhlY3V0ZXMgYSBibG9jayBvZiBjb2RlIHdpdGggY29ya2VkIGxvZ2dpbmcuIEFsbCBsb2cgbWVzc2FnZXMgZHVyaW5nIGV4ZWN1dGlvblxuICAgKiBhcmUgYnVmZmVyZWQgYW5kIG9ubHkgd3JpdHRlbiB3aGVuIGFsbCBuZXN0ZWQgY29yayBibG9ja3MgY29tcGxldGUgKHdoZW4gQ09SS19DT1VOVEVSIHJlYWNoZXMgMCkuXG4gICAqIFRoZSBjb3JraW5nIGlzIGJvdW5kIHRvIHRoZSBzcGVjaWZpYyBpbnN0YW5jZSBvZiB0aGUgQ2xpSW9Ib3N0LlxuICAgKlxuICAgKiBAcGFyYW0gYmxvY2sgLSBBc3luYyBmdW5jdGlvbiB0byBleGVjdXRlIHdpdGggY29ya2VkIGxvZ2dpbmdcbiAgICogQHJldHVybnMgUHJvbWlzZSB0aGF0IHJlc29sdmVzIHdpdGggdGhlIGJsb2NrJ3MgcmV0dXJuIHZhbHVlXG4gICAqL1xuICBwdWJsaWMgYXN5bmMgd2l0aENvcmtlZExvZ2dpbmc8VD4oYmxvY2s6ICgpID0+IFByb21pc2U8VD4pOiBQcm9taXNlPFQ+IHtcbiAgICB0aGlzLmNvcmtlZENvdW50ZXIrKztcbiAgICB0cnkge1xuICAgICAgcmV0dXJuIGF3YWl0IGJsb2NrKCk7XG4gICAgfSBmaW5hbGx5IHtcbiAgICAgIHRoaXMuY29ya2VkQ291bnRlci0tO1xuICAgICAgaWYgKHRoaXMuY29ya2VkQ291bnRlciA9PT0gMCkge1xuICAgICAgICAvLyBQcm9jZXNzIGVhY2ggYnVmZmVyZWQgbWVzc2FnZSB0aHJvdWdoIG5vdGlmeVxuICAgICAgICBmb3IgKGNvbnN0IGlvTWVzc2FnZSBvZiB0aGlzLmNvcmtlZExvZ2dpbmdCdWZmZXIpIHtcbiAgICAgICAgICBhd2FpdCB0aGlzLm5vdGlmeShpb01lc3NhZ2UpO1xuICAgICAgICB9XG4gICAgICAgIC8vIHJlbW92ZSBhbGwgYnVmZmVyZWQgbWVzc2FnZXMgaW4tcGxhY2VcbiAgICAgICAgdGhpcy5jb3JrZWRMb2dnaW5nQnVmZmVyLnNwbGljZSgwKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogTm90aWZpZXMgdGhlIGhvc3Qgb2YgYSBtZXNzYWdlLlxuICAgKiBUaGUgY2FsbGVyIHdhaXRzIHVudGlsIHRoZSBub3RpZmljYXRpb24gY29tcGxldGVzLlxuICAgKi9cbiAgcHVibGljIGFzeW5jIG5vdGlmeShtc2c6IElvTWVzc2FnZTx1bmtub3duPik6IFByb21pc2U8dm9pZD4ge1xuICAgIGF3YWl0IHRoaXMubWF5YmVFbWl0VGVsZW1ldHJ5KG1zZyk7XG5cbiAgICBpZiAodGhpcy5pc1N0YWNrQWN0aXZpdHkobXNnKSkge1xuICAgICAgaWYgKCF0aGlzLmFjdGl2aXR5UHJpbnRlcikge1xuICAgICAgICB0aGlzLmFjdGl2aXR5UHJpbnRlciA9IHRoaXMubWFrZUFjdGl2aXR5UHJpbnRlcigpO1xuICAgICAgfVxuICAgICAgdGhpcy5hY3Rpdml0eVByaW50ZXIubm90aWZ5KG1zZyk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgaWYgKCFpc01lc3NhZ2VSZWxldmFudEZvckxldmVsKG1zZywgdGhpcy5sb2dMZXZlbCkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5jb3JrZWRDb3VudGVyID4gMCkge1xuICAgICAgdGhpcy5jb3JrZWRMb2dnaW5nQnVmZmVyLnB1c2gobXNnKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBvdXRwdXQgPSB0aGlzLmZvcm1hdE1lc3NhZ2UobXNnKTtcbiAgICBjb25zdCBzdHJlYW0gPSB0aGlzLnNlbGVjdFN0cmVhbShtc2cpO1xuICAgIHN0cmVhbT8ud3JpdGUob3V0cHV0KTtcbiAgfVxuXG4gIHByaXZhdGUgYXN5bmMgbWF5YmVFbWl0VGVsZW1ldHJ5KG1zZzogSW9NZXNzYWdlPHVua25vd24+KSB7XG4gICAgdHJ5IHtcbiAgICAgIGlmICh0aGlzLnRlbGVtZXRyeSAmJiBpc1RlbGVtZXRyeU1lc3NhZ2UobXNnKSkge1xuICAgICAgICBhd2FpdCB0aGlzLnRlbGVtZXRyeS5lbWl0KHtcbiAgICAgICAgICBldmVudFR5cGU6IGdldEV2ZW50VHlwZShtc2cpLFxuICAgICAgICAgIGR1cmF0aW9uOiBtc2cuZGF0YS5kdXJhdGlvbixcbiAgICAgICAgICBlcnJvcjogbXNnLmRhdGEuZXJyb3IsXG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgICAgYXdhaXQgdGhpcy5kZWZhdWx0cy50cmFjZShgRW1pdCBUZWxlbWV0cnkgRmFpbGVkICR7ZS5tZXNzYWdlfWApO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBEZXRlY3Qgc3RhY2sgYWN0aXZpdHkgbWVzc2FnZXMgc28gdGhleSBjYW4gYmUgc2VuZCB0byB0aGUgcHJpbnRlci5cbiAgICovXG4gIHByaXZhdGUgaXNTdGFja0FjdGl2aXR5KG1zZzogSW9NZXNzYWdlPHVua25vd24+KSB7XG4gICAgcmV0dXJuIG1zZy5jb2RlICYmIFtcbiAgICAgICdDREtfVE9PTEtJVF9JNTUwMScsXG4gICAgICAnQ0RLX1RPT0xLSVRfSTU1MDInLFxuICAgICAgJ0NES19UT09MS0lUX0k1NTAzJyxcbiAgICBdLmluY2x1ZGVzKG1zZy5jb2RlKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBEZXRlY3Qgc3BlY2lhbCBtZXNzYWdlcyBlbmNvZGUgaW5mb3JtYXRpb24gYWJvdXQgd2hldGhlciBvciBub3RcbiAgICogdGhleSByZXF1aXJlIGFwcHJvdmFsXG4gICAqL1xuICBwcml2YXRlIHNraXBBcHByb3ZhbFN0ZXAobXNnOiBJb1JlcXVlc3Q8YW55LCBhbnk+KTogYm9vbGVhbiB7XG4gICAgY29uc3QgYXBwcm92YWxUb29sa2l0Q29kZXMgPSBbJ0NES19UT09MS0lUX0k1MDYwJ107XG4gICAgaWYgKCEobXNnLmNvZGUgJiYgYXBwcm92YWxUb29sa2l0Q29kZXMuaW5jbHVkZXMobXNnLmNvZGUpKSkge1xuICAgICAgZmFsc2U7XG4gICAgfVxuXG4gICAgc3dpdGNoICh0aGlzLnJlcXVpcmVEZXBsb3lBcHByb3ZhbCkge1xuICAgICAgLy8gTmV2ZXIgcmVxdWlyZSBhcHByb3ZhbFxuICAgICAgY2FzZSBSZXF1aXJlQXBwcm92YWwuTkVWRVI6XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgLy8gQWx3YXlzIHJlcXVpcmUgYXBwcm92YWxcbiAgICAgIGNhc2UgUmVxdWlyZUFwcHJvdmFsLkFOWUNIQU5HRTpcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgLy8gUmVxdWlyZSBhcHByb3ZhbCBpZiBjaGFuZ2VzIGluY2x1ZGUgYnJvYWRlbmluZyBwZXJtaXNzaW9uc1xuICAgICAgY2FzZSBSZXF1aXJlQXBwcm92YWwuQlJPQURFTklORzpcbiAgICAgICAgcmV0dXJuIFsnbm9uZScsICdub24tYnJvYWRlbmluZyddLmluY2x1ZGVzKG1zZy5kYXRhPy5wZXJtaXNzaW9uQ2hhbmdlVHlwZSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIERldGVybWluZXMgdGhlIG91dHB1dCBzdHJlYW0sIGJhc2VkIG9uIG1lc3NhZ2UgYW5kIGNvbmZpZ3VyYXRpb24uXG4gICAqL1xuICBwcml2YXRlIHNlbGVjdFN0cmVhbShtc2c6IElvTWVzc2FnZTxhbnk+KTogTm9kZUpTLldyaXRlU3RyZWFtIHwgdW5kZWZpbmVkIHtcbiAgICBpZiAoaXNOb3RpY2VzTWVzc2FnZShtc2cpKSB7XG4gICAgICByZXR1cm4gdGFyZ2V0U3RyZWFtT2JqZWN0KHRoaXMubm90aWNlc0Rlc3RpbmF0aW9uKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5zZWxlY3RTdHJlYW1Gcm9tTGV2ZWwobXNnLmxldmVsKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBEZXRlcm1pbmVzIHRoZSBvdXRwdXQgc3RyZWFtLCBiYXNlZCBvbiBtZXNzYWdlIGxldmVsIGFuZCBjb25maWd1cmF0aW9uLlxuICAgKi9cbiAgcHJpdmF0ZSBzZWxlY3RTdHJlYW1Gcm9tTGV2ZWwobGV2ZWw6IElvTWVzc2FnZUxldmVsKTogTm9kZUpTLldyaXRlU3RyZWFtIHtcbiAgICAvLyBUaGUgc3RyZWFtIHNlbGVjdGlvbiBwb2xpY3kgZm9yIHRoZSBDTEkgaXMgdGhlIGZvbGxvd2luZzpcbiAgICAvL1xuICAgIC8vICAgKDEpIE1lc3NhZ2VzIG9mIGxldmVsIGByZXN1bHRgIGFsd2F5cyBnbyB0byBgc3Rkb3V0YFxuICAgIC8vICAgKDIpIE1lc3NhZ2VzIG9mIGxldmVsIGBlcnJvcmAgYWx3YXlzIGdvIHRvIGBzdGRlcnJgLlxuICAgIC8vICAgKDNhKSBBbGwgcmVtYWluaW5nIG1lc3NhZ2VzIGdvIHRvIGBzdGRlcnJgLlxuICAgIC8vICAgKDNiKSBJZiB3ZSBhcmUgaW4gQ0kgbW9kZSwgYWxsIHJlbWFpbmluZyBtZXNzYWdlcyBnbyB0byBgc3Rkb3V0YC5cbiAgICAvL1xuICAgIHN3aXRjaCAobGV2ZWwpIHtcbiAgICAgIGNhc2UgJ2Vycm9yJzpcbiAgICAgICAgcmV0dXJuIHByb2Nlc3Muc3RkZXJyO1xuICAgICAgY2FzZSAncmVzdWx0JzpcbiAgICAgICAgcmV0dXJuIHByb2Nlc3Muc3Rkb3V0O1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgcmV0dXJuIHRoaXMuaXNDSSA/IHByb2Nlc3Muc3Rkb3V0IDogcHJvY2Vzcy5zdGRlcnI7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIE5vdGlmaWVzIHRoZSBob3N0IG9mIGEgbWVzc2FnZSB0aGF0IHJlcXVpcmVzIGEgcmVzcG9uc2UuXG4gICAqXG4gICAqIElmIHRoZSBob3N0IGRvZXMgbm90IHJldHVybiBhIHJlc3BvbnNlIHRoZSBzdWdnZXN0ZWRcbiAgICogZGVmYXVsdCByZXNwb25zZSBmcm9tIHRoZSBpbnB1dCBtZXNzYWdlIHdpbGwgYmUgdXNlZC5cbiAgICovXG4gIHB1YmxpYyBhc3luYyByZXF1ZXN0UmVzcG9uc2U8RGF0YVR5cGUsIFJlc3BvbnNlVHlwZT4obXNnOiBJb1JlcXVlc3Q8RGF0YVR5cGUsIFJlc3BvbnNlVHlwZT4pOiBQcm9taXNlPFJlc3BvbnNlVHlwZT4ge1xuICAgIC8vIElmIHRoZSByZXF1ZXN0IGNhbm5vdCBiZSBwcm9tcHRlZCBmb3IgYnkgdGhlIENsaUlvSG9zdCwgd2UganVzdCBhY2NlcHQgdGhlIGRlZmF1bHRcbiAgICBpZiAoIWlzUHJvbXB0YWJsZVJlcXVlc3QobXNnKSkge1xuICAgICAgYXdhaXQgdGhpcy5ub3RpZnkobXNnKTtcbiAgICAgIHJldHVybiBtc2cuZGVmYXVsdFJlc3BvbnNlO1xuICAgIH1cblxuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgdGhpcy53aXRoQ29ya2VkTG9nZ2luZyhhc3luYyAoKTogUHJvbWlzZTxzdHJpbmcgfCBudW1iZXIgfCB0cnVlPiA9PiB7XG4gICAgICAvLyBwcmVwYXJlIHByb21wdCBkYXRhXG4gICAgICAvLyBAdG9kbyB0aGlzIGZvcm1hdCBpcyBub3QgZGVmaW5lZCBhbnl3aGVyZSwgcHJvYmFibHkgc2hvdWxkIGJlXG4gICAgICBjb25zdCBkYXRhOiB7XG4gICAgICAgIG1vdGl2YXRpb24/OiBzdHJpbmc7XG4gICAgICAgIGNvbmN1cnJlbmN5PzogbnVtYmVyO1xuICAgICAgICByZXNwb25zZURlc2NyaXB0aW9uPzogc3RyaW5nO1xuICAgICAgfSA9IG1zZy5kYXRhID8/IHt9O1xuXG4gICAgICBjb25zdCBtb3RpdmF0aW9uID0gZGF0YS5tb3RpdmF0aW9uID8/ICdVc2VyIGlucHV0IGlzIG5lZWRlZCc7XG4gICAgICBjb25zdCBjb25jdXJyZW5jeSA9IGRhdGEuY29uY3VycmVuY3kgPz8gMDtcbiAgICAgIGNvbnN0IHJlc3BvbnNlRGVzY3JpcHRpb24gPSBkYXRhLnJlc3BvbnNlRGVzY3JpcHRpb247XG5cbiAgICAgIC8vIFNwZWNpYWwgYXBwcm92YWwgcHJvbXB0XG4gICAgICAvLyBEZXRlcm1pbmUgaWYgdGhlIG1lc3NhZ2UgbmVlZHMgYXBwcm92YWwuIElmIGl0IGRvZXMsIGNvbnRpbnVlIChpdCBpcyBhIGJhc2ljIGNvbmZpcm1hdGlvbiBwcm9tcHQpXG4gICAgICAvLyBJZiBpdCBkb2VzIG5vdCwgcmV0dXJuIHN1Y2Nlc3MgKHRydWUpLiBXZSBvbmx5IGNoZWNrIG1lc3NhZ2VzIHdpdGggY29kZXMgdGhhdCB3ZSBhcmUgYXdhcmVcbiAgICAgIC8vIGFyZSByZXF1aXJlcyBhcHByb3ZhbCBjb2Rlcy5cbiAgICAgIGlmICh0aGlzLnNraXBBcHByb3ZhbFN0ZXAobXNnKSkge1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIH1cblxuICAgICAgLy8gSW4gLS15ZXMgbW9kZSwgcmVzcG9uZCBmb3IgdGhlIHVzZXIgaWYgd2UgY2FuXG4gICAgICBpZiAodGhpcy5hdXRvUmVzcG9uZCkge1xuICAgICAgICAvLyByZXNwb25kIHdpdGggeWVzIHRvIGFsbCBjb25maXJtYXRpb25zXG4gICAgICAgIGlmIChpc0NvbmZpcm1hdGlvblByb21wdChtc2cpKSB7XG4gICAgICAgICAgYXdhaXQgdGhpcy5ub3RpZnkoe1xuICAgICAgICAgICAgLi4ubXNnLFxuICAgICAgICAgICAgbWVzc2FnZTogYCR7Y2hhbGsuY3lhbihtc2cubWVzc2FnZSl9IChhdXRvLWNvbmZpcm1lZClgLFxuICAgICAgICAgIH0pO1xuICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gcmVzcG9uZCB3aXRoIHRoZSBkZWZhdWx0IGZvciBhbGwgb3RoZXIgbWVzc2FnZXNcbiAgICAgICAgaWYgKG1zZy5kZWZhdWx0UmVzcG9uc2UpIHtcbiAgICAgICAgICBhd2FpdCB0aGlzLm5vdGlmeSh7XG4gICAgICAgICAgICAuLi5tc2csXG4gICAgICAgICAgICBtZXNzYWdlOiBgJHtjaGFsay5jeWFuKG1zZy5tZXNzYWdlKX0gKGF1dG8tcmVzcG9uZGVkIHdpdGggZGVmYXVsdDogJHt1dGlsLmZvcm1hdChtc2cuZGVmYXVsdFJlc3BvbnNlKX0pYCxcbiAgICAgICAgICB9KTtcbiAgICAgICAgICByZXR1cm4gbXNnLmRlZmF1bHRSZXNwb25zZTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICAvLyBvbmx5IHRhbGsgdG8gdXNlciBpZiBTVERJTiBpcyBhIHRlcm1pbmFsIChvdGhlcndpc2UsIGZhaWwpXG4gICAgICBpZiAoIXRoaXMuaXNUVFkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihgJHttb3RpdmF0aW9ufSwgYnV0IHRlcm1pbmFsIChUVFkpIGlzIG5vdCBhdHRhY2hlZCBzbyB3ZSBhcmUgdW5hYmxlIHRvIGdldCBhIGNvbmZpcm1hdGlvbiBmcm9tIHRoZSB1c2VyYCk7XG4gICAgICB9XG5cbiAgICAgIC8vIG9ubHkgdGFsayB0byB1c2VyIGlmIGNvbmN1cnJlbmN5IGlzIDEgKG90aGVyd2lzZSwgZmFpbClcbiAgICAgIGlmIChjb25jdXJyZW5jeSA+IDEpIHtcbiAgICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihgJHttb3RpdmF0aW9ufSwgYnV0IGNvbmN1cnJlbmN5IGlzIGdyZWF0ZXIgdGhhbiAxIHNvIHdlIGFyZSB1bmFibGUgdG8gZ2V0IGEgY29uZmlybWF0aW9uIGZyb20gdGhlIHVzZXJgKTtcbiAgICAgIH1cblxuICAgICAgLy8gQmFzaWMgY29uZmlybWF0aW9uIHByb21wdFxuICAgICAgLy8gV2UgdHJlYXQgYWxsIHJlcXVlc3RzIHdpdGggYSBib29sZWFuIHJlc3BvbnNlIGFzIGNvbmZpcm1hdGlvbiBwcm9tcHRzXG4gICAgICBpZiAoaXNDb25maXJtYXRpb25Qcm9tcHQobXNnKSkge1xuICAgICAgICBjb25zdCBjb25maXJtZWQgPSBhd2FpdCBwcm9tcHRseS5jb25maXJtKGAke2NoYWxrLmN5YW4obXNnLm1lc3NhZ2UpfSAoeS9uKWApO1xuICAgICAgICBpZiAoIWNvbmZpcm1lZCkge1xuICAgICAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoJ0Fib3J0ZWQgYnkgdXNlcicpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBjb25maXJtZWQ7XG4gICAgICB9XG5cbiAgICAgIC8vIEFza2luZyBmb3IgYSBzcGVjaWZpYyB2YWx1ZVxuICAgICAgY29uc3QgcHJvbXB0ID0gZXh0cmFjdFByb21wdEluZm8obXNnKTtcbiAgICAgIGNvbnN0IGRlc2MgPSByZXNwb25zZURlc2NyaXB0aW9uID8/IHByb21wdC5kZWZhdWx0O1xuICAgICAgY29uc3QgYW5zd2VyID0gYXdhaXQgcHJvbXB0bHkucHJvbXB0KGAke2NoYWxrLmN5YW4obXNnLm1lc3NhZ2UpfSR7ZGVzYyA/IGAgKCR7ZGVzY30pYCA6ICcnfWAsIHtcbiAgICAgICAgZGVmYXVsdDogcHJvbXB0LmRlZmF1bHQsXG4gICAgICAgIHRyaW06IHRydWUsXG4gICAgICB9KTtcbiAgICAgIHJldHVybiBwcm9tcHQuY29udmVydEFuc3dlcihhbnN3ZXIpO1xuICAgIH0pO1xuXG4gICAgLy8gV2UgbmVlZCB0byBjYXN0IHRoaXMgYmVjYXVzZSBpdCBpcyBpbXBvc3NpYmxlIHRvIG5hcnJvdyB0aGUgZ2VuZXJpYyB0eXBlXG4gICAgLy8gaXNQcm9tcHRhYmxlUmVxdWVzdCBlbnN1cmVzIHRoYXQgdGhlIHJlc3BvbnNlIHR5cGUgaXMgb25lIHdlIGNhbiBwcm9tcHQgZm9yXG4gICAgLy8gdGhlIHJlbWFpbmluZyBjb2RlIGVuc3VyZSB3ZSBhcmUgaW5kZWVkIHJldHVybmluZyB0aGUgY29ycmVjdCB0eXBlXG4gICAgcmV0dXJuIHJlc3BvbnNlIGFzIFJlc3BvbnNlVHlwZTtcbiAgfVxuXG4gIC8qKlxuICAgKiBGb3JtYXRzIGEgbWVzc2FnZSBmb3IgY29uc29sZSBvdXRwdXQgd2l0aCBvcHRpb25hbCBjb2xvciBzdXBwb3J0XG4gICAqL1xuICBwcml2YXRlIGZvcm1hdE1lc3NhZ2UobXNnOiBJb01lc3NhZ2U8dW5rbm93bj4pOiBzdHJpbmcge1xuICAgIC8vIGFwcGx5IHByb3ZpZGVkIHN0eWxlIG9yIGEgZGVmYXVsdCBzdHlsZSBpZiB3ZSdyZSBpbiBUVFkgbW9kZVxuICAgIGxldCBtZXNzYWdlX3RleHQgPSB0aGlzLmlzVFRZXG4gICAgICA/IHN0eWxlTWFwW21zZy5sZXZlbF0obXNnLm1lc3NhZ2UpXG4gICAgICA6IG1zZy5tZXNzYWdlO1xuXG4gICAgLy8gcHJlcGVuZCB0aW1lc3RhbXAgaWYgSW9NZXNzYWdlTGV2ZWwgaXMgREVCVUcgb3IgVFJBQ0UuIFBvc3RwZW5kIGEgbmV3bGluZS5cbiAgICByZXR1cm4gKChtc2cubGV2ZWwgPT09ICdkZWJ1ZycgfHwgbXNnLmxldmVsID09PSAndHJhY2UnKVxuICAgICAgPyBgWyR7dGhpcy5mb3JtYXRUaW1lKG1zZy50aW1lKX1dICR7bWVzc2FnZV90ZXh0fWBcbiAgICAgIDogbWVzc2FnZV90ZXh0KSArICdcXG4nO1xuICB9XG5cbiAgLyoqXG4gICAqIEZvcm1hdHMgZGF0ZSB0byBISDpNTTpTU1xuICAgKi9cbiAgcHJpdmF0ZSBmb3JtYXRUaW1lKGQ6IERhdGUpOiBzdHJpbmcge1xuICAgIGNvbnN0IHBhZCA9IChuOiBudW1iZXIpOiBzdHJpbmcgPT4gbi50b1N0cmluZygpLnBhZFN0YXJ0KDIsICcwJyk7XG4gICAgcmV0dXJuIGAke3BhZChkLmdldEhvdXJzKCkpfToke3BhZChkLmdldE1pbnV0ZXMoKSl9OiR7cGFkKGQuZ2V0U2Vjb25kcygpKX1gO1xuICB9XG5cbiAgLyoqXG4gICAqIEdldCBhbiBpbnN0YW5jZSBvZiB0aGUgQWN0aXZpdHlQcmludGVyXG4gICAqL1xuICBwcml2YXRlIG1ha2VBY3Rpdml0eVByaW50ZXIoKSB7XG4gICAgY29uc3QgcHJvcHM6IEFjdGl2aXR5UHJpbnRlclByb3BzID0ge1xuICAgICAgc3RyZWFtOiB0aGlzLnNlbGVjdFN0cmVhbUZyb21MZXZlbCgnaW5mbycpLFxuICAgIH07XG5cbiAgICBzd2l0Y2ggKHRoaXMuc3RhY2tQcm9ncmVzcykge1xuICAgICAgY2FzZSBTdGFja0FjdGl2aXR5UHJvZ3Jlc3MuRVZFTlRTOlxuICAgICAgICByZXR1cm4gbmV3IEhpc3RvcnlBY3Rpdml0eVByaW50ZXIocHJvcHMpO1xuICAgICAgY2FzZSBTdGFja0FjdGl2aXR5UHJvZ3Jlc3MuQkFSOlxuICAgICAgICByZXR1cm4gbmV3IEN1cnJlbnRBY3Rpdml0eVByaW50ZXIocHJvcHMpO1xuICAgIH1cbiAgfVxufVxuXG4vKipcbiAqIFRoaXMgSW9Ib3N0IGltcGxlbWVudGF0aW9uIGNvbnNpZGVycyBhIHJlcXVlc3QgcHJvbXB0YWJsZSwgaWY6XG4gKiAtIGl0J3MgYSB5ZXMvbm8gY29uZmlybWF0aW9uXG4gKiAtIGFza2luZyBmb3IgYSBzdHJpbmcgb3IgbnVtYmVyIHZhbHVlXG4gKi9cbmZ1bmN0aW9uIGlzUHJvbXB0YWJsZVJlcXVlc3QobXNnOiBJb1JlcXVlc3Q8YW55LCBhbnk+KTogbXNnIGlzIElvUmVxdWVzdDxhbnksIHN0cmluZyB8IG51bWJlciB8IGJvb2xlYW4+IHtcbiAgcmV0dXJuIGlzQ29uZmlybWF0aW9uUHJvbXB0KG1zZylcbiAgICB8fCB0eXBlb2YgbXNnLmRlZmF1bHRSZXNwb25zZSA9PT0gJ3N0cmluZydcbiAgICB8fCB0eXBlb2YgbXNnLmRlZmF1bHRSZXNwb25zZSA9PT0gJ251bWJlcic7XG59XG5cbi8qKlxuICogQ2hlY2sgaWYgdGhlIHJlcXVlc3QgaXMgYSBjb25maXJtYXRpb24gcHJvbXB0XG4gKiBXZSB0cmVhdCBhbGwgcmVxdWVzdHMgd2l0aCBhIGJvb2xlYW4gcmVzcG9uc2UgYXMgY29uZmlybWF0aW9uIHByb21wdHNcbiAqL1xuZnVuY3Rpb24gaXNDb25maXJtYXRpb25Qcm9tcHQobXNnOiBJb1JlcXVlc3Q8YW55LCBhbnk+KTogbXNnIGlzIElvUmVxdWVzdDxhbnksIGJvb2xlYW4+IHtcbiAgcmV0dXJuIHR5cGVvZiBtc2cuZGVmYXVsdFJlc3BvbnNlID09PSAnYm9vbGVhbic7XG59XG5cbi8qKlxuICogSGVscGVyIHRvIGV4dHJhY3QgaW5mb3JtYXRpb24gZm9yIHByb21wdGx5IGZyb20gdGhlIHJlcXVlc3RcbiAqL1xuZnVuY3Rpb24gZXh0cmFjdFByb21wdEluZm8obXNnOiBJb1JlcXVlc3Q8YW55LCBhbnk+KToge1xuICBkZWZhdWx0OiBzdHJpbmc7XG4gIGRlZmF1bHREZXNjOiBzdHJpbmc7XG4gIGNvbnZlcnRBbnN3ZXI6IChpbnB1dDogc3RyaW5nKSA9PiBzdHJpbmcgfCBudW1iZXI7XG59IHtcbiAgY29uc3QgaXNOdW1iZXIgPSAodHlwZW9mIG1zZy5kZWZhdWx0UmVzcG9uc2UgPT09ICdudW1iZXInKTtcbiAgY29uc3QgZGVmYXVsdFJlc3BvbnNlID0gdXRpbC5mb3JtYXQobXNnLmRlZmF1bHRSZXNwb25zZSk7XG4gIHJldHVybiB7XG4gICAgZGVmYXVsdDogZGVmYXVsdFJlc3BvbnNlLFxuICAgIGRlZmF1bHREZXNjOiAnZGVmYXVsdERlc2NyaXB0aW9uJyBpbiBtc2cgJiYgbXNnLmRlZmF1bHREZXNjcmlwdGlvbiA/IHV0aWwuZm9ybWF0KG1zZy5kZWZhdWx0RGVzY3JpcHRpb24pIDogZGVmYXVsdFJlc3BvbnNlLFxuICAgIGNvbnZlcnRBbnN3ZXI6IGlzTnVtYmVyID8gKHYpID0+IE51bWJlcih2KSA6ICh2KSA9PiBTdHJpbmcodiksXG4gIH07XG59XG5cbmNvbnN0IHN0eWxlTWFwOiBSZWNvcmQ8SW9NZXNzYWdlTGV2ZWwsIChzdHI6IHN0cmluZykgPT4gc3RyaW5nPiA9IHtcbiAgZXJyb3I6IGNoYWxrLnJlZCxcbiAgd2FybjogY2hhbGsueWVsbG93LFxuICByZXN1bHQ6IGNoYWxrLnJlc2V0LFxuICBpbmZvOiBjaGFsay5yZXNldCxcbiAgZGVidWc6IGNoYWxrLmdyYXksXG4gIHRyYWNlOiBjaGFsay5ncmF5LFxufTtcblxuZnVuY3Rpb24gdGFyZ2V0U3RyZWFtT2JqZWN0KHg6IFRhcmdldFN0cmVhbSk6IE5vZGVKUy5Xcml0ZVN0cmVhbSB8IHVuZGVmaW5lZCB7XG4gIHN3aXRjaCAoeCkge1xuICAgIGNhc2UgJ3N0ZGVycic6XG4gICAgICByZXR1cm4gcHJvY2Vzcy5zdGRlcnI7XG4gICAgY2FzZSAnc3Rkb3V0JzpcbiAgICAgIHJldHVybiBwcm9jZXNzLnN0ZG91dDtcbiAgICBjYXNlICdkcm9wJzpcbiAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gIH1cbn1cblxuZnVuY3Rpb24gaXNOb3RpY2VzTWVzc2FnZShtc2c6IElvTWVzc2FnZTx1bmtub3duPik6IG1zZyBpcyBJb01lc3NhZ2U8dm9pZD4ge1xuICByZXR1cm4gSU8uQ0RLX1RPT0xLSVRfSTAxMDAuaXMobXNnKSB8fCBJTy5DREtfVE9PTEtJVF9XMDEwMS5pcyhtc2cpIHx8IElPLkNES19UT09MS0lUX0UwMTAxLmlzKG1zZykgfHwgSU8uQ0RLX1RPT0xLSVRfSTAxMDEuaXMobXNnKTtcbn1cblxuZnVuY3Rpb24gaXNUZWxlbWV0cnlNZXNzYWdlKG1zZzogSW9NZXNzYWdlPHVua25vd24+KTogbXNnIGlzIElvTWVzc2FnZTxFdmVudFJlc3VsdD4ge1xuICByZXR1cm4gQ0xJX1RFTEVNRVRSWV9DT0RFUy5zb21lKChjKSA9PiBjLmlzKG1zZykpO1xufVxuXG5mdW5jdGlvbiBnZXRFdmVudFR5cGUobXNnOiBJb01lc3NhZ2U8dW5rbm93bj4pOiBFdmVudFR5cGUge1xuICBzd2l0Y2ggKG1zZy5jb2RlKSB7XG4gICAgY2FzZSBDTElfUFJJVkFURV9JTy5DREtfQ0xJX0kxMDAxLmNvZGU6XG4gICAgICByZXR1cm4gJ1NZTlRIJztcbiAgICBjYXNlIENMSV9QUklWQVRFX0lPLkNES19DTElfSTIwMDEuY29kZTpcbiAgICAgIHJldHVybiAnSU5WT0tFJztcbiAgICBjYXNlIENMSV9QUklWQVRFX0lPLkNES19DTElfSTMwMDEuY29kZTpcbiAgICAgIHJldHVybiAnREVQTE9ZJztcbiAgICBkZWZhdWx0OlxuICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihgVW5yZWNvZ25pemVkIFRlbGVtZXRyeSBNZXNzYWdlIENvZGU6ICR7bXNnLmNvZGV9YCk7XG4gIH1cbn1cbiJdfQ==