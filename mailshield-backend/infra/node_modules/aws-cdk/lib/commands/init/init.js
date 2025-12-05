"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InitTemplate = void 0;
exports.cliInit = cliInit;
exports.expandPlaceholders = expandPlaceholders;
exports.availableInitTemplates = availableInitTemplates;
exports.availableInitLanguages = availableInitLanguages;
exports.printAvailableTemplates = printAvailableTemplates;
exports.currentlyRecommendedAwsCdkLibFlags = currentlyRecommendedAwsCdkLibFlags;
const childProcess = require("child_process");
const path = require("path");
const toolkit_lib_1 = require("@aws-cdk/toolkit-lib");
const chalk = require("chalk");
const fs = require("fs-extra");
const init_hooks_1 = require("./init-hooks");
const root_dir_1 = require("../../cli/root-dir");
const version_1 = require("../../cli/version");
const util_1 = require("../../util");
const language_1 = require("../language");
/* eslint-disable @typescript-eslint/no-var-requires */ // Packages don't have @types module
// eslint-disable-next-line @typescript-eslint/no-require-imports
const camelCase = require('camelcase');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const decamelize = require('decamelize');
const SUPPORTED_LANGUAGE_NAMES = language_1.SUPPORTED_LANGUAGES.map((l) => l.name);
/**
 * Initialize a CDK package in the current directory
 */
async function cliInit(options) {
    const ioHelper = options.ioHelper;
    const canUseNetwork = options.canUseNetwork ?? true;
    const generateOnly = options.generateOnly ?? false;
    const workDir = options.workDir ?? process.cwd();
    // Show available templates only if no fromPath, type, or language provided
    if (!options.fromPath && !options.type && !options.language) {
        await printAvailableTemplates(ioHelper);
        return;
    }
    // Step 1: Load template
    let template;
    if (options.fromPath) {
        template = await loadLocalTemplate(options.fromPath, options.templatePath);
    }
    else {
        template = await loadBuiltinTemplate(ioHelper, options.type, options.language);
    }
    // Step 2: Resolve language
    const language = await resolveLanguage(ioHelper, template, options.language, options.type);
    // Step 3: Initialize project following standard process
    await initializeProject(ioHelper, template, language, canUseNetwork, generateOnly, workDir, options.stackName, options.migrate, options.libVersion);
}
/**
 * Load a local custom template from file system path
 * @param fromPath - Path to the local template directory or multi-template repository
 * @param templatePath - Optional path to a specific template within a multi-template repository
 * @returns Promise resolving to the loaded InitTemplate
 */
async function loadLocalTemplate(fromPath, templatePath) {
    try {
        let actualTemplatePath = fromPath;
        // If templatePath is provided, it's a multi-template repository
        if (templatePath) {
            actualTemplatePath = path.join(fromPath, templatePath);
            if (!await fs.pathExists(actualTemplatePath)) {
                throw new toolkit_lib_1.ToolkitError(`Template path does not exist: ${actualTemplatePath}`);
            }
        }
        const template = await InitTemplate.fromPath(actualTemplatePath);
        if (template.languages.length === 0) {
            // Check if this might be a multi-template repository
            if (!templatePath) {
                const availableTemplates = await findPotentialTemplates(fromPath);
                if (availableTemplates.length > 0) {
                    throw new toolkit_lib_1.ToolkitError('Use --template-path to specify which template to use.');
                }
            }
            throw new toolkit_lib_1.ToolkitError('Custom template must contain at least one language directory');
        }
        return template;
    }
    catch (error) {
        const displayPath = templatePath ? `${fromPath}/${templatePath}` : fromPath;
        throw new toolkit_lib_1.ToolkitError(`Failed to load template from path: ${displayPath}. ${error.message}`);
    }
}
/**
 * Load a built-in template by name
 */
async function loadBuiltinTemplate(ioHelper, type, language) {
    const templateType = type || 'default'; // "default" is the default type (and maps to "app")
    const template = (await availableInitTemplates()).find((t) => t.hasName(templateType));
    if (!template) {
        await printAvailableTemplates(ioHelper, language);
        throw new toolkit_lib_1.ToolkitError(`Unknown init template: ${templateType}`);
    }
    return template;
}
/**
 * Resolve the programming language for the template
 * @param ioHelper - IO helper for user interaction
 * @param template - The template to resolve language for
 * @param requestedLanguage - User-requested language (optional)
 * @param type - The template type name for messages
 * @default undefined
 * @returns Promise resolving to the selected language
 */
async function resolveLanguage(ioHelper, template, requestedLanguage, type) {
    return (async () => {
        if (requestedLanguage) {
            return requestedLanguage;
        }
        if (template.languages.length === 1) {
            const templateLanguage = template.languages[0];
            // Only show auto-detection message for built-in templates
            if (template.templateType !== TemplateType.CUSTOM) {
                await ioHelper.defaults.warn(`No --language was provided, but '${type || template.name}' supports only '${templateLanguage}', so defaulting to --language=${templateLanguage}`);
            }
            return templateLanguage;
        }
        await ioHelper.defaults.info(`Available languages for ${chalk.green(type || template.name)}: ${template.languages.map((l) => chalk.blue(l)).join(', ')}`);
        throw new toolkit_lib_1.ToolkitError('No language was selected');
    })();
}
/**
 * Find potential template directories in a multi-template repository
 * @param repositoryPath - Path to the repository root
 * @returns Promise resolving to array of potential template directory names
 */
async function findPotentialTemplates(repositoryPath) {
    const entries = await fs.readdir(repositoryPath, { withFileTypes: true });
    const templateValidationPromises = entries
        .filter(entry => entry.isDirectory() && !entry.name.startsWith('.'))
        .map(async (entry) => {
        try {
            const templatePath = path.join(repositoryPath, entry.name);
            const { languages } = await getLanguageDirectories(templatePath);
            return languages.length > 0 ? entry.name : null;
        }
        catch (error) {
            // If we can't read a specific template directory, skip it but don't fail the entire operation
            return null;
        }
    });
    /* eslint-disable-next-line @cdklabs/promiseall-no-unbounded-parallelism */ // Limited to directory entries
    const validationResults = await Promise.all(templateValidationPromises);
    return validationResults.filter((templateName) => templateName !== null);
}
/**
 * Get valid CDK language directories from a template path
 * @param templatePath - Path to the template directory
 * @returns Promise resolving to array of supported language names
 */
/**
 * Get valid CDK language directories from a template path
 * @param templatePath - Path to the template directory
 * @returns Promise resolving to array of supported language names and directory entries
 * @throws ToolkitError if directory cannot be read or validated
 */
async function getLanguageDirectories(templatePath) {
    try {
        const entries = await fs.readdir(templatePath, { withFileTypes: true });
        const languageValidationPromises = entries
            .filter(directoryEntry => directoryEntry.isDirectory() && SUPPORTED_LANGUAGE_NAMES.includes(directoryEntry.name))
            .map(async (directoryEntry) => {
            const languageDirectoryPath = path.join(templatePath, directoryEntry.name);
            try {
                const hasValidLanguageFiles = await hasLanguageFiles(languageDirectoryPath, (0, language_1.getLanguageExtensions)(directoryEntry.name));
                return hasValidLanguageFiles ? directoryEntry.name : null;
            }
            catch (error) {
                throw new toolkit_lib_1.ToolkitError(`Cannot read language directory '${directoryEntry.name}': ${error.message}`);
            }
        });
        /* eslint-disable-next-line @cdklabs/promiseall-no-unbounded-parallelism */ // Limited to supported CDK languages (7 max)
        const validationResults = await Promise.all(languageValidationPromises);
        return {
            languages: validationResults.filter((languageName) => languageName !== null),
            entries,
        };
    }
    catch (error) {
        throw new toolkit_lib_1.ToolkitError(`Cannot read template directory '${templatePath}': ${error.message}`);
    }
}
/**
 * Iteratively check if a directory contains files with the specified extensions
 * @param directoryPath - Path to search for language files
 * @param extensions - Array of file extensions to look for
 * @returns Promise resolving to true if language files are found
 */
async function hasLanguageFiles(directoryPath, extensions) {
    const dirsToCheck = [directoryPath];
    while (dirsToCheck.length > 0) {
        const currentDir = dirsToCheck.pop();
        try {
            const entries = await fs.readdir(currentDir, { withFileTypes: true });
            for (const entry of entries) {
                if (entry.isFile() && extensions.some(ext => entry.name.endsWith(ext))) {
                    return true;
                }
                else if (entry.isDirectory()) {
                    dirsToCheck.push(path.join(currentDir, entry.name));
                }
            }
        }
        catch (error) {
            throw error;
        }
    }
    return false;
}
/**
 * Returns the name of the Python executable for this OS
 * @returns The Python executable name for the current platform
 */
function pythonExecutable() {
    let python = 'python3';
    if (process.platform === 'win32') {
        python = 'python';
    }
    return python;
}
const INFO_DOT_JSON = 'info.json';
var TemplateType;
(function (TemplateType) {
    TemplateType["BUILT_IN"] = "builtin";
    TemplateType["CUSTOM"] = "custom";
})(TemplateType || (TemplateType = {}));
class InitTemplate {
    static async fromName(templatesDir, name) {
        const basePath = path.join(templatesDir, name);
        const languages = await listDirectory(basePath);
        const initInfo = await fs.readJson(path.join(basePath, INFO_DOT_JSON));
        return new InitTemplate(basePath, name, languages, initInfo, TemplateType.BUILT_IN);
    }
    static async fromPath(templatePath) {
        const basePath = path.resolve(templatePath);
        if (!await fs.pathExists(basePath)) {
            throw new toolkit_lib_1.ToolkitError(`Template path does not exist: ${basePath}`);
        }
        let templateSourcePath = basePath;
        let { languages, entries } = await getLanguageDirectories(basePath);
        if (languages.length === 0) {
            const languageDirs = entries.filter(entry => entry.isDirectory() &&
                SUPPORTED_LANGUAGE_NAMES.includes(entry.name));
            if (languageDirs.length === 1) {
                // Validate that the language directory contains appropriate files
                const langDir = languageDirs[0].name;
                templateSourcePath = path.join(basePath, langDir);
                const hasValidFiles = await hasLanguageFiles(templateSourcePath, (0, language_1.getLanguageExtensions)(langDir));
                if (!hasValidFiles) {
                    // If we found a language directory but it doesn't contain valid files, we should inform the user
                    throw new toolkit_lib_1.ToolkitError(`Found '${langDir}' directory but it doesn't contain the expected language files. Ensure the template contains ${langDir} source files.`);
                }
            }
        }
        const name = path.basename(basePath);
        return new InitTemplate(templateSourcePath, name, languages, null, TemplateType.CUSTOM);
    }
    constructor(basePath, name, languages, initInfo, templateType) {
        this.basePath = basePath;
        this.name = name;
        this.languages = languages;
        this.aliases = new Set();
        this.templateType = templateType;
        // Only built-in templates have descriptions and aliases from info.json
        if (templateType === TemplateType.BUILT_IN && initInfo) {
            this.description = initInfo.description;
            for (const alias of initInfo.aliases || []) {
                this.aliases.add(alias);
            }
        }
    }
    /**
     * @param name - the name that is being checked
     * @returns ``true`` if ``name`` is the name of this template or an alias of it.
     */
    hasName(name) {
        return name === this.name || this.aliases.has(name);
    }
    /**
     * Creates a new instance of this ``InitTemplate`` for a given language to a specified folder.
     *
     * @param language - the language to instantiate this template with
     * @param targetDirectory - the directory where the template is to be instantiated into
     * @param stackName - the name of the stack to create
     * @default undefined
     * @param libVersion - the version of the CDK library to use
     * @default undefined
     */
    async install(ioHelper, language, targetDirectory, stackName, libVersion) {
        if (this.languages.indexOf(language) === -1) {
            await ioHelper.defaults.error(`The ${chalk.blue(language)} language is not supported for ${chalk.green(this.name)} ` +
                `(it supports: ${this.languages.map((l) => chalk.blue(l)).join(', ')})`);
            throw new toolkit_lib_1.ToolkitError(`Unsupported language: ${language}`);
        }
        const projectInfo = {
            name: decamelize(path.basename(path.resolve(targetDirectory))),
            stackName,
            versions: await loadInitVersions(),
        };
        if (libVersion) {
            projectInfo.versions['aws-cdk-lib'] = libVersion;
        }
        let sourceDirectory = path.join(this.basePath, language);
        // For auto-detected single language templates, use basePath directly
        if (this.templateType === TemplateType.CUSTOM && this.languages.length === 1 &&
            path.basename(this.basePath) === language) {
            sourceDirectory = this.basePath;
        }
        if (this.templateType === TemplateType.CUSTOM) {
            // For custom templates, copy files without processing placeholders
            await this.installFilesWithoutProcessing(sourceDirectory, targetDirectory);
        }
        else {
            // For built-in templates, process placeholders as usual
            await this.installFiles(sourceDirectory, targetDirectory, language, projectInfo);
            await this.applyFutureFlags(targetDirectory);
            await (0, init_hooks_1.invokeBuiltinHooks)(ioHelper, { targetDirectory, language, templateName: this.name }, {
                substitutePlaceholdersIn: async (...fileNames) => {
                    const fileProcessingPromises = fileNames.map(async (fileName) => {
                        const fullPath = path.join(targetDirectory, fileName);
                        const template = await fs.readFile(fullPath, { encoding: 'utf-8' });
                        await fs.writeFile(fullPath, expandPlaceholders(template, language, projectInfo));
                    });
                    /* eslint-disable-next-line @cdklabs/promiseall-no-unbounded-parallelism */ // Processing a small, known set of template files
                    await Promise.all(fileProcessingPromises);
                },
                placeholder: (ph) => expandPlaceholders(`%${ph}%`, language, projectInfo),
            });
        }
    }
    async installFiles(sourceDirectory, targetDirectory, language, project) {
        for (const file of await fs.readdir(sourceDirectory)) {
            const fromFile = path.join(sourceDirectory, file);
            const toFile = path.join(targetDirectory, expandPlaceholders(file, language, project));
            if ((await fs.stat(fromFile)).isDirectory()) {
                await fs.mkdir(toFile);
                await this.installFiles(fromFile, toFile, language, project);
                continue;
            }
            else if (file.match(/^.*\.template\.[^.]+$/)) {
                await this.installProcessed(fromFile, toFile.replace(/\.template(\.[^.]+)$/, '$1'), language, project);
                continue;
            }
            else if (file.match(/^.*\.hook\.(d.)?[^.]+$/)) {
                // Ignore
                continue;
            }
            else {
                await fs.copy(fromFile, toFile);
            }
        }
    }
    async installProcessed(templatePath, toFile, language, project) {
        const template = await fs.readFile(templatePath, { encoding: 'utf-8' });
        await fs.writeFile(toFile, expandPlaceholders(template, language, project));
    }
    /**
     * Copy template files without processing placeholders (for custom templates)
     */
    async installFilesWithoutProcessing(sourceDirectory, targetDirectory) {
        await fs.copy(sourceDirectory, targetDirectory, {
            filter: (src) => {
                const filename = path.basename(src);
                return !filename.match(/^.*\.hook\.(d.)?[^.]+$/);
            },
        });
    }
    /**
     * Adds context variables to `cdk.json` in the generated project directory to
     * enable future behavior for new projects.
     */
    async applyFutureFlags(projectDir) {
        const cdkJson = path.join(projectDir, 'cdk.json');
        if (!(await fs.pathExists(cdkJson))) {
            return;
        }
        const config = await fs.readJson(cdkJson);
        config.context = {
            ...config.context,
            ...await currentlyRecommendedAwsCdkLibFlags(),
        };
        await fs.writeJson(cdkJson, config, { spaces: 2 });
    }
    async addMigrateContext(projectDir) {
        const cdkJson = path.join(projectDir, 'cdk.json');
        if (!(await fs.pathExists(cdkJson))) {
            return;
        }
        const config = await fs.readJson(cdkJson);
        config.context = {
            ...config.context,
            'cdk-migrate': true,
        };
        await fs.writeJson(cdkJson, config, { spaces: 2 });
    }
}
exports.InitTemplate = InitTemplate;
function expandPlaceholders(template, language, project) {
    const cdkVersion = project.versions['aws-cdk-lib'];
    const cdkCliVersion = project.versions['aws-cdk'];
    let constructsVersion = project.versions.constructs;
    switch (language) {
        case 'java':
        case 'csharp':
        case 'fsharp':
            constructsVersion = (0, util_1.rangeFromSemver)(constructsVersion, 'bracket');
            break;
        case 'python':
            constructsVersion = (0, util_1.rangeFromSemver)(constructsVersion, 'pep');
            break;
    }
    return template
        .replace(/%name%/g, project.name)
        .replace(/%stackname%/, project.stackName ?? '%name.PascalCased%Stack')
        .replace(/%PascalNameSpace%/, project.stackName ? camelCase(project.stackName + 'Stack', { pascalCase: true }) : '%name.PascalCased%')
        .replace(/%PascalStackProps%/, project.stackName ? camelCase(project.stackName, { pascalCase: true }) + 'StackProps' : 'StackProps')
        .replace(/%name\.camelCased%/g, camelCase(project.name))
        .replace(/%name\.PascalCased%/g, camelCase(project.name, { pascalCase: true }))
        .replace(/%cdk-version%/g, cdkVersion)
        .replace(/%cdk-cli-version%/g, cdkCliVersion)
        .replace(/%constructs-version%/g, constructsVersion)
        .replace(/%cdk-home%/g, (0, util_1.cdkHomeDir)())
        .replace(/%name\.PythonModule%/g, project.name.replace(/-/g, '_'))
        .replace(/%python-executable%/g, pythonExecutable())
        .replace(/%name\.StackName%/g, project.name.replace(/[^A-Za-z0-9-]/g, '-'));
}
async function availableInitTemplates() {
    try {
        const templatesDir = path.join((0, root_dir_1.cliRootDir)(), 'lib', 'init-templates');
        const templateNames = await listDirectory(templatesDir);
        const templatePromises = templateNames.map(templateName => InitTemplate.fromName(templatesDir, templateName));
        /* eslint-disable-next-line @cdklabs/promiseall-no-unbounded-parallelism */ // Built-in templates are limited in number
        return await Promise.all(templatePromises);
    }
    catch (error) {
        // Return empty array if templates directory doesn't exist or can't be read
        // This allows the CLI to gracefully handle missing built-in templates
        if (error.code === 'ENOENT' || error.code === 'EACCES') {
            return [];
        }
        throw error;
    }
}
async function availableInitLanguages() {
    const templates = await availableInitTemplates();
    const result = new Set();
    for (const template of templates) {
        for (const language of template.languages) {
            const alias = (0, language_1.getLanguageAlias)(language);
            result.add(language);
            alias && result.add(alias);
        }
    }
    return [...result];
}
/**
 * @param dirPath - is the directory to be listed.
 * @returns the list of file or directory names contained in ``dirPath``, excluding any dot-file, and sorted.
 */
async function listDirectory(dirPath) {
    return ((await fs.readdir(dirPath))
        .filter((p) => !p.startsWith('.'))
        .filter((p) => !(p === 'LICENSE'))
        // if, for some reason, the temp folder for the hook doesn't get deleted we don't want to display it in this list
        .filter((p) => !(p === INFO_DOT_JSON))
        .sort());
}
/**
 * Print available templates to the user
 * @param ioHelper - IO helper for user interaction
 * @param language - Programming language filter
 * @default undefined
 */
async function printAvailableTemplates(ioHelper, language) {
    await ioHelper.defaults.info('Available templates:');
    for (const template of await availableInitTemplates()) {
        if (language && template.languages.indexOf(language) === -1) {
            continue;
        }
        await ioHelper.defaults.info(`* ${chalk.green(template.name)}: ${template.description}`);
        const languageArg = language
            ? chalk.bold(language)
            : template.languages.length > 1
                ? `[${template.languages.map((t) => chalk.bold(t)).join('|')}]`
                : chalk.bold(template.languages[0]);
        await ioHelper.defaults.info(`   └─ ${chalk.blue(`cdk init ${chalk.bold(template.name)} --language=${languageArg}`)}`);
    }
}
async function initializeProject(ioHelper, template, language, canUseNetwork, generateOnly, workDir, stackName, migrate, cdkVersion) {
    // Step 1: Ensure target directory is empty
    await assertIsEmptyDirectory(workDir);
    // Step 2: Copy template files
    await ioHelper.defaults.info(`Applying project template ${chalk.green(template.name)} for ${chalk.blue(language)}`);
    await template.install(ioHelper, language, workDir, stackName, cdkVersion);
    if (migrate) {
        await template.addMigrateContext(workDir);
    }
    if (await fs.pathExists(`${workDir}/README.md`)) {
        const readme = await fs.readFile(`${workDir}/README.md`, { encoding: 'utf-8' });
        await ioHelper.defaults.info(chalk.green(readme));
    }
    if (!generateOnly) {
        // Step 3: Initialize Git repository and create initial commit
        await initializeGitRepository(ioHelper, workDir);
        // Step 4: Post-install steps
        await postInstall(ioHelper, language, canUseNetwork, workDir);
    }
    await ioHelper.defaults.info('✅ All done!');
}
/**
 * Validate that a directory exists and is empty (ignoring hidden files)
 * @param workDir - Directory path to validate
 * @throws ToolkitError if directory doesn't exist or is not empty
 */
async function assertIsEmptyDirectory(workDir) {
    try {
        const stats = await fs.stat(workDir);
        if (!stats.isDirectory()) {
            throw new toolkit_lib_1.ToolkitError(`Path exists but is not a directory: ${workDir}`);
        }
        const files = await fs.readdir(workDir);
        const visibleFiles = files.filter(f => !f.startsWith('.'));
        if (visibleFiles.length > 0) {
            throw new toolkit_lib_1.ToolkitError('`cdk init` cannot be run in a non-empty directory!\n' +
                `Found ${visibleFiles.length} visible files in ${workDir}:\n` +
                visibleFiles.map(f => `  - ${f}`).join('\n'));
        }
    }
    catch (e) {
        if (e.code === 'ENOENT') {
            throw new toolkit_lib_1.ToolkitError(`Directory does not exist: ${workDir}\n` +
                'Please create the directory first using: mkdir -p ' + workDir);
        }
        throw new toolkit_lib_1.ToolkitError(`Failed to validate directory ${workDir}: ${e.message}`);
    }
}
async function initializeGitRepository(ioHelper, workDir) {
    if (await isInGitRepository(workDir)) {
        return;
    }
    await ioHelper.defaults.info('Initializing a new git repository...');
    try {
        await execute(ioHelper, 'git', ['init'], { cwd: workDir });
        await execute(ioHelper, 'git', ['add', '.'], { cwd: workDir });
        await execute(ioHelper, 'git', ['commit', '--message="Initial commit"', '--no-gpg-sign'], { cwd: workDir });
    }
    catch {
        await ioHelper.defaults.warn('Unable to initialize git repository for your project.');
    }
}
async function postInstall(ioHelper, language, canUseNetwork, workDir) {
    switch (language) {
        case 'javascript':
            return postInstallJavascript(ioHelper, canUseNetwork, workDir);
        case 'typescript':
            return postInstallTypescript(ioHelper, canUseNetwork, workDir);
        case 'java':
            return postInstallJava(ioHelper, canUseNetwork, workDir);
        case 'python':
            return postInstallPython(ioHelper, workDir);
        case 'go':
            return postInstallGo(ioHelper, canUseNetwork, workDir);
        case 'csharp':
            return postInstallCSharp(ioHelper, canUseNetwork, workDir);
        case 'fsharp':
            return postInstallFSharp(ioHelper, canUseNetwork, workDir);
    }
}
async function postInstallJavascript(ioHelper, canUseNetwork, cwd) {
    return postInstallTypescript(ioHelper, canUseNetwork, cwd);
}
async function postInstallTypescript(ioHelper, canUseNetwork, cwd) {
    const command = 'npm';
    if (!canUseNetwork) {
        await ioHelper.defaults.warn(`Please run '${command} install'!`);
        return;
    }
    await ioHelper.defaults.info(`Executing ${chalk.green(`${command} install`)}...`);
    try {
        await execute(ioHelper, command, ['install'], { cwd });
    }
    catch (e) {
        await ioHelper.defaults.warn(`${command} install failed: ` + (0, util_1.formatErrorMessage)(e));
    }
}
async function postInstallJava(ioHelper, canUseNetwork, cwd) {
    // Check if this is a Gradle or Maven project
    const hasGradleBuild = await fs.pathExists(path.join(cwd, 'build.gradle'));
    const hasMavenPom = await fs.pathExists(path.join(cwd, 'pom.xml'));
    if (hasGradleBuild) {
        // Gradle project
        const gradleWarning = "Please run './gradlew build'!";
        if (!canUseNetwork) {
            await ioHelper.defaults.warn(gradleWarning);
            return;
        }
        await ioHelper.defaults.info("Executing './gradlew build'");
        try {
            await execute(ioHelper, './gradlew', ['build'], { cwd });
        }
        catch {
            await ioHelper.defaults.warn('Unable to build Gradle project');
            await ioHelper.defaults.warn(gradleWarning);
        }
    }
    else if (hasMavenPom) {
        // Maven project
        const mvnPackageWarning = "Please run 'mvn package'!";
        if (!canUseNetwork) {
            await ioHelper.defaults.warn(mvnPackageWarning);
            return;
        }
        await ioHelper.defaults.info("Executing 'mvn package'");
        try {
            await execute(ioHelper, 'mvn', ['package'], { cwd });
        }
        catch {
            await ioHelper.defaults.warn('Unable to package compiled code as JAR');
            await ioHelper.defaults.warn(mvnPackageWarning);
        }
    }
    else {
        // No recognized build file
        await ioHelper.defaults.warn('No build.gradle or pom.xml found. Please set up your build system manually.');
    }
}
async function postInstallPython(ioHelper, cwd) {
    const python = pythonExecutable();
    // Check if requirements.txt exists
    const hasRequirements = await fs.pathExists(path.join(cwd, 'requirements.txt'));
    if (hasRequirements) {
        await ioHelper.defaults.info(`Executing ${chalk.green('Creating virtualenv...')}`);
        try {
            await execute(ioHelper, python, ['-m', 'venv', '.venv'], { cwd });
            await ioHelper.defaults.info(`Executing ${chalk.green('Installing dependencies...')}`);
            // Install dependencies in the virtual environment
            const pipPath = process.platform === 'win32' ? '.venv\\Scripts\\pip' : '.venv/bin/pip';
            await execute(ioHelper, pipPath, ['install', '-r', 'requirements.txt'], { cwd });
        }
        catch {
            await ioHelper.defaults.warn('Unable to create virtualenv or install dependencies automatically');
            await ioHelper.defaults.warn(`Please run '${python} -m venv .venv && .venv/bin/pip install -r requirements.txt'!`);
        }
    }
    else {
        await ioHelper.defaults.warn('No requirements.txt found. Please set up your Python environment manually.');
    }
}
async function postInstallGo(ioHelper, canUseNetwork, cwd) {
    if (!canUseNetwork) {
        await ioHelper.defaults.warn('Please run \'go mod tidy\'!');
        return;
    }
    await ioHelper.defaults.info(`Executing ${chalk.green('go mod tidy')}...`);
    try {
        await execute(ioHelper, 'go', ['mod', 'tidy'], { cwd });
    }
    catch (e) {
        await ioHelper.defaults.warn('\'go mod tidy\' failed: ' + (0, util_1.formatErrorMessage)(e));
    }
}
async function postInstallCSharp(ioHelper, canUseNetwork, cwd) {
    const dotnetWarning = "Please run 'dotnet restore && dotnet build'!";
    if (!canUseNetwork) {
        await ioHelper.defaults.warn(dotnetWarning);
        return;
    }
    await ioHelper.defaults.info(`Executing ${chalk.green('dotnet restore')}...`);
    try {
        await execute(ioHelper, 'dotnet', ['restore'], { cwd });
        await ioHelper.defaults.info(`Executing ${chalk.green('dotnet build')}...`);
        await execute(ioHelper, 'dotnet', ['build'], { cwd });
    }
    catch (e) {
        await ioHelper.defaults.warn('Unable to restore/build .NET project: ' + (0, util_1.formatErrorMessage)(e));
        await ioHelper.defaults.warn(dotnetWarning);
    }
}
async function postInstallFSharp(ioHelper, canUseNetwork, cwd) {
    // F# uses the same build system as C#
    return postInstallCSharp(ioHelper, canUseNetwork, cwd);
}
/**
 * @param dir - a directory to be checked
 * @returns true if ``dir`` is within a git repository.
 */
async function isInGitRepository(dir) {
    while (true) {
        if (await fs.pathExists(path.join(dir, '.git'))) {
            return true;
        }
        if (isRoot(dir)) {
            return false;
        }
        dir = path.dirname(dir);
    }
}
/**
 * @param dir - a directory to be checked.
 * @returns true if ``dir`` is the root of a filesystem.
 */
function isRoot(dir) {
    return path.dirname(dir) === dir;
}
/**
 * Executes `command`. STDERR is emitted in real-time.
 *
 * If command exits with non-zero exit code, an exception is thrown and includes
 * the contents of STDOUT.
 *
 * @returns STDOUT (if successful).
 */
async function execute(ioHelper, cmd, args, { cwd }) {
    const child = childProcess.spawn(cmd, args, {
        cwd,
        shell: true,
        stdio: ['ignore', 'pipe', 'inherit'],
    });
    let stdout = '';
    child.stdout.on('data', (chunk) => (stdout += chunk.toString()));
    return new Promise((ok, fail) => {
        child.once('error', (err) => fail(err));
        child.once('exit', (status) => {
            if (status === 0) {
                return ok(stdout);
            }
            else {
                return fail(new toolkit_lib_1.ToolkitError(`${cmd} exited with status ${status}`));
            }
        });
    }).catch(async (err) => {
        await ioHelper.defaults.error(stdout);
        throw err;
    });
}
/**
 * Return the 'aws-cdk-lib' version we will init
 *
 * This has been built into the CLI at build time.
 */
async function loadInitVersions() {
    const initVersionFile = path.join((0, root_dir_1.cliRootDir)(), 'lib', 'init-templates', '.init-version.json');
    const contents = JSON.parse(await fs.readFile(initVersionFile, { encoding: 'utf-8' }));
    const ret = {
        'aws-cdk-lib': contents['aws-cdk-lib'],
        'constructs': contents.constructs,
        'aws-cdk': (0, version_1.versionNumber)(),
    };
    for (const [key, value] of Object.entries(ret)) {
        if (!value) {
            throw new toolkit_lib_1.ToolkitError(`Missing init version from ${initVersionFile}: ${key}`);
        }
    }
    return ret;
}
/**
 * Return the currently recommended flags for `aws-cdk-lib`.
 *
 * These have been built into the CLI at build time.
 */
async function currentlyRecommendedAwsCdkLibFlags() {
    const recommendedFlagsFile = path.join((0, root_dir_1.cliRootDir)(), 'lib', 'init-templates', '.recommended-feature-flags.json');
    return JSON.parse(await fs.readFile(recommendedFlagsFile, { encoding: 'utf-8' }));
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5pdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImluaXQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBb0ZBLDBCQW1DQztBQTRaRCxnREFtQ0M7QUFVRCx3REFpQkM7QUFFRCx3REFXQztBQXVCRCwwREFjQztBQTRURCxnRkFHQztBQWw4QkQsOENBQThDO0FBQzlDLDZCQUE2QjtBQUM3QixzREFBb0Q7QUFDcEQsK0JBQStCO0FBQy9CLCtCQUErQjtBQUMvQiw2Q0FBa0Q7QUFFbEQsaURBQWdEO0FBQ2hELCtDQUFrRDtBQUNsRCxxQ0FBNkU7QUFFN0UsMENBQTJGO0FBRTNGLHVEQUF1RCxDQUFDLG9DQUFvQztBQUM1RixpRUFBaUU7QUFDakUsTUFBTSxTQUFTLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFDO0FBQ3ZDLGlFQUFpRTtBQUNqRSxNQUFNLFVBQVUsR0FBRyxPQUFPLENBQUMsWUFBWSxDQUFDLENBQUM7QUFFekMsTUFBTSx3QkFBd0IsR0FBRyw4QkFBbUIsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFlLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQztBQThEdEY7O0dBRUc7QUFDSSxLQUFLLFVBQVUsT0FBTyxDQUFDLE9BQXVCO0lBQ25ELE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxRQUFRLENBQUM7SUFDbEMsTUFBTSxhQUFhLEdBQUcsT0FBTyxDQUFDLGFBQWEsSUFBSSxJQUFJLENBQUM7SUFDcEQsTUFBTSxZQUFZLEdBQUcsT0FBTyxDQUFDLFlBQVksSUFBSSxLQUFLLENBQUM7SUFDbkQsTUFBTSxPQUFPLEdBQUcsT0FBTyxDQUFDLE9BQU8sSUFBSSxPQUFPLENBQUMsR0FBRyxFQUFFLENBQUM7SUFFakQsMkVBQTJFO0lBQzNFLElBQUksQ0FBQyxPQUFPLENBQUMsUUFBUSxJQUFJLENBQUMsT0FBTyxDQUFDLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxRQUFRLEVBQUUsQ0FBQztRQUM1RCxN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ZUFBZSxFQUFFLEVBQUUsUUFBUSxFQUFFLE9BQU8sRUFBRSxDQUFDLENBQUMsQ0FBQztJQUV2RixNQUFNLEdBQUcsR0FBRztRQUNWLGFBQWEsRUFBRSxRQUFRLENBQUMsYUFBYSxDQUFDO1FBQ3RDLFlBQVksRUFBRSxRQUFRLENBQUMsVUFBVTtRQUNqQyxTQUFTLEVBQUUsSUFBQSx1QkFBYSxHQUFFO0tBQzNCLENBQUM7SUFDRixLQUFLLE1BQU0sQ0FBQyxHQUFHLEVBQUUsS0FBSyxDQUFDLElBQUksTUFBTSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDO1FBQy9DLElBQUksQ0FBQyxLQUFLLEVBQUUsQ0FBQztZQUNYLE1BQU0sSUFBSSwwQkFBWSxDQUFDLDZCQUE2QixlQUFlLEtBQUssR0FBRyxFQUFFLENBQUMsQ0FBQztRQUNqRixDQUFDO0lBQ0gsQ0FBQztJQUVELE9BQU8sR0FBRyxDQUFDO0FBQ2IsQ0FBQztBQUVEOzs7O0dBSUc7QUFDSSxLQUFLLFVBQVUsa0NBQWtDO0lBQ3RELE1BQU0sb0JBQW9CLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxJQUFBLHFCQUFVLEdBQUUsRUFBRSxLQUFLLEVBQUUsZ0JBQWdCLEVBQUUsaUNBQWlDLENBQUMsQ0FBQztJQUNqSCxPQUFPLElBQUksQ0FBQyxLQUFLLENBQUMsTUFBTSxFQUFFLENBQUMsUUFBUSxDQUFDLG9CQUFvQixFQUFFLEVBQUUsUUFBUSxFQUFFLE9BQU8sRUFBRSxDQUFDLENBQUMsQ0FBQztBQUNwRixDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0ICogYXMgY2hpbGRQcm9jZXNzIGZyb20gJ2NoaWxkX3Byb2Nlc3MnO1xuaW1wb3J0ICogYXMgcGF0aCBmcm9tICdwYXRoJztcbmltcG9ydCB7IFRvb2xraXRFcnJvciB9IGZyb20gJ0Bhd3MtY2RrL3Rvb2xraXQtbGliJztcbmltcG9ydCAqIGFzIGNoYWxrIGZyb20gJ2NoYWxrJztcbmltcG9ydCAqIGFzIGZzIGZyb20gJ2ZzLWV4dHJhJztcbmltcG9ydCB7IGludm9rZUJ1aWx0aW5Ib29rcyB9IGZyb20gJy4vaW5pdC1ob29rcyc7XG5pbXBvcnQgdHlwZSB7IElvSGVscGVyIH0gZnJvbSAnLi4vLi4vYXBpLXByaXZhdGUnO1xuaW1wb3J0IHsgY2xpUm9vdERpciB9IGZyb20gJy4uLy4uL2NsaS9yb290LWRpcic7XG5pbXBvcnQgeyB2ZXJzaW9uTnVtYmVyIH0gZnJvbSAnLi4vLi4vY2xpL3ZlcnNpb24nO1xuaW1wb3J0IHsgY2RrSG9tZURpciwgZm9ybWF0RXJyb3JNZXNzYWdlLCByYW5nZUZyb21TZW12ZXIgfSBmcm9tICcuLi8uLi91dGlsJztcbmltcG9ydCB0eXBlIHsgTGFuZ3VhZ2VJbmZvIH0gZnJvbSAnLi4vbGFuZ3VhZ2UnO1xuaW1wb3J0IHsgZ2V0TGFuZ3VhZ2VBbGlhcywgZ2V0TGFuZ3VhZ2VFeHRlbnNpb25zLCBTVVBQT1JURURfTEFOR1VBR0VTIH0gZnJvbSAnLi4vbGFuZ3VhZ2UnO1xuXG4vKiBlc2xpbnQtZGlzYWJsZSBAdHlwZXNjcmlwdC1lc2xpbnQvbm8tdmFyLXJlcXVpcmVzICovIC8vIFBhY2thZ2VzIGRvbid0IGhhdmUgQHR5cGVzIG1vZHVsZVxuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIEB0eXBlc2NyaXB0LWVzbGludC9uby1yZXF1aXJlLWltcG9ydHNcbmNvbnN0IGNhbWVsQ2FzZSA9IHJlcXVpcmUoJ2NhbWVsY2FzZScpO1xuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIEB0eXBlc2NyaXB0LWVzbGludC9uby1yZXF1aXJlLWltcG9ydHNcbmNvbnN0IGRlY2FtZWxpemUgPSByZXF1aXJlKCdkZWNhbWVsaXplJyk7XG5cbmNvbnN0IFNVUFBPUlRFRF9MQU5HVUFHRV9OQU1FUyA9IFNVUFBPUlRFRF9MQU5HVUFHRVMubWFwKChsOiBMYW5ndWFnZUluZm8pID0+IGwubmFtZSk7XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ2xpSW5pdE9wdGlvbnMge1xuICAvKipcbiAgICogVGVtcGxhdGUgbmFtZSB0byBpbml0aWFsaXplXG4gICAqIEBkZWZhdWx0IHVuZGVmaW5lZFxuICAgKi9cbiAgcmVhZG9ubHkgdHlwZT86IHN0cmluZztcblxuICAvKipcbiAgICogUHJvZ3JhbW1pbmcgbGFuZ3VhZ2UgZm9yIHRoZSBwcm9qZWN0XG4gICAqIEBkZWZhdWx0IC0gT3B0aW9uYWwvYXV0by1kZXRlY3RlZCBpZiB0ZW1wbGF0ZSBzdXBwb3J0cyBvbmx5IG9uZSBsYW5ndWFnZSwgb3RoZXJ3aXNlIHJlcXVpcmVkXG4gICAqL1xuICByZWFkb25seSBsYW5ndWFnZT86IHN0cmluZztcblxuICAvKipcbiAgICogQGRlZmF1bHQgdHJ1ZVxuICAgKi9cbiAgcmVhZG9ubHkgY2FuVXNlTmV0d29yaz86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIEBkZWZhdWx0IGZhbHNlXG4gICAqL1xuICByZWFkb25seSBnZW5lcmF0ZU9ubHk/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBAZGVmYXVsdCBwcm9jZXNzLmN3ZCgpXG4gICAqL1xuICByZWFkb25seSB3b3JrRGlyPzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBAZGVmYXVsdCB1bmRlZmluZWRcbiAgICovXG4gIHJlYWRvbmx5IHN0YWNrTmFtZT86IHN0cmluZztcblxuICAvKipcbiAgICogQGRlZmF1bHQgdW5kZWZpbmVkXG4gICAqL1xuICByZWFkb25seSBtaWdyYXRlPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogT3ZlcnJpZGUgdGhlIGJ1aWx0LWluIENESyB2ZXJzaW9uXG4gICAqIEBkZWZhdWx0IHVuZGVmaW5lZFxuICAgKi9cbiAgcmVhZG9ubHkgbGliVmVyc2lvbj86IHN0cmluZztcblxuICAvKipcbiAgICogUGF0aCB0byBhIGxvY2FsIGN1c3RvbSB0ZW1wbGF0ZSBkaXJlY3RvcnlcbiAgICogQGRlZmF1bHQgdW5kZWZpbmVkXG4gICAqL1xuICByZWFkb25seSBmcm9tUGF0aD86IHN0cmluZztcblxuICAvKipcbiAgICogUGF0aCB0byBhIHNwZWNpZmljIHRlbXBsYXRlIHdpdGhpbiBhIG11bHRpLXRlbXBsYXRlIHJlcG9zaXRvcnkuXG4gICAqIFRoaXMgcGFyYW1ldGVyIHJlcXVpcmVzIC0tZnJvbS1wYXRoIHRvIGJlIHNwZWNpZmllZC5cbiAgICogQGRlZmF1bHQgdW5kZWZpbmVkXG4gICAqL1xuICByZWFkb25seSB0ZW1wbGF0ZVBhdGg/OiBzdHJpbmc7XG5cbiAgcmVhZG9ubHkgaW9IZWxwZXI6IElvSGVscGVyO1xufVxuXG4vKipcbiAqIEluaXRpYWxpemUgYSBDREsgcGFja2FnZSBpbiB0aGUgY3VycmVudCBkaXJlY3RvcnlcbiAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNsaUluaXQob3B0aW9uczogQ2xpSW5pdE9wdGlvbnMpIHtcbiAgY29uc3QgaW9IZWxwZXIgPSBvcHRpb25zLmlvSGVscGVyO1xuICBjb25zdCBjYW5Vc2VOZXR3b3JrID0gb3B0aW9ucy5jYW5Vc2VOZXR3b3JrID8/IHRydWU7XG4gIGNvbnN0IGdlbmVyYXRlT25seSA9IG9wdGlvbnMuZ2VuZXJhdGVPbmx5ID8/IGZhbHNlO1xuICBjb25zdCB3b3JrRGlyID0gb3B0aW9ucy53b3JrRGlyID8/IHByb2Nlc3MuY3dkKCk7XG5cbiAgLy8gU2hvdyBhdmFpbGFibGUgdGVtcGxhdGVzIG9ubHkgaWYgbm8gZnJvbVBhdGgsIHR5cGUsIG9yIGxhbmd1YWdlIHByb3ZpZGVkXG4gIGlmICghb3B0aW9ucy5mcm9tUGF0aCAmJiAhb3B0aW9ucy50eXBlICYmICFvcHRpb25zLmxhbmd1YWdlKSB7XG4gICAgYXdhaXQgcHJpbnRBdmFpbGFibGVUZW1wbGF0ZXMoaW9IZWxwZXIpO1xuICAgIHJldHVybjtcbiAgfVxuXG4gIC8vIFN0ZXAgMTogTG9hZCB0ZW1wbGF0ZVxuICBsZXQgdGVtcGxhdGU6IEluaXRUZW1wbGF0ZTtcbiAgaWYgKG9wdGlvbnMuZnJvbVBhdGgpIHtcbiAgICB0ZW1wbGF0ZSA9IGF3YWl0IGxvYWRMb2NhbFRlbXBsYXRlKG9wdGlvbnMuZnJvbVBhdGgsIG9wdGlvbnMudGVtcGxhdGVQYXRoKTtcbiAgfSBlbHNlIHtcbiAgICB0ZW1wbGF0ZSA9IGF3YWl0IGxvYWRCdWlsdGluVGVtcGxhdGUoaW9IZWxwZXIsIG9wdGlvbnMudHlwZSwgb3B0aW9ucy5sYW5ndWFnZSk7XG4gIH1cblxuICAvLyBTdGVwIDI6IFJlc29sdmUgbGFuZ3VhZ2VcbiAgY29uc3QgbGFuZ3VhZ2UgPSBhd2FpdCByZXNvbHZlTGFuZ3VhZ2UoaW9IZWxwZXIsIHRlbXBsYXRlLCBvcHRpb25zLmxhbmd1YWdlLCBvcHRpb25zLnR5cGUpO1xuXG4gIC8vIFN0ZXAgMzogSW5pdGlhbGl6ZSBwcm9qZWN0IGZvbGxvd2luZyBzdGFuZGFyZCBwcm9jZXNzXG4gIGF3YWl0IGluaXRpYWxpemVQcm9qZWN0KFxuICAgIGlvSGVscGVyLFxuICAgIHRlbXBsYXRlLFxuICAgIGxhbmd1YWdlLFxuICAgIGNhblVzZU5ldHdvcmssXG4gICAgZ2VuZXJhdGVPbmx5LFxuICAgIHdvcmtEaXIsXG4gICAgb3B0aW9ucy5zdGFja05hbWUsXG4gICAgb3B0aW9ucy5taWdyYXRlLFxuICAgIG9wdGlvbnMubGliVmVyc2lvbixcbiAgKTtcbn1cblxuLyoqXG4gKiBMb2FkIGEgbG9jYWwgY3VzdG9tIHRlbXBsYXRlIGZyb20gZmlsZSBzeXN0ZW0gcGF0aFxuICogQHBhcmFtIGZyb21QYXRoIC0gUGF0aCB0byB0aGUgbG9jYWwgdGVtcGxhdGUgZGlyZWN0b3J5IG9yIG11bHRpLXRlbXBsYXRlIHJlcG9zaXRvcnlcbiAqIEBwYXJhbSB0ZW1wbGF0ZVBhdGggLSBPcHRpb25hbCBwYXRoIHRvIGEgc3BlY2lmaWMgdGVtcGxhdGUgd2l0aGluIGEgbXVsdGktdGVtcGxhdGUgcmVwb3NpdG9yeVxuICogQHJldHVybnMgUHJvbWlzZSByZXNvbHZpbmcgdG8gdGhlIGxvYWRlZCBJbml0VGVtcGxhdGVcbiAqL1xuYXN5bmMgZnVuY3Rpb24gbG9hZExvY2FsVGVtcGxhdGUoZnJvbVBhdGg6IHN0cmluZywgdGVtcGxhdGVQYXRoPzogc3RyaW5nKTogUHJvbWlzZTxJbml0VGVtcGxhdGU+IHtcbiAgdHJ5IHtcbiAgICBsZXQgYWN0dWFsVGVtcGxhdGVQYXRoID0gZnJvbVBhdGg7XG5cbiAgICAvLyBJZiB0ZW1wbGF0ZVBhdGggaXMgcHJvdmlkZWQsIGl0J3MgYSBtdWx0aS10ZW1wbGF0ZSByZXBvc2l0b3J5XG4gICAgaWYgKHRlbXBsYXRlUGF0aCkge1xuICAgICAgYWN0dWFsVGVtcGxhdGVQYXRoID0gcGF0aC5qb2luKGZyb21QYXRoLCB0ZW1wbGF0ZVBhdGgpO1xuXG4gICAgICBpZiAoIWF3YWl0IGZzLnBhdGhFeGlzdHMoYWN0dWFsVGVtcGxhdGVQYXRoKSkge1xuICAgICAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKGBUZW1wbGF0ZSBwYXRoIGRvZXMgbm90IGV4aXN0OiAke2FjdHVhbFRlbXBsYXRlUGF0aH1gKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCB0ZW1wbGF0ZSA9IGF3YWl0IEluaXRUZW1wbGF0ZS5mcm9tUGF0aChhY3R1YWxUZW1wbGF0ZVBhdGgpO1xuXG4gICAgaWYgKHRlbXBsYXRlLmxhbmd1YWdlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIC8vIENoZWNrIGlmIHRoaXMgbWlnaHQgYmUgYSBtdWx0aS10ZW1wbGF0ZSByZXBvc2l0b3J5XG4gICAgICBpZiAoIXRlbXBsYXRlUGF0aCkge1xuICAgICAgICBjb25zdCBhdmFpbGFibGVUZW1wbGF0ZXMgPSBhd2FpdCBmaW5kUG90ZW50aWFsVGVtcGxhdGVzKGZyb21QYXRoKTtcbiAgICAgICAgaWYgKGF2YWlsYWJsZVRlbXBsYXRlcy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihcbiAgICAgICAgICAgICdVc2UgLS10ZW1wbGF0ZS1wYXRoIHRvIHNwZWNpZnkgd2hpY2ggdGVtcGxhdGUgdG8gdXNlLicsXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcignQ3VzdG9tIHRlbXBsYXRlIG11c3QgY29udGFpbiBhdCBsZWFzdCBvbmUgbGFuZ3VhZ2UgZGlyZWN0b3J5Jyk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRlbXBsYXRlO1xuICB9IGNhdGNoIChlcnJvcjogYW55KSB7XG4gICAgY29uc3QgZGlzcGxheVBhdGggPSB0ZW1wbGF0ZVBhdGggPyBgJHtmcm9tUGF0aH0vJHt0ZW1wbGF0ZVBhdGh9YCA6IGZyb21QYXRoO1xuICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoYEZhaWxlZCB0byBsb2FkIHRlbXBsYXRlIGZyb20gcGF0aDogJHtkaXNwbGF5UGF0aH0uICR7ZXJyb3IubWVzc2FnZX1gKTtcbiAgfVxufVxuXG4vKipcbiAqIExvYWQgYSBidWlsdC1pbiB0ZW1wbGF0ZSBieSBuYW1lXG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGxvYWRCdWlsdGluVGVtcGxhdGUoaW9IZWxwZXI6IElvSGVscGVyLCB0eXBlPzogc3RyaW5nLCBsYW5ndWFnZT86IHN0cmluZyk6IFByb21pc2U8SW5pdFRlbXBsYXRlPiB7XG4gIGNvbnN0IHRlbXBsYXRlVHlwZSA9IHR5cGUgfHwgJ2RlZmF1bHQnOyAvLyBcImRlZmF1bHRcIiBpcyB0aGUgZGVmYXVsdCB0eXBlIChhbmQgbWFwcyB0byBcImFwcFwiKVxuXG4gIGNvbnN0IHRlbXBsYXRlID0gKGF3YWl0IGF2YWlsYWJsZUluaXRUZW1wbGF0ZXMoKSkuZmluZCgodCkgPT4gdC5oYXNOYW1lKHRlbXBsYXRlVHlwZSkpO1xuICBpZiAoIXRlbXBsYXRlKSB7XG4gICAgYXdhaXQgcHJpbnRBdmFpbGFibGVUZW1wbGF0ZXMoaW9IZWxwZXIsIGxhbmd1YWdlKTtcbiAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKGBVbmtub3duIGluaXQgdGVtcGxhdGU6ICR7dGVtcGxhdGVUeXBlfWApO1xuICB9XG5cbiAgcmV0dXJuIHRlbXBsYXRlO1xufVxuXG4vKipcbiAqIFJlc29sdmUgdGhlIHByb2dyYW1taW5nIGxhbmd1YWdlIGZvciB0aGUgdGVtcGxhdGVcbiAqIEBwYXJhbSBpb0hlbHBlciAtIElPIGhlbHBlciBmb3IgdXNlciBpbnRlcmFjdGlvblxuICogQHBhcmFtIHRlbXBsYXRlIC0gVGhlIHRlbXBsYXRlIHRvIHJlc29sdmUgbGFuZ3VhZ2UgZm9yXG4gKiBAcGFyYW0gcmVxdWVzdGVkTGFuZ3VhZ2UgLSBVc2VyLXJlcXVlc3RlZCBsYW5ndWFnZSAob3B0aW9uYWwpXG4gKiBAcGFyYW0gdHlwZSAtIFRoZSB0ZW1wbGF0ZSB0eXBlIG5hbWUgZm9yIG1lc3NhZ2VzXG4gKiBAZGVmYXVsdCB1bmRlZmluZWRcbiAqIEByZXR1cm5zIFByb21pc2UgcmVzb2x2aW5nIHRvIHRoZSBzZWxlY3RlZCBsYW5ndWFnZVxuICovXG5hc3luYyBmdW5jdGlvbiByZXNvbHZlTGFuZ3VhZ2UoaW9IZWxwZXI6IElvSGVscGVyLCB0ZW1wbGF0ZTogSW5pdFRlbXBsYXRlLCByZXF1ZXN0ZWRMYW5ndWFnZT86IHN0cmluZywgdHlwZT86IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gIHJldHVybiAoYXN5bmMgKCkgPT4ge1xuICAgIGlmIChyZXF1ZXN0ZWRMYW5ndWFnZSkge1xuICAgICAgcmV0dXJuIHJlcXVlc3RlZExhbmd1YWdlO1xuICAgIH1cbiAgICBpZiAodGVtcGxhdGUubGFuZ3VhZ2VzLmxlbmd0aCA9PT0gMSkge1xuICAgICAgY29uc3QgdGVtcGxhdGVMYW5ndWFnZSA9IHRlbXBsYXRlLmxhbmd1YWdlc1swXTtcbiAgICAgIC8vIE9ubHkgc2hvdyBhdXRvLWRldGVjdGlvbiBtZXNzYWdlIGZvciBidWlsdC1pbiB0ZW1wbGF0ZXNcbiAgICAgIGlmICh0ZW1wbGF0ZS50ZW1wbGF0ZVR5cGUgIT09IFRlbXBsYXRlVHlwZS5DVVNUT00pIHtcbiAgICAgICAgYXdhaXQgaW9IZWxwZXIuZGVmYXVsdHMud2FybihcbiAgICAgICAgICBgTm8gLS1sYW5ndWFnZSB3YXMgcHJvdmlkZWQsIGJ1dCAnJHt0eXBlIHx8IHRlbXBsYXRlLm5hbWV9JyBzdXBwb3J0cyBvbmx5ICcke3RlbXBsYXRlTGFuZ3VhZ2V9Jywgc28gZGVmYXVsdGluZyB0byAtLWxhbmd1YWdlPSR7dGVtcGxhdGVMYW5ndWFnZX1gLFxuICAgICAgICApO1xuICAgICAgfVxuICAgICAgcmV0dXJuIHRlbXBsYXRlTGFuZ3VhZ2U7XG4gICAgfVxuICAgIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLmluZm8oXG4gICAgICBgQXZhaWxhYmxlIGxhbmd1YWdlcyBmb3IgJHtjaGFsay5ncmVlbih0eXBlIHx8IHRlbXBsYXRlLm5hbWUpfTogJHt0ZW1wbGF0ZS5sYW5ndWFnZXMubWFwKChsKSA9PiBjaGFsay5ibHVlKGwpKS5qb2luKCcsICcpfWAsXG4gICAgKTtcbiAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKCdObyBsYW5ndWFnZSB3YXMgc2VsZWN0ZWQnKTtcbiAgfSkoKTtcbn1cblxuLyoqXG4gKiBGaW5kIHBvdGVudGlhbCB0ZW1wbGF0ZSBkaXJlY3RvcmllcyBpbiBhIG11bHRpLXRlbXBsYXRlIHJlcG9zaXRvcnlcbiAqIEBwYXJhbSByZXBvc2l0b3J5UGF0aCAtIFBhdGggdG8gdGhlIHJlcG9zaXRvcnkgcm9vdFxuICogQHJldHVybnMgUHJvbWlzZSByZXNvbHZpbmcgdG8gYXJyYXkgb2YgcG90ZW50aWFsIHRlbXBsYXRlIGRpcmVjdG9yeSBuYW1lc1xuICovXG5hc3luYyBmdW5jdGlvbiBmaW5kUG90ZW50aWFsVGVtcGxhdGVzKHJlcG9zaXRvcnlQYXRoOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZ1tdPiB7XG4gIGNvbnN0IGVudHJpZXMgPSBhd2FpdCBmcy5yZWFkZGlyKHJlcG9zaXRvcnlQYXRoLCB7IHdpdGhGaWxlVHlwZXM6IHRydWUgfSk7XG5cbiAgY29uc3QgdGVtcGxhdGVWYWxpZGF0aW9uUHJvbWlzZXMgPSBlbnRyaWVzXG4gICAgLmZpbHRlcihlbnRyeSA9PiBlbnRyeS5pc0RpcmVjdG9yeSgpICYmICFlbnRyeS5uYW1lLnN0YXJ0c1dpdGgoJy4nKSlcbiAgICAubWFwKGFzeW5jIChlbnRyeSkgPT4ge1xuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgdGVtcGxhdGVQYXRoID0gcGF0aC5qb2luKHJlcG9zaXRvcnlQYXRoLCBlbnRyeS5uYW1lKTtcbiAgICAgICAgY29uc3QgeyBsYW5ndWFnZXMgfSA9IGF3YWl0IGdldExhbmd1YWdlRGlyZWN0b3JpZXModGVtcGxhdGVQYXRoKTtcbiAgICAgICAgcmV0dXJuIGxhbmd1YWdlcy5sZW5ndGggPiAwID8gZW50cnkubmFtZSA6IG51bGw7XG4gICAgICB9IGNhdGNoIChlcnJvcjogYW55KSB7XG4gICAgICAgIC8vIElmIHdlIGNhbid0IHJlYWQgYSBzcGVjaWZpYyB0ZW1wbGF0ZSBkaXJlY3RvcnksIHNraXAgaXQgYnV0IGRvbid0IGZhaWwgdGhlIGVudGlyZSBvcGVyYXRpb25cbiAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgLyogZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIEBjZGtsYWJzL3Byb21pc2VhbGwtbm8tdW5ib3VuZGVkLXBhcmFsbGVsaXNtICovIC8vIExpbWl0ZWQgdG8gZGlyZWN0b3J5IGVudHJpZXNcbiAgY29uc3QgdmFsaWRhdGlvblJlc3VsdHMgPSBhd2FpdCBQcm9taXNlLmFsbCh0ZW1wbGF0ZVZhbGlkYXRpb25Qcm9taXNlcyk7XG4gIHJldHVybiB2YWxpZGF0aW9uUmVzdWx0cy5maWx0ZXIoKHRlbXBsYXRlTmFtZSk6IHRlbXBsYXRlTmFtZSBpcyBzdHJpbmcgPT4gdGVtcGxhdGVOYW1lICE9PSBudWxsKTtcbn1cblxuLyoqXG4gKiBHZXQgdmFsaWQgQ0RLIGxhbmd1YWdlIGRpcmVjdG9yaWVzIGZyb20gYSB0ZW1wbGF0ZSBwYXRoXG4gKiBAcGFyYW0gdGVtcGxhdGVQYXRoIC0gUGF0aCB0byB0aGUgdGVtcGxhdGUgZGlyZWN0b3J5XG4gKiBAcmV0dXJucyBQcm9taXNlIHJlc29sdmluZyB0byBhcnJheSBvZiBzdXBwb3J0ZWQgbGFuZ3VhZ2UgbmFtZXNcbiAqL1xuLyoqXG4gKiBHZXQgdmFsaWQgQ0RLIGxhbmd1YWdlIGRpcmVjdG9yaWVzIGZyb20gYSB0ZW1wbGF0ZSBwYXRoXG4gKiBAcGFyYW0gdGVtcGxhdGVQYXRoIC0gUGF0aCB0byB0aGUgdGVtcGxhdGUgZGlyZWN0b3J5XG4gKiBAcmV0dXJucyBQcm9taXNlIHJlc29sdmluZyB0byBhcnJheSBvZiBzdXBwb3J0ZWQgbGFuZ3VhZ2UgbmFtZXMgYW5kIGRpcmVjdG9yeSBlbnRyaWVzXG4gKiBAdGhyb3dzIFRvb2xraXRFcnJvciBpZiBkaXJlY3RvcnkgY2Fubm90IGJlIHJlYWQgb3IgdmFsaWRhdGVkXG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGdldExhbmd1YWdlRGlyZWN0b3JpZXModGVtcGxhdGVQYXRoOiBzdHJpbmcpOiBQcm9taXNlPHsgbGFuZ3VhZ2VzOiBzdHJpbmdbXTsgZW50cmllczogZnMuRGlyZW50W10gfT4ge1xuICB0cnkge1xuICAgIGNvbnN0IGVudHJpZXMgPSBhd2FpdCBmcy5yZWFkZGlyKHRlbXBsYXRlUGF0aCwgeyB3aXRoRmlsZVR5cGVzOiB0cnVlIH0pO1xuXG4gICAgY29uc3QgbGFuZ3VhZ2VWYWxpZGF0aW9uUHJvbWlzZXMgPSBlbnRyaWVzXG4gICAgICAuZmlsdGVyKGRpcmVjdG9yeUVudHJ5ID0+IGRpcmVjdG9yeUVudHJ5LmlzRGlyZWN0b3J5KCkgJiYgU1VQUE9SVEVEX0xBTkdVQUdFX05BTUVTLmluY2x1ZGVzKGRpcmVjdG9yeUVudHJ5Lm5hbWUpKVxuICAgICAgLm1hcChhc3luYyAoZGlyZWN0b3J5RW50cnkpID0+IHtcbiAgICAgICAgY29uc3QgbGFuZ3VhZ2VEaXJlY3RvcnlQYXRoID0gcGF0aC5qb2luKHRlbXBsYXRlUGF0aCwgZGlyZWN0b3J5RW50cnkubmFtZSk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgY29uc3QgaGFzVmFsaWRMYW5ndWFnZUZpbGVzID0gYXdhaXQgaGFzTGFuZ3VhZ2VGaWxlcyhsYW5ndWFnZURpcmVjdG9yeVBhdGgsIGdldExhbmd1YWdlRXh0ZW5zaW9ucyhkaXJlY3RvcnlFbnRyeS5uYW1lKSk7XG4gICAgICAgICAgcmV0dXJuIGhhc1ZhbGlkTGFuZ3VhZ2VGaWxlcyA/IGRpcmVjdG9yeUVudHJ5Lm5hbWUgOiBudWxsO1xuICAgICAgICB9IGNhdGNoIChlcnJvcjogYW55KSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihgQ2Fubm90IHJlYWQgbGFuZ3VhZ2UgZGlyZWN0b3J5ICcke2RpcmVjdG9yeUVudHJ5Lm5hbWV9JzogJHtlcnJvci5tZXNzYWdlfWApO1xuICAgICAgICB9XG4gICAgICB9KTtcblxuICAgIC8qIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBAY2RrbGFicy9wcm9taXNlYWxsLW5vLXVuYm91bmRlZC1wYXJhbGxlbGlzbSAqLyAvLyBMaW1pdGVkIHRvIHN1cHBvcnRlZCBDREsgbGFuZ3VhZ2VzICg3IG1heClcbiAgICBjb25zdCB2YWxpZGF0aW9uUmVzdWx0cyA9IGF3YWl0IFByb21pc2UuYWxsKGxhbmd1YWdlVmFsaWRhdGlvblByb21pc2VzKTtcbiAgICByZXR1cm4ge1xuICAgICAgbGFuZ3VhZ2VzOiB2YWxpZGF0aW9uUmVzdWx0cy5maWx0ZXIoKGxhbmd1YWdlTmFtZSk6IGxhbmd1YWdlTmFtZSBpcyBzdHJpbmcgPT4gbGFuZ3VhZ2VOYW1lICE9PSBudWxsKSxcbiAgICAgIGVudHJpZXMsXG4gICAgfTtcbiAgfSBjYXRjaCAoZXJyb3I6IGFueSkge1xuICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoYENhbm5vdCByZWFkIHRlbXBsYXRlIGRpcmVjdG9yeSAnJHt0ZW1wbGF0ZVBhdGh9JzogJHtlcnJvci5tZXNzYWdlfWApO1xuICB9XG59XG5cbi8qKlxuICogSXRlcmF0aXZlbHkgY2hlY2sgaWYgYSBkaXJlY3RvcnkgY29udGFpbnMgZmlsZXMgd2l0aCB0aGUgc3BlY2lmaWVkIGV4dGVuc2lvbnNcbiAqIEBwYXJhbSBkaXJlY3RvcnlQYXRoIC0gUGF0aCB0byBzZWFyY2ggZm9yIGxhbmd1YWdlIGZpbGVzXG4gKiBAcGFyYW0gZXh0ZW5zaW9ucyAtIEFycmF5IG9mIGZpbGUgZXh0ZW5zaW9ucyB0byBsb29rIGZvclxuICogQHJldHVybnMgUHJvbWlzZSByZXNvbHZpbmcgdG8gdHJ1ZSBpZiBsYW5ndWFnZSBmaWxlcyBhcmUgZm91bmRcbiAqL1xuYXN5bmMgZnVuY3Rpb24gaGFzTGFuZ3VhZ2VGaWxlcyhkaXJlY3RvcnlQYXRoOiBzdHJpbmcsIGV4dGVuc2lvbnM6IHN0cmluZ1tdKTogUHJvbWlzZTxib29sZWFuPiB7XG4gIGNvbnN0IGRpcnNUb0NoZWNrID0gW2RpcmVjdG9yeVBhdGhdO1xuXG4gIHdoaWxlIChkaXJzVG9DaGVjay5sZW5ndGggPiAwKSB7XG4gICAgY29uc3QgY3VycmVudERpciA9IGRpcnNUb0NoZWNrLnBvcCgpITtcblxuICAgIHRyeSB7XG4gICAgICBjb25zdCBlbnRyaWVzID0gYXdhaXQgZnMucmVhZGRpcihjdXJyZW50RGlyLCB7IHdpdGhGaWxlVHlwZXM6IHRydWUgfSk7XG5cbiAgICAgIGZvciAoY29uc3QgZW50cnkgb2YgZW50cmllcykge1xuICAgICAgICBpZiAoZW50cnkuaXNGaWxlKCkgJiYgZXh0ZW5zaW9ucy5zb21lKGV4dCA9PiBlbnRyeS5uYW1lLmVuZHNXaXRoKGV4dCkpKSB7XG4gICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH0gZWxzZSBpZiAoZW50cnkuaXNEaXJlY3RvcnkoKSkge1xuICAgICAgICAgIGRpcnNUb0NoZWNrLnB1c2gocGF0aC5qb2luKGN1cnJlbnREaXIsIGVudHJ5Lm5hbWUpKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0gY2F0Y2ggKGVycm9yOiBhbnkpIHtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiBmYWxzZTtcbn1cblxuLyoqXG4gKiBSZXR1cm5zIHRoZSBuYW1lIG9mIHRoZSBQeXRob24gZXhlY3V0YWJsZSBmb3IgdGhpcyBPU1xuICogQHJldHVybnMgVGhlIFB5dGhvbiBleGVjdXRhYmxlIG5hbWUgZm9yIHRoZSBjdXJyZW50IHBsYXRmb3JtXG4gKi9cbmZ1bmN0aW9uIHB5dGhvbkV4ZWN1dGFibGUoKSB7XG4gIGxldCBweXRob24gPSAncHl0aG9uMyc7XG4gIGlmIChwcm9jZXNzLnBsYXRmb3JtID09PSAnd2luMzInKSB7XG4gICAgcHl0aG9uID0gJ3B5dGhvbic7XG4gIH1cbiAgcmV0dXJuIHB5dGhvbjtcbn1cbmNvbnN0IElORk9fRE9UX0pTT04gPSAnaW5mby5qc29uJztcblxuaW50ZXJmYWNlIFRlbXBsYXRlSW5pdEluZm8ge1xuICByZWFkb25seSBkZXNjcmlwdGlvbjogc3RyaW5nO1xuICByZWFkb25seSBhbGlhc2VzPzogc3RyaW5nW107XG59XG5cbmVudW0gVGVtcGxhdGVUeXBlIHtcbiAgQlVJTFRfSU4gPSAnYnVpbHRpbicsXG4gIENVU1RPTSA9ICdjdXN0b20nLFxufVxuXG5leHBvcnQgY2xhc3MgSW5pdFRlbXBsYXRlIHtcbiAgcHVibGljIHN0YXRpYyBhc3luYyBmcm9tTmFtZSh0ZW1wbGF0ZXNEaXI6IHN0cmluZywgbmFtZTogc3RyaW5nKSB7XG4gICAgY29uc3QgYmFzZVBhdGggPSBwYXRoLmpvaW4odGVtcGxhdGVzRGlyLCBuYW1lKTtcbiAgICBjb25zdCBsYW5ndWFnZXMgPSBhd2FpdCBsaXN0RGlyZWN0b3J5KGJhc2VQYXRoKTtcbiAgICBjb25zdCBpbml0SW5mbyA9IGF3YWl0IGZzLnJlYWRKc29uKHBhdGguam9pbihiYXNlUGF0aCwgSU5GT19ET1RfSlNPTikpO1xuICAgIHJldHVybiBuZXcgSW5pdFRlbXBsYXRlKGJhc2VQYXRoLCBuYW1lLCBsYW5ndWFnZXMsIGluaXRJbmZvLCBUZW1wbGF0ZVR5cGUuQlVJTFRfSU4pO1xuICB9XG5cbiAgcHVibGljIHN0YXRpYyBhc3luYyBmcm9tUGF0aCh0ZW1wbGF0ZVBhdGg6IHN0cmluZykge1xuICAgIGNvbnN0IGJhc2VQYXRoID0gcGF0aC5yZXNvbHZlKHRlbXBsYXRlUGF0aCk7XG5cbiAgICBpZiAoIWF3YWl0IGZzLnBhdGhFeGlzdHMoYmFzZVBhdGgpKSB7XG4gICAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKGBUZW1wbGF0ZSBwYXRoIGRvZXMgbm90IGV4aXN0OiAke2Jhc2VQYXRofWApO1xuICAgIH1cblxuICAgIGxldCB0ZW1wbGF0ZVNvdXJjZVBhdGggPSBiYXNlUGF0aDtcbiAgICBsZXQgeyBsYW5ndWFnZXMsIGVudHJpZXMgfSA9IGF3YWl0IGdldExhbmd1YWdlRGlyZWN0b3JpZXMoYmFzZVBhdGgpO1xuXG4gICAgaWYgKGxhbmd1YWdlcy5sZW5ndGggPT09IDApIHtcbiAgICAgIGNvbnN0IGxhbmd1YWdlRGlycyA9IGVudHJpZXMuZmlsdGVyKGVudHJ5ID0+XG4gICAgICAgIGVudHJ5LmlzRGlyZWN0b3J5KCkgJiZcbiAgICAgICAgU1VQUE9SVEVEX0xBTkdVQUdFX05BTUVTLmluY2x1ZGVzKGVudHJ5Lm5hbWUpLFxuICAgICAgKTtcblxuICAgICAgaWYgKGxhbmd1YWdlRGlycy5sZW5ndGggPT09IDEpIHtcbiAgICAgICAgLy8gVmFsaWRhdGUgdGhhdCB0aGUgbGFuZ3VhZ2UgZGlyZWN0b3J5IGNvbnRhaW5zIGFwcHJvcHJpYXRlIGZpbGVzXG4gICAgICAgIGNvbnN0IGxhbmdEaXIgPSBsYW5ndWFnZURpcnNbMF0ubmFtZTtcbiAgICAgICAgdGVtcGxhdGVTb3VyY2VQYXRoID0gcGF0aC5qb2luKGJhc2VQYXRoLCBsYW5nRGlyKTtcbiAgICAgICAgY29uc3QgaGFzVmFsaWRGaWxlcyA9IGF3YWl0IGhhc0xhbmd1YWdlRmlsZXModGVtcGxhdGVTb3VyY2VQYXRoLCBnZXRMYW5ndWFnZUV4dGVuc2lvbnMobGFuZ0RpcikpO1xuXG4gICAgICAgIGlmICghaGFzVmFsaWRGaWxlcykge1xuICAgICAgICAgIC8vIElmIHdlIGZvdW5kIGEgbGFuZ3VhZ2UgZGlyZWN0b3J5IGJ1dCBpdCBkb2Vzbid0IGNvbnRhaW4gdmFsaWQgZmlsZXMsIHdlIHNob3VsZCBpbmZvcm0gdGhlIHVzZXJcbiAgICAgICAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKGBGb3VuZCAnJHtsYW5nRGlyfScgZGlyZWN0b3J5IGJ1dCBpdCBkb2Vzbid0IGNvbnRhaW4gdGhlIGV4cGVjdGVkIGxhbmd1YWdlIGZpbGVzLiBFbnN1cmUgdGhlIHRlbXBsYXRlIGNvbnRhaW5zICR7bGFuZ0Rpcn0gc291cmNlIGZpbGVzLmApO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgY29uc3QgbmFtZSA9IHBhdGguYmFzZW5hbWUoYmFzZVBhdGgpO1xuXG4gICAgcmV0dXJuIG5ldyBJbml0VGVtcGxhdGUodGVtcGxhdGVTb3VyY2VQYXRoLCBuYW1lLCBsYW5ndWFnZXMsIG51bGwsIFRlbXBsYXRlVHlwZS5DVVNUT00pO1xuICB9XG5cbiAgcHVibGljIHJlYWRvbmx5IGRlc2NyaXB0aW9uPzogc3RyaW5nO1xuICBwdWJsaWMgcmVhZG9ubHkgYWxpYXNlcyA9IG5ldyBTZXQ8c3RyaW5nPigpO1xuICBwdWJsaWMgcmVhZG9ubHkgdGVtcGxhdGVUeXBlOiBUZW1wbGF0ZVR5cGU7XG5cbiAgY29uc3RydWN0b3IoXG4gICAgcHJpdmF0ZSByZWFkb25seSBiYXNlUGF0aDogc3RyaW5nLFxuICAgIHB1YmxpYyByZWFkb25seSBuYW1lOiBzdHJpbmcsXG4gICAgcHVibGljIHJlYWRvbmx5IGxhbmd1YWdlczogc3RyaW5nW10sXG4gICAgaW5pdEluZm86IFRlbXBsYXRlSW5pdEluZm8gfCBudWxsLFxuICAgIHRlbXBsYXRlVHlwZTogVGVtcGxhdGVUeXBlLFxuICApIHtcbiAgICB0aGlzLnRlbXBsYXRlVHlwZSA9IHRlbXBsYXRlVHlwZTtcbiAgICAvLyBPbmx5IGJ1aWx0LWluIHRlbXBsYXRlcyBoYXZlIGRlc2NyaXB0aW9ucyBhbmQgYWxpYXNlcyBmcm9tIGluZm8uanNvblxuICAgIGlmICh0ZW1wbGF0ZVR5cGUgPT09IFRlbXBsYXRlVHlwZS5CVUlMVF9JTiAmJiBpbml0SW5mbykge1xuICAgICAgdGhpcy5kZXNjcmlwdGlvbiA9IGluaXRJbmZvLmRlc2NyaXB0aW9uO1xuICAgICAgZm9yIChjb25zdCBhbGlhcyBvZiBpbml0SW5mby5hbGlhc2VzIHx8IFtdKSB7XG4gICAgICAgIHRoaXMuYWxpYXNlcy5hZGQoYWxpYXMpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBAcGFyYW0gbmFtZSAtIHRoZSBuYW1lIHRoYXQgaXMgYmVpbmcgY2hlY2tlZFxuICAgKiBAcmV0dXJucyBgYHRydWVgYCBpZiBgYG5hbWVgYCBpcyB0aGUgbmFtZSBvZiB0aGlzIHRlbXBsYXRlIG9yIGFuIGFsaWFzIG9mIGl0LlxuICAgKi9cbiAgcHVibGljIGhhc05hbWUobmFtZTogc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIG5hbWUgPT09IHRoaXMubmFtZSB8fCB0aGlzLmFsaWFzZXMuaGFzKG5hbWUpO1xuICB9XG5cbiAgLyoqXG4gICAqIENyZWF0ZXMgYSBuZXcgaW5zdGFuY2Ugb2YgdGhpcyBgYEluaXRUZW1wbGF0ZWBgIGZvciBhIGdpdmVuIGxhbmd1YWdlIHRvIGEgc3BlY2lmaWVkIGZvbGRlci5cbiAgICpcbiAgICogQHBhcmFtIGxhbmd1YWdlIC0gdGhlIGxhbmd1YWdlIHRvIGluc3RhbnRpYXRlIHRoaXMgdGVtcGxhdGUgd2l0aFxuICAgKiBAcGFyYW0gdGFyZ2V0RGlyZWN0b3J5IC0gdGhlIGRpcmVjdG9yeSB3aGVyZSB0aGUgdGVtcGxhdGUgaXMgdG8gYmUgaW5zdGFudGlhdGVkIGludG9cbiAgICogQHBhcmFtIHN0YWNrTmFtZSAtIHRoZSBuYW1lIG9mIHRoZSBzdGFjayB0byBjcmVhdGVcbiAgICogQGRlZmF1bHQgdW5kZWZpbmVkXG4gICAqIEBwYXJhbSBsaWJWZXJzaW9uIC0gdGhlIHZlcnNpb24gb2YgdGhlIENESyBsaWJyYXJ5IHRvIHVzZVxuICAgKiBAZGVmYXVsdCB1bmRlZmluZWRcbiAgICovXG4gIHB1YmxpYyBhc3luYyBpbnN0YWxsKGlvSGVscGVyOiBJb0hlbHBlciwgbGFuZ3VhZ2U6IHN0cmluZywgdGFyZ2V0RGlyZWN0b3J5OiBzdHJpbmcsIHN0YWNrTmFtZT86IHN0cmluZywgbGliVmVyc2lvbj86IHN0cmluZykge1xuICAgIGlmICh0aGlzLmxhbmd1YWdlcy5pbmRleE9mKGxhbmd1YWdlKSA9PT0gLTEpIHtcbiAgICAgIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLmVycm9yKFxuICAgICAgICBgVGhlICR7Y2hhbGsuYmx1ZShsYW5ndWFnZSl9IGxhbmd1YWdlIGlzIG5vdCBzdXBwb3J0ZWQgZm9yICR7Y2hhbGsuZ3JlZW4odGhpcy5uYW1lKX0gYCArXG4gICAgICAgICAgYChpdCBzdXBwb3J0czogJHt0aGlzLmxhbmd1YWdlcy5tYXAoKGwpID0+IGNoYWxrLmJsdWUobCkpLmpvaW4oJywgJyl9KWAsXG4gICAgICApO1xuICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihgVW5zdXBwb3J0ZWQgbGFuZ3VhZ2U6ICR7bGFuZ3VhZ2V9YCk7XG4gICAgfVxuXG4gICAgY29uc3QgcHJvamVjdEluZm86IFByb2plY3RJbmZvID0ge1xuICAgICAgbmFtZTogZGVjYW1lbGl6ZShwYXRoLmJhc2VuYW1lKHBhdGgucmVzb2x2ZSh0YXJnZXREaXJlY3RvcnkpKSksXG4gICAgICBzdGFja05hbWUsXG4gICAgICB2ZXJzaW9uczogYXdhaXQgbG9hZEluaXRWZXJzaW9ucygpLFxuICAgIH07XG5cbiAgICBpZiAobGliVmVyc2lvbikge1xuICAgICAgcHJvamVjdEluZm8udmVyc2lvbnNbJ2F3cy1jZGstbGliJ10gPSBsaWJWZXJzaW9uO1xuICAgIH1cblxuICAgIGxldCBzb3VyY2VEaXJlY3RvcnkgPSBwYXRoLmpvaW4odGhpcy5iYXNlUGF0aCwgbGFuZ3VhZ2UpO1xuXG4gICAgLy8gRm9yIGF1dG8tZGV0ZWN0ZWQgc2luZ2xlIGxhbmd1YWdlIHRlbXBsYXRlcywgdXNlIGJhc2VQYXRoIGRpcmVjdGx5XG4gICAgaWYgKHRoaXMudGVtcGxhdGVUeXBlID09PSBUZW1wbGF0ZVR5cGUuQ1VTVE9NICYmIHRoaXMubGFuZ3VhZ2VzLmxlbmd0aCA9PT0gMSAmJlxuICAgICAgICBwYXRoLmJhc2VuYW1lKHRoaXMuYmFzZVBhdGgpID09PSBsYW5ndWFnZSkge1xuICAgICAgc291cmNlRGlyZWN0b3J5ID0gdGhpcy5iYXNlUGF0aDtcbiAgICB9XG5cbiAgICBpZiAodGhpcy50ZW1wbGF0ZVR5cGUgPT09IFRlbXBsYXRlVHlwZS5DVVNUT00pIHtcbiAgICAgIC8vIEZvciBjdXN0b20gdGVtcGxhdGVzLCBjb3B5IGZpbGVzIHdpdGhvdXQgcHJvY2Vzc2luZyBwbGFjZWhvbGRlcnNcbiAgICAgIGF3YWl0IHRoaXMuaW5zdGFsbEZpbGVzV2l0aG91dFByb2Nlc3Npbmcoc291cmNlRGlyZWN0b3J5LCB0YXJnZXREaXJlY3RvcnkpO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBGb3IgYnVpbHQtaW4gdGVtcGxhdGVzLCBwcm9jZXNzIHBsYWNlaG9sZGVycyBhcyB1c3VhbFxuICAgICAgYXdhaXQgdGhpcy5pbnN0YWxsRmlsZXMoc291cmNlRGlyZWN0b3J5LCB0YXJnZXREaXJlY3RvcnksIGxhbmd1YWdlLCBwcm9qZWN0SW5mbyk7XG4gICAgICBhd2FpdCB0aGlzLmFwcGx5RnV0dXJlRmxhZ3ModGFyZ2V0RGlyZWN0b3J5KTtcbiAgICAgIGF3YWl0IGludm9rZUJ1aWx0aW5Ib29rcyhcbiAgICAgICAgaW9IZWxwZXIsXG4gICAgICAgIHsgdGFyZ2V0RGlyZWN0b3J5LCBsYW5ndWFnZSwgdGVtcGxhdGVOYW1lOiB0aGlzLm5hbWUgfSxcbiAgICAgICAge1xuICAgICAgICAgIHN1YnN0aXR1dGVQbGFjZWhvbGRlcnNJbjogYXN5bmMgKC4uLmZpbGVOYW1lczogc3RyaW5nW10pID0+IHtcbiAgICAgICAgICAgIGNvbnN0IGZpbGVQcm9jZXNzaW5nUHJvbWlzZXMgPSBmaWxlTmFtZXMubWFwKGFzeW5jIChmaWxlTmFtZSkgPT4ge1xuICAgICAgICAgICAgICBjb25zdCBmdWxsUGF0aCA9IHBhdGguam9pbih0YXJnZXREaXJlY3RvcnksIGZpbGVOYW1lKTtcbiAgICAgICAgICAgICAgY29uc3QgdGVtcGxhdGUgPSBhd2FpdCBmcy5yZWFkRmlsZShmdWxsUGF0aCwgeyBlbmNvZGluZzogJ3V0Zi04JyB9KTtcbiAgICAgICAgICAgICAgYXdhaXQgZnMud3JpdGVGaWxlKGZ1bGxQYXRoLCBleHBhbmRQbGFjZWhvbGRlcnModGVtcGxhdGUsIGxhbmd1YWdlLCBwcm9qZWN0SW5mbykpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAvKiBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgQGNka2xhYnMvcHJvbWlzZWFsbC1uby11bmJvdW5kZWQtcGFyYWxsZWxpc20gKi8gLy8gUHJvY2Vzc2luZyBhIHNtYWxsLCBrbm93biBzZXQgb2YgdGVtcGxhdGUgZmlsZXNcbiAgICAgICAgICAgIGF3YWl0IFByb21pc2UuYWxsKGZpbGVQcm9jZXNzaW5nUHJvbWlzZXMpO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgcGxhY2Vob2xkZXI6IChwaDogc3RyaW5nKSA9PiBleHBhbmRQbGFjZWhvbGRlcnMoYCUke3BofSVgLCBsYW5ndWFnZSwgcHJvamVjdEluZm8pLFxuICAgICAgICB9LFxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIGluc3RhbGxGaWxlcyhzb3VyY2VEaXJlY3Rvcnk6IHN0cmluZywgdGFyZ2V0RGlyZWN0b3J5OiBzdHJpbmcsIGxhbmd1YWdlOiBzdHJpbmcsIHByb2plY3Q6IFByb2plY3RJbmZvKSB7XG4gICAgZm9yIChjb25zdCBmaWxlIG9mIGF3YWl0IGZzLnJlYWRkaXIoc291cmNlRGlyZWN0b3J5KSkge1xuICAgICAgY29uc3QgZnJvbUZpbGUgPSBwYXRoLmpvaW4oc291cmNlRGlyZWN0b3J5LCBmaWxlKTtcbiAgICAgIGNvbnN0IHRvRmlsZSA9IHBhdGguam9pbih0YXJnZXREaXJlY3RvcnksIGV4cGFuZFBsYWNlaG9sZGVycyhmaWxlLCBsYW5ndWFnZSwgcHJvamVjdCkpO1xuICAgICAgaWYgKChhd2FpdCBmcy5zdGF0KGZyb21GaWxlKSkuaXNEaXJlY3RvcnkoKSkge1xuICAgICAgICBhd2FpdCBmcy5ta2Rpcih0b0ZpbGUpO1xuICAgICAgICBhd2FpdCB0aGlzLmluc3RhbGxGaWxlcyhmcm9tRmlsZSwgdG9GaWxlLCBsYW5ndWFnZSwgcHJvamVjdCk7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfSBlbHNlIGlmIChmaWxlLm1hdGNoKC9eLipcXC50ZW1wbGF0ZVxcLlteLl0rJC8pKSB7XG4gICAgICAgIGF3YWl0IHRoaXMuaW5zdGFsbFByb2Nlc3NlZChmcm9tRmlsZSwgdG9GaWxlLnJlcGxhY2UoL1xcLnRlbXBsYXRlKFxcLlteLl0rKSQvLCAnJDEnKSwgbGFuZ3VhZ2UsIHByb2plY3QpO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH0gZWxzZSBpZiAoZmlsZS5tYXRjaCgvXi4qXFwuaG9va1xcLihkLik/W14uXSskLykpIHtcbiAgICAgICAgLy8gSWdub3JlXG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgYXdhaXQgZnMuY29weShmcm9tRmlsZSwgdG9GaWxlKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGFzeW5jIGluc3RhbGxQcm9jZXNzZWQodGVtcGxhdGVQYXRoOiBzdHJpbmcsIHRvRmlsZTogc3RyaW5nLCBsYW5ndWFnZTogc3RyaW5nLCBwcm9qZWN0OiBQcm9qZWN0SW5mbykge1xuICAgIGNvbnN0IHRlbXBsYXRlID0gYXdhaXQgZnMucmVhZEZpbGUodGVtcGxhdGVQYXRoLCB7IGVuY29kaW5nOiAndXRmLTgnIH0pO1xuICAgIGF3YWl0IGZzLndyaXRlRmlsZSh0b0ZpbGUsIGV4cGFuZFBsYWNlaG9sZGVycyh0ZW1wbGF0ZSwgbGFuZ3VhZ2UsIHByb2plY3QpKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDb3B5IHRlbXBsYXRlIGZpbGVzIHdpdGhvdXQgcHJvY2Vzc2luZyBwbGFjZWhvbGRlcnMgKGZvciBjdXN0b20gdGVtcGxhdGVzKVxuICAgKi9cbiAgcHJpdmF0ZSBhc3luYyBpbnN0YWxsRmlsZXNXaXRob3V0UHJvY2Vzc2luZyhzb3VyY2VEaXJlY3Rvcnk6IHN0cmluZywgdGFyZ2V0RGlyZWN0b3J5OiBzdHJpbmcpIHtcbiAgICBhd2FpdCBmcy5jb3B5KHNvdXJjZURpcmVjdG9yeSwgdGFyZ2V0RGlyZWN0b3J5LCB7XG4gICAgICBmaWx0ZXI6IChzcmM6IHN0cmluZykgPT4ge1xuICAgICAgICBjb25zdCBmaWxlbmFtZSA9IHBhdGguYmFzZW5hbWUoc3JjKTtcbiAgICAgICAgcmV0dXJuICFmaWxlbmFtZS5tYXRjaCgvXi4qXFwuaG9va1xcLihkLik/W14uXSskLyk7XG4gICAgICB9LFxuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIEFkZHMgY29udGV4dCB2YXJpYWJsZXMgdG8gYGNkay5qc29uYCBpbiB0aGUgZ2VuZXJhdGVkIHByb2plY3QgZGlyZWN0b3J5IHRvXG4gICAqIGVuYWJsZSBmdXR1cmUgYmVoYXZpb3IgZm9yIG5ldyBwcm9qZWN0cy5cbiAgICovXG4gIHByaXZhdGUgYXN5bmMgYXBwbHlGdXR1cmVGbGFncyhwcm9qZWN0RGlyOiBzdHJpbmcpIHtcbiAgICBjb25zdCBjZGtKc29uID0gcGF0aC5qb2luKHByb2plY3REaXIsICdjZGsuanNvbicpO1xuICAgIGlmICghKGF3YWl0IGZzLnBhdGhFeGlzdHMoY2RrSnNvbikpKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgY29uZmlnID0gYXdhaXQgZnMucmVhZEpzb24oY2RrSnNvbik7XG4gICAgY29uZmlnLmNvbnRleHQgPSB7XG4gICAgICAuLi5jb25maWcuY29udGV4dCxcbiAgICAgIC4uLmF3YWl0IGN1cnJlbnRseVJlY29tbWVuZGVkQXdzQ2RrTGliRmxhZ3MoKSxcbiAgICB9O1xuXG4gICAgYXdhaXQgZnMud3JpdGVKc29uKGNka0pzb24sIGNvbmZpZywgeyBzcGFjZXM6IDIgfSk7XG4gIH1cblxuICBwdWJsaWMgYXN5bmMgYWRkTWlncmF0ZUNvbnRleHQocHJvamVjdERpcjogc3RyaW5nKSB7XG4gICAgY29uc3QgY2RrSnNvbiA9IHBhdGguam9pbihwcm9qZWN0RGlyLCAnY2RrLmpzb24nKTtcbiAgICBpZiAoIShhd2FpdCBmcy5wYXRoRXhpc3RzKGNka0pzb24pKSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IGNvbmZpZyA9IGF3YWl0IGZzLnJlYWRKc29uKGNka0pzb24pO1xuICAgIGNvbmZpZy5jb250ZXh0ID0ge1xuICAgICAgLi4uY29uZmlnLmNvbnRleHQsXG4gICAgICAnY2RrLW1pZ3JhdGUnOiB0cnVlLFxuICAgIH07XG5cbiAgICBhd2FpdCBmcy53cml0ZUpzb24oY2RrSnNvbiwgY29uZmlnLCB7IHNwYWNlczogMiB9KTtcbiAgfVxufVxuXG5leHBvcnQgZnVuY3Rpb24gZXhwYW5kUGxhY2Vob2xkZXJzKHRlbXBsYXRlOiBzdHJpbmcsIGxhbmd1YWdlOiBzdHJpbmcsIHByb2plY3Q6IFByb2plY3RJbmZvKSB7XG4gIGNvbnN0IGNka1ZlcnNpb24gPSBwcm9qZWN0LnZlcnNpb25zWydhd3MtY2RrLWxpYiddO1xuICBjb25zdCBjZGtDbGlWZXJzaW9uID0gcHJvamVjdC52ZXJzaW9uc1snYXdzLWNkayddO1xuICBsZXQgY29uc3RydWN0c1ZlcnNpb24gPSBwcm9qZWN0LnZlcnNpb25zLmNvbnN0cnVjdHM7XG5cbiAgc3dpdGNoIChsYW5ndWFnZSkge1xuICAgIGNhc2UgJ2phdmEnOlxuICAgIGNhc2UgJ2NzaGFycCc6XG4gICAgY2FzZSAnZnNoYXJwJzpcbiAgICAgIGNvbnN0cnVjdHNWZXJzaW9uID0gcmFuZ2VGcm9tU2VtdmVyKGNvbnN0cnVjdHNWZXJzaW9uLCAnYnJhY2tldCcpO1xuICAgICAgYnJlYWs7XG4gICAgY2FzZSAncHl0aG9uJzpcbiAgICAgIGNvbnN0cnVjdHNWZXJzaW9uID0gcmFuZ2VGcm9tU2VtdmVyKGNvbnN0cnVjdHNWZXJzaW9uLCAncGVwJyk7XG4gICAgICBicmVhaztcbiAgfVxuICByZXR1cm4gdGVtcGxhdGVcbiAgICAucmVwbGFjZSgvJW5hbWUlL2csIHByb2plY3QubmFtZSlcbiAgICAucmVwbGFjZSgvJXN0YWNrbmFtZSUvLCBwcm9qZWN0LnN0YWNrTmFtZSA/PyAnJW5hbWUuUGFzY2FsQ2FzZWQlU3RhY2snKVxuICAgIC5yZXBsYWNlKFxuICAgICAgLyVQYXNjYWxOYW1lU3BhY2UlLyxcbiAgICAgIHByb2plY3Quc3RhY2tOYW1lID8gY2FtZWxDYXNlKHByb2plY3Quc3RhY2tOYW1lICsgJ1N0YWNrJywgeyBwYXNjYWxDYXNlOiB0cnVlIH0pIDogJyVuYW1lLlBhc2NhbENhc2VkJScsXG4gICAgKVxuICAgIC5yZXBsYWNlKFxuICAgICAgLyVQYXNjYWxTdGFja1Byb3BzJS8sXG4gICAgICBwcm9qZWN0LnN0YWNrTmFtZSA/IGNhbWVsQ2FzZShwcm9qZWN0LnN0YWNrTmFtZSwgeyBwYXNjYWxDYXNlOiB0cnVlIH0pICsgJ1N0YWNrUHJvcHMnIDogJ1N0YWNrUHJvcHMnLFxuICAgIClcbiAgICAucmVwbGFjZSgvJW5hbWVcXC5jYW1lbENhc2VkJS9nLCBjYW1lbENhc2UocHJvamVjdC5uYW1lKSlcbiAgICAucmVwbGFjZSgvJW5hbWVcXC5QYXNjYWxDYXNlZCUvZywgY2FtZWxDYXNlKHByb2plY3QubmFtZSwgeyBwYXNjYWxDYXNlOiB0cnVlIH0pKVxuICAgIC5yZXBsYWNlKC8lY2RrLXZlcnNpb24lL2csIGNka1ZlcnNpb24pXG4gICAgLnJlcGxhY2UoLyVjZGstY2xpLXZlcnNpb24lL2csIGNka0NsaVZlcnNpb24pXG4gICAgLnJlcGxhY2UoLyVjb25zdHJ1Y3RzLXZlcnNpb24lL2csIGNvbnN0cnVjdHNWZXJzaW9uKVxuICAgIC5yZXBsYWNlKC8lY2RrLWhvbWUlL2csIGNka0hvbWVEaXIoKSlcbiAgICAucmVwbGFjZSgvJW5hbWVcXC5QeXRob25Nb2R1bGUlL2csIHByb2plY3QubmFtZS5yZXBsYWNlKC8tL2csICdfJykpXG4gICAgLnJlcGxhY2UoLyVweXRob24tZXhlY3V0YWJsZSUvZywgcHl0aG9uRXhlY3V0YWJsZSgpKVxuICAgIC5yZXBsYWNlKC8lbmFtZVxcLlN0YWNrTmFtZSUvZywgcHJvamVjdC5uYW1lLnJlcGxhY2UoL1teQS1aYS16MC05LV0vZywgJy0nKSk7XG59XG5cbmludGVyZmFjZSBQcm9qZWN0SW5mbyB7XG4gIC8qKiBUaGUgdmFsdWUgdXNlZCBmb3IgJW5hbWUlICovXG4gIHJlYWRvbmx5IG5hbWU6IHN0cmluZztcbiAgcmVhZG9ubHkgc3RhY2tOYW1lPzogc3RyaW5nO1xuXG4gIHJlYWRvbmx5IHZlcnNpb25zOiBWZXJzaW9ucztcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGF2YWlsYWJsZUluaXRUZW1wbGF0ZXMoKTogUHJvbWlzZTxJbml0VGVtcGxhdGVbXT4ge1xuICB0cnkge1xuICAgIGNvbnN0IHRlbXBsYXRlc0RpciA9IHBhdGguam9pbihjbGlSb290RGlyKCksICdsaWInLCAnaW5pdC10ZW1wbGF0ZXMnKTtcbiAgICBjb25zdCB0ZW1wbGF0ZU5hbWVzID0gYXdhaXQgbGlzdERpcmVjdG9yeSh0ZW1wbGF0ZXNEaXIpO1xuICAgIGNvbnN0IHRlbXBsYXRlUHJvbWlzZXMgPSB0ZW1wbGF0ZU5hbWVzLm1hcCh0ZW1wbGF0ZU5hbWUgPT5cbiAgICAgIEluaXRUZW1wbGF0ZS5mcm9tTmFtZSh0ZW1wbGF0ZXNEaXIsIHRlbXBsYXRlTmFtZSksXG4gICAgKTtcbiAgICAvKiBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgQGNka2xhYnMvcHJvbWlzZWFsbC1uby11bmJvdW5kZWQtcGFyYWxsZWxpc20gKi8gLy8gQnVpbHQtaW4gdGVtcGxhdGVzIGFyZSBsaW1pdGVkIGluIG51bWJlclxuICAgIHJldHVybiBhd2FpdCBQcm9taXNlLmFsbCh0ZW1wbGF0ZVByb21pc2VzKTtcbiAgfSBjYXRjaCAoZXJyb3I6IGFueSkge1xuICAgIC8vIFJldHVybiBlbXB0eSBhcnJheSBpZiB0ZW1wbGF0ZXMgZGlyZWN0b3J5IGRvZXNuJ3QgZXhpc3Qgb3IgY2FuJ3QgYmUgcmVhZFxuICAgIC8vIFRoaXMgYWxsb3dzIHRoZSBDTEkgdG8gZ3JhY2VmdWxseSBoYW5kbGUgbWlzc2luZyBidWlsdC1pbiB0ZW1wbGF0ZXNcbiAgICBpZiAoZXJyb3IuY29kZSA9PT0gJ0VOT0VOVCcgfHwgZXJyb3IuY29kZSA9PT0gJ0VBQ0NFUycpIHtcbiAgICAgIHJldHVybiBbXTtcbiAgICB9XG4gICAgdGhyb3cgZXJyb3I7XG4gIH1cbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGF2YWlsYWJsZUluaXRMYW5ndWFnZXMoKTogUHJvbWlzZTxzdHJpbmdbXT4ge1xuICBjb25zdCB0ZW1wbGF0ZXMgPSBhd2FpdCBhdmFpbGFibGVJbml0VGVtcGxhdGVzKCk7XG4gIGNvbnN0IHJlc3VsdCA9IG5ldyBTZXQ8c3RyaW5nPigpO1xuICBmb3IgKGNvbnN0IHRlbXBsYXRlIG9mIHRlbXBsYXRlcykge1xuICAgIGZvciAoY29uc3QgbGFuZ3VhZ2Ugb2YgdGVtcGxhdGUubGFuZ3VhZ2VzKSB7XG4gICAgICBjb25zdCBhbGlhcyA9IGdldExhbmd1YWdlQWxpYXMobGFuZ3VhZ2UpO1xuICAgICAgcmVzdWx0LmFkZChsYW5ndWFnZSk7XG4gICAgICBhbGlhcyAmJiByZXN1bHQuYWRkKGFsaWFzKTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIFsuLi5yZXN1bHRdO1xufVxuXG4vKipcbiAqIEBwYXJhbSBkaXJQYXRoIC0gaXMgdGhlIGRpcmVjdG9yeSB0byBiZSBsaXN0ZWQuXG4gKiBAcmV0dXJucyB0aGUgbGlzdCBvZiBmaWxlIG9yIGRpcmVjdG9yeSBuYW1lcyBjb250YWluZWQgaW4gYGBkaXJQYXRoYGAsIGV4Y2x1ZGluZyBhbnkgZG90LWZpbGUsIGFuZCBzb3J0ZWQuXG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGxpc3REaXJlY3RvcnkoZGlyUGF0aDogc3RyaW5nKSB7XG4gIHJldHVybiAoXG4gICAgKGF3YWl0IGZzLnJlYWRkaXIoZGlyUGF0aCkpXG4gICAgICAuZmlsdGVyKChwKSA9PiAhcC5zdGFydHNXaXRoKCcuJykpXG4gICAgICAuZmlsdGVyKChwKSA9PiAhKHAgPT09ICdMSUNFTlNFJykpXG4gICAgICAvLyBpZiwgZm9yIHNvbWUgcmVhc29uLCB0aGUgdGVtcCBmb2xkZXIgZm9yIHRoZSBob29rIGRvZXNuJ3QgZ2V0IGRlbGV0ZWQgd2UgZG9uJ3Qgd2FudCB0byBkaXNwbGF5IGl0IGluIHRoaXMgbGlzdFxuICAgICAgLmZpbHRlcigocCkgPT4gIShwID09PSBJTkZPX0RPVF9KU09OKSlcbiAgICAgIC5zb3J0KClcbiAgKTtcbn1cblxuLyoqXG4gKiBQcmludCBhdmFpbGFibGUgdGVtcGxhdGVzIHRvIHRoZSB1c2VyXG4gKiBAcGFyYW0gaW9IZWxwZXIgLSBJTyBoZWxwZXIgZm9yIHVzZXIgaW50ZXJhY3Rpb25cbiAqIEBwYXJhbSBsYW5ndWFnZSAtIFByb2dyYW1taW5nIGxhbmd1YWdlIGZpbHRlclxuICogQGRlZmF1bHQgdW5kZWZpbmVkXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBwcmludEF2YWlsYWJsZVRlbXBsYXRlcyhpb0hlbHBlcjogSW9IZWxwZXIsIGxhbmd1YWdlPzogc3RyaW5nKSB7XG4gIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLmluZm8oJ0F2YWlsYWJsZSB0ZW1wbGF0ZXM6Jyk7XG4gIGZvciAoY29uc3QgdGVtcGxhdGUgb2YgYXdhaXQgYXZhaWxhYmxlSW5pdFRlbXBsYXRlcygpKSB7XG4gICAgaWYgKGxhbmd1YWdlICYmIHRlbXBsYXRlLmxhbmd1YWdlcy5pbmRleE9mKGxhbmd1YWdlKSA9PT0gLTEpIHtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy5pbmZvKGAqICR7Y2hhbGsuZ3JlZW4odGVtcGxhdGUubmFtZSl9OiAke3RlbXBsYXRlLmRlc2NyaXB0aW9uIX1gKTtcbiAgICBjb25zdCBsYW5ndWFnZUFyZyA9IGxhbmd1YWdlXG4gICAgICA/IGNoYWxrLmJvbGQobGFuZ3VhZ2UpXG4gICAgICA6IHRlbXBsYXRlLmxhbmd1YWdlcy5sZW5ndGggPiAxXG4gICAgICAgID8gYFske3RlbXBsYXRlLmxhbmd1YWdlcy5tYXAoKHQpID0+IGNoYWxrLmJvbGQodCkpLmpvaW4oJ3wnKX1dYFxuICAgICAgICA6IGNoYWxrLmJvbGQodGVtcGxhdGUubGFuZ3VhZ2VzWzBdKTtcbiAgICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy5pbmZvKGAgICDilJTilIAgJHtjaGFsay5ibHVlKGBjZGsgaW5pdCAke2NoYWxrLmJvbGQodGVtcGxhdGUubmFtZSl9IC0tbGFuZ3VhZ2U9JHtsYW5ndWFnZUFyZ31gKX1gKTtcbiAgfVxufVxuXG5hc3luYyBmdW5jdGlvbiBpbml0aWFsaXplUHJvamVjdChcbiAgaW9IZWxwZXI6IElvSGVscGVyLFxuICB0ZW1wbGF0ZTogSW5pdFRlbXBsYXRlLFxuICBsYW5ndWFnZTogc3RyaW5nLFxuICBjYW5Vc2VOZXR3b3JrOiBib29sZWFuLFxuICBnZW5lcmF0ZU9ubHk6IGJvb2xlYW4sXG4gIHdvcmtEaXI6IHN0cmluZyxcbiAgc3RhY2tOYW1lPzogc3RyaW5nLFxuICBtaWdyYXRlPzogYm9vbGVhbixcbiAgY2RrVmVyc2lvbj86IHN0cmluZyxcbikge1xuICAvLyBTdGVwIDE6IEVuc3VyZSB0YXJnZXQgZGlyZWN0b3J5IGlzIGVtcHR5XG4gIGF3YWl0IGFzc2VydElzRW1wdHlEaXJlY3Rvcnkod29ya0Rpcik7XG5cbiAgLy8gU3RlcCAyOiBDb3B5IHRlbXBsYXRlIGZpbGVzXG4gIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLmluZm8oYEFwcGx5aW5nIHByb2plY3QgdGVtcGxhdGUgJHtjaGFsay5ncmVlbih0ZW1wbGF0ZS5uYW1lKX0gZm9yICR7Y2hhbGsuYmx1ZShsYW5ndWFnZSl9YCk7XG4gIGF3YWl0IHRlbXBsYXRlLmluc3RhbGwoaW9IZWxwZXIsIGxhbmd1YWdlLCB3b3JrRGlyLCBzdGFja05hbWUsIGNka1ZlcnNpb24pO1xuXG4gIGlmIChtaWdyYXRlKSB7XG4gICAgYXdhaXQgdGVtcGxhdGUuYWRkTWlncmF0ZUNvbnRleHQod29ya0Rpcik7XG4gIH1cblxuICBpZiAoYXdhaXQgZnMucGF0aEV4aXN0cyhgJHt3b3JrRGlyfS9SRUFETUUubWRgKSkge1xuICAgIGNvbnN0IHJlYWRtZSA9IGF3YWl0IGZzLnJlYWRGaWxlKGAke3dvcmtEaXJ9L1JFQURNRS5tZGAsIHsgZW5jb2Rpbmc6ICd1dGYtOCcgfSk7XG4gICAgYXdhaXQgaW9IZWxwZXIuZGVmYXVsdHMuaW5mbyhjaGFsay5ncmVlbihyZWFkbWUpKTtcbiAgfVxuXG4gIGlmICghZ2VuZXJhdGVPbmx5KSB7XG4gICAgLy8gU3RlcCAzOiBJbml0aWFsaXplIEdpdCByZXBvc2l0b3J5IGFuZCBjcmVhdGUgaW5pdGlhbCBjb21taXRcbiAgICBhd2FpdCBpbml0aWFsaXplR2l0UmVwb3NpdG9yeShpb0hlbHBlciwgd29ya0Rpcik7XG5cbiAgICAvLyBTdGVwIDQ6IFBvc3QtaW5zdGFsbCBzdGVwc1xuICAgIGF3YWl0IHBvc3RJbnN0YWxsKGlvSGVscGVyLCBsYW5ndWFnZSwgY2FuVXNlTmV0d29yaywgd29ya0Rpcik7XG4gIH1cblxuICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy5pbmZvKCfinIUgQWxsIGRvbmUhJyk7XG59XG5cbi8qKlxuICogVmFsaWRhdGUgdGhhdCBhIGRpcmVjdG9yeSBleGlzdHMgYW5kIGlzIGVtcHR5IChpZ25vcmluZyBoaWRkZW4gZmlsZXMpXG4gKiBAcGFyYW0gd29ya0RpciAtIERpcmVjdG9yeSBwYXRoIHRvIHZhbGlkYXRlXG4gKiBAdGhyb3dzIFRvb2xraXRFcnJvciBpZiBkaXJlY3RvcnkgZG9lc24ndCBleGlzdCBvciBpcyBub3QgZW1wdHlcbiAqL1xuYXN5bmMgZnVuY3Rpb24gYXNzZXJ0SXNFbXB0eURpcmVjdG9yeSh3b3JrRGlyOiBzdHJpbmcpIHtcbiAgdHJ5IHtcbiAgICBjb25zdCBzdGF0cyA9IGF3YWl0IGZzLnN0YXQod29ya0Rpcik7XG4gICAgaWYgKCFzdGF0cy5pc0RpcmVjdG9yeSgpKSB7XG4gICAgICB0aHJvdyBuZXcgVG9vbGtpdEVycm9yKGBQYXRoIGV4aXN0cyBidXQgaXMgbm90IGEgZGlyZWN0b3J5OiAke3dvcmtEaXJ9YCk7XG4gICAgfVxuXG4gICAgY29uc3QgZmlsZXMgPSBhd2FpdCBmcy5yZWFkZGlyKHdvcmtEaXIpO1xuICAgIGNvbnN0IHZpc2libGVGaWxlcyA9IGZpbGVzLmZpbHRlcihmID0+ICFmLnN0YXJ0c1dpdGgoJy4nKSk7XG5cbiAgICBpZiAodmlzaWJsZUZpbGVzLmxlbmd0aCA+IDApIHtcbiAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoXG4gICAgICAgICdgY2RrIGluaXRgIGNhbm5vdCBiZSBydW4gaW4gYSBub24tZW1wdHkgZGlyZWN0b3J5IVxcbicgK1xuICAgICAgICBgRm91bmQgJHt2aXNpYmxlRmlsZXMubGVuZ3RofSB2aXNpYmxlIGZpbGVzIGluICR7d29ya0Rpcn06XFxuYCArXG4gICAgICAgIHZpc2libGVGaWxlcy5tYXAoZiA9PiBgICAtICR7Zn1gKS5qb2luKCdcXG4nKSxcbiAgICAgICk7XG4gICAgfVxuICB9IGNhdGNoIChlOiBhbnkpIHtcbiAgICBpZiAoZS5jb2RlID09PSAnRU5PRU5UJykge1xuICAgICAgdGhyb3cgbmV3IFRvb2xraXRFcnJvcihcbiAgICAgICAgYERpcmVjdG9yeSBkb2VzIG5vdCBleGlzdDogJHt3b3JrRGlyfVxcbmAgK1xuICAgICAgICAnUGxlYXNlIGNyZWF0ZSB0aGUgZGlyZWN0b3J5IGZpcnN0IHVzaW5nOiBta2RpciAtcCAnICsgd29ya0RpcixcbiAgICAgICk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoYEZhaWxlZCB0byB2YWxpZGF0ZSBkaXJlY3RvcnkgJHt3b3JrRGlyfTogJHtlLm1lc3NhZ2V9YCk7XG4gIH1cbn1cblxuYXN5bmMgZnVuY3Rpb24gaW5pdGlhbGl6ZUdpdFJlcG9zaXRvcnkoaW9IZWxwZXI6IElvSGVscGVyLCB3b3JrRGlyOiBzdHJpbmcpIHtcbiAgaWYgKGF3YWl0IGlzSW5HaXRSZXBvc2l0b3J5KHdvcmtEaXIpKSB7XG4gICAgcmV0dXJuO1xuICB9XG4gIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLmluZm8oJ0luaXRpYWxpemluZyBhIG5ldyBnaXQgcmVwb3NpdG9yeS4uLicpO1xuICB0cnkge1xuICAgIGF3YWl0IGV4ZWN1dGUoaW9IZWxwZXIsICdnaXQnLCBbJ2luaXQnXSwgeyBjd2Q6IHdvcmtEaXIgfSk7XG4gICAgYXdhaXQgZXhlY3V0ZShpb0hlbHBlciwgJ2dpdCcsIFsnYWRkJywgJy4nXSwgeyBjd2Q6IHdvcmtEaXIgfSk7XG4gICAgYXdhaXQgZXhlY3V0ZShpb0hlbHBlciwgJ2dpdCcsIFsnY29tbWl0JywgJy0tbWVzc2FnZT1cIkluaXRpYWwgY29tbWl0XCInLCAnLS1uby1ncGctc2lnbiddLCB7IGN3ZDogd29ya0RpciB9KTtcbiAgfSBjYXRjaCB7XG4gICAgYXdhaXQgaW9IZWxwZXIuZGVmYXVsdHMud2FybignVW5hYmxlIHRvIGluaXRpYWxpemUgZ2l0IHJlcG9zaXRvcnkgZm9yIHlvdXIgcHJvamVjdC4nKTtcbiAgfVxufVxuXG5hc3luYyBmdW5jdGlvbiBwb3N0SW5zdGFsbChpb0hlbHBlcjogSW9IZWxwZXIsIGxhbmd1YWdlOiBzdHJpbmcsIGNhblVzZU5ldHdvcms6IGJvb2xlYW4sIHdvcmtEaXI6IHN0cmluZykge1xuICBzd2l0Y2ggKGxhbmd1YWdlKSB7XG4gICAgY2FzZSAnamF2YXNjcmlwdCc6XG4gICAgICByZXR1cm4gcG9zdEluc3RhbGxKYXZhc2NyaXB0KGlvSGVscGVyLCBjYW5Vc2VOZXR3b3JrLCB3b3JrRGlyKTtcbiAgICBjYXNlICd0eXBlc2NyaXB0JzpcbiAgICAgIHJldHVybiBwb3N0SW5zdGFsbFR5cGVzY3JpcHQoaW9IZWxwZXIsIGNhblVzZU5ldHdvcmssIHdvcmtEaXIpO1xuICAgIGNhc2UgJ2phdmEnOlxuICAgICAgcmV0dXJuIHBvc3RJbnN0YWxsSmF2YShpb0hlbHBlciwgY2FuVXNlTmV0d29yaywgd29ya0Rpcik7XG4gICAgY2FzZSAncHl0aG9uJzpcbiAgICAgIHJldHVybiBwb3N0SW5zdGFsbFB5dGhvbihpb0hlbHBlciwgd29ya0Rpcik7XG4gICAgY2FzZSAnZ28nOlxuICAgICAgcmV0dXJuIHBvc3RJbnN0YWxsR28oaW9IZWxwZXIsIGNhblVzZU5ldHdvcmssIHdvcmtEaXIpO1xuICAgIGNhc2UgJ2NzaGFycCc6XG4gICAgICByZXR1cm4gcG9zdEluc3RhbGxDU2hhcnAoaW9IZWxwZXIsIGNhblVzZU5ldHdvcmssIHdvcmtEaXIpO1xuICAgIGNhc2UgJ2ZzaGFycCc6XG4gICAgICByZXR1cm4gcG9zdEluc3RhbGxGU2hhcnAoaW9IZWxwZXIsIGNhblVzZU5ldHdvcmssIHdvcmtEaXIpO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHBvc3RJbnN0YWxsSmF2YXNjcmlwdChpb0hlbHBlcjogSW9IZWxwZXIsIGNhblVzZU5ldHdvcms6IGJvb2xlYW4sIGN3ZDogc3RyaW5nKSB7XG4gIHJldHVybiBwb3N0SW5zdGFsbFR5cGVzY3JpcHQoaW9IZWxwZXIsIGNhblVzZU5ldHdvcmssIGN3ZCk7XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHBvc3RJbnN0YWxsVHlwZXNjcmlwdChpb0hlbHBlcjogSW9IZWxwZXIsIGNhblVzZU5ldHdvcms6IGJvb2xlYW4sIGN3ZDogc3RyaW5nKSB7XG4gIGNvbnN0IGNvbW1hbmQgPSAnbnBtJztcblxuICBpZiAoIWNhblVzZU5ldHdvcmspIHtcbiAgICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy53YXJuKGBQbGVhc2UgcnVuICcke2NvbW1hbmR9IGluc3RhbGwnIWApO1xuICAgIHJldHVybjtcbiAgfVxuXG4gIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLmluZm8oYEV4ZWN1dGluZyAke2NoYWxrLmdyZWVuKGAke2NvbW1hbmR9IGluc3RhbGxgKX0uLi5gKTtcbiAgdHJ5IHtcbiAgICBhd2FpdCBleGVjdXRlKGlvSGVscGVyLCBjb21tYW5kLCBbJ2luc3RhbGwnXSwgeyBjd2QgfSk7XG4gIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLndhcm4oYCR7Y29tbWFuZH0gaW5zdGFsbCBmYWlsZWQ6IGAgKyBmb3JtYXRFcnJvck1lc3NhZ2UoZSkpO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHBvc3RJbnN0YWxsSmF2YShpb0hlbHBlcjogSW9IZWxwZXIsIGNhblVzZU5ldHdvcms6IGJvb2xlYW4sIGN3ZDogc3RyaW5nKSB7XG4gIC8vIENoZWNrIGlmIHRoaXMgaXMgYSBHcmFkbGUgb3IgTWF2ZW4gcHJvamVjdFxuICBjb25zdCBoYXNHcmFkbGVCdWlsZCA9IGF3YWl0IGZzLnBhdGhFeGlzdHMocGF0aC5qb2luKGN3ZCwgJ2J1aWxkLmdyYWRsZScpKTtcbiAgY29uc3QgaGFzTWF2ZW5Qb20gPSBhd2FpdCBmcy5wYXRoRXhpc3RzKHBhdGguam9pbihjd2QsICdwb20ueG1sJykpO1xuXG4gIGlmIChoYXNHcmFkbGVCdWlsZCkge1xuICAgIC8vIEdyYWRsZSBwcm9qZWN0XG4gICAgY29uc3QgZ3JhZGxlV2FybmluZyA9IFwiUGxlYXNlIHJ1biAnLi9ncmFkbGV3IGJ1aWxkJyFcIjtcbiAgICBpZiAoIWNhblVzZU5ldHdvcmspIHtcbiAgICAgIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLndhcm4oZ3JhZGxlV2FybmluZyk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgYXdhaXQgaW9IZWxwZXIuZGVmYXVsdHMuaW5mbyhcIkV4ZWN1dGluZyAnLi9ncmFkbGV3IGJ1aWxkJ1wiKTtcbiAgICB0cnkge1xuICAgICAgYXdhaXQgZXhlY3V0ZShpb0hlbHBlciwgJy4vZ3JhZGxldycsIFsnYnVpbGQnXSwgeyBjd2QgfSk7XG4gICAgfSBjYXRjaCB7XG4gICAgICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy53YXJuKCdVbmFibGUgdG8gYnVpbGQgR3JhZGxlIHByb2plY3QnKTtcbiAgICAgIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLndhcm4oZ3JhZGxlV2FybmluZyk7XG4gICAgfVxuICB9IGVsc2UgaWYgKGhhc01hdmVuUG9tKSB7XG4gICAgLy8gTWF2ZW4gcHJvamVjdFxuICAgIGNvbnN0IG12blBhY2thZ2VXYXJuaW5nID0gXCJQbGVhc2UgcnVuICdtdm4gcGFja2FnZSchXCI7XG4gICAgaWYgKCFjYW5Vc2VOZXR3b3JrKSB7XG4gICAgICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy53YXJuKG12blBhY2thZ2VXYXJuaW5nKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy5pbmZvKFwiRXhlY3V0aW5nICdtdm4gcGFja2FnZSdcIik7XG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IGV4ZWN1dGUoaW9IZWxwZXIsICdtdm4nLCBbJ3BhY2thZ2UnXSwgeyBjd2QgfSk7XG4gICAgfSBjYXRjaCB7XG4gICAgICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy53YXJuKCdVbmFibGUgdG8gcGFja2FnZSBjb21waWxlZCBjb2RlIGFzIEpBUicpO1xuICAgICAgYXdhaXQgaW9IZWxwZXIuZGVmYXVsdHMud2Fybihtdm5QYWNrYWdlV2FybmluZyk7XG4gICAgfVxuICB9IGVsc2Uge1xuICAgIC8vIE5vIHJlY29nbml6ZWQgYnVpbGQgZmlsZVxuICAgIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLndhcm4oJ05vIGJ1aWxkLmdyYWRsZSBvciBwb20ueG1sIGZvdW5kLiBQbGVhc2Ugc2V0IHVwIHlvdXIgYnVpbGQgc3lzdGVtIG1hbnVhbGx5LicpO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHBvc3RJbnN0YWxsUHl0aG9uKGlvSGVscGVyOiBJb0hlbHBlciwgY3dkOiBzdHJpbmcpIHtcbiAgY29uc3QgcHl0aG9uID0gcHl0aG9uRXhlY3V0YWJsZSgpO1xuXG4gIC8vIENoZWNrIGlmIHJlcXVpcmVtZW50cy50eHQgZXhpc3RzXG4gIGNvbnN0IGhhc1JlcXVpcmVtZW50cyA9IGF3YWl0IGZzLnBhdGhFeGlzdHMocGF0aC5qb2luKGN3ZCwgJ3JlcXVpcmVtZW50cy50eHQnKSk7XG5cbiAgaWYgKGhhc1JlcXVpcmVtZW50cykge1xuICAgIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLmluZm8oYEV4ZWN1dGluZyAke2NoYWxrLmdyZWVuKCdDcmVhdGluZyB2aXJ0dWFsZW52Li4uJyl9YCk7XG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IGV4ZWN1dGUoaW9IZWxwZXIsIHB5dGhvbiwgWyctbScsICd2ZW52JywgJy52ZW52J10sIHsgY3dkIH0pO1xuICAgICAgYXdhaXQgaW9IZWxwZXIuZGVmYXVsdHMuaW5mbyhgRXhlY3V0aW5nICR7Y2hhbGsuZ3JlZW4oJ0luc3RhbGxpbmcgZGVwZW5kZW5jaWVzLi4uJyl9YCk7XG4gICAgICAvLyBJbnN0YWxsIGRlcGVuZGVuY2llcyBpbiB0aGUgdmlydHVhbCBlbnZpcm9ubWVudFxuICAgICAgY29uc3QgcGlwUGF0aCA9IHByb2Nlc3MucGxhdGZvcm0gPT09ICd3aW4zMicgPyAnLnZlbnZcXFxcU2NyaXB0c1xcXFxwaXAnIDogJy52ZW52L2Jpbi9waXAnO1xuICAgICAgYXdhaXQgZXhlY3V0ZShpb0hlbHBlciwgcGlwUGF0aCwgWydpbnN0YWxsJywgJy1yJywgJ3JlcXVpcmVtZW50cy50eHQnXSwgeyBjd2QgfSk7XG4gICAgfSBjYXRjaCB7XG4gICAgICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy53YXJuKCdVbmFibGUgdG8gY3JlYXRlIHZpcnR1YWxlbnYgb3IgaW5zdGFsbCBkZXBlbmRlbmNpZXMgYXV0b21hdGljYWxseScpO1xuICAgICAgYXdhaXQgaW9IZWxwZXIuZGVmYXVsdHMud2FybihgUGxlYXNlIHJ1biAnJHtweXRob259IC1tIHZlbnYgLnZlbnYgJiYgLnZlbnYvYmluL3BpcCBpbnN0YWxsIC1yIHJlcXVpcmVtZW50cy50eHQnIWApO1xuICAgIH1cbiAgfSBlbHNlIHtcbiAgICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy53YXJuKCdObyByZXF1aXJlbWVudHMudHh0IGZvdW5kLiBQbGVhc2Ugc2V0IHVwIHlvdXIgUHl0aG9uIGVudmlyb25tZW50IG1hbnVhbGx5LicpO1xuICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIHBvc3RJbnN0YWxsR28oaW9IZWxwZXI6IElvSGVscGVyLCBjYW5Vc2VOZXR3b3JrOiBib29sZWFuLCBjd2Q6IHN0cmluZykge1xuICBpZiAoIWNhblVzZU5ldHdvcmspIHtcbiAgICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy53YXJuKCdQbGVhc2UgcnVuIFxcJ2dvIG1vZCB0aWR5XFwnIScpO1xuICAgIHJldHVybjtcbiAgfVxuXG4gIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLmluZm8oYEV4ZWN1dGluZyAke2NoYWxrLmdyZWVuKCdnbyBtb2QgdGlkeScpfS4uLmApO1xuICB0cnkge1xuICAgIGF3YWl0IGV4ZWN1dGUoaW9IZWxwZXIsICdnbycsIFsnbW9kJywgJ3RpZHknXSwgeyBjd2QgfSk7XG4gIH0gY2F0Y2ggKGU6IGFueSkge1xuICAgIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLndhcm4oJ1xcJ2dvIG1vZCB0aWR5XFwnIGZhaWxlZDogJyArIGZvcm1hdEVycm9yTWVzc2FnZShlKSk7XG4gIH1cbn1cblxuYXN5bmMgZnVuY3Rpb24gcG9zdEluc3RhbGxDU2hhcnAoaW9IZWxwZXI6IElvSGVscGVyLCBjYW5Vc2VOZXR3b3JrOiBib29sZWFuLCBjd2Q6IHN0cmluZykge1xuICBjb25zdCBkb3RuZXRXYXJuaW5nID0gXCJQbGVhc2UgcnVuICdkb3RuZXQgcmVzdG9yZSAmJiBkb3RuZXQgYnVpbGQnIVwiO1xuICBpZiAoIWNhblVzZU5ldHdvcmspIHtcbiAgICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy53YXJuKGRvdG5ldFdhcm5pbmcpO1xuICAgIHJldHVybjtcbiAgfVxuXG4gIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLmluZm8oYEV4ZWN1dGluZyAke2NoYWxrLmdyZWVuKCdkb3RuZXQgcmVzdG9yZScpfS4uLmApO1xuICB0cnkge1xuICAgIGF3YWl0IGV4ZWN1dGUoaW9IZWxwZXIsICdkb3RuZXQnLCBbJ3Jlc3RvcmUnXSwgeyBjd2QgfSk7XG4gICAgYXdhaXQgaW9IZWxwZXIuZGVmYXVsdHMuaW5mbyhgRXhlY3V0aW5nICR7Y2hhbGsuZ3JlZW4oJ2RvdG5ldCBidWlsZCcpfS4uLmApO1xuICAgIGF3YWl0IGV4ZWN1dGUoaW9IZWxwZXIsICdkb3RuZXQnLCBbJ2J1aWxkJ10sIHsgY3dkIH0pO1xuICB9IGNhdGNoIChlOiBhbnkpIHtcbiAgICBhd2FpdCBpb0hlbHBlci5kZWZhdWx0cy53YXJuKCdVbmFibGUgdG8gcmVzdG9yZS9idWlsZCAuTkVUIHByb2plY3Q6ICcgKyBmb3JtYXRFcnJvck1lc3NhZ2UoZSkpO1xuICAgIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLndhcm4oZG90bmV0V2FybmluZyk7XG4gIH1cbn1cblxuYXN5bmMgZnVuY3Rpb24gcG9zdEluc3RhbGxGU2hhcnAoaW9IZWxwZXI6IElvSGVscGVyLCBjYW5Vc2VOZXR3b3JrOiBib29sZWFuLCBjd2Q6IHN0cmluZykge1xuICAvLyBGIyB1c2VzIHRoZSBzYW1lIGJ1aWxkIHN5c3RlbSBhcyBDI1xuICByZXR1cm4gcG9zdEluc3RhbGxDU2hhcnAoaW9IZWxwZXIsIGNhblVzZU5ldHdvcmssIGN3ZCk7XG59XG5cbi8qKlxuICogQHBhcmFtIGRpciAtIGEgZGlyZWN0b3J5IHRvIGJlIGNoZWNrZWRcbiAqIEByZXR1cm5zIHRydWUgaWYgYGBkaXJgYCBpcyB3aXRoaW4gYSBnaXQgcmVwb3NpdG9yeS5cbiAqL1xuYXN5bmMgZnVuY3Rpb24gaXNJbkdpdFJlcG9zaXRvcnkoZGlyOiBzdHJpbmcpIHtcbiAgd2hpbGUgKHRydWUpIHtcbiAgICBpZiAoYXdhaXQgZnMucGF0aEV4aXN0cyhwYXRoLmpvaW4oZGlyLCAnLmdpdCcpKSkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGlmIChpc1Jvb3QoZGlyKSkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgICBkaXIgPSBwYXRoLmRpcm5hbWUoZGlyKTtcbiAgfVxufVxuXG4vKipcbiAqIEBwYXJhbSBkaXIgLSBhIGRpcmVjdG9yeSB0byBiZSBjaGVja2VkLlxuICogQHJldHVybnMgdHJ1ZSBpZiBgYGRpcmBgIGlzIHRoZSByb290IG9mIGEgZmlsZXN5c3RlbS5cbiAqL1xuZnVuY3Rpb24gaXNSb290KGRpcjogc3RyaW5nKSB7XG4gIHJldHVybiBwYXRoLmRpcm5hbWUoZGlyKSA9PT0gZGlyO1xufVxuXG4vKipcbiAqIEV4ZWN1dGVzIGBjb21tYW5kYC4gU1RERVJSIGlzIGVtaXR0ZWQgaW4gcmVhbC10aW1lLlxuICpcbiAqIElmIGNvbW1hbmQgZXhpdHMgd2l0aCBub24temVybyBleGl0IGNvZGUsIGFuIGV4Y2VwdGlvbiBpcyB0aHJvd24gYW5kIGluY2x1ZGVzXG4gKiB0aGUgY29udGVudHMgb2YgU1RET1VULlxuICpcbiAqIEByZXR1cm5zIFNURE9VVCAoaWYgc3VjY2Vzc2Z1bCkuXG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGV4ZWN1dGUoaW9IZWxwZXI6IElvSGVscGVyLCBjbWQ6IHN0cmluZywgYXJnczogc3RyaW5nW10sIHsgY3dkIH06IHsgY3dkOiBzdHJpbmcgfSkge1xuICBjb25zdCBjaGlsZCA9IGNoaWxkUHJvY2Vzcy5zcGF3bihjbWQsIGFyZ3MsIHtcbiAgICBjd2QsXG4gICAgc2hlbGw6IHRydWUsXG4gICAgc3RkaW86IFsnaWdub3JlJywgJ3BpcGUnLCAnaW5oZXJpdCddLFxuICB9KTtcbiAgbGV0IHN0ZG91dCA9ICcnO1xuICBjaGlsZC5zdGRvdXQub24oJ2RhdGEnLCAoY2h1bmspID0+IChzdGRvdXQgKz0gY2h1bmsudG9TdHJpbmcoKSkpO1xuICByZXR1cm4gbmV3IFByb21pc2U8c3RyaW5nPigob2ssIGZhaWwpID0+IHtcbiAgICBjaGlsZC5vbmNlKCdlcnJvcicsIChlcnIpID0+IGZhaWwoZXJyKSk7XG4gICAgY2hpbGQub25jZSgnZXhpdCcsIChzdGF0dXMpID0+IHtcbiAgICAgIGlmIChzdGF0dXMgPT09IDApIHtcbiAgICAgICAgcmV0dXJuIG9rKHN0ZG91dCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gZmFpbChuZXcgVG9vbGtpdEVycm9yKGAke2NtZH0gZXhpdGVkIHdpdGggc3RhdHVzICR7c3RhdHVzfWApKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfSkuY2F0Y2goYXN5bmMgKGVycikgPT4ge1xuICAgIGF3YWl0IGlvSGVscGVyLmRlZmF1bHRzLmVycm9yKHN0ZG91dCk7XG4gICAgdGhyb3cgZXJyO1xuICB9KTtcbn1cblxuaW50ZXJmYWNlIFZlcnNpb25zIHtcbiAgWydhd3MtY2RrJ106IHN0cmluZztcbiAgWydhd3MtY2RrLWxpYiddOiBzdHJpbmc7XG4gIGNvbnN0cnVjdHM6IHN0cmluZztcbn1cblxuLyoqXG4gKiBSZXR1cm4gdGhlICdhd3MtY2RrLWxpYicgdmVyc2lvbiB3ZSB3aWxsIGluaXRcbiAqXG4gKiBUaGlzIGhhcyBiZWVuIGJ1aWx0IGludG8gdGhlIENMSSBhdCBidWlsZCB0aW1lLlxuICovXG5hc3luYyBmdW5jdGlvbiBsb2FkSW5pdFZlcnNpb25zKCk6IFByb21pc2U8VmVyc2lvbnM+IHtcbiAgY29uc3QgaW5pdFZlcnNpb25GaWxlID0gcGF0aC5qb2luKGNsaVJvb3REaXIoKSwgJ2xpYicsICdpbml0LXRlbXBsYXRlcycsICcuaW5pdC12ZXJzaW9uLmpzb24nKTtcbiAgY29uc3QgY29udGVudHMgPSBKU09OLnBhcnNlKGF3YWl0IGZzLnJlYWRGaWxlKGluaXRWZXJzaW9uRmlsZSwgeyBlbmNvZGluZzogJ3V0Zi04JyB9KSk7XG5cbiAgY29uc3QgcmV0ID0ge1xuICAgICdhd3MtY2RrLWxpYic6IGNvbnRlbnRzWydhd3MtY2RrLWxpYiddLFxuICAgICdjb25zdHJ1Y3RzJzogY29udGVudHMuY29uc3RydWN0cyxcbiAgICAnYXdzLWNkayc6IHZlcnNpb25OdW1iZXIoKSxcbiAgfTtcbiAgZm9yIChjb25zdCBba2V5LCB2YWx1ZV0gb2YgT2JqZWN0LmVudHJpZXMocmV0KSkge1xuICAgIGlmICghdmFsdWUpIHtcbiAgICAgIHRocm93IG5ldyBUb29sa2l0RXJyb3IoYE1pc3NpbmcgaW5pdCB2ZXJzaW9uIGZyb20gJHtpbml0VmVyc2lvbkZpbGV9OiAke2tleX1gKTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gcmV0O1xufVxuXG4vKipcbiAqIFJldHVybiB0aGUgY3VycmVudGx5IHJlY29tbWVuZGVkIGZsYWdzIGZvciBgYXdzLWNkay1saWJgLlxuICpcbiAqIFRoZXNlIGhhdmUgYmVlbiBidWlsdCBpbnRvIHRoZSBDTEkgYXQgYnVpbGQgdGltZS5cbiAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGN1cnJlbnRseVJlY29tbWVuZGVkQXdzQ2RrTGliRmxhZ3MoKSB7XG4gIGNvbnN0IHJlY29tbWVuZGVkRmxhZ3NGaWxlID0gcGF0aC5qb2luKGNsaVJvb3REaXIoKSwgJ2xpYicsICdpbml0LXRlbXBsYXRlcycsICcucmVjb21tZW5kZWQtZmVhdHVyZS1mbGFncy5qc29uJyk7XG4gIHJldHVybiBKU09OLnBhcnNlKGF3YWl0IGZzLnJlYWRGaWxlKHJlY29tbWVuZGVkRmxhZ3NGaWxlLCB7IGVuY29kaW5nOiAndXRmLTgnIH0pKTtcbn1cbiJdfQ==